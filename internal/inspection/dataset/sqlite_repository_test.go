package dataset

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

type repositoryFixture struct {
	now        time.Time
	clock      *time.Time
	verifier   *MemoryReviewVerifier
	governance *MemoryGovernanceAuthorizer
}

type phaseGovernanceAuthorizer struct {
	denyPreflight bool
	preflights    atomic.Int32
	finals        atomic.Int32
}

func (a *phaseGovernanceAuthorizer) PreflightGovernance(context.Context, GovernancePreflightDemand) error {
	a.preflights.Add(1)
	if a.denyPreflight {
		return ErrUnauthorized
	}
	return nil
}
func (a *phaseGovernanceAuthorizer) AuthorizeGovernance(context.Context, GovernanceDemand) error {
	a.finals.Add(1)
	return ErrUnauthorized
}

func newRepositoryFixture() *repositoryFixture {
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	return &repositoryFixture{now: now, clock: &now, verifier: NewMemoryReviewVerifier(), governance: NewMemoryGovernanceAuthorizer()}
}

func (f *repositoryFixture) options() SQLiteRepositoryOptions {
	return SQLiteRepositoryOptions{GovernanceAuthorizer: f.governance, ReviewVerifier: f.verifier, Now: func() time.Time { return *f.clock }, IntegrityKey: []byte("0123456789abcdef0123456789abcdef")}
}

func TestSQLiteRepositoryCreateReopenAndMultipleAnnotations(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "inspection-datasets-v3.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := repository.CreateWithReceipt(context.Background(), accepted)
	if err != nil || receipt.ContentSHA256 == "" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	got, err := repository.Get(context.Background(), accepted.TenantStratum, accepted.SiteStratum, accepted.DatasetID, accepted.Revision)
	if err != nil || !equalProjection(got, accepted) || len(got.Items[0].Annotations) != 2 {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	got, err = reopened.Get(context.Background(), accepted.TenantStratum, accepted.SiteStratum, accepted.DatasetID, accepted.Revision)
	if err != nil || !equalProjection(got, accepted) {
		t.Fatalf("reopened=%#v err=%v", got, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), accepted.Items[0].MediaRef) || !strings.Contains(string(raw), accepted.Items[0].Annotations[1].CriterionID) {
		t.Fatal("media or annotation was not persisted")
	}
	for _, forbidden := range []string{fixtureTenant, fixtureSite, "source-private-1", "rtsp://", "https://", protectedDatasetRootPathFragment(path)} {
		if forbidden != "" && strings.Contains(string(raw), forbidden) {
			t.Fatalf("database leaked %q", forbidden)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
		}
	}
}

func TestSQLiteGlobalSplitLedgerAcrossDatasetAndRevision(t *testing.T) {
	base := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	repository, err := OpenSQLiteRepository(filepath.Join(protectedDatasetRoot(t), "ledger-v3.db"), config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Create(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	sameSplit := cloneDataset(base, true)
	sameSplit.DatasetID = "dataset-another"
	sameSplit.Revision = 8
	sameSplit.admissionSHA256, _ = admissionDigest(sameSplit)
	if err := repository.Create(context.Background(), sameSplit); err != nil {
		t.Fatalf("same split reuse must be stable: %v", err)
	}
	leaking := cloneDataset(base, true)
	leaking.DatasetID = "dataset-leaking"
	leaking.Revision = 9
	for index := range leaking.claims {
		if leaking.claims[index].Split == SplitTrain {
			leaking.claims[index].Split = SplitTest
			break
		}
	}
	sortClaims(leaking.claims)
	leaking.admissionSHA256, _ = admissionDigest(leaking)
	if err := repository.Create(context.Background(), leaking); !errors.Is(err, ErrLeakage) {
		t.Fatalf("cross-revision leakage error=%v", err)
	}
	var datasets, ledger int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM dataset_records`).Scan(&datasets); err != nil || datasets != 2 {
		t.Fatalf("datasets=%d err=%v", datasets, err)
	}
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM identity_ledger`).Scan(&ledger); err != nil || ledger == 0 {
		t.Fatalf("ledger=%d err=%v", ledger, err)
	}
	var primaryScope int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('identity_ledger') WHERE pk>0 AND name IN ('dataset_id','revision','split')`).Scan(&primaryScope); err != nil || primaryScope != 0 {
		t.Fatalf("ledger key includes scope/split: %d err=%v", primaryScope, err)
	}
}

func TestSQLiteGlobalSplitLedgerSerializesCompetingSplits(t *testing.T) {
	base := fixtureAcceptedDataset(t)
	leaking := cloneDataset(base, true)
	leaking.DatasetID = "dataset-competing-split"
	leaking.Revision = 2
	for index := range leaking.claims {
		if leaking.claims[index].Split == SplitTrain {
			leaking.claims[index].Split = SplitTest
			break
		}
	}
	sortClaims(leaking.claims)
	leaking.admissionSHA256, _ = admissionDigest(leaking)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "competing-ledger-v3.db")
	first, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- first.Create(context.Background(), base) }()
	go func() { <-start; results <- second.Create(context.Background(), leaking) }()
	close(start)
	successes, leakages := 0, 0
	for index := 0; index < 2; index++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLeakage):
			leakages++
		default:
			t.Fatalf("competing create error=%v", err)
		}
	}
	if successes != 1 || leakages != 1 {
		t.Fatalf("success=%d leakage=%d", successes, leakages)
	}
}

func TestSQLiteSourceIntervalLedgerRejectsAdjacentSplitAfterRestart(t *testing.T) {
	base := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "source-interval-restart-v3.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Create(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	repository, err = OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer repository.Close()
	neighbor := cloneDataset(base, true)
	neighbor.DatasetID = "dataset-adjacent-other-revision"
	neighbor.Revision = 77
	changed := false
	for index := range neighbor.sourceIntervals {
		if neighbor.sourceIntervals[index].Split != SplitTrain {
			continue
		}
		neighbor.sourceIntervals[index] = shiftInterval(t, neighbor.sourceIntervals[index], time.Second, SplitTest)
		changed = true
		break
	}
	if !changed {
		t.Fatal("fixture has no train interval")
	}
	sortSourceIntervals(neighbor.sourceIntervals)
	neighbor.admissionSHA256, _ = admissionDigest(neighbor)
	if err := repository.Create(context.Background(), neighbor); !errors.Is(err, ErrLeakage) {
		t.Fatalf("adjacent cross-revision error=%v", err)
	}
	var records int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM dataset_records`).Scan(&records); err != nil || records != 1 {
		t.Fatalf("records=%d err=%v", records, err)
	}
	var intervals int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM source_interval_ledger`).Scan(&intervals); err != nil || intervals != len(base.sourceIntervals) {
		t.Fatalf("intervals=%d err=%v", intervals, err)
	}
}

func TestSQLiteConcurrentCreateIsTransactional(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "concurrent-v3.db")
	first, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	const workers = 20
	start := make(chan struct{})
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			target := first
			if index%2 == 1 {
				target = second
			}
			results <- target.Create(context.Background(), accepted)
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			t.Fatalf("create error=%v", err)
		}
	}
	if successes != workers {
		t.Fatalf("success=%d", successes)
	}
	different := cloneDataset(accepted, true)
	different.PurposeRef = "purpose-different-content"
	different.admissionSHA256, _ = admissionDigest(different)
	if err := second.Create(context.Background(), different); !errors.Is(err, ErrConflict) {
		t.Fatalf("different-content error=%v", err)
	}
}

func TestCreateOutcomeUnknownResolvesBothCommitSides(t *testing.T) {
	for _, test := range []struct {
		name   string
		commit bool
		want   CreateResolutionState
	}{
		{"before commit", false, CreateNotCommitted},
		{"after commit", true, CreateCommitted},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted := fixtureAcceptedDataset(t)
			config := newRepositoryFixture()
			repository, err := OpenSQLiteRepository(filepath.Join(protectedDatasetRoot(t), "create-"+test.name+".db"), config.options())
			if err != nil {
				t.Fatal(err)
			}
			defer repository.Close()
			repository.commit = func(tx *sql.Tx) error {
				if test.commit {
					if err := tx.Commit(); err != nil {
						return err
					}
				}
				return errors.New("lost commit acknowledgement")
			}
			_, err = repository.CreateWithReceipt(context.Background(), accepted)
			var unknown *CreateOutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("error=%v", err)
			}
			resolution, err := repository.ResolveCreate(context.Background(), unknown.Receipt)
			if err != nil || resolution.State != test.want {
				t.Fatalf("resolution=%#v err=%v", resolution, err)
			}
		})
	}
}

func TestTrustedReviewRepositoryPersistsOnlyVerifiedRecords(t *testing.T) {
	f := newFixture(t, nil)
	item := f.request.Items[0]
	subject, _ := BuildReviewSubject(f.request, item, item.Annotations[0], f.descriptors[0])
	annotationDigest, _ := AnnotationSHA256(subject)
	record := ReviewRecord{Schema: ReviewSchema, ReviewID: "review-persistent", AnnotationSHA256: annotationDigest, ReviewerSHA256: strings.Repeat("d", 64), ReviewerRole: ReviewerRoleDataset, Decision: ReviewApproved, PolicyRef: f.request.Policy.ReviewPolicyRef, ReviewedAt: f.now.Add(-20 * time.Minute)}
	record.RecordSHA256, _ = ReviewRecordSHA256(record)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "reviews-v3.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordReview(context.Background(), record); !errors.Is(err, ErrReviewIncomplete) {
		t.Fatalf("untrusted record error=%v", err)
	}
	if err := config.verifier.Trust(record); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordReview(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordReview(context.Background(), record); err != nil {
		t.Fatalf("idempotent review retry: %v", err)
	}
	reviews, err := repository.ListReviews(context.Background(), ReviewQuery{AnnotationSHA256: annotationDigest, PolicyRef: record.PolicyRef, NotAfter: f.now})
	if err != nil || len(reviews) != 1 || reviews[0].RecordSHA256 != record.RecordSHA256 {
		t.Fatalf("reviews=%#v err=%v", reviews, err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	reviews, err = reopened.ListReviews(context.Background(), ReviewQuery{AnnotationSHA256: annotationDigest, PolicyRef: record.PolicyRef, NotAfter: f.now})
	if err != nil || len(reviews) != 1 || reviews[0].RecordSHA256 != record.RecordSHA256 {
		t.Fatalf("reopened reviews=%#v err=%v", reviews, err)
	}
}

func TestReviewRepositoryEnforcesPerAnnotationCapacity(t *testing.T) {
	config := newRepositoryFixture()
	repository, err := OpenSQLiteRepository(filepath.Join(protectedDatasetRoot(t), "review-capacity.db"), config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	annotationDigest := strings.Repeat("1", 64)
	for index := 0; index <= maximumReviewDecisions; index++ {
		record := ReviewRecord{Schema: ReviewSchema, ReviewID: fmt.Sprintf("review-capacity-%02d", index), AnnotationSHA256: annotationDigest,
			ReviewerSHA256: fmt.Sprintf("%064x", index+1), ReviewerRole: ReviewerRoleDataset, Decision: ReviewApproved,
			PolicyRef: "capacity-review-policy", ReviewedAt: config.now.Add(time.Duration(index) * time.Second)}
		record.RecordSHA256, _ = ReviewRecordSHA256(record)
		if err := config.verifier.Trust(record); err != nil {
			t.Fatal(err)
		}
		err := repository.RecordReview(context.Background(), record)
		if index < maximumReviewDecisions && err != nil {
			t.Fatalf("index=%d error=%v", index, err)
		}
		if index == maximumReviewDecisions && !errors.Is(err, ErrCapacity) {
			t.Fatalf("capacity error=%v", err)
		}
	}
}

func TestPurgeRequiresAuthorityRetentionAndLeavesPermanentTombstone(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "purge-v3.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	receipt, err := repository.CreateWithReceipt(context.Background(), accepted)
	if err != nil {
		t.Fatal(err)
	}
	request := purgeRequestFor(accepted, "purge-operation-a")
	installPurgeGrant(t, config.governance, request, receipt.ContentSHA256, accepted.RetainUntil, *config.clock)
	if _, err := repository.Purge(context.Background(), request); !errors.Is(err, ErrRetentionActive) {
		t.Fatalf("early purge error=%v", err)
	}
	*config.clock = accepted.RetainUntil.Add(time.Hour)
	unauthorized := request
	unauthorized.AuthorityRef = "purge-authority-missing"
	unauthorized.OperationID = "purge-operation-unauthorized"
	if _, err := repository.Purge(context.Background(), unauthorized); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unauthorized purge error=%v", err)
	}
	request = purgeRequestFor(accepted, "purge-operation-final")
	request.AuthorityRef = "purge-authority-final"
	installPurgeGrant(t, config.governance, request, receipt.ContentSHA256, accepted.RetainUntil, *config.clock)
	purgeReceipt, err := repository.Purge(context.Background(), request)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	resolution, err := repository.ResolvePurge(context.Background(), purgeReceipt)
	if err != nil || resolution.State != PurgeCompleted {
		t.Fatalf("resolution=%#v err=%v", resolution, err)
	}
	if _, err := repository.Get(context.Background(), accepted.TenantStratum, accepted.SiteStratum, accepted.DatasetID, accepted.Revision); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("get error=%v", err)
	}
	governance, err := repository.GetGovernance(context.Background(), accepted.TenantStratum, accepted.SiteStratum, accepted.DatasetID, accepted.Revision)
	if err != nil || governance.State != GovernanceTombstoned || governance.TombstonedAt == nil {
		t.Fatalf("governance=%#v err=%v", governance, err)
	}
	var items, claims, sourceIntervals, operations int
	_ = repository.db.QueryRow(`SELECT COUNT(*) FROM dataset_items`).Scan(&items)
	_ = repository.db.QueryRow(`SELECT COUNT(*) FROM dataset_identity_claims`).Scan(&claims)
	_ = repository.db.QueryRow(`SELECT COUNT(*) FROM source_interval_ledger`).Scan(&sourceIntervals)
	_ = repository.db.QueryRow(`SELECT COUNT(*) FROM governance_operations`).Scan(&operations)
	if items != 0 || claims == 0 || sourceIntervals != len(accepted.sourceIntervals) || operations != 1 {
		t.Fatalf("items=%d claims=%d sourceIntervals=%d operations=%d", items, claims, sourceIntervals, operations)
	}
}

func TestPurgeOutcomeUnknownRecoveryBeforeAndAfterCommit(t *testing.T) {
	for _, test := range []struct {
		name        string
		commitPhase bool
		want        PurgeResolutionState
	}{{"before commit", false, PurgeNotStarted}, {"after commit", true, PurgePending}} {
		t.Run(test.name, func(t *testing.T) {
			accepted := fixtureAcceptedDataset(t)
			config := newRepositoryFixture()
			path := filepath.Join(protectedDatasetRoot(t), test.name+".db")
			repository, err := OpenSQLiteRepository(path, config.options())
			if err != nil {
				t.Fatal(err)
			}
			defer repository.Close()
			createReceipt, err := repository.CreateWithReceipt(context.Background(), accepted)
			if err != nil {
				t.Fatal(err)
			}
			*config.clock = accepted.RetainUntil.Add(time.Hour)
			request := purgeRequestFor(accepted, "purge-unknown")
			installPurgeGrant(t, config.governance, request, createReceipt.ContentSHA256, accepted.RetainUntil, *config.clock)
			repository.commit = func(tx *sql.Tx) error {
				if test.commitPhase {
					if err := tx.Commit(); err != nil {
						return err
					}
				}
				return errors.New("lost commit acknowledgement")
			}
			_, err = repository.Purge(context.Background(), request)
			var unknown *PurgeOutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("error=%v", err)
			}
			resolution, resolveErr := repository.ResolvePurge(context.Background(), unknown.Receipt)
			if resolveErr != nil && test.want != PurgeNotStarted {
				t.Fatalf("resolve=%v", resolveErr)
			}
			if resolution.State != test.want {
				t.Fatalf("state=%s want=%s", resolution.State, test.want)
			}
			if test.want == PurgePending {
				if err := repository.Close(); err != nil {
					t.Fatal(err)
				}
				repository, err = OpenSQLiteRepository(path, config.options())
				if err != nil {
					t.Fatalf("restart pending repository: %v", err)
				}
				defer repository.Close()
				recovered, err := repository.RecoverPurges(context.Background())
				if err != nil || len(recovered) != 1 {
					t.Fatalf("recovered=%#v err=%v", recovered, err)
				}
				resolution, err = repository.ResolvePurge(context.Background(), unknown.Receipt)
				if err != nil || resolution.State != PurgeCompleted {
					t.Fatalf("final=%#v err=%v", resolution, err)
				}
			}
		})
	}
}

func TestRecoverPurgeRejectsForgedAuthorizationProof(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	repository, err := OpenSQLiteRepository(filepath.Join(protectedDatasetRoot(t), "purge-forged-proof.db"), config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	createReceipt, err := repository.CreateWithReceipt(context.Background(), accepted)
	if err != nil {
		t.Fatal(err)
	}
	*config.clock = accepted.RetainUntil.Add(time.Hour)
	request := purgeRequestFor(accepted, "purge-forged-proof")
	installPurgeGrant(t, config.governance, request, createReceipt.ContentSHA256, accepted.RetainUntil, *config.clock)
	repository.commit = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("lost commit acknowledgement")
	}
	_, err = repository.Purge(context.Background(), request)
	var unknown *PurgeOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("error=%v", err)
	}
	repository.commit = func(tx *sql.Tx) error { return tx.Commit() }
	var authorizationRaw []byte
	if err := repository.db.QueryRow(`SELECT authorization_json FROM governance_operations WHERE operation_id=?`, request.OperationID).Scan(&authorizationRaw); err != nil {
		t.Fatal(err)
	}
	var demand GovernanceDemand
	if err := json.Unmarshal(authorizationRaw, &demand); err != nil {
		t.Fatal(err)
	}
	demand.Preflight.PrincipalSHA256 = strings.Repeat("8", 64)
	forged, err := json.Marshal(demand)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.db.Exec(`DROP TRIGGER governance_operations_guard_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.db.Exec(`UPDATE governance_operations SET authorization_json=? WHERE operation_id=?`, forged, request.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RecoverPurges(context.Background()); !errors.Is(err, ErrPurgeOutcomeUnknown) {
		t.Fatalf("recovery error=%v", err)
	}
	governance, err := repository.GetGovernance(context.Background(), accepted.TenantStratum, accepted.SiteStratum, accepted.DatasetID, accepted.Revision)
	if err != nil || governance.State != GovernancePurgeSubmitting {
		t.Fatalf("governance=%#v err=%v", governance, err)
	}
}

func TestPurgeSecondCommitOutcomeUnknownResolvesCompleted(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "purge-second-commit.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	createReceipt, err := repository.CreateWithReceipt(context.Background(), accepted)
	if err != nil {
		t.Fatal(err)
	}
	*config.clock = accepted.RetainUntil.Add(time.Hour)
	request := purgeRequestFor(accepted, "purge-second-commit")
	installPurgeGrant(t, config.governance, request, createReceipt.ContentSHA256, accepted.RetainUntil, *config.clock)
	commits := 0
	repository.commit = func(tx *sql.Tx) error {
		commits++
		if err := tx.Commit(); err != nil {
			return err
		}
		if commits == 2 {
			return errors.New("lost final commit acknowledgement")
		}
		return nil
	}
	_, err = repository.Purge(context.Background(), request)
	var unknown *PurgeOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("error=%v", err)
	}
	resolution, err := repository.ResolvePurge(context.Background(), unknown.Receipt)
	if err != nil || resolution.State != PurgeCompleted {
		t.Fatalf("resolution=%#v err=%v", resolution, err)
	}
}

func TestRepositoryRejectsTamperAndOldSchema(t *testing.T) {
	t.Run("ledger tamper", func(t *testing.T) {
		accepted := fixtureAcceptedDataset(t)
		config := newRepositoryFixture()
		path := filepath.Join(protectedDatasetRoot(t), "tamper-ledger.db")
		repository, _ := OpenSQLiteRepository(path, config.options())
		if err := repository.Create(context.Background(), accepted); err != nil {
			t.Fatal(err)
		}
		_ = repository.Close()
		database := openRawDatasetDatabase(t, path)
		_, _ = database.Exec(`DROP TRIGGER identity_ledger_no_update`)
		_, err := database.Exec(`UPDATE identity_ledger SET split='test' WHERE split='train'`)
		if err != nil {
			t.Fatal(err)
		}
		_ = database.Close()
		if reopened, err := OpenSQLiteRepository(path, config.options()); !errors.Is(err, ErrCorruptRepository) && !errors.Is(err, ErrUnsupportedRepositorySchema) {
			if reopened != nil {
				_ = reopened.Close()
			}
			t.Fatalf("tamper error=%v", err)
		}
	})
	t.Run("review tamper", func(t *testing.T) {
		f := newFixture(t, nil)
		subject, _ := BuildReviewSubject(f.request, f.request.Items[0], f.request.Items[0].Annotations[0], f.descriptors[0])
		digest, _ := AnnotationSHA256(subject)
		record := ReviewRecord{Schema: ReviewSchema, ReviewID: "review-tamper", AnnotationSHA256: digest, ReviewerSHA256: strings.Repeat("e", 64), ReviewerRole: ReviewerRoleDataset, Decision: ReviewApproved, PolicyRef: f.request.Policy.ReviewPolicyRef, ReviewedAt: f.now.Add(-time.Minute)}
		record.RecordSHA256, _ = ReviewRecordSHA256(record)
		config := newRepositoryFixture()
		_ = config.verifier.Trust(record)
		path := filepath.Join(protectedDatasetRoot(t), "tamper-review.db")
		repository, _ := OpenSQLiteRepository(path, config.options())
		if err := repository.RecordReview(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		_ = repository.Close()
		database := openRawDatasetDatabase(t, path)
		_, _ = database.Exec(`DROP TRIGGER review_records_no_update`)
		_, err := database.Exec(`UPDATE review_records SET review_json=?`, []byte(`{"schema":"broken"}`))
		if err != nil {
			t.Fatal(err)
		}
		_ = database.Close()
		if reopened, err := OpenSQLiteRepository(path, config.options()); !errors.Is(err, ErrCorruptRepository) && !errors.Is(err, ErrUnsupportedRepositorySchema) {
			if reopened != nil {
				_ = reopened.Close()
			}
			t.Fatalf("tamper error=%v", err)
		}
	})
	t.Run("old v2", func(t *testing.T) {
		config := newRepositoryFixture()
		root := protectedDatasetRoot(t)
		path := filepath.Join(root, "old-v2.db")
		database, _ := sql.Open("sqlite", path)
		_, err := database.Exec(`CREATE TABLE legacy(value TEXT); PRAGMA application_id=1128612914; PRAGMA user_version=2`)
		if err != nil {
			t.Fatal(err)
		}
		_ = database.Close()
		protectDatasetFile(t, path)
		if repository, err := OpenSQLiteRepository(path, config.options()); !errors.Is(err, ErrUnsupportedRepositorySchema) {
			if repository != nil {
				_ = repository.Close()
			}
			t.Fatalf("old schema error=%v", err)
		}
	})
}

func TestFrozenReviewSetIsImmutableAcrossLaterReviewsAndPurge(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "frozen-reviews.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	receipt, err := repository.CreateWithReceipt(context.Background(), accepted)
	if err != nil {
		t.Fatal(err)
	}
	before, err := repository.Get(context.Background(), accepted.TenantStratum, accepted.SiteStratum, accepted.DatasetID, accepted.Revision)
	if err != nil {
		t.Fatal(err)
	}
	beforeRaw, _ := json.Marshal(before)
	annotation := accepted.Items[0].Annotations[0]
	later := ReviewRecord{Schema: ReviewSchema, ReviewID: "review-later", AnnotationSHA256: annotation.AnnotationSHA256,
		ReviewerSHA256: strings.Repeat("f", 64), ReviewerRole: ReviewerRoleDataset, Decision: ReviewApproved,
		PolicyRef: "two-person-review-v3", ReviewedAt: accepted.CreatedAt.Add(time.Minute)}
	later.RecordSHA256, _ = ReviewRecordSHA256(later)
	if err := config.verifier.Trust(later); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordReview(context.Background(), later); err != nil {
		t.Fatal(err)
	}
	after, err := repository.Get(context.Background(), accepted.TenantStratum, accepted.SiteStratum, accepted.DatasetID, accepted.Revision)
	if err != nil {
		t.Fatal(err)
	}
	afterRaw, _ := json.Marshal(after)
	if !bytes.Equal(beforeRaw, afterRaw) || before.Items[0].Annotations[0].ReviewSetSHA256 != after.Items[0].Annotations[0].ReviewSetSHA256 {
		t.Fatal("later review changed the frozen admitted dataset")
	}
	resolution, err := repository.ResolveCreate(context.Background(), receipt)
	if err != nil || resolution.State != CreateCommitted {
		t.Fatalf("resolution=%#v err=%v", resolution, err)
	}
	var frozenBefore int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM dataset_annotation_reviews`).Scan(&frozenBefore); err != nil || frozenBefore == 0 {
		t.Fatalf("frozen=%d err=%v", frozenBefore, err)
	}
	*config.clock = accepted.RetainUntil.Add(time.Hour)
	purge := purgeRequestFor(accepted, "purge-frozen-reviews")
	installPurgeGrant(t, config.governance, purge, receipt.ContentSHA256, accepted.RetainUntil, *config.clock)
	if _, err := repository.Purge(context.Background(), purge); err != nil {
		t.Fatal(err)
	}
	var frozenAfter int
	if err := repository.db.QueryRow(`SELECT COUNT(*) FROM dataset_annotation_reviews`).Scan(&frozenAfter); err != nil || frozenAfter != frozenBefore {
		t.Fatalf("frozen before=%d after=%d err=%v", frozenBefore, frozenAfter, err)
	}
}

func TestRepositoryRejectsSameNameWeakIndexAndTrigger(t *testing.T) {
	for _, test := range []struct {
		name, drop, create string
	}{
		{"trigger", `DROP TRIGGER dataset_records_no_delete`, `CREATE TRIGGER dataset_records_no_delete BEFORE DELETE ON dataset_records BEGIN SELECT 1; END`},
		{"index", `DROP INDEX idx_dataset_records_scope`, `CREATE INDEX idx_dataset_records_scope ON dataset_records(dataset_id)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := newRepositoryFixture()
			path := filepath.Join(protectedDatasetRoot(t), "weak-"+test.name+".db")
			repository, err := OpenSQLiteRepository(path, config.options())
			if err != nil {
				t.Fatal(err)
			}
			_ = repository.Close()
			database := openRawDatasetDatabase(t, path)
			if _, err := database.Exec(test.drop); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(test.create); err != nil {
				t.Fatal(err)
			}
			_ = database.Close()
			if reopened, err := OpenSQLiteRepository(path, config.options()); !errors.Is(err, ErrUnsupportedRepositorySchema) {
				if reopened != nil {
					_ = reopened.Close()
				}
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestLedgerProvenanceRejectsWrongIntegrityKey(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "wrong-integrity-key.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Create(context.Background(), accepted); err != nil {
		t.Fatal(err)
	}
	_ = repository.Close()
	wrong := config.options()
	wrong.IntegrityKey = []byte("abcdef0123456789abcdef0123456789")
	if reopened, err := OpenSQLiteRepository(path, wrong); !errors.Is(err, ErrCorruptRepository) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("error=%v", err)
	}
}

func TestRecoverPurgesNeverMovesClockBackward(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "purge-clock.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	receipt, err := repository.CreateWithReceipt(context.Background(), accepted)
	if err != nil {
		t.Fatal(err)
	}
	requestedAt := accepted.RetainUntil.Add(2 * time.Hour)
	*config.clock = requestedAt
	request := purgeRequestFor(accepted, "purge-clock")
	installPurgeGrant(t, config.governance, request, receipt.ContentSHA256, accepted.RetainUntil, requestedAt)
	repository.commit = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("lost acknowledgement")
	}
	_, err = repository.Purge(context.Background(), request)
	var unknown *PurgeOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("error=%v", err)
	}
	repository.commit = func(tx *sql.Tx) error { return tx.Commit() }
	*config.clock = accepted.RetainUntil.Add(time.Hour)
	if _, err := repository.RecoverPurges(context.Background()); !errors.Is(err, ErrPurgeOutcomeUnknown) {
		t.Fatalf("backward recovery error=%v", err)
	}
	resolution, err := repository.ResolvePurge(context.Background(), unknown.Receipt)
	if err != nil || resolution.State != PurgePending {
		t.Fatalf("resolution=%#v err=%v", resolution, err)
	}
	*config.clock = requestedAt.Add(time.Hour)
	if recovered, err := repository.RecoverPurges(context.Background()); err != nil || len(recovered) != 1 {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
}

func TestPurgeAuthorizationDenialHasProvableReadOrder(t *testing.T) {
	accepted := fixtureAcceptedDataset(t)
	config := newRepositoryFixture()
	path := filepath.Join(protectedDatasetRoot(t), "purge-auth-order.db")
	repository, err := OpenSQLiteRepository(path, config.options())
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.Create(context.Background(), accepted); err != nil {
		t.Fatal(err)
	}
	*config.clock = accepted.RetainUntil.Add(time.Hour)
	originalLookup := repository.governanceLookup
	var lookups atomic.Int32
	repository.governanceLookup = func(ctx context.Context, tenant, site, id string, revision uint64) (GovernanceRecord, error) {
		lookups.Add(1)
		return originalLookup(ctx, tenant, site, id, revision)
	}
	request := purgeRequestFor(accepted, "purge-auth-order")
	preflight := &phaseGovernanceAuthorizer{denyPreflight: true}
	repository.governanceAuthorizer = preflight
	if _, err := repository.Purge(context.Background(), request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("preflight error=%v", err)
	}
	if preflight.preflights.Load() != 1 || preflight.finals.Load() != 0 || lookups.Load() != 0 {
		t.Fatalf("preflights=%d finals=%d lookups=%d", preflight.preflights.Load(), preflight.finals.Load(), lookups.Load())
	}
	final := &phaseGovernanceAuthorizer{}
	repository.governanceAuthorizer = final
	if _, err := repository.Purge(context.Background(), request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("final error=%v", err)
	}
	if final.preflights.Load() != 1 || final.finals.Load() != 1 || lookups.Load() != 1 {
		t.Fatalf("preflights=%d finals=%d lookups=%d", final.preflights.Load(), final.finals.Load(), lookups.Load())
	}
}

func fixtureAcceptedDataset(t *testing.T) Dataset {
	t.Helper()
	f := newFixture(t, nil)
	value, err := f.validator.Validate(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func purgeRequestFor(value Dataset, operationID string) PurgeRequest {
	return PurgeRequest{Schema: GovernanceRequestSchema, OperationID: operationID, AuthorityRef: "purge-authority", PrincipalSHA256: strings.Repeat("7", 64), TenantStratum: value.TenantStratum, SiteStratum: value.SiteStratum, DatasetID: value.DatasetID, Revision: value.Revision}
}
func installPurgeGrant(t *testing.T, authorizer *MemoryGovernanceAuthorizer, request PurgeRequest, content string, retainUntil, now time.Time) {
	t.Helper()
	if err := authorizer.PutGrant(GovernanceAuthorizationGrant{Schema: GovernanceAuthorizationSchema, AuthorityRef: request.AuthorityRef, PrincipalSHA256: request.PrincipalSHA256, OperationID: request.OperationID, Operation: OperationPurge, TenantStratum: request.TenantStratum, SiteStratum: request.SiteStratum, DatasetID: request.DatasetID, Revision: request.Revision, ContentSHA256: content, RetainUntil: retainUntil, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}
func sortClaims(values []identityClaim) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Kind != values[j].Kind {
			return values[i].Kind < values[j].Kind
		}
		return values[i].SHA256 < values[j].SHA256
	})
}
func sortSourceIntervals(values []sourceIntervalClaim) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].SourceSHA256 != values[j].SourceSHA256 {
			return values[i].SourceSHA256 < values[j].SourceSHA256
		}
		if values[i].WindowStartUnixNano != values[j].WindowStartUnixNano {
			return values[i].WindowStartUnixNano < values[j].WindowStartUnixNano
		}
		return values[i].IntervalSHA256 < values[j].IntervalSHA256
	})
}
func shiftInterval(t *testing.T, value sourceIntervalClaim, shift time.Duration, split Split) sourceIntervalClaim {
	t.Helper()
	value.WindowStart = value.WindowStart.Add(shift)
	value.WindowEnd = value.WindowEnd.Add(shift)
	value.WindowStartUnixNano = value.WindowStart.UnixNano()
	value.WindowEndUnixNano = value.WindowEnd.UnixNano()
	adjacency := time.Duration(value.AdjacencySeconds) * time.Second
	value.GuardStartUnixNano = value.WindowStart.Add(-adjacency).UnixNano()
	value.GuardEndUnixNano = value.WindowEnd.Add(adjacency).UnixNano()
	value.Split = split
	digest, err := sha256JSON(struct {
		SourceSHA256     string    `json:"sourceSha256"`
		WindowStart      time.Time `json:"windowStart"`
		WindowEnd        time.Time `json:"windowEnd"`
		AdjacencySeconds int       `json:"adjacencySeconds"`
	}{value.SourceSHA256, value.WindowStart, value.WindowEnd, value.AdjacencySeconds})
	if err != nil {
		t.Fatal(err)
	}
	value.IntervalSHA256 = digest
	return value
}
func equalProjection(left, right Dataset) bool {
	return reflect.DeepEqual(cloneDataset(left, false), cloneDataset(right, false))
}
func protectedDatasetRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "protected-dataset-state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return root
}
func protectedDatasetRootPathFragment(path string) string { return filepath.Base(filepath.Dir(path)) }
func openRawDatasetDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return database
}
func protectDatasetFile(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
}
