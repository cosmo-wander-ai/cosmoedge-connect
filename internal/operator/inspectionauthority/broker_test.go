package inspectionauthority

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

func TestDurableBrokerSurvivesRestartAndConsumesExactlyOnce(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	path := secureDBPath(t)
	secrets := newFaultStore()
	broker := openTestBroker(t, path, secrets, &now)
	demand := fixtureIssueDemand("run-restart", now, 14*time.Hour)
	authorization, created, err := broker.Issue(context.Background(), demand)
	if err != nil || !created {
		t.Fatalf("Issue() created=%v err=%v", created, err)
	}
	if !authorization.ExpiresAt.Equal(demand.Deadline) || authorization.ExpiresAt.Sub(authorization.IssuedAt) <= 5*time.Minute {
		t.Fatalf("authority deadline was shortened: issued=%s expires=%s", authorization.IssuedAt, authorization.ExpiresAt)
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}

	broker = openTestBroker(t, path, secrets, &now)
	defer broker.Close()
	replayed, created, err := broker.Issue(context.Background(), demand)
	if err != nil || created || !sameAuthorization(replayed, authorization) {
		t.Fatalf("restart replay created=%v err=%v", created, err)
	}
	lookedUp, err := broker.Lookup(context.Background(), demand.RunID)
	if err != nil || !sameAuthorization(lookedUp, authorization) {
		t.Fatalf("Lookup() err=%v", err)
	}
	step := fixtureStepDemand(authorization, "attempt-restart")
	if err := broker.VerifyAndConsume(context.Background(), authorization, step); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}
	broker = openTestBroker(t, path, secrets, &now)
	if err := broker.VerifyAndConsume(context.Background(), authorization, step); !errors.Is(err, coreauthority.ErrUnauthorized) {
		t.Fatalf("consumed authority replay error=%v", err)
	}
	if err := broker.Revoke(context.Background(), demand.RunID); err != nil {
		t.Fatal(err)
	}
	if err := broker.Revoke(context.Background(), demand.RunID); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if _, err := broker.Lookup(context.Background(), demand.RunID); !errors.Is(err, coreauthority.ErrNotFound) {
		t.Fatalf("revoked Lookup() error=%v", err)
	}
	if _, _, err := broker.Issue(context.Background(), demand); !errors.Is(err, coreauthority.ErrConflict) {
		t.Fatalf("revoked run was reissued: %v", err)
	}
	var consumed int
	if err := broker.db.QueryRow(`SELECT COUNT(*) FROM execution_consumptions`).Scan(&consumed); err != nil || consumed != 1 {
		t.Fatalf("revocation removed anti-replay evidence: count=%d err=%v", consumed, err)
	}
}

func TestDurableBrokerConcurrentConsumptionCAS(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	broker := openTestBroker(t, secureDBPath(t), newFaultStore(), &now)
	defer broker.Close()
	authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-cas", now, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	demand := fixtureStepDemand(authorization, "attempt-cas")
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := broker.VerifyAndConsume(context.Background(), authorization, demand); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, coreauthority.ErrUnauthorized) {
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent successes=%d, want 1", successes.Load())
	}
}

func TestDurableBrokerChainsMultipleAttemptsAcrossRestart(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 10, 15, 0, 0, time.UTC)
	path := secureDBPath(t)
	store := newFaultStore()
	broker := openTestBroker(t, path, store, &now)
	authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-chain", now, 2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []string{"attempt-chain-a", "attempt-chain-b", "attempt-chain-c"} {
		if err := broker.VerifyAndConsume(context.Background(), authorization, fixtureStepDemand(authorization, attempt)); err != nil {
			t.Fatalf("consume %s: %v", attempt, err)
		}
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}
	broker = openTestBroker(t, path, store, &now)
	defer broker.Close()
	state, found, err := readKeyRecord(context.Background(), broker.db)
	if err != nil || !found || state.generation != 3 {
		t.Fatalf("anchor generation=%d found=%v err=%v", state.generation, found, err)
	}
	if err := validateConsumptionChain(context.Background(), broker.db, broker.key, state); err != nil {
		t.Fatal(err)
	}
}

func TestDurableBrokerCrossInstanceAdmissionAndConsumptionCAS(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 10, 30, 0, 0, time.UTC)
	path := secureDBPath(t)
	store := newFaultStore()
	first := openTestBroker(t, path, store, &now)
	defer first.Close()
	second := openTestBroker(t, path, store, &now)
	defer second.Close()
	demand := fixtureIssueDemand("run-cross-instance", now, time.Hour)
	type issued struct {
		authorization coreauthority.Authorization
		created       bool
		err           error
	}
	issuedResults := make(chan issued, 2)
	for _, broker := range []*DurableBroker{first, second} {
		broker := broker
		go func() {
			authorization, created, err := broker.Issue(context.Background(), demand)
			issuedResults <- issued{authorization: authorization, created: created, err: err}
		}()
	}
	left, right := <-issuedResults, <-issuedResults
	if left.err != nil || right.err != nil || left.created == right.created || !sameAuthorization(left.authorization, right.authorization) {
		t.Fatalf("cross-instance Issue left=(%v,%v) right=(%v,%v)", left.created, left.err, right.created, right.err)
	}
	step := fixtureStepDemand(left.authorization, "attempt-cross-instance")
	consumeResults := make(chan error, 2)
	go func() { consumeResults <- first.VerifyAndConsume(context.Background(), left.authorization, step) }()
	go func() { consumeResults <- second.VerifyAndConsume(context.Background(), left.authorization, step) }()
	var successes int
	for range 2 {
		if err := <-consumeResults; err == nil {
			successes++
		} else if !errors.Is(err, coreauthority.ErrUnauthorized) {
			t.Fatalf("unexpected cross-instance consume error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("cross-instance consume successes=%d", successes)
	}
}

func TestDurableBrokerConflictsFailClosedWithoutConsuming(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC)
	broker := openTestBroker(t, secureDBPath(t), newFaultStore(), &now)
	defer broker.Close()
	demand := fixtureIssueDemand("run-conflict", now, time.Hour)
	authorization, _, err := broker.Issue(context.Background(), demand)
	if err != nil {
		t.Fatal(err)
	}
	changes := []func(*coreauthority.IssueDemand){
		func(value *coreauthority.IssueDemand) {
			value.Identity = fixtureIdentity(t, coreauthority.IdentityService)
		},
		func(value *coreauthority.IssueDemand) { value.PlanSHA256 = strings.Repeat("b", 64) },
		func(value *coreauthority.IssueDemand) { value.RuntimeID = "runtime-other" },
		func(value *coreauthority.IssueDemand) {
			value.Steps[0].Authority = coreauthority.StepAuthorityInspectionExecution
		},
		func(value *coreauthority.IssueDemand) { value.Deadline = value.Deadline.Add(time.Minute) },
	}
	for index, change := range changes {
		changed := demand
		changed.Steps = cloneScopes(demand.Steps)
		change(&changed)
		if _, _, err := broker.Issue(context.Background(), changed); !errors.Is(err, coreauthority.ErrConflict) {
			t.Fatalf("conflict %d error=%v", index, err)
		}
	}
	wrong := fixtureStepDemand(authorization, "attempt-exact")
	wrong.Identity = fixtureIdentity(t, coreauthority.IdentityService)
	if err := broker.VerifyAndConsume(context.Background(), authorization, wrong); !errors.Is(err, coreauthority.ErrUnauthorized) {
		t.Fatalf("wrong identity error=%v", err)
	}
	correct := fixtureStepDemand(authorization, "attempt-exact")
	if err := broker.VerifyAndConsume(context.Background(), authorization, correct); err != nil {
		t.Fatalf("rejected demand consumed authority: %v", err)
	}
}

func TestDurableBrokerKeySagaRecoversEveryCrashBoundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		fault func(*faultStore)
	}{
		{"after_database_prepare", func(store *faultStore) { store.failPutBefore.Store(true) }},
		{"after_secret_put", func(store *faultStore) { store.failPutAfter.Store(true); store.failRecover.Store(true) }},
		{"after_database_attach", func(store *faultStore) { store.failAcknowledge.Store(true) }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := secureDBPath(t)
			store := newFaultStore()
			test.fault(store)
			if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil {
				_ = broker.Close()
				t.Fatal("faulted first open unexpectedly succeeded")
			}
			firstOperation := readPutOperationID(t, path)
			store.clearFaults()
			broker := openTestBroker(t, path, store, &now)
			defer broker.Close()
			if secondOperation := readPutOperationID(t, path); secondOperation != firstOperation {
				t.Fatalf("bootstrap operation changed across crash: %q -> %q", firstOperation, secondOperation)
			}
			if _, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-recovered", now, time.Hour)); err != nil {
				t.Fatalf("recovered broker issue: %v", err)
			}
			var keys int
			if err := broker.db.QueryRow(`SELECT COUNT(*) FROM authority_key WHERE phase='attached'`).Scan(&keys); err != nil || keys != 1 {
				t.Fatalf("attached keys=%d err=%v", keys, err)
			}
		})
	}
}

func TestDurableBrokerConcurrentOpenFencesNativeSecretSaga(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 15, 0, 0, time.UTC)
	path := secureDBPath(t)
	base := newFaultStore()
	detector := &operationDetector{}
	stores := []credential.SecretStore{
		&detectingStore{faultStore: base, detector: detector},
		&detectingStore{faultStore: base, detector: detector},
	}
	start := make(chan struct{})
	results := make(chan struct {
		broker *DurableBroker
		err    error
	}, 2)
	for _, store := range stores {
		store := store
		go func() {
			<-start
			broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }})
			results <- struct {
				broker *DurableBroker
				err    error
			}{broker, err}
		}()
	}
	close(start)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent Open: %v", result.err)
		}
		if err := result.broker.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if detector.overlaps.Load() != 0 {
		t.Fatalf("native secret saga had %d overlapping operations", detector.overlaps.Load())
	}
}

func TestDurableBrokerConvergesRolledBackBootstrap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 30, 0, 0, time.UTC)
	store := newFaultStore()
	store.rollBackPut.Store(true)
	broker := openTestBroker(t, secureDBPath(t), store, &now)
	defer broker.Close()
	if store.compensations.Load() == 0 {
		t.Fatal("rolled-back bootstrap did not execute explicit compensation")
	}
}

func TestDurableBrokerConsumptionAnchorRecoversCrashBoundaries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 45, 0, 0, time.UTC)
	tests := []struct {
		name          string
		fault         func(*faultStore)
		firstSucceeds bool
	}{
		{"after_pending_before_rotation", func(store *faultStore) { store.failRotateBefore.Store(true) }, false},
		{"after_rotation_before_database_apply", func(store *faultStore) { store.failRotateAfter.Store(true) }, false},
		{"after_database_apply_before_ack", func(store *faultStore) { store.failAcknowledgeRotation.Store(true) }, true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := secureDBPath(t)
			store := newFaultStore()
			broker := openTestBroker(t, path, store, &now)
			authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-anchor-crash", now, time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			demand := fixtureStepDemand(authorization, "attempt-anchor-crash")
			test.fault(store)
			err = broker.VerifyAndConsume(context.Background(), authorization, demand)
			if (err == nil) != test.firstSucceeds {
				t.Fatalf("first consume success=%v err=%v", err == nil, err)
			}
			if err := broker.Close(); err != nil {
				t.Fatal(err)
			}
			store.clearFaults()
			broker = openTestBroker(t, path, store, &now)
			defer broker.Close()
			if err := broker.VerifyAndConsume(context.Background(), authorization, demand); !errors.Is(err, coreauthority.ErrUnauthorized) {
				t.Fatalf("recovered consumption replay error=%v", err)
			}
			var pending, consumed int
			if err := broker.db.QueryRow(`SELECT COUNT(*) FROM execution_consumption_pending`).Scan(&pending); err != nil {
				t.Fatal(err)
			}
			if err := broker.db.QueryRow(`SELECT COUNT(*) FROM execution_consumptions`).Scan(&consumed); err != nil {
				t.Fatal(err)
			}
			if pending != 0 || consumed != 1 {
				t.Fatalf("recovered pending=%d consumed=%d", pending, consumed)
			}
		})
	}
}

func TestDurableBrokerRevocationAnchorRecoversCrashBoundaries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 12, 50, 0, 0, time.UTC)
	tests := []struct {
		name          string
		fault         func(*faultStore)
		firstSucceeds bool
	}{
		{"after_pending_before_rotation", func(store *faultStore) { store.failRotateBefore.Store(true) }, false},
		{"after_rotation_before_database_apply", func(store *faultStore) { store.failRotateAfter.Store(true) }, false},
		{"after_database_apply_before_ack", func(store *faultStore) { store.failAcknowledgeRotation.Store(true) }, true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := secureDBPath(t)
			store := newFaultStore()
			broker := openTestBroker(t, path, store, &now)
			if _, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-revoke-crash", now, time.Hour)); err != nil {
				t.Fatal(err)
			}
			test.fault(store)
			err := broker.Revoke(context.Background(), "run-revoke-crash")
			if (err == nil) != test.firstSucceeds {
				t.Fatalf("first revoke success=%v err=%v", err == nil, err)
			}
			if err := broker.Close(); err != nil {
				t.Fatal(err)
			}
			store.clearFaults()
			broker = openTestBroker(t, path, store, &now)
			defer broker.Close()
			if _, err := broker.Lookup(context.Background(), "run-revoke-crash"); !errors.Is(err, coreauthority.ErrNotFound) {
				t.Fatalf("recovered revocation Lookup error=%v", err)
			}
			if err := broker.Revoke(context.Background(), "run-revoke-crash"); err != nil {
				t.Fatalf("recovered idempotent revoke: %v", err)
			}
			var pending, revocations int
			if err := broker.db.QueryRow(`SELECT COUNT(*) FROM execution_consumption_pending`).Scan(&pending); err != nil {
				t.Fatal(err)
			}
			if err := broker.db.QueryRow(`SELECT COUNT(*) FROM execution_revocations`).Scan(&revocations); err != nil {
				t.Fatal(err)
			}
			if pending != 0 || revocations != 1 {
				t.Fatalf("recovered pending=%d revocations=%d", pending, revocations)
			}
		})
	}
}

func TestDurableBrokerRejectsMissingWrongKeyAndDatabaseTampering(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	t.Run("missing key", func(t *testing.T) {
		path, store := createPopulatedBroker(t, now, "run-missing")
		store.missingGet.Store(true)
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("missing key error=%v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		path, store := createPopulatedBroker(t, now, "run-wrong")
		store.wrongGet.Store(true)
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("wrong key error=%v", err)
		}
	})
	t.Run("authorization row", func(t *testing.T) {
		path, store := createPopulatedBroker(t, now, "run-tampered")
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE execution_authorizations SET principal_sha256=? WHERE run_id=?`, strings.Repeat("c", 64), "run-tampered"); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("tampered row error=%v", err)
		}
	})
	t.Run("consumption row", func(t *testing.T) {
		path := secureDBPath(t)
		store := newFaultStore()
		broker := openTestBroker(t, path, store, &now)
		authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-consumption-tamper", now, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := broker.VerifyAndConsume(context.Background(), authorization, fixtureStepDemand(authorization, "attempt-tamper")); err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE execution_consumptions SET operation_sha256=?`, strings.Repeat("e", 64)); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("tampered consumption error=%v", err)
		}
	})
}

func TestDurableBrokerDetectsConsumptionDeletionAndDatabaseRollback(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 13, 15, 0, 0, time.UTC)
	t.Run("deleted consumption", func(t *testing.T) {
		path := secureDBPath(t)
		store := newFaultStore()
		broker := openTestBroker(t, path, store, &now)
		authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-delete", now, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := broker.VerifyAndConsume(context.Background(), authorization, fixtureStepDemand(authorization, "attempt-delete")); err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`DELETE FROM execution_consumptions`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("deleted consumption error=%v", err)
		}
	})
	t.Run("database rollback", func(t *testing.T) {
		path := secureDBPath(t)
		store := newFaultStore()
		broker := openTestBroker(t, path, store, &now)
		authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-rollback", now, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(); err != nil {
			t.Fatal(err)
		}
		beforeConsumption, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		broker = openTestBroker(t, path, store, &now)
		if err := broker.VerifyAndConsume(context.Background(), authorization, fixtureStepDemand(authorization, "attempt-rollback")); err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, beforeConsumption, 0o600); err != nil {
			t.Fatal(err)
		}
		clearBytes(beforeConsumption)
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("rolled-back database error=%v", err)
		}
	})
}

func TestDurableBrokerDetectsRevocationDeletionAndRollback(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 13, 20, 0, 0, time.UTC)
	t.Run("deleted revocation anchor", func(t *testing.T) {
		path := secureDBPath(t)
		store := newFaultStore()
		broker := openTestBroker(t, path, store, &now)
		if _, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-revoke-delete", now, time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := broker.Revoke(context.Background(), "run-revoke-delete"); err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`PRAGMA foreign_keys=OFF; DELETE FROM execution_revocations`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("deleted revocation error=%v", err)
		}
	})
	t.Run("database rollback before revoke", func(t *testing.T) {
		path := secureDBPath(t)
		store := newFaultStore()
		broker := openTestBroker(t, path, store, &now)
		if _, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-revoke-rollback", now, time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(); err != nil {
			t.Fatal(err)
		}
		beforeRevoke, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		broker = openTestBroker(t, path, store, &now)
		if err := broker.Revoke(context.Background(), "run-revoke-rollback"); err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, beforeRevoke, 0o600); err != nil {
			t.Fatal(err)
		}
		clearBytes(beforeRevoke)
		if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return now }}); err == nil || !errors.Is(err, ErrIntegrity) {
			if broker != nil {
				_ = broker.Close()
			}
			t.Fatalf("rolled-back revocation error=%v", err)
		}
	})
}

func TestDurableBrokerRejectsIssuerRebindingAcrossRestart(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 13, 30, 0, 0, time.UTC)
	path, store := createPopulatedBroker(t, now, "run-issuer")
	broker, err := Open(Config{Path: path, IssuerID: "different-runtime", Secrets: store, Now: func() time.Time { return now }})
	if err == nil || !errors.Is(err, ErrIntegrity) {
		if broker != nil {
			_ = broker.Close()
		}
		t.Fatalf("issuer rebind error=%v", err)
	}
}

func TestDurableBrokerRejectsOldAlteredAndTypedNilInputs(t *testing.T) {
	t.Parallel()
	var nilStore *faultStore
	if broker, err := Open(Config{Path: secureDBPath(t), IssuerID: "operator-runtime", Secrets: nilStore}); err == nil || !errors.Is(err, ErrInvalidConfig) {
		if broker != nil {
			_ = broker.Close()
		}
		t.Fatalf("typed nil error=%v", err)
	}
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "old.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE old_authority(value TEXT); PRAGMA application_id=1128612145; PRAGMA user_version=1`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: newFaultStore()}); err == nil || !errors.Is(err, ErrSchema) {
		if broker != nil {
			_ = broker.Close()
		}
		t.Fatalf("altered schema error=%v", err)
	}
}

func TestDurableBrokerDoesNotPersistOrProjectKeyAndClearsOnClose(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	path := secureDBPath(t)
	store := newFaultStore()
	broker := openTestBroker(t, path, store, &now)
	authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand("run-secret-scan", now, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(authorization); !errors.Is(err, coreauthority.ErrProtectedIdentityProjection) {
		t.Fatalf("authorization projection error=%v", err)
	}
	if _, err := json.Marshal(authorization.Identity); !errors.Is(err, coreauthority.ErrProtectedIdentityProjection) {
		t.Fatalf("identity projection error=%v", err)
	}
	keyAlias := broker.key
	secret := append([]byte(nil), keyAlias...)
	if !validDigest(string(secret)) {
		t.Fatal("MAC key is not a native-store-safe 256-bit hex secret")
	}
	if rendered := fmt.Sprintf("%+v %#v", broker, broker); strings.Contains(rendered, fmt.Sprint(secret[0])) ||
		!strings.Contains(rendered, "redacted") {
		t.Fatalf("broker log rendering was not protected: %q", rendered)
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}
	for index, value := range keyAlias {
		if value != 0 {
			t.Fatalf("key byte %d was not cleared", index)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("raw MAC key was persisted in SQLite")
	}
	for _, forbidden := range [][]byte{[]byte("password"), []byte("rtsp://"), []byte("device-write-grant")} {
		if bytes.Contains(bytes.ToLower(raw), forbidden) {
			t.Fatalf("SQLite contains forbidden secret marker %q", forbidden)
		}
	}
	clearBytes(secret)
}

func TestDurableBrokerExpiryIsFailClosedAndRetained(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
	broker := openTestBroker(t, secureDBPath(t), newFaultStore(), &now)
	defer broker.Close()
	demand := fixtureIssueDemand("run-expired", now, 12*time.Hour)
	authorization, _, err := broker.Issue(context.Background(), demand)
	if err != nil {
		t.Fatal(err)
	}
	now = demand.Deadline
	if _, err := broker.Lookup(context.Background(), demand.RunID); !errors.Is(err, coreauthority.ErrNotFound) {
		t.Fatalf("expired Lookup error=%v", err)
	}
	if err := broker.VerifyAndConsume(context.Background(), authorization, fixtureStepDemand(authorization, "attempt-expired")); !errors.Is(err, coreauthority.ErrUnauthorized) {
		t.Fatalf("expired consume error=%v", err)
	}
	if _, _, err := broker.Issue(context.Background(), demand); !errors.Is(err, coreauthority.ErrUnauthorized) {
		// The original frozen deadline is no longer a valid new demand. It must
		// never silently create replacement authority.
		t.Fatalf("expired re-admission error=%v", err)
	}
}

func createPopulatedBroker(t *testing.T, now time.Time, runID string) (string, *faultStore) {
	t.Helper()
	path := secureDBPath(t)
	store := newFaultStore()
	broker := openTestBroker(t, path, store, &now)
	if _, _, err := broker.Issue(context.Background(), fixtureIssueDemand(runID, now, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}
	return path, store
}

func openTestBroker(t *testing.T, path string, store credential.SecretStore, now *time.Time) *DurableBroker {
	t.Helper()
	broker, err := Open(Config{Path: path, IssuerID: "operator-runtime", Secrets: store, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := broker.Close(); err != nil {
			t.Errorf("close test broker: %v", err)
		}
	})
	return broker
}

func secureDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state", "execution-authority.db")
}

func readPutOperationID(t *testing.T, path string) string {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var operationID string
	if err := database.QueryRow(`SELECT put_operation_id FROM authority_key WHERE singleton=1`).Scan(&operationID); err != nil {
		t.Fatal(err)
	}
	return operationID
}

func fixtureIssueDemand(runID string, now time.Time, lifetime time.Duration) coreauthority.IssueDemand {
	identity, err := coreauthority.NewExecutionIdentity(coreauthority.IdentityActor, strings.Repeat("a", 64))
	if err != nil {
		panic(err)
	}
	return coreauthority.IssueDemand{
		Identity: identity, TenantID: "tenant-a", SiteID: "site-a", RunID: runID,
		PlanSHA256: strings.Repeat("1", 64), AssignmentID: "assignment-a", AssignmentRevision: 1,
		RequestKey: "req_" + strings.Repeat("2", 32), RuntimeID: "runtime-a",
		Steps:    []coreauthority.StepScope{{StepID: "step-a", Authority: coreauthority.StepAuthorityDeviceRead}},
		Deadline: now.Add(lifetime),
	}
}

func fixtureStepDemand(value coreauthority.Authorization, attemptID string) coreauthority.StepDemand {
	return coreauthority.StepDemand{
		Identity: value.Identity, Authority: coreauthority.StepAuthorityDeviceRead, TenantID: value.TenantID,
		SiteID: value.SiteID, RunID: value.RunID, PlanSHA256: value.PlanSHA256, AssignmentID: value.AssignmentID,
		AssignmentRevision: value.AssignmentRevision, RequestKey: value.RequestKey, RuntimeID: value.RuntimeID,
		StepID: "step-a", AttemptID: attemptID,
	}
}

func fixtureIdentity(t *testing.T, kind coreauthority.ExecutionIdentityKind) coreauthority.ExecutionIdentity {
	t.Helper()
	identity, err := coreauthority.NewExecutionIdentity(kind, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

type faultStore struct {
	inner                   *credential.MemoryStore
	failPutBefore           atomic.Bool
	failPutAfter            atomic.Bool
	failRecover             atomic.Bool
	failAcknowledge         atomic.Bool
	rollBackPut             atomic.Bool
	failRotateBefore        atomic.Bool
	failRotateAfter         atomic.Bool
	failRecoverRotation     atomic.Bool
	failAcknowledgeRotation atomic.Bool
	missingGet              atomic.Bool
	wrongGet                atomic.Bool
	compensations           atomic.Int32
}

func newFaultStore() *faultStore { return &faultStore{inner: credential.NewMemoryStore()} }

func (s *faultStore) clearFaults() {
	s.failPutBefore.Store(false)
	s.failPutAfter.Store(false)
	s.failRecover.Store(false)
	s.failAcknowledge.Store(false)
	s.rollBackPut.Store(false)
	s.failRotateBefore.Store(false)
	s.failRotateAfter.Store(false)
	s.failRecoverRotation.Store(false)
	s.failAcknowledgeRotation.Store(false)
}

func (s *faultStore) Put(ctx context.Context, operationID credential.PutOperationID, secret []byte) (credential.PutReceipt, error) {
	if s.failPutBefore.Swap(false) {
		return credential.PutReceipt{}, errors.New("injected before put")
	}
	receipt, err := s.inner.Put(ctx, operationID, secret)
	if err == nil && s.rollBackPut.Swap(false) {
		return s.inner.CompensatePut(ctx, operationID)
	}
	if err == nil && s.failPutAfter.Swap(false) {
		return receipt, errors.New("injected after put")
	}
	return receipt, err
}

func (s *faultStore) PutByOperationID(ctx context.Context, id credential.PutOperationID) (credential.PutReceipt, error) {
	return s.inner.PutByOperationID(ctx, id)
}
func (s *faultStore) RecoverPut(ctx context.Context, id credential.PutOperationID) (credential.PutReceipt, error) {
	if s.failRecover.Swap(false) {
		return credential.PutReceipt{}, errors.New("injected recover failure")
	}
	return s.inner.RecoverPut(ctx, id)
}
func (s *faultStore) CompensatePut(ctx context.Context, id credential.PutOperationID) (credential.PutReceipt, error) {
	s.compensations.Add(1)
	return s.inner.CompensatePut(ctx, id)
}
func (s *faultStore) AcknowledgePut(ctx context.Context, id credential.PutOperationID) error {
	if s.failAcknowledge.Swap(false) {
		return errors.New("injected acknowledgement failure")
	}
	return s.inner.AcknowledgePut(ctx, id)
}
func (s *faultStore) Get(ctx context.Context, ref credential.Ref) ([]byte, error) {
	if s.missingGet.Load() {
		return nil, credential.ErrNotFound
	}
	value, err := s.inner.Get(ctx, ref)
	if err == nil && s.wrongGet.Load() && len(value) > 0 {
		value[0] ^= 0xff
	}
	return value, err
}
func (s *faultStore) Delete(ctx context.Context, ref credential.Ref) error {
	return s.inner.Delete(ctx, ref)
}
func (s *faultStore) Rotate(ctx context.Context, ref credential.Ref, secret []byte) (credential.RotationReceipt, error) {
	if s.failRotateBefore.Swap(false) {
		return credential.RotationReceipt{}, errors.New("injected before rotation")
	}
	receipt, err := s.inner.Rotate(ctx, ref, secret)
	if err == nil && s.failRotateAfter.Swap(false) {
		return receipt, errors.New("injected after rotation")
	}
	return receipt, err
}
func (s *faultStore) RotationByOldRef(ctx context.Context, ref credential.Ref) (credential.RotationReceipt, error) {
	return s.inner.RotationByOldRef(ctx, ref)
}
func (s *faultStore) RecoverRotation(ctx context.Context, id credential.RotationID) (credential.RotationReceipt, error) {
	if s.failRecoverRotation.Swap(false) {
		return credential.RotationReceipt{}, errors.New("injected rotation recovery failure")
	}
	return s.inner.RecoverRotation(ctx, id)
}
func (s *faultStore) AcknowledgeRotation(ctx context.Context, id credential.RotationID) error {
	if s.failAcknowledgeRotation.Swap(false) {
		return errors.New("injected rotation acknowledgement failure")
	}
	return s.inner.AcknowledgeRotation(ctx, id)
}

var _ credential.SecretStore = (*faultStore)(nil)

type operationDetector struct {
	active   atomic.Int32
	overlaps atomic.Int32
}

type detectingStore struct {
	*faultStore
	detector *operationDetector
}

func (s *detectingStore) enter() func() {
	if s.detector.active.Add(1) != 1 {
		s.detector.overlaps.Add(1)
	}
	time.Sleep(3 * time.Millisecond)
	return func() { s.detector.active.Add(-1) }
}

func (s *detectingStore) Put(ctx context.Context, id credential.PutOperationID, secret []byte) (credential.PutReceipt, error) {
	done := s.enter()
	defer done()
	return s.faultStore.Put(ctx, id, secret)
}

func (s *detectingStore) PutByOperationID(ctx context.Context, id credential.PutOperationID) (credential.PutReceipt, error) {
	done := s.enter()
	defer done()
	return s.faultStore.PutByOperationID(ctx, id)
}

func (s *detectingStore) RecoverPut(ctx context.Context, id credential.PutOperationID) (credential.PutReceipt, error) {
	done := s.enter()
	defer done()
	return s.faultStore.RecoverPut(ctx, id)
}

func (s *detectingStore) AcknowledgePut(ctx context.Context, id credential.PutOperationID) error {
	done := s.enter()
	defer done()
	return s.faultStore.AcknowledgePut(ctx, id)
}

func (s *detectingStore) Get(ctx context.Context, ref credential.Ref) ([]byte, error) {
	done := s.enter()
	defer done()
	return s.faultStore.Get(ctx, ref)
}

var _ credential.SecretStore = (*detectingStore)(nil)
