package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

func TestEntryServiceConvergesSkillAndDirectLocalOntoSameStores(t *testing.T) {
	now := time.Date(2026, 7, 19, 17, 0, 0, 0, time.UTC)
	paths := newEntryTestPaths(t)
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	signer := newEntryTestSigner(t)
	defer signer.Close()
	stack := openEntryTestStack(t, paths, func() time.Time { return now }, credentials, signer, nil)
	defer stack.close(t)
	binding := testHandoffBinding()
	grant := issueEntryCreateGrant(t, signer, now, binding, "entry-both-routes")

	skillRef := "skill_handoff_same_core"
	ticket, err := stack.entry.BeginSkill(context.Background(), SkillHandoffRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: skillRef, ExpiresAt: now.Add(20 * time.Minute),
	})
	if err != nil || ticket.HandoffRef != skillRef || !ticket.ExpiresAt.Equal(now.Add(20*time.Minute)) {
		t.Fatalf("BeginSkill()=(%+v, %v)", ticket, err)
	}
	skillSecret := []byte("skill-route-private-secret")
	skillResult, err := stack.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256, HandoffRef: skillRef,
		Connection: LocalConnectionInput{
			Alias: "Skill 接入设备", IP: "10.30.40.51", Port: 8000, Username: "skill-private-user",
			Password: skillSecret, PinnedSerial: "skill-private-serial", PinnedType: "edge-box",
		},
		Grant: grant,
	})
	if err != nil || skillResult.Status != StatusCompleted || skillResult.Summary == nil || !allZero(skillSecret) {
		t.Fatalf("CompleteSkill()=(%+v, %v) cause=%v secretCleared=%v", skillResult, err, entryOperationCause(err), allZero(skillSecret))
	}

	directSecret := []byte("direct-route-private-secret")
	directResult, err := stack.entry.ConnectLocal(context.Background(), DirectConnectRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		RequestRef: "local_request_same_core", ExpiresAt: now.Add(20 * time.Minute),
		Connection: LocalConnectionInput{
			Alias: "本机直接接入设备", IP: "10.30.40.52", Port: 8443, Username: "direct-private-user",
			Password: directSecret, PinnedSerial: "direct-private-serial", PinnedType: "edge-box",
		},
		Grant: grant,
	})
	if err != nil || directResult.Status != StatusCompleted || directResult.Summary == nil || !allZero(directSecret) {
		t.Fatalf("ConnectLocal()=(%+v, %v) secretCleared=%v", directResult, err, allZero(directSecret))
	}
	if skillResult.OperationID == directResult.OperationID || skillResult.Summary.ProfileID == directResult.Summary.ProfileID {
		t.Fatal("the two independently keyed entries reused an operation or profile identity")
	}

	profiles, err := stack.profiles.ListSite(context.Background(), binding.TenantID, binding.SiteID)
	if err != nil || len(profiles) != 2 {
		t.Fatalf("shared profile registry entries=%d err=%v", len(profiles), err)
	}
	wantSecrets := map[string]string{
		"Skill 接入设备": "skill-route-private-secret",
		"本机直接接入设备":   "direct-route-private-secret",
	}
	for _, item := range profiles {
		stored, err := credentials.Get(context.Background(), item.CredentialRef)
		if err != nil || string(stored) != wantSecrets[item.Alias] {
			t.Fatalf("shared credential provider alias=%q err=%v", item.Alias, err)
		}
		clearBytes(stored)
	}
	skillRecord, err := stack.handoffs.Resolve(context.Background(), binding, skillRef)
	if err != nil || skillRecord.State != HandoffCompleted || skillRecord.OperationID != skillResult.OperationID {
		t.Fatalf("skill handoff=%+v err=%v", skillRecord, err)
	}
	directRef := stableDirectHandoffRef(binding, "local_request_same_core")
	directRecord, err := stack.handoffs.Resolve(context.Background(), binding, directRef)
	if err != nil || directRecord.State != HandoffCompleted || directRecord.OperationID != directResult.OperationID {
		t.Fatalf("direct handoff=%+v err=%v", directRecord, err)
	}

	assertFilesExclude(t, []string{paths.profiles, paths.journal, paths.handoffs},
		"skill-route-private-secret", "direct-route-private-secret")
	assertFilesExclude(t, []string{paths.handoffs},
		"10.30.40.51", "10.30.40.52", "skill-private-user", "direct-private-user",
		"skill-private-serial", "direct-private-serial", skillResult.Summary.ProfileID, directResult.Summary.ProfileID)
}

func TestAcknowledgeSkillPersistedClosesExactHandoffWithoutCreatingAnotherProfile(t *testing.T) {
	now := time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC)
	paths := newEntryTestPaths(t)
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	signer := newEntryTestSigner(t)
	defer signer.Close()
	stack := openEntryTestStack(t, paths, func() time.Time { return now }, credentials, signer, nil)
	defer stack.close(t)
	binding := testHandoffBinding()
	request := SkillHandoffRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: "skill_persisted_current", ExpiresAt: now.Add(20 * time.Minute),
	}
	if _, err := stack.entry.BeginSkill(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	verifier := &persistedVerifierFixture{}
	receipt, err := stack.entry.AcknowledgeSkillPersisted(context.Background(), request, verifier)
	if err != nil || receipt.HandoffRef != request.HandoffRef || receipt.ExpiresAt != request.ExpiresAt || verifier.calls != 1 {
		t.Fatalf("acknowledge=(%#v,%v) verifier calls=%d", receipt, err, verifier.calls)
	}
	profiles, err := stack.profiles.ListSite(context.Background(), binding.TenantID, binding.SiteID)
	if err != nil || len(profiles) != 0 {
		t.Fatalf("handoff acknowledgment created profiles=%d err=%v", len(profiles), err)
	}
	stored, err := stack.handoffs.Resolve(context.Background(), binding, request.HandoffRef)
	if err != nil || stored.State != HandoffCompleted {
		t.Fatalf("stored handoff=%#v err=%v", stored, err)
	}
	if _, err := stack.entry.AcknowledgeSkillPersisted(context.Background(), request, &persistedVerifierFixture{err: errors.New("must not run")}); err != nil {
		t.Fatalf("completed acknowledgment was not idempotent: %v", err)
	}

	other := request
	other.PrincipalSHA256 = strings.Repeat("b", 64)
	if _, err := stack.entry.AcknowledgeSkillPersisted(context.Background(), other, verifier); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("cross-scope acknowledgment error=%v", err)
	}
}

type persistedVerifierFixture struct {
	calls int
	err   error
}

func (v *persistedVerifierFixture) VerifyCurrent(context.Context) error {
	v.calls++
	return v.err
}

func TestEntryServiceRejectsExpiredCrossScopeAndInvalidLocalInputWithSecretClearing(t *testing.T) {
	base := time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)
	current := base
	paths := newEntryTestPaths(t)
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	signer := newEntryTestSigner(t)
	defer signer.Close()
	stack := openEntryTestStack(t, paths, func() time.Time { return current }, credentials, signer, nil)
	defer stack.close(t)
	binding := testHandoffBinding()
	expiresAt := base.Add(10 * time.Minute)
	request := SkillHandoffRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: "skill_handoff_rejections", ExpiresAt: expiresAt,
	}
	if _, err := stack.entry.BeginSkill(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	reserved := request
	reserved.HandoffRef = "local_reserved_for_direct_entry"
	if _, err := stack.entry.BeginSkill(context.Background(), reserved); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("BeginSkill(reserved local namespace) error=%v", err)
	}
	conflict := request
	conflict.ExpiresAt = expiresAt.Add(time.Minute)
	if _, err := stack.entry.BeginSkill(context.Background(), conflict); !errors.Is(err, ErrHandoffConflict) {
		t.Fatalf("BeginSkill(conflict) error=%v", err)
	}

	wrongBindings := []HandoffBinding{
		{TenantID: "tenant-b", SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256},
		{TenantID: binding.TenantID, SiteID: "site-b", PrincipalSHA256: binding.PrincipalSHA256},
		{TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: strings.Repeat("b", 64)},
	}
	for index, wrong := range wrongBindings {
		secret := []byte(fmt.Sprintf("cross-binding-secret-%d", index))
		_, err := stack.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
			TenantID: wrong.TenantID, SiteID: wrong.SiteID, PrincipalSHA256: wrong.PrincipalSHA256,
			HandoffRef: request.HandoffRef,
			Connection: LocalConnectionInput{IP: "10.40.50.60", Port: 8000, Password: secret},
		})
		if !errors.Is(err, ErrBindingMismatch) || !allZero(secret) {
			t.Fatalf("CompleteSkill(cross binding %d) error=%v secretCleared=%v", index, err, allZero(secret))
		}
	}

	invalidIPSecret := []byte("invalid-ip-secret")
	_, err := stack.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256, HandoffRef: request.HandoffRef,
		Connection: LocalConnectionInput{Alias: "设备", IP: "device.local", Port: 8000, Username: "admin", Password: invalidIPSecret, PinnedSerial: "serial", PinnedType: "edge"},
	})
	if !errors.Is(err, ErrInvalidInput) || !allZero(invalidIPSecret) {
		t.Fatalf("CompleteSkill(invalid IP) error=%v secretCleared=%v", err, allZero(invalidIPSecret))
	}

	deniedSecret := []byte("denied-grant-secret")
	_, err = stack.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256, HandoffRef: request.HandoffRef,
		Connection: LocalConnectionInput{Alias: "设备", IP: "10.40.50.60", Port: 8000, Username: "admin", Password: deniedSecret, PinnedSerial: "serial", PinnedType: "edge"},
		Grant:      authority.Grant{},
	})
	if !errors.Is(err, ErrAuthorityDenied) || !allZero(deniedSecret) {
		t.Fatalf("CompleteSkill(denied grant) error=%v secretCleared=%v", err, allZero(deniedSecret))
	}

	invalidDirectSecret := []byte("invalid-direct-secret")
	_, err = stack.entry.ConnectLocal(context.Background(), DirectConnectRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		RequestRef: "invalid ref with spaces", ExpiresAt: expiresAt,
		Connection: LocalConnectionInput{Password: invalidDirectSecret},
	})
	if !errors.Is(err, ErrInvalidInput) || !allZero(invalidDirectSecret) {
		t.Fatalf("ConnectLocal(invalid ref) error=%v secretCleared=%v", err, allZero(invalidDirectSecret))
	}

	current = expiresAt
	expiredSecret := []byte("expired-handoff-secret")
	_, err = stack.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256, HandoffRef: request.HandoffRef,
		Connection: LocalConnectionInput{IP: "10.40.50.60", Port: 8000, Password: expiredSecret},
	})
	if !errors.Is(err, ErrHandoffExpired) || !allZero(expiredSecret) {
		t.Fatalf("CompleteSkill(expired) error=%v secretCleared=%v", err, allZero(expiredSecret))
	}
	profiles, listErr := stack.profiles.ListSite(context.Background(), binding.TenantID, binding.SiteID)
	if listErr != nil || len(profiles) != 0 {
		t.Fatalf("rejected entries wrote profiles=%d err=%v", len(profiles), listErr)
	}
}

func TestEntryServiceReplaysStableOperationAfterCoreCommitBeforeHandoffMark(t *testing.T) {
	now := time.Date(2026, 7, 19, 19, 0, 0, 0, time.UTC)
	paths := newEntryTestPaths(t)
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	signer := newEntryTestSigner(t)
	defer signer.Close()
	binding := testHandoffBinding()
	grant := issueEntryCreateGrant(t, signer, now, binding, "entry-crash-replay")
	failing := &failMarkRepository{remaining: 1}
	first := openEntryTestStack(t, paths, func() time.Time { return now }, credentials, signer, func(store *HandoffStore) HandoffRepository {
		failing.delegate = store
		return failing
	})
	ref := "skill_handoff_core_committed"
	if _, err := first.entry.BeginSkill(context.Background(), SkillHandoffRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: ref, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	firstSecret := []byte("crash-replay-private-secret")
	firstResult, err := first.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256, HandoffRef: ref,
		Connection: LocalConnectionInput{
			Alias: "断点恢复设备", IP: "10.50.60.70", Port: 8000, Username: "operator", Password: firstSecret,
			PinnedSerial: "replay-serial", PinnedType: "edge-box",
		},
		Grant: grant,
	})
	if !errors.Is(err, ErrHandoffCommit) || firstResult.Status != StatusCompleted || firstResult.Summary == nil || !allZero(firstSecret) {
		t.Fatalf("CompleteSkill(before mark crash)=(%+v, %v) cause=%v secretCleared=%v", firstResult, err, entryOperationCause(err), allZero(firstSecret))
	}
	pending, err := first.handoffs.Resolve(context.Background(), binding, ref)
	if err != nil || pending.State != HandoffPending {
		t.Fatalf("handoff after injected mark failure=%+v err=%v", pending, err)
	}
	first.close(t)

	second := openEntryTestStack(t, paths, func() time.Time { return now }, credentials, signer, nil)
	defer second.close(t)
	secondSecret := []byte("crash-replay-private-secret")
	secondResult, err := second.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256, HandoffRef: ref,
		Connection: LocalConnectionInput{
			Alias: "断点恢复设备", IP: "10.50.60.70", Port: 8000, Username: "operator", Password: secondSecret,
			PinnedSerial: "replay-serial", PinnedType: "edge-box",
		},
		Grant: grant,
	})
	if err != nil || secondResult.Status != StatusCompleted || secondResult.Summary == nil || !allZero(secondSecret) {
		t.Fatalf("CompleteSkill(replay)=(%+v, %v) secretCleared=%v", secondResult, err, allZero(secondSecret))
	}
	if secondResult.OperationID != firstResult.OperationID || secondResult.Summary.ProfileID != firstResult.Summary.ProfileID {
		t.Fatalf("replay identity changed: first=%+v second=%+v", firstResult, secondResult)
	}
	completed, err := second.handoffs.Resolve(context.Background(), binding, ref)
	if err != nil || completed.State != HandoffCompleted || completed.OperationID != firstResult.OperationID {
		t.Fatalf("completed replay handoff=%+v err=%v", completed, err)
	}
	profiles, err := second.profiles.ListSite(context.Background(), binding.TenantID, binding.SiteID)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("replay profiles=%d err=%v", len(profiles), err)
	}
	stored, err := credentials.Get(context.Background(), profiles[0].CredentialRef)
	if err != nil || string(stored) != "crash-replay-private-secret" {
		t.Fatalf("replay credential mismatch err=%v", err)
	}
	clearBytes(stored)
}

func TestEntryServiceReconcilesExpiredCompletedHandoffAfterCrashRestartWithoutReplay(t *testing.T) {
	now := time.Date(2026, 7, 20, 3, 0, 0, 0, time.UTC)
	current := now
	paths := newEntryTestPaths(t)
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	signer := newEntryTestSigner(t)
	defer signer.Close()
	binding := testHandoffBinding()
	grant := issueEntryCreateGrant(t, signer, now, binding, "entry-local-reconcile")
	failing := &failMarkRepository{remaining: 1}
	first := openEntryTestStack(t, paths, func() time.Time { return current }, credentials, signer, func(store *HandoffStore) HandoffRepository {
		failing.delegate = store
		return failing
	})
	ref := "skill_handoff_local_reconcile"
	expiresAt := now.Add(2 * time.Minute)
	if _, err := first.entry.BeginSkill(context.Background(), SkillHandoffRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		HandoffRef: ref, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	secret := []byte("local-reconcile-private-secret")
	completed, err := first.entry.CompleteSkill(context.Background(), CompleteSkillRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256, HandoffRef: ref,
		Connection: LocalConnectionInput{
			Alias: "本机对账设备", IP: "10.70.80.90", Port: 8000, Username: "operator", Password: secret,
			PinnedSerial: "reconcile-serial", PinnedType: "edge-box",
		},
		Grant: grant,
	})
	if !errors.Is(err, ErrHandoffCommit) || completed.Status != StatusCompleted || !allZero(secret) {
		t.Fatalf("CompleteSkill(crash window)=(%+v, %v) secretCleared=%v", completed, err, allZero(secret))
	}
	saga, err := first.journal.Get(context.Background(), completed.OperationID)
	if err != nil || saga.Phase != PhaseCompleted {
		t.Fatalf("authoritative completed saga=%+v err=%v", saga, err)
	}
	journalOnly := &completionJournalFixture{record: saga}
	reader := &Service{journal: journalOnly}
	proof, err := reader.InspectOperationCompletion(context.Background(), completed.OperationID)
	if err != nil || !proof.Found || !proof.Completed || proof.OperationID != completed.OperationID ||
		proof.TenantID != binding.TenantID || proof.SiteID != binding.SiteID || proof.PrincipalSHA256 != binding.PrincipalSHA256 || journalOnly.writes != 0 {
		t.Fatalf("InspectOperationCompletion()=%+v err=%v writes=%d", proof, err, journalOnly.writes)
	}
	drifted := saga
	drifted.ProfileID = "dpf_" + strings.Repeat("f", 32)
	if _, err := (&Service{journal: &completionJournalFixture{record: drifted}}).InspectOperationCompletion(context.Background(), completed.OperationID); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("InspectOperationCompletion(non-entry profile identity) error=%v", err)
	}
	first.close(t)

	current = expiresAt.Add(time.Minute)
	second := openEntryTestStack(t, paths, func() time.Time { return current }, credentials, signer, nil)
	defer second.close(t)
	if _, err := second.handoffs.Resolve(context.Background(), binding, ref); !errors.Is(err, ErrHandoffExpired) {
		t.Fatalf("Resolve(expired pending) error=%v", err)
	}

	const workers = 12
	results := make(chan HandoffReconcileResult, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, reconcileErr := second.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{Limit: 10})
			if reconcileErr != nil {
				errorsFound <- reconcileErr
				return
			}
			results <- result
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for reconcileErr := range errorsFound {
		t.Fatalf("ReconcileCompletedHandoffs(concurrent) error=%v", reconcileErr)
	}
	marked := 0
	for result := range results {
		if result.Examined > 1 || result.ConfirmedCompleted > 1 {
			t.Fatalf("unbounded reconcile result=%+v", result)
		}
		marked += result.ConfirmedCompleted
	}
	if marked == 0 {
		t.Fatal("no concurrent reconciliation observed the completed pending handoff")
	}
	stored, err := second.handoffs.load(context.Background(), ref)
	if err != nil || stored.State != HandoffCompleted || stored.OperationID != completed.OperationID {
		t.Fatalf("reconciled handoff=%+v err=%v", stored, err)
	}
	if _, err := second.handoffs.Resolve(context.Background(), binding, ref); !errors.Is(err, ErrHandoffExpired) {
		t.Fatalf("Resolve(expired completed) error=%v", err)
	}
	idempotent, err := second.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{Limit: 10})
	if err != nil || idempotent.Examined != 0 || idempotent.ConfirmedCompleted != 0 || idempotent.NextAfterRef != "" {
		t.Fatalf("ReconcileCompletedHandoffs(idempotent)=%+v err=%v", idempotent, err)
	}
	profiles, err := second.profiles.ListSite(context.Background(), binding.TenantID, binding.SiteID)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("reconciliation changed profile count=%d err=%v", len(profiles), err)
	}
	assertFilesExclude(t, []string{paths.handoffs}, "local-reconcile-private-secret", "10.70.80.90", "operator", "reconcile-serial")
}

func TestEntryServiceReconciliationPagesPastIncompleteAndRejectsScopeOrEvidenceDrift(t *testing.T) {
	now := time.Date(2026, 7, 20, 4, 0, 0, 0, time.UTC)
	paths := newEntryTestPaths(t)
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	signer := newEntryTestSigner(t)
	defer signer.Close()
	stack := openEntryTestStack(t, paths, func() time.Time { return now }, credentials, signer, nil)
	defer stack.close(t)
	binding := testHandoffBinding()
	refs := []string{"skill_reconcile_a", "skill_reconcile_m", "skill_reconcile_z"}
	for _, ref := range refs {
		if _, err := stack.entry.BeginSkill(context.Background(), SkillHandoffRequest{
			TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
			HandoffRef: ref, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	missing, err := stack.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{Limit: 1})
	if err != nil || missing.Examined != 1 || missing.ConfirmedCompleted != 0 || missing.NextAfterRef != refs[0] {
		t.Fatalf("ReconcileCompletedHandoffs(missing core operation)=%+v err=%v", missing, err)
	}
	completedOperation := stableHandoffOperationID(binding, refs[2])
	stack.entry.completions = &completionReaderFixture{values: map[string]OperationCompletion{
		completedOperation: {
			OperationID: completedOperation, TenantID: binding.TenantID, SiteID: binding.SiteID,
			PrincipalSHA256: binding.PrincipalSHA256, Found: true, Completed: true,
		},
	}}
	cursor := ""
	for index, wantRef := range refs {
		result, err := stack.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{AfterRef: cursor, Limit: 1})
		if err != nil || result.Examined != 1 || result.NextAfterRef != wantRef {
			t.Fatalf("ReconcileCompletedHandoffs(page %d)=%+v err=%v", index, result, err)
		}
		wantConfirmed := 0
		if wantRef == refs[2] {
			wantConfirmed = 1
		}
		if got := result.ConfirmedCompleted; got != wantConfirmed {
			t.Fatalf("page %d marked=%d", index, got)
		}
		cursor = result.NextAfterRef
	}
	for _, ref := range refs[:2] {
		record, err := stack.handoffs.load(context.Background(), ref)
		if err != nil || record.State != HandoffPending {
			t.Fatalf("incomplete handoff %s=%+v err=%v", ref, record, err)
		}
	}
	marked, err := stack.handoffs.load(context.Background(), refs[2])
	if err != nil || marked.State != HandoffCompleted {
		t.Fatalf("completed handoff=%+v err=%v", marked, err)
	}
	for _, request := range []HandoffReconcileRequest{{Limit: 0}, {Limit: MaximumHandoffRecoveryBatch + 1}, {AfterRef: "invalid cursor", Limit: 1}} {
		if _, err := stack.entry.ReconcileCompletedHandoffs(context.Background(), request); !errors.Is(err, ErrInvalidHandoff) {
			t.Fatalf("ReconcileCompletedHandoffs(%+v) error=%v", request, err)
		}
	}

	scopeRef := refs[0]
	scopeOperation := stableHandoffOperationID(binding, scopeRef)
	stack.entry.completions = &completionReaderFixture{values: map[string]OperationCompletion{
		scopeOperation: {
			OperationID: scopeOperation, TenantID: "tenant-other", SiteID: binding.SiteID,
			PrincipalSHA256: binding.PrincipalSHA256, Found: true, Completed: true,
		},
	}}
	if _, err := stack.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{Limit: 1}); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("ReconcileCompletedHandoffs(scope drift) error=%v", err)
	}
	record, err := stack.handoffs.load(context.Background(), scopeRef)
	if err != nil || record.State != HandoffPending {
		t.Fatalf("scope-drift handoff=%+v err=%v", record, err)
	}

	stack.entry.completions = &completionReaderFixture{values: map[string]OperationCompletion{
		scopeOperation: {OperationID: "onb_" + strings.Repeat("f", 32), Found: false},
	}}
	if _, err := stack.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{Limit: 1}); !errors.Is(err, ErrHandoffIntegrity) {
		t.Fatalf("ReconcileCompletedHandoffs(evidence drift) error=%v", err)
	}
}

func TestEntryServiceReconciliationKeepsCursorBeforeFailedCASAndRetriesIdempotently(t *testing.T) {
	now := time.Date(2026, 7, 20, 4, 30, 0, 0, time.UTC)
	paths := newEntryTestPaths(t)
	credentials := credential.NewMemoryStore()
	defer credentials.Purge()
	signer := newEntryTestSigner(t)
	defer signer.Close()
	failing := &failMarkRepository{remaining: 1}
	stack := openEntryTestStack(t, paths, func() time.Time { return now }, credentials, signer, func(store *HandoffStore) HandoffRepository {
		failing.delegate = store
		return failing
	})
	defer stack.close(t)
	binding := testHandoffBinding()
	refs := []string{"skill_reconcile_cas_a", "skill_reconcile_cas_b"}
	for _, ref := range refs {
		if _, err := stack.entry.BeginSkill(context.Background(), SkillHandoffRequest{
			TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
			HandoffRef: ref, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	secondOperation := stableHandoffOperationID(binding, refs[1])
	stack.entry.completions = &completionReaderFixture{values: map[string]OperationCompletion{
		secondOperation: {
			OperationID: secondOperation, TenantID: binding.TenantID, SiteID: binding.SiteID,
			PrincipalSHA256: binding.PrincipalSHA256, Found: true, Completed: true,
		},
	}}
	partial, err := stack.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{Limit: 2})
	if !errors.Is(err, ErrHandoffCommit) || partial.Examined != 1 || partial.ConfirmedCompleted != 0 || partial.NextAfterRef != refs[0] {
		t.Fatalf("ReconcileCompletedHandoffs(failed CAS)=%+v err=%v", partial, err)
	}
	pending, err := stack.handoffs.load(context.Background(), refs[1])
	if err != nil || pending.State != HandoffPending {
		t.Fatalf("failed-CAS handoff=%+v err=%v", pending, err)
	}
	retried, err := stack.entry.ReconcileCompletedHandoffs(context.Background(), HandoffReconcileRequest{AfterRef: partial.NextAfterRef, Limit: 1})
	if err != nil || retried.Examined != 1 || retried.ConfirmedCompleted != 1 || retried.NextAfterRef != refs[1] {
		t.Fatalf("ReconcileCompletedHandoffs(retry)=%+v err=%v", retried, err)
	}
	completed, err := stack.handoffs.load(context.Background(), refs[1])
	if err != nil || completed.State != HandoffCompleted {
		t.Fatalf("retried handoff=%+v err=%v", completed, err)
	}
}

func TestOnboardingEntryTypesKeepSkillAndLocalBoundariesExplicit(t *testing.T) {
	for name, domain := range map[string]string{
		"operation": handoffOperationDomain,
		"record":    handoffRecordDomain,
		"profile":   onboardingProfileDomain,
		"local":     onboardingLocalEntryDomain,
	} {
		if !strings.Contains(domain, ".v2\x00") {
			t.Fatalf("%s domain is not an explicit v2 domain: %q", name, domain)
		}
	}
	if handoffDatabaseVersion != 2 {
		t.Fatalf("handoff database version=%d want=2", handoffDatabaseVersion)
	}
	for _, protectedType := range []reflect.Type{
		reflect.TypeOf(OperationCompletion{}), reflect.TypeOf(HandoffReconcileRequest{}), reflect.TypeOf(HandoffReconcileResult{}),
	} {
		for index := 0; index < protectedType.NumField(); index++ {
			name := strings.ToLower(protectedType.Field(index).Name)
			for _, forbidden := range []string{"grant", "secret", "password", "credential", "connection", "endpoint", "username", "native", "device", "command"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s contains forbidden field %q", protectedType.Name(), protectedType.Field(index).Name)
				}
			}
		}
	}
	typeOfRequest := reflect.TypeOf(SkillHandoffRequest{})
	var fields []string
	for index := 0; index < typeOfRequest.NumField(); index++ {
		fields = append(fields, typeOfRequest.Field(index).Name)
	}
	if got, want := strings.Join(fields, ","), "TenantID,SiteID,PrincipalSHA256,HandoffRef,ExpiresAt"; got != want {
		t.Fatalf("SkillHandoffRequest fields=%s want=%s", got, want)
	}
	exactRaw := []byte(`{"tenantId":"tenant-a","siteId":"site-a","principalSha256":"` + strings.Repeat("a", 64) + `","handoffRef":"handoff-exact","expiresAt":"2026-07-19T20:00:00Z"}`)
	var exact SkillHandoffRequest
	if err := json.Unmarshal(exactRaw, &exact); err != nil || exact.HandoffRef != "handoff-exact" {
		t.Fatalf("exact SkillHandoffRequest decode=%+v err=%v", exact, err)
	}
	for _, forbidden := range []string{"endpoint", "username", "password", "nativeId", "pinnedSerial"} {
		raw := append([]byte(nil), exactRaw[:len(exactRaw)-1]...)
		raw = append(raw, []byte(`,"`+forbidden+`":"forbidden"}`)...)
		if err := json.Unmarshal(raw, &SkillHandoffRequest{}); !errors.Is(err, ErrInvalidHandoff) {
			t.Fatalf("SkillHandoffRequest accepted forbidden field %q: %v", forbidden, err)
		}
	}
	ticketRaw, err := json.Marshal(SkillHandoff{HandoffRef: "handoff-public", ExpiresAt: time.Now().UTC()})
	if err != nil || strings.Contains(string(ticketRaw), "operation") || strings.Contains(string(ticketRaw), "principal") {
		t.Fatalf("SkillHandoff projection=%s err=%v", ticketRaw, err)
	}

	secret := []byte("projection-private-secret")
	values := []any{
		SkillHandoffRequest{TenantID: "tenant-private", SiteID: "site-private", PrincipalSHA256: strings.Repeat("a", 64), HandoffRef: "handoff-private"},
		LocalConnectionInput{IP: "10.60.70.80", Username: "private-user", Password: secret, PinnedSerial: "private-serial"},
		CompleteSkillRequest{TenantID: "tenant-private", Connection: LocalConnectionInput{Password: secret}},
		DirectConnectRequest{TenantID: "tenant-private", Connection: LocalConnectionInput{Password: secret}},
		HandoffBinding{TenantID: "tenant-private", SiteID: "site-private", PrincipalSHA256: strings.Repeat("a", 64)},
		testHandoffRecord(testHandoffBinding(), "handoff-protected", time.Now().UTC().Add(time.Hour)),
		OperationCompletion{OperationID: "onb_" + strings.Repeat("a", 32), TenantID: "tenant-private", SiteID: "site-private", PrincipalSHA256: strings.Repeat("a", 64), Found: true},
		HandoffReconcileRequest{AfterRef: "handoff-private", Limit: 10},
		HandoffReconcileResult{Examined: 1, NextAfterRef: "handoff-private"},
	}
	for _, value := range values {
		if _, err := json.Marshal(value); !errors.Is(err, credential.ErrProtectedProjection) {
			t.Fatalf("protected entry projection type=%T error=%v", value, err)
		}
		projected := fmt.Sprintf("%+v %#v", value, value)
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("entry", slog.Any("value", value))
		projected += output.String()
		for _, sensitive := range []string{"tenant-private", "handoff-private", "10.60.70.80", "private-user", "projection-private-secret", "private-serial"} {
			if strings.Contains(projected, sensitive) {
				t.Fatalf("entry projection type=%T leaked %q: %s", value, sensitive, projected)
			}
		}
	}
}

type entryTestPaths struct {
	profiles string
	journal  string
	handoffs string
}

func newEntryTestPaths(t *testing.T) entryTestPaths {
	t.Helper()
	root := filepath.Join(t.TempDir(), "protected")
	return entryTestPaths{
		profiles: filepath.Join(root, "profiles.db"),
		journal:  filepath.Join(root, "onboarding.db"),
		handoffs: filepath.Join(root, "handoffs.db"),
	}
}

type entryTestStack struct {
	profiles *profile.Store
	journal  *Journal
	handoffs *HandoffStore
	entry    *EntryService
}

func openEntryTestStack(
	t *testing.T,
	paths entryTestPaths,
	now func() time.Time,
	credentials credential.SecretStore,
	signer *authority.Signer,
	repository func(*HandoffStore) HandoffRepository,
) *entryTestStack {
	t.Helper()
	profiles, err := profile.Open(paths.profiles)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(paths.journal)
	if err != nil {
		_ = profiles.Close()
		t.Fatal(err)
	}
	journal.now = now
	handoffs, err := OpenHandoffStore(HandoffStoreConfig{Path: paths.handoffs, Now: now})
	if err != nil {
		_ = journal.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	core, err := NewService(profiles, credentials, journal, signer, WithClock(now))
	if err != nil {
		_ = handoffs.Close()
		_ = journal.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	var handoffPort HandoffRepository = handoffs
	if repository != nil {
		handoffPort = repository(handoffs)
	}
	entry, err := NewEntryService(EntryServiceConfig{Core: core, Handoffs: handoffPort})
	if err != nil {
		_ = handoffs.Close()
		_ = journal.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	return &entryTestStack{profiles: profiles, journal: journal, handoffs: handoffs, entry: entry}
}

func (s *entryTestStack) close(t *testing.T) {
	t.Helper()
	for _, closeStore := range []func() error{s.handoffs.Close, s.journal.Close, s.profiles.Close} {
		if err := closeStore(); err != nil {
			t.Error(err)
		}
	}
}

func newEntryTestSigner(t *testing.T) *authority.Signer {
	t.Helper()
	signer, err := authority.NewSigner("entry-test-issuer", bytes.Repeat([]byte{0x7c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func issueEntryCreateGrant(t *testing.T, signer *authority.Signer, now time.Time, binding HandoffBinding, id string) authority.Grant {
	t.Helper()
	grant, err := signer.Issue(id, authority.ConnectionProfileWrite, binding.PrincipalSHA256, authority.Scope{
		TenantID: binding.TenantID, SiteID: binding.SiteID, OperationKinds: []string{authority.OpProfileCreate},
	}, now.Add(-time.Minute), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func assertFilesExclude(t *testing.T, paths []string, forbidden ...string) {
	t.Helper()
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if strings.Contains(string(raw), value) {
				t.Fatalf("protected state %s contains forbidden value %q", filepath.Base(path), value)
			}
		}
	}
}

var errInjectedHandoffMark = errors.New("injected handoff mark failure")

func entryOperationCause(err error) error {
	var operationError *OperationError
	if errors.As(err, &operationError) {
		return operationError.cause
	}
	return err
}

type failMarkRepository struct {
	mu        sync.Mutex
	delegate  HandoffRepository
	remaining int
}

type completionReaderFixture struct {
	mu     sync.Mutex
	values map[string]OperationCompletion
	err    error
	calls  []string
}

func (r *completionReaderFixture) InspectOperationCompletion(_ context.Context, operationID string) (OperationCompletion, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, operationID)
	if r.err != nil {
		return OperationCompletion{}, r.err
	}
	if value, ok := r.values[operationID]; ok {
		return value, nil
	}
	return OperationCompletion{OperationID: operationID}, nil
}

var _ OperationCompletionReader = (*completionReaderFixture)(nil)

type completionJournalFixture struct {
	record SagaRecord
	err    error
	writes int
}

func (j *completionJournalFixture) Begin(context.Context, SagaRecord) (SagaRecord, error) {
	j.writes++
	return SagaRecord{}, ErrSagaConflict
}

func (j *completionJournalFixture) Get(_ context.Context, operationID string) (SagaRecord, error) {
	if j.err != nil {
		return SagaRecord{}, j.err
	}
	if j.record.OperationID != operationID {
		return SagaRecord{}, ErrSagaNotFound
	}
	return j.record, nil
}

func (j *completionJournalFixture) Save(context.Context, SagaRecord) (SagaRecord, error) {
	j.writes++
	return SagaRecord{}, ErrSagaConflict
}

var _ SagaJournal = (*completionJournalFixture)(nil)

func (r *failMarkRepository) Begin(ctx context.Context, record HandoffRecord) (HandoffRecord, error) {
	return r.delegate.Begin(ctx, record)
}

func (r *failMarkRepository) Resolve(ctx context.Context, binding HandoffBinding, ref string) (HandoffRecord, error) {
	return r.delegate.Resolve(ctx, binding, ref)
}

func (r *failMarkRepository) PendingForRecovery(ctx context.Context, afterRef string, limit int) ([]HandoffRecord, error) {
	return r.delegate.PendingForRecovery(ctx, afterRef, limit)
}

func (r *failMarkRepository) MarkCompleted(ctx context.Context, record HandoffRecord) (HandoffRecord, error) {
	r.mu.Lock()
	if r.remaining > 0 {
		r.remaining--
		r.mu.Unlock()
		return HandoffRecord{}, errInjectedHandoffMark
	}
	r.mu.Unlock()
	return r.delegate.MarkCompleted(ctx, record)
}

var _ HandoffRepository = (*failMarkRepository)(nil)
