package inspectionlocal

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

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectioninteraction"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
	operatorsession "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestSessionBinderRequiresVaultSealedInspectionHandoffAndExactCSRF(t *testing.T) {
	vault := operatorsession.New(nil)
	binder, err := NewSessionBinder(SessionBinderConfig{Sessions: vaultBrowserSessions{vault: vault}})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := vault.IssueBootstrapForIntent(operatorsession.OpenIntent{
		View: operatorsession.ViewInspectionInteraction, HandoffRef: "sealed_handoff",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	current, readOnly, err := binder.Authenticate(auth.SessionID)
	if err != nil || !readOnly.valid() || readOnly.handoffRef != "sealed_handoff" || readOnly.writeAuthorized {
		t.Fatalf("Authenticate() auth=%+v local=%+v err=%v", current, readOnly, err)
	}
	if _, _, err := binder.AuthorizePost(auth.SessionID, strings.Repeat("0", 64)); !errors.Is(err, ErrDenied) {
		t.Fatalf("AuthorizePost(CSRF spoof) error=%v", err)
	}
	_, writable, err := binder.AuthorizePost(auth.SessionID, auth.CSRF)
	if err != nil || !writable.writeAuthorized || writable.handoffRef != "sealed_handoff" {
		t.Fatalf("AuthorizePost() local=%+v err=%v", writable, err)
	}

	forged := writable
	forged.handoffRef = "other_handoff"
	if _, err := binder.validate(forged, false); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("validate(forged handoff) error=%v", err)
	}
	forged = writable
	forged.browserBindingSHA256 = strings.Repeat("0", 64)
	if _, err := binder.validate(forged, false); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("validate(forged binding) error=%v", err)
	}
	homeBootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	home, err := vault.ConsumeBootstrap(homeBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := binder.Authenticate(home.SessionID); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Authenticate(non-inspection) error=%v", err)
	}
	if _, err := NewSessionBinder(SessionBinderConfig{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewSessionBinder(nil) error=%v", err)
	}
	for _, config := range []Config{
		{}, {Sessions: binder}, {Onboarding: &onboarding.EntryService{}},
		{Connections: &onboarding.HandoffStore{}}, {Changes: &inspectioninteraction.Store{}},
	} {
		if _, err := NewService(config); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("NewService(incomplete) error=%v", err)
		}
	}
}

func TestResolveUsesOnlySessionBoundHandoffAndFailsClosedOnAmbiguity(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	connectionRef := "skill_connection_resolve"
	changeRef := "local_change_resolve"
	ambiguousRef := "skill_ambiguous_resolve"
	h.beginConnection(t, connectionRef, h.now.Add(time.Hour))
	h.registerChange(t, changeRef, h.now.Add(time.Hour))
	h.beginConnection(t, ambiguousRef, h.now.Add(time.Hour))
	h.registerChange(t, ambiguousRef, h.now.Add(time.Hour))
	connectionSession := h.bindSession(t, connectionRef)
	changeSession := h.bindSession(t, changeRef)
	ambiguousSession := h.bindSession(t, ambiguousRef)

	connection, err := h.service.Resolve(context.Background(), connectionSession)
	if err != nil || connection != (Interaction{Kind: KindConnection, Action: ActionCompleteConnection, Status: StatusPending}) {
		t.Fatalf("Resolve(connection)=%+v err=%v", connection, err)
	}
	change, err := h.service.Resolve(context.Background(), changeSession)
	if err != nil || change != (Interaction{Kind: KindPersistentChange, Action: ActionPreparePersistentTransfer, Status: StatusPending}) {
		t.Fatalf("Resolve(change)=%+v err=%v", change, err)
	}
	if _, err := h.service.Resolve(context.Background(), ambiguousSession); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("Resolve(ambiguous) error=%v", err)
	}
	ambiguousPassword := []byte("ambiguous-private-password")
	if _, err := h.service.CompleteConnection(context.Background(), ambiguousSession, CompleteConnectionRequest{
		Connection: onboarding.LocalConnectionInput{Password: ambiguousPassword},
	}); !errors.Is(err, ErrAmbiguous) || !allZero(ambiguousPassword) {
		t.Fatalf("CompleteConnection(ambiguous) error=%v passwordCleared=%v", err, allZero(ambiguousPassword))
	}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), ambiguousSession, PersistentTransferRequest{
		ProposalRef: "proposal_ambiguous",
	}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("PreparePersistentTransfer(ambiguous) error=%v", err)
	}
	missingSession := h.bindSession(t, "local_missing_resolve")
	if _, err := h.service.Resolve(context.Background(), missingSession); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Resolve(missing) error=%v", err)
	}
	forgedCrossHandoff := connectionSession
	forgedCrossHandoff.handoffRef = changeRef
	if _, err := h.service.Resolve(context.Background(), forgedCrossHandoff); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Resolve(cross-handoff spoof) error=%v", err)
	}
	if _, err := h.service.Resolve(context.Background(), LocalSession{}); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Resolve(empty session) error=%v", err)
	}
}

func TestResolvePreservesOrdinaryExpiryAndDetectsExpiredDualStoreConflict(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	expiresAt := h.now.Add(time.Minute)
	h.beginConnection(t, "expired_connection", expiresAt)
	h.registerChange(t, "expired_change", expiresAt)
	h.beginConnection(t, "expired_ambiguous", expiresAt)
	h.registerChange(t, "expired_ambiguous", expiresAt)
	h.setNow(expiresAt)
	for _, ref := range []string{"expired_connection", "expired_change"} {
		if _, err := h.service.Resolve(context.Background(), h.bindSession(t, ref)); !errors.Is(err, ErrExpired) {
			t.Fatalf("Resolve(%s) error=%v", ref, err)
		}
	}
	if _, err := h.service.Resolve(context.Background(), h.bindSession(t, "expired_ambiguous")); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("Resolve(expired ambiguity) error=%v", err)
	}
}

func TestCompleteConnectionDelegatesRecordDerivedScopeAndAlwaysClearsPassword(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	ref := "complete_connection_exact"
	h.beginConnection(t, ref, h.now.Add(time.Hour))
	local := h.bindSession(t, ref)
	grant := h.connectionGrant(t, "complete-connection")
	password := []byte("connection-private-password")
	completed, err := h.service.CompleteConnection(context.Background(), local, CompleteConnectionRequest{
		Connection: onboarding.LocalConnectionInput{
			Alias: "前台接入设备", IP: "10.90.80.70", Port: 8000, Username: "local-operator", Password: password,
			PinnedSerial: "local-private-serial", PinnedType: "edge-box",
		},
		Grant: grant,
	})
	if err != nil || completed != (Interaction{Kind: KindConnection, Action: ActionNone, Status: StatusCompleted}) || !allZero(password) {
		t.Fatalf("CompleteConnection()=%+v err=%v passwordCleared=%v", completed, err, allZero(password))
	}
	resolved, err := h.service.Resolve(context.Background(), local)
	if err != nil || resolved.Status != StatusCompleted || resolved.Action != ActionNone {
		t.Fatalf("Resolve(completed)=%+v err=%v", resolved, err)
	}
	replayPassword := []byte("connection-private-password")
	replayed, err := h.service.CompleteConnection(context.Background(), local, CompleteConnectionRequest{
		Connection: onboarding.LocalConnectionInput{
			Alias: "前台接入设备", IP: "10.90.80.70", Port: 8000, Username: "local-operator", Password: replayPassword,
			PinnedSerial: "local-private-serial", PinnedType: "edge-box",
		},
		Grant: grant,
	})
	if err != nil || replayed.Status != StatusCompleted || !allZero(replayPassword) {
		t.Fatalf("CompleteConnection(replay)=%+v err=%v passwordCleared=%v", replayed, err, allZero(replayPassword))
	}

	forgedPassword := []byte("forged-session-private-password")
	forged := local
	forged.handoffRef = "complete_connection_other"
	_, err = h.service.CompleteConnection(context.Background(), forged, CompleteConnectionRequest{
		Connection: onboarding.LocalConnectionInput{Password: forgedPassword}, Grant: grant,
	})
	if !errors.Is(err, ErrInvalidSession) || !allZero(forgedPassword) {
		t.Fatalf("CompleteConnection(session spoof) error=%v passwordCleared=%v", err, allZero(forgedPassword))
	}
	invalidRef := "complete_connection_invalid"
	h.beginConnection(t, invalidRef, h.now.Add(time.Hour))
	invalidPassword := []byte("invalid-request-private-password")
	_, err = h.service.CompleteConnection(context.Background(), h.bindSession(t, invalidRef), CompleteConnectionRequest{
		Connection: onboarding.LocalConnectionInput{Password: invalidPassword}, Grant: grant,
	})
	if !errors.Is(err, ErrInvalidRequest) || !allZero(invalidPassword) {
		t.Fatalf("CompleteConnection(invalid) error=%v passwordCleared=%v", err, allZero(invalidPassword))
	}

	deniedRef := "complete_connection_denied"
	h.beginConnection(t, deniedRef, h.now.Add(time.Hour))
	deniedSession := h.bindSession(t, deniedRef)
	deniedPassword := []byte("denied-private-password")
	_, err = h.service.CompleteConnection(context.Background(), deniedSession, CompleteConnectionRequest{
		Connection: onboarding.LocalConnectionInput{
			Alias: "拒绝设备", IP: "10.90.80.71", Port: 8000, Username: "operator", Password: deniedPassword,
			PinnedSerial: "denied-serial", PinnedType: "edge-box",
		},
	})
	if !errors.Is(err, ErrDenied) || !allZero(deniedPassword) || strings.Contains(err.Error(), "denied-private-password") {
		t.Fatalf("CompleteConnection(denied) error=%v passwordCleared=%v", err, allZero(deniedPassword))
	}

	profiles, err := h.profiles.ListSite(context.Background(), h.tenant, h.site)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles after completion=%d err=%v", len(profiles), err)
	}
	assertFilesExclude(t, []string{h.profilePath, h.journalPath, h.handoffPath, h.changePath},
		"connection-private-password", "forged-session-private-password", "invalid-request-private-password", "denied-private-password")
}

func TestCompleteVerifiedConnectionClosesExactHandoffWithoutCreatingProfile(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	verifier := &localPersistedVerifier{}
	h.service.persistentConnection = verifier
	ref := "complete_persisted_exact"
	h.beginConnection(t, ref, h.now.Add(time.Hour))
	local := h.bindSession(t, ref)
	completed, err := h.service.CompleteVerifiedConnection(context.Background(), local)
	if err != nil || completed != (Interaction{Kind: KindConnection, Action: ActionNone, Status: StatusCompleted}) || verifier.calls != 1 {
		t.Fatalf("CompleteVerifiedConnection()=%#v err=%v verifier calls=%d", completed, err, verifier.calls)
	}
	profiles, err := h.profiles.ListSite(context.Background(), h.tenant, h.site)
	if err != nil || len(profiles) != 0 {
		t.Fatalf("verified handoff created profiles=%d err=%v", len(profiles), err)
	}
	resolved, err := h.service.Resolve(context.Background(), local)
	if err != nil || resolved.Status != StatusCompleted || resolved.Action != ActionNone {
		t.Fatalf("Resolve(completed)=%#v err=%v", resolved, err)
	}
	forged := local
	forged.handoffRef = "complete_persisted_other"
	if _, err := h.service.CompleteVerifiedConnection(context.Background(), forged); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("forged verified completion error=%v", err)
	}
}

type localPersistedVerifier struct {
	calls int
	err   error
}

func (v *localPersistedVerifier) VerifyCurrent(context.Context) error {
	v.calls++
	return v.err
}

func TestPersistentTransferIsStableCASIdempotentConcurrentAndRestartSafe(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	ref := "persistent_transfer_restart"
	proposalRef := "proposal_stable_restart"
	h.registerChange(t, ref, h.now.Add(time.Hour))
	local := h.bindSession(t, ref)
	request := PersistentTransferRequest{ProposalRef: proposalRef}
	forged := local
	forged.handoffRef = "persistent_transfer_other"
	if _, err := h.service.PreparePersistentTransfer(context.Background(), forged, request); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("PreparePersistentTransfer(handoff spoof) error=%v", err)
	}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), local, PersistentTransferRequest{
		ProposalRef: " " + proposalRef,
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PreparePersistentTransfer(non-canonical proposal) error=%v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		prepared, err := h.service.PreparePersistentTransfer(context.Background(), local, request)
		if err != nil || prepared != (Interaction{Kind: KindPersistentChange, Action: ActionMarkPersistentTransferred, Status: StatusTransferPrepared}) {
			t.Fatalf("PreparePersistentTransfer(%d)=%+v err=%v", attempt, prepared, err)
		}
	}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), local, PersistentTransferRequest{
		ProposalRef: "proposal_conflict_restart",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("PreparePersistentTransfer(conflict) error=%v", err)
	}
	if err := h.changes.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := inspectioninteraction.OpenStore(inspectioninteraction.StoreConfig{Path: h.changePath, Now: h.clock})
	if err != nil {
		t.Fatal(err)
	}
	h.changes = reopened
	h.service, err = NewService(Config{Sessions: h.binder, Onboarding: h.entry, Connections: h.handoffs, Changes: reopened})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 16
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			transferred, transferErr := h.service.MarkPersistentTransferred(context.Background(), local, request)
			if transferErr != nil {
				errorsFound <- transferErr
				return
			}
			if transferred != (Interaction{Kind: KindPersistentChange, Action: ActionNone, Status: StatusTransferred}) {
				errorsFound <- fmt.Errorf("unexpected transfer result: %v", transferred)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for transferErr := range errorsFound {
		t.Fatalf("MarkPersistentTransferred(concurrent) error=%v", transferErr)
	}
	resolved, err := h.service.Resolve(context.Background(), local)
	if err != nil || resolved != (Interaction{Kind: KindPersistentChange, Action: ActionNone, Status: StatusTransferred}) {
		t.Fatalf("Resolve(transferred)=%+v err=%v", resolved, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := h.service.MarkPersistentTransferred(context.Background(), local, request); err != nil {
			t.Fatalf("MarkPersistentTransferred(replay %d) error=%v", attempt, err)
		}
	}
}

func TestPersistentTransferDerivesScopeOnlyFromProtectedRecord(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	ref := "record_derived_scope"
	binding := inspectioninteraction.Binding{
		TenantID: "tenant-record", SiteID: "site-record", PrincipalSHA256: strings.Repeat("e", 64),
	}
	_, err := h.changes.Register(context.Background(), inspectioninteraction.Record{
		HandoffRef: ref, TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		InteractionType: planning.LocalInteractionPersistentChange, Operation: planning.PendingTaskDisable,
		SourceRef: "source-record", ExpectedSourceRevision: 4, TaskRef: "task-record", ExpectedTaskRevision: 7,
		ExpiresAt: h.now.Add(time.Hour), State: inspectioninteraction.StatePending,
	})
	if err != nil {
		t.Fatal(err)
	}
	local := h.bindSession(t, ref)
	prepared, err := h.service.PreparePersistentTransfer(context.Background(), local, PersistentTransferRequest{
		ProposalRef: "proposal_record_scope",
	})
	if err != nil || prepared.Status != StatusTransferPrepared {
		t.Fatalf("PreparePersistentTransfer(record-derived scope)=%+v err=%v", prepared, err)
	}
	record, err := h.changes.Resolve(context.Background(), binding, ref)
	if err != nil || record.ProposalRef != "proposal_record_scope" {
		t.Fatalf("Resolve(record-derived scope) proposal=%q err=%v", record.ProposalRef, err)
	}
}

func TestPersistentTransferPreservesPreparedExpirySemanticsAndRejectsWrongKind(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	expiresAt := h.now.Add(time.Minute)
	preparedRef := "transfer_expired_prepared"
	pendingRef := "transfer_expired_pending"
	connectionRef := "transfer_wrong_connection"
	h.registerChange(t, preparedRef, expiresAt)
	h.registerChange(t, pendingRef, expiresAt)
	h.beginConnection(t, connectionRef, h.now.Add(time.Hour))
	preparedSession := h.bindSession(t, preparedRef)
	pendingSession := h.bindSession(t, pendingRef)
	connectionSession := h.bindSession(t, connectionRef)
	request := PersistentTransferRequest{ProposalRef: "proposal_expiry_exact"}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), preparedSession, request); err != nil {
		t.Fatal(err)
	}
	h.setNow(expiresAt)
	if _, err := h.service.Resolve(context.Background(), preparedSession); !errors.Is(err, ErrExpired) {
		t.Fatalf("Resolve(expired prepared) error=%v", err)
	}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), preparedSession, request); err != nil {
		t.Fatalf("PreparePersistentTransfer(expired replay) error=%v", err)
	}
	if _, err := h.service.MarkPersistentTransferred(context.Background(), preparedSession, request); err != nil {
		t.Fatalf("MarkPersistentTransferred(expired prepared) error=%v", err)
	}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), pendingSession, PersistentTransferRequest{
		ProposalRef: "proposal_expired_pending",
	}); !errors.Is(err, ErrExpired) {
		t.Fatalf("PreparePersistentTransfer(expired pending) error=%v", err)
	}
	if _, err := h.service.MarkPersistentTransferred(context.Background(), pendingSession, PersistentTransferRequest{
		ProposalRef: "proposal_not_prepared",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("MarkPersistentTransferred(not prepared) error=%v", err)
	}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), connectionSession, PersistentTransferRequest{
		ProposalRef: "proposal_wrong_kind",
	}); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("PreparePersistentTransfer(connection) error=%v", err)
	}
}

func TestServiceReauthenticatesEveryCallAndRejectsExpiredOrDriftedBrowser(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	ref := "reauthenticated_handoff"
	h.registerChange(t, ref, h.now.Add(time.Hour))
	source := &mutableBrowserSessions{
		auth: BrowserSession{
			SessionID: strings.Repeat("b", 64), CSRF: strings.Repeat("c", 64),
			View: operatorsession.ViewInspectionInteraction, HandoffRef: ref,
		},
	}
	binder, err := newSessionBinder(source)
	if err != nil {
		t.Fatal(err)
	}
	h.service, err = NewService(Config{
		Sessions: binder, Onboarding: h.entry, Connections: h.handoffs, Changes: h.changes,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, local, err := binder.Authenticate(strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Resolve(context.Background(), local); err != nil {
		t.Fatalf("Resolve(live) error=%v", err)
	}
	source.setCSRF(strings.Repeat("d", 64))
	if _, err := h.service.Resolve(context.Background(), local); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("Resolve(re-authentication drift) error=%v", err)
	}
	source.setCSRF(strings.Repeat("c", 64))
	if _, err := h.service.Resolve(context.Background(), local); err != nil {
		t.Fatalf("Resolve(restored authentication) error=%v", err)
	}
	source.setUnavailable(errors.New("private-session-backend-detail"))
	if _, err := h.service.Resolve(context.Background(), local); !errors.Is(err, ErrInvalidSession) || strings.Contains(err.Error(), "private-session") {
		t.Fatalf("Resolve(expired browser) error=%v", err)
	}
	if calls := source.authenticateCalls(); calls < 5 {
		t.Fatalf("Authenticate calls=%d, want one mint plus every service call", calls)
	}
}

func TestReadOnlyLocalSessionCannotMutateAndPasswordIsStillCleared(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	connectionRef := "readonly_connection"
	changeRef := "readonly_change"
	h.beginConnection(t, connectionRef, h.now.Add(time.Hour))
	h.registerChange(t, changeRef, h.now.Add(time.Hour))
	connectionSession := h.bindReadSession(t, connectionRef)
	changeSession := h.bindReadSession(t, changeRef)
	if _, err := h.service.Resolve(context.Background(), connectionSession); err != nil {
		t.Fatalf("Resolve(read-only connection) error=%v", err)
	}
	if _, err := h.service.Resolve(context.Background(), changeSession); err != nil {
		t.Fatalf("Resolve(read-only change) error=%v", err)
	}
	password := []byte("read-only-private-password")
	if _, err := h.service.CompleteConnection(context.Background(), connectionSession, CompleteConnectionRequest{
		Connection: onboarding.LocalConnectionInput{Password: password},
	}); !errors.Is(err, ErrDenied) || !allZero(password) {
		t.Fatalf("CompleteConnection(read-only) error=%v passwordCleared=%v", err, allZero(password))
	}
	if _, err := h.service.PreparePersistentTransfer(context.Background(), changeSession, PersistentTransferRequest{
		ProposalRef: "proposal_read_only",
	}); !errors.Is(err, ErrDenied) {
		t.Fatalf("PreparePersistentTransfer(read-only) error=%v", err)
	}
}

func TestProtectedLocalTypesAndServiceBoundaryDoNotProjectSensitiveState(t *testing.T) {
	h := newHarness(t)
	defer h.close(t)
	secret := []byte("projection-private-password")
	local := h.bindSession(t, "projection_handoff")
	values := []any{
		local,
		Interaction{Kind: KindConnection, Action: ActionCompleteConnection, Status: StatusPending},
		CompleteConnectionRequest{
			Connection: onboarding.LocalConnectionInput{
				IP: "10.11.12.13", Username: "private-user", Password: secret, PinnedSerial: "private-native-serial",
			},
		},
		PersistentTransferRequest{ProposalRef: "proposal-private"},
	}
	for _, value := range values {
		if _, err := json.Marshal(value); !errors.Is(err, credential.ErrProtectedProjection) {
			t.Fatalf("projection type=%T error=%v", value, err)
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, credential.ErrProtectedProjection) {
			t.Fatalf("text projection type=%T error=%v", value, err)
		}
		projected := fmt.Sprintf("%+v %#v", value, value)
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("value", slog.Any("protected", value))
		projected += output.String()
		for _, forbidden := range []string{
			"tenant-local", "site-local", "projection_handoff", "handoff-private", "proposal-private", "10.11.12.13",
			"private-user", "projection-private-password", "private-native-serial",
		} {
			if strings.Contains(projected, forbidden) {
				t.Fatalf("projection type=%T leaked %q: %s", value, forbidden, projected)
			}
		}
	}
	interactionType := reflect.TypeOf(Interaction{})
	if interactionType.NumField() != 3 {
		t.Fatalf("Interaction fields=%d", interactionType.NumField())
	}
	for index := 0; index < interactionType.NumField(); index++ {
		name := strings.ToLower(interactionType.Field(index).Name)
		for _, forbidden := range []string{"endpoint", "secret", "password", "credential", "native", "source", "task", "proposal", "handoff", "tenant", "site", "principal"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Interaction contains forbidden field %q", interactionType.Field(index).Name)
			}
		}
	}
	serviceType := reflect.TypeOf(Service{})
	for index := 0; index < serviceType.NumField(); index++ {
		name := strings.ToLower(serviceType.Field(index).Name)
		for _, forbidden := range []string{"issuer", "signer", "creator", "adapter", "dispatch", "device", "authority"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Service contains forbidden dependency %q", serviceType.Field(index).Name)
			}
		}
	}
	for _, requestType := range []reflect.Type{reflect.TypeOf(CompleteConnectionRequest{}), reflect.TypeOf(PersistentTransferRequest{})} {
		for index := 0; index < requestType.NumField(); index++ {
			name := strings.ToLower(requestType.Field(index).Name)
			for _, forbidden := range []string{"handoff", "tenant", "site", "principal", "scope"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s contains request-controlled binding field %q", requestType.Name(), requestType.Field(index).Name)
				}
			}
		}
	}
}

type harness struct {
	mu sync.Mutex

	now       time.Time
	tenant    string
	site      string
	principal string

	profilePath string
	journalPath string
	handoffPath string
	changePath  string

	profiles    *profile.Store
	credentials *credential.MemoryStore
	journal     *onboarding.Journal
	signer      *authority.Signer
	handoffs    *onboarding.HandoffStore
	changes     *inspectioninteraction.Store
	entry       *onboarding.EntryService
	vault       *operatorsession.Vault
	binder      *SessionBinder
	service     *Service
}

type mutableBrowserSessions struct {
	mu          sync.Mutex
	auth        BrowserSession
	unavailable bool
	failure     error
	calls       int
}

type vaultBrowserSessions struct{ vault *operatorsession.Vault }

func (s vaultBrowserSessions) ResolveInspectionSession(sessionID string) (BrowserSession, error) {
	auth, err := s.vault.Authenticate(sessionID)
	if err != nil {
		return BrowserSession{}, err
	}
	handoffRef, err := s.vault.InspectionHandoff(auth)
	if err != nil {
		return BrowserSession{}, err
	}
	return BrowserSession{
		SessionID: auth.SessionID, CSRF: auth.CSRF, View: auth.View,
		TaskName: auth.TaskName, TaskAction: auth.TaskAction, HandoffRef: handoffRef,
	}, nil
}

func (s *mutableBrowserSessions) ResolveInspectionSession(sessionID string) (BrowserSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.unavailable || sessionID != s.auth.SessionID {
		if s.failure != nil {
			return BrowserSession{}, s.failure
		}
		return BrowserSession{}, operatorsession.ErrUnauthorized
	}
	return s.auth, nil
}

func (s *mutableBrowserSessions) setCSRF(value string) {
	s.mu.Lock()
	s.auth.CSRF = value
	s.mu.Unlock()
}

func (s *mutableBrowserSessions) setUnavailable(failure error) {
	s.mu.Lock()
	s.unavailable = true
	s.failure = failure
	s.mu.Unlock()
}

func (s *mutableBrowserSessions) authenticateCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := filepath.Join(t.TempDir(), "protected")
	h := &harness{
		now: time.Now().UTC().Truncate(time.Second), tenant: "tenant-local", site: "site-local",
		principal:   strings.Repeat("a", 64),
		profilePath: filepath.Join(root, "profiles.db"), journalPath: filepath.Join(root, "journal.db"),
		handoffPath: filepath.Join(root, "handoffs.db"), changePath: filepath.Join(root, "changes.db"),
	}
	var err error
	h.profiles, err = profile.Open(h.profilePath)
	if err != nil {
		t.Fatal(err)
	}
	h.credentials = credential.NewMemoryStore()
	h.journal, err = onboarding.OpenJournal(h.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	h.signer, err = authority.NewSigner("inspection-local-test", bytes.Repeat([]byte{0x5d}, 32))
	if err != nil {
		t.Fatal(err)
	}
	h.handoffs, err = onboarding.OpenHandoffStore(onboarding.HandoffStoreConfig{Path: h.handoffPath, Now: h.clock})
	if err != nil {
		t.Fatal(err)
	}
	h.changes, err = inspectioninteraction.OpenStore(inspectioninteraction.StoreConfig{Path: h.changePath, Now: h.clock})
	if err != nil {
		t.Fatal(err)
	}
	core, err := onboarding.NewService(h.profiles, h.credentials, h.journal, h.signer, onboarding.WithClock(h.clock))
	if err != nil {
		t.Fatal(err)
	}
	h.entry, err = onboarding.NewEntryService(onboarding.EntryServiceConfig{Core: core, Handoffs: h.handoffs})
	if err != nil {
		t.Fatal(err)
	}
	h.vault = operatorsession.New(nil)
	h.binder, err = NewSessionBinder(SessionBinderConfig{Sessions: vaultBrowserSessions{vault: h.vault}})
	if err != nil {
		t.Fatal(err)
	}
	h.service, err = NewService(Config{Sessions: h.binder, Onboarding: h.entry, Connections: h.handoffs, Changes: h.changes})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) setNow(value time.Time) {
	h.mu.Lock()
	h.now = value.UTC()
	h.mu.Unlock()
}

func (h *harness) bindSession(t *testing.T, handoffRef string) LocalSession {
	t.Helper()
	bootstrap, err := h.vault.IssueBootstrapForIntent(operatorsession.OpenIntent{
		View: operatorsession.ViewInspectionInteraction, HandoffRef: handoffRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := h.vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	_, bound, err := h.binder.AuthorizePost(auth.SessionID, auth.CSRF)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func (h *harness) bindReadSession(t *testing.T, handoffRef string) LocalSession {
	t.Helper()
	bootstrap, err := h.vault.IssueBootstrapForIntent(operatorsession.OpenIntent{
		View: operatorsession.ViewInspectionInteraction, HandoffRef: handoffRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := h.vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	_, bound, err := h.binder.Authenticate(auth.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func (h *harness) beginConnection(t *testing.T, handoffRef string, expiresAt time.Time) {
	t.Helper()
	if _, err := h.entry.BeginSkill(context.Background(), onboarding.SkillHandoffRequest{
		TenantID: h.tenant, SiteID: h.site, PrincipalSHA256: h.principal,
		HandoffRef: handoffRef, ExpiresAt: expiresAt.UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) registerChange(t *testing.T, handoffRef string, expiresAt time.Time) {
	t.Helper()
	_, err := h.changes.Register(context.Background(), inspectioninteraction.Record{
		HandoffRef: handoffRef, TenantID: h.tenant, SiteID: h.site, PrincipalSHA256: h.principal,
		InteractionType: planning.LocalInteractionPersistentChange, Operation: planning.PendingTaskDisable,
		SourceRef: "source-opaque", ExpectedSourceRevision: 2, TaskRef: "task-opaque", ExpectedTaskRevision: 3,
		ExpiresAt: expiresAt.UTC(), State: inspectioninteraction.StatePending,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (h *harness) connectionGrant(t *testing.T, id string) authority.Grant {
	t.Helper()
	grant, err := h.signer.Issue(id, authority.ConnectionProfileWrite, h.principal, authority.Scope{
		TenantID: h.tenant, SiteID: h.site, OperationKinds: []string{authority.OpProfileCreate},
	}, h.clock().Add(-time.Minute), h.clock().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func (h *harness) close(t *testing.T) {
	t.Helper()
	for _, closeStore := range []func() error{h.changes.Close, h.handoffs.Close, h.journal.Close, h.profiles.Close} {
		if err := closeStore(); err != nil {
			t.Error(err)
		}
	}
	h.credentials.Purge()
	h.signer.Close()
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
				t.Fatalf("protected file %s contains forbidden value %q", filepath.Base(path), value)
			}
		}
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
