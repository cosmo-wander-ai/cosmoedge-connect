package onboarding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

func TestJournalPersistsV2SagaThroughExplicitProtectedDTO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "onboarding-sagas.db")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	ref := testRef(t, "a")
	record := SagaRecord{
		Schema: SagaSchemaVersion, OperationID: operationID("2"), Operation: OperationRotateCredential, Phase: PhasePrepared,
		TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("b", 64),
		ProfileID: profileID("2"), ExpectedGeneration: 3,
		Alias: "设备", Endpoint: "http://10.20.30.40:8000", Username: "admin",
		PinnedSerial: "serial-a", PinnedType: "edge", TransportFingerprint: "sha256:" + strings.Repeat("c", 64),
		OldCredentialRef: ref,
	}
	stored, err := journal.Begin(context.Background(), record)
	if err != nil || stored.Version != 1 || stored.Schema != "cosmoedge.operator.onboarding.v2" {
		t.Fatalf("Begin()=(%+v, %v)", stored, err)
	}
	if _, err := json.Marshal(stored); !errors.Is(err, credential.ErrProtectedProjection) {
		t.Fatalf("generic saga projection exposed a credential ref: %v", err)
	}
	stored.NewCredentialRef = testRef(t, "d")
	stored.CredentialRotationID = testRotationID(t, "e")
	stored.CredentialRotationPhase = credential.RotationCommitted
	stored.Phase = PhaseCredentialStored
	stored, err = journal.Save(context.Background(), stored)
	if err != nil || stored.Version != 2 {
		t.Fatalf("Save()=(%+v, %v)", stored, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Get(context.Background(), record.OperationID)
	if err != nil || loaded.OldCredentialRef != ref || loaded.NewCredentialRef != stored.NewCredentialRef ||
		loaded.CredentialRotationID != stored.CredentialRotationID || loaded.CredentialRotationPhase != credential.RotationCommitted || loaded.Version != 2 {
		t.Fatalf("Get()=(%+v, %v)", loaded, err)
	}
	var userVersion int
	if err := reopened.db.QueryRow(`PRAGMA user_version`).Scan(&userVersion); err != nil || userVersion != 2 {
		t.Fatalf("journal user_version=%d err=%v", userVersion, err)
	}
	if err := localstate.ValidateFile(path); err != nil {
		t.Fatalf("journal permissions: %v", err)
	}
}

func TestJournalPersistsProtectedPutReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "create-sagas.db")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	putID := testPutOperationID(t, "f")
	record := SagaRecord{
		Schema: SagaSchemaVersion, OperationID: operationID("4"), Operation: OperationCreate, Phase: PhasePrepared,
		TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("b", 64),
		ProfileID: profileID("4"), Alias: "设备", Endpoint: "http://10.20.30.41:8000", Username: "admin",
		PinnedSerial: "serial-b", PinnedType: "edge", TransportFingerprint: "sha256:" + strings.Repeat("d", 64),
		CredentialPutID: putID,
	}
	stored, err := journal.Begin(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	stored.NewCredentialRef = testRef(t, "f")
	stored.CredentialPutPhase = credential.PutCommitted
	stored.Phase = PhaseCredentialStored
	if _, err := journal.Save(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Get(context.Background(), record.OperationID)
	if err != nil || loaded.CredentialPutID != putID || loaded.CredentialPutPhase != credential.PutCommitted || !loaded.NewCredentialRef.Valid() {
		t.Fatalf("protected put saga=%+v err=%v", loaded, err)
	}
}

func TestJournalRejectsV1AndUnprotectedFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	unprotected := filepath.Join(root, "unprotected.db")
	if err := os.WriteFile(unprotected, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(unprotected); err == nil {
		t.Fatal("unprotected journal was accepted")
	}

	v1 := filepath.Join(root, "v1.db")
	database, err := sql.Open("sqlite", v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`PRAGMA user_version=1`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(v1); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(v1); !errors.Is(err, ErrInvalidSaga) {
		t.Fatalf("v1 journal error=%v", err)
	}
}

func TestMemoryJournalUsesRevisionCAS(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	journal := NewMemoryJournal()
	journal.now = func() time.Time { return now }
	record := SagaRecord{
		Schema: SagaSchemaVersion, OperationID: operationID("3"), Operation: OperationForget, Phase: PhasePrepared,
		TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("a", 64),
		ProfileID: profileID("3"), ExpectedGeneration: 1, OldCredentialRef: testRef(t, "e"),
	}
	first, err := journal.Begin(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	first.Phase = PhaseProfileRevoking
	if _, err := journal.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second.Phase = PhaseProfileRevoking
	if _, err := journal.Save(context.Background(), second); !errors.Is(err, ErrSagaConflict) {
		t.Fatalf("stale saga revision error=%v", err)
	}
}

func TestJournalsAllowOnlyOneActiveSagaPerProfile(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		journal, err := OpenJournal(filepath.Join(t.TempDir(), "state", "active-sagas.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = journal.Close() })
		assertSingleActiveSaga(t, journal)
	})
	t.Run("memory", func(t *testing.T) {
		assertSingleActiveSaga(t, NewMemoryJournal())
	})
}

func assertSingleActiveSaga(t *testing.T, journal SagaJournal) {
	t.Helper()
	first := SagaRecord{
		Schema: SagaSchemaVersion, OperationID: operationID("6"), Operation: OperationForget, Phase: PhasePrepared,
		TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("a", 64),
		ProfileID: profileID("6"), ExpectedGeneration: 3, OldCredentialRef: testRef(t, "6"),
	}
	stored, err := journal.Begin(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.OperationID = operationID("7")
	if _, err := journal.Begin(context.Background(), second); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("second active saga error=%v", err)
	}
	stored.Phase = PhaseCompleted
	if _, err := journal.Save(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(context.Background(), second); err != nil {
		t.Fatalf("terminal saga did not release profile: %v", err)
	}
}

func testRef(t *testing.T, character string) credential.Ref {
	t.Helper()
	ref, err := credential.ParseRef("cred_" + strings.Repeat(character, 64))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func testRotationID(t *testing.T, character string) credential.RotationID {
	t.Helper()
	id, err := credential.ParseRotationID("cro_" + strings.Repeat(character, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testPutOperationID(t *testing.T, character string) credential.PutOperationID {
	t.Helper()
	id, err := credential.ParsePutOperationID("cpo_" + strings.Repeat(character, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
