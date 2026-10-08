package onboarding

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

var errInjected = errors.New("injected onboarding dependency failure")

func TestCreateUpdateRotateAndForgetPreserveBindingsAndSecretBoundary(t *testing.T) {
	credentialObservations := &faultCredentialStore{}
	harness := newHarness(t, nil, credentialObservations, nil)
	created, oldRef := harness.create(t, "1", "192.168.20.10", "initial-private-secret")
	if created.Summary == nil || created.Summary.State != "ready" {
		t.Fatalf("create result=%+v", created)
	}

	updateGrant := harness.grant(t, "update", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, created.Summary.ProfileID)
	updated, err := harness.service.UpdateEndpoint(context.Background(), UpdateEndpointRequest{
		OperationID: operationID("2"), Access: harness.access(updateGrant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: created.Summary.Generation, Endpoint: "https://192.168.20.11", Username: "operator-v2",
	})
	if err != nil || updated.Status != StatusCompleted || updated.Summary == nil {
		t.Fatalf("UpdateEndpoint()=(%+v, %v)", updated, err)
	}
	if !credentialObservations.lastPutWasCleared() {
		t.Fatal("UpdateEndpoint retained the credential copy returned by SecretStore.Get")
	}
	item, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, created.Summary.ProfileID)
	if err != nil || item.Endpoint != "https://192.168.20.11:443" || item.Username != "operator-v2" || item.CredentialRef == oldRef {
		t.Fatalf("updated profile=%+v err=%v", item.BusinessSummary(), err)
	}
	if _, err := harness.credentials.Get(context.Background(), oldRef); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("old credential still resolves: %v", err)
	}
	stored, err := harness.credentials.Get(context.Background(), item.CredentialRef)
	if err != nil || string(stored) != "initial-private-secret" {
		t.Fatalf("copied credential mismatch: %v", err)
	}
	clearBytes(stored)

	rotateGrant := harness.grant(t, "rotate", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, item.ProfileID)
	newSecret := []byte("rotated-private-secret")
	rotated, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("3"), Access: harness.access(rotateGrant), ProfileID: item.ProfileID,
		ExpectedGeneration: item.Generation, Secret: newSecret,
	})
	if err != nil || rotated.Status != StatusCompleted || !allZero(newSecret) {
		t.Fatalf("RotateCredential()=(%+v, %v) secretCleared=%v", rotated, err, allZero(newSecret))
	}
	rotatedProfile, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, item.ProfileID)
	if err != nil || rotatedProfile.CredentialRef == item.CredentialRef {
		t.Fatalf("rotated profile=%+v err=%v", rotatedProfile.BusinessSummary(), err)
	}
	if _, err := harness.credentials.Get(context.Background(), item.CredentialRef); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("pre-rotation credential still resolves: %v", err)
	}
	stored, err = harness.credentials.Get(context.Background(), rotatedProfile.CredentialRef)
	if err != nil || string(stored) != "rotated-private-secret" {
		t.Fatalf("rotated credential mismatch: %v", err)
	}
	clearBytes(stored)

	forgetGrant := harness.grant(t, "forget", []string{authority.OpProfileForget}, item.ProfileID)
	forgotten, err := harness.service.Forget(context.Background(), ForgetRequest{
		OperationID: operationID("4"), Access: harness.access(forgetGrant), ProfileID: item.ProfileID,
		ExpectedGeneration: rotatedProfile.Generation,
	})
	if err != nil || forgotten.Status != StatusCompleted || forgotten.Summary != nil {
		t.Fatalf("Forget()=(%+v, %v)", forgotten, err)
	}
	if _, err := harness.credentials.Get(context.Background(), rotatedProfile.CredentialRef); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("forgotten credential still resolves: %v", err)
	}
	if _, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, item.ProfileID); !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("forgotten profile still resolves: %v", err)
	}
	if got := harness.verifier.demandsSnapshot(); len(got) == 0 {
		t.Fatal("authority verifier saw no demands")
	} else {
		for _, demand := range got {
			if demand.Class != authority.ConnectionProfileWrite || demand.RunID != "" || demand.ScheduleID != "" ||
				len(demand.SourceHandles) != 0 || demand.MaxFrames != 0 || demand.MaxBytes != 0 || demand.MaxDurationSeconds != 0 {
				t.Fatalf("onboarding demanded forbidden execution authority: %+v", demand)
			}
			if demand.OperationKind != authority.OpProfileCreate && demand.DeviceProfileID == "" {
				t.Fatalf("profile mutation demand omitted its profile binding: %+v", demand)
			}
		}
	}
}

func TestForgetRevokesCredentialBeforeDeletingProfile(t *testing.T) {
	events := &eventRecorder{}
	profileObservations := &faultProfileStore{events: events}
	credentialObservations := &faultCredentialStore{events: events}
	harness := newHarness(t, profileObservations, credentialObservations, nil)
	created, _ := harness.create(t, "4", "10.20.30.44", "forget-order-secret")
	grant := harness.grant(t, "forget-order", []string{authority.OpProfileForget}, created.Summary.ProfileID)
	result, err := harness.service.Forget(context.Background(), ForgetRequest{
		OperationID: operationID("5"), Access: harness.access(grant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: created.Summary.Generation,
	})
	if err != nil || result.Status != StatusCompleted {
		t.Fatalf("Forget(order)=(%+v, %v)", result, err)
	}
	want := "profile_revoking,credential_deleted,profile_revoked,profile_forgotten"
	if got := strings.Join(events.snapshot(), ","); got != want {
		t.Fatalf("forget order=%q want=%q", got, want)
	}
}

func TestCreateFailureIsRecoverableWithoutPersistingSecret(t *testing.T) {
	profileFaults := &faultProfileStore{failCreate: 1}
	harness := newHarness(t, profileFaults, nil, nil)
	secret := []byte("recoverable-create-secret")
	grant := harness.grant(t, "create-recovery", []string{authority.OpProfileCreate}, "")
	request := CreateRequest{
		OperationID: operationID("5"), Access: harness.access(grant), ProfileID: profileID("5"),
		Alias: "恢复设备", Endpoint: "10.20.30.50", Username: "admin", Secret: secret,
		PinnedSerial: "serial-recovery", PinnedType: "edge",
	}
	result, err := harness.service.Create(context.Background(), request)
	if !errors.Is(err, ErrRecoveryRequired) || result.Status != StatusRecoverable || result.Phase != PhaseCredentialStored || !allZero(secret) {
		t.Fatalf("Create()=(%+v, %v) secretCleared=%v", result, err, allZero(secret))
	}
	record, err := harness.journal.Get(context.Background(), request.OperationID)
	if err != nil || record.Phase != PhaseCredentialStored || !record.NewCredentialRef.Valid() {
		t.Fatalf("durable create saga=%+v err=%v", record, err)
	}
	resumed, err := harness.service.Resume(context.Background(), ResumeRequest{OperationID: request.OperationID, Access: request.Access})
	if err != nil || resumed.Status != StatusCompleted {
		t.Fatalf("Resume(create)=(%+v, %v)", resumed, err)
	}
	stored, err := harness.credentials.Get(context.Background(), record.NewCredentialRef)
	if err != nil || string(stored) != "recoverable-create-secret" {
		t.Fatalf("recovered credential mismatch: %v", err)
	}
	clearBytes(stored)
}

func TestCreateRecoversDurablePutReceiptAfterJournalCrash(t *testing.T) {
	journalFaults := &faultJournal{failPhase: PhaseCredentialStored, remaining: 1}
	harness := newHarness(t, nil, nil, journalFaults)
	grant := harness.grant(t, "create-put-recovery", []string{authority.OpProfileCreate}, "")
	secret := []byte("durable-create-secret")
	request := CreateRequest{
		OperationID: operationID("5"), Access: harness.access(grant), ProfileID: profileID("5"),
		Alias: "可恢复设备", Endpoint: "10.20.30.51", Username: "admin", Secret: secret,
		PinnedSerial: "serial-put-recovery", PinnedType: "edge",
	}
	result, err := harness.service.Create(context.Background(), request)
	if !errors.Is(err, ErrRecoveryRequired) || result.Status != StatusRecoverable || result.Phase != PhasePrepared || !allZero(secret) {
		t.Fatalf("Create(journal crash)=(%+v, %v) secretCleared=%v", result, err, allZero(secret))
	}
	record, err := harness.journal.Get(context.Background(), request.OperationID)
	if err != nil || record.Phase != PhasePrepared || !record.CredentialPutID.Valid() || record.NewCredentialRef != "" {
		t.Fatalf("prepared create saga=%+v err=%v", record, err)
	}
	receipt, err := harness.credentials.PutByOperationID(context.Background(), record.CredentialPutID)
	if err != nil || receipt.Phase != credential.PutCommitted || !receipt.Ref.Valid() {
		t.Fatalf("durable put receipt=(%+v, %v)", receipt, err)
	}
	if _, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, request.ProfileID); !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("profile unexpectedly exists before resume: %v", err)
	}
	result, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: request.OperationID, Access: request.Access})
	if err != nil || result.Status != StatusCompleted || result.Summary == nil {
		t.Fatalf("Resume(create put receipt)=(%+v, %v)", result, err)
	}
	if _, err := harness.credentials.PutByOperationID(context.Background(), record.CredentialPutID); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("put receipt was not acknowledged: %v", err)
	}
	item, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, request.ProfileID)
	if err != nil || item.CredentialRef != receipt.Ref {
		t.Fatalf("profile did not bind recovered ref: %+v err=%v", item.BusinessSummary(), err)
	}
}

func TestCreatePutAcknowledgementIsRetried(t *testing.T) {
	credentialFaults := &faultCredentialStore{failPutAck: 1}
	harness := newHarness(t, nil, credentialFaults, nil)
	grant := harness.grant(t, "create-put-ack", []string{authority.OpProfileCreate}, "")
	secret := []byte("create-ack-secret")
	request := CreateRequest{
		OperationID: operationID("6"), Access: harness.access(grant), ProfileID: profileID("6"),
		Alias: "确认重试设备", Endpoint: "10.20.30.52", Username: "admin", Secret: secret,
		PinnedSerial: "serial-put-ack", PinnedType: "edge",
	}
	result, err := harness.service.Create(context.Background(), request)
	if !errors.Is(err, ErrRecoveryRequired) || result.Status != StatusRecoverable || result.Phase != PhaseProfileSwitched || !allZero(secret) {
		t.Fatalf("Create(ack failure)=(%+v, %v) secretCleared=%v", result, err, allZero(secret))
	}
	record, err := harness.journal.Get(context.Background(), request.OperationID)
	if err != nil || record.Phase != PhaseProfileSwitched {
		t.Fatalf("profile-switched saga=%+v err=%v", record, err)
	}
	if _, err := harness.credentials.PutByOperationID(context.Background(), record.CredentialPutID); err != nil {
		t.Fatalf("receipt disappeared before acknowledgement retry: %v", err)
	}
	result, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: request.OperationID, Access: request.Access})
	if err != nil || result.Status != StatusCompleted {
		t.Fatalf("Resume(create ack)=(%+v, %v)", result, err)
	}
}

func TestCreateConflictCompensatesDurablePutWithoutOrphan(t *testing.T) {
	harness := newHarness(t, nil, nil, nil)
	created, existingRef := harness.create(t, "d", "10.20.30.53", "existing-secret")
	grant := harness.grant(t, "create-conflict", []string{authority.OpProfileCreate}, "")
	secret := []byte("must-not-be-orphaned")
	request := CreateRequest{
		OperationID: operationID("e"), Access: harness.access(grant), ProfileID: created.Summary.ProfileID,
		Alias: "冲突设备", Endpoint: "10.20.30.54", Username: "other", Secret: secret,
		PinnedSerial: "conflicting-serial", PinnedType: "edge",
	}
	result, err := harness.service.Create(context.Background(), request)
	if err == nil || result.Status != StatusFailed || result.Phase != PhaseFailed || !allZero(secret) {
		t.Fatalf("Create(conflict)=(%+v, %v) secretCleared=%v", result, err, allZero(secret))
	}
	record, err := harness.journal.Get(context.Background(), request.OperationID)
	if err != nil || record.CredentialPutPhase != credential.PutRolledBack || !record.NewCredentialRef.Valid() {
		t.Fatalf("compensated create saga=%+v err=%v", record, err)
	}
	if _, err := harness.credentials.PutByOperationID(context.Background(), record.CredentialPutID); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("compensated receipt was not acknowledged: %v", err)
	}
	if _, err := harness.credentials.Get(context.Background(), record.NewCredentialRef); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("compensated credential still resolves: %v", err)
	}
	item, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, created.Summary.ProfileID)
	if err != nil || item.CredentialRef != existingRef {
		t.Fatalf("existing profile changed during conflict compensation: %+v err=%v", item.BusinessSummary(), err)
	}
}

func TestUnknownPutReceiptIsPersistedAndRecovered(t *testing.T) {
	credentialFaults := &faultCredentialStore{forceUnknownPut: 1, forceUnknownPutRecover: 1}
	harness := newHarness(t, nil, credentialFaults, nil)
	grant := harness.grant(t, "create-put-unknown", []string{authority.OpProfileCreate}, "")
	secret := []byte("unknown-create-secret")
	request := CreateRequest{
		OperationID: operationID("f"), Access: harness.access(grant), ProfileID: profileID("f"),
		Alias: "待核对设备", Endpoint: "10.20.30.55", Username: "admin", Secret: secret,
		PinnedSerial: "serial-put-unknown", PinnedType: "edge",
	}
	result, err := harness.service.Create(context.Background(), request)
	if !errors.Is(err, ErrOutcomeUnknown) || result.Status != StatusOutcomeUnknown || result.Phase != PhaseCredentialStored || !allZero(secret) {
		t.Fatalf("Create(unknown put)=(%+v, %v) secretCleared=%v", result, err, allZero(secret))
	}
	record, err := harness.journal.Get(context.Background(), request.OperationID)
	if err != nil || record.CredentialPutPhase != credential.PutUnknown || !record.CredentialPutID.Valid() || !record.NewCredentialRef.Valid() {
		t.Fatalf("unknown put receipt was not persisted: %+v err=%v", record, err)
	}
	result, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: request.OperationID, Access: request.Access})
	if err != nil || result.Status != StatusCompleted || result.Summary == nil {
		t.Fatalf("Resume(unknown put)=(%+v, %v)", result, err)
	}
}

func TestRotateAndForgetSagasResumeAfterCrossStoreFailures(t *testing.T) {
	profileFaults := &faultProfileStore{failUpdate: 1, failCredentialState: map[profile.CredentialState]int{profile.CredentialRevoked: 1}}
	harness := newHarness(t, profileFaults, nil, nil)
	created, _ := harness.create(t, "6", "10.20.30.60", "old-secret")
	rotateGrant := harness.grant(t, "rotate-recovery", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, created.Summary.ProfileID)
	secret := []byte("new-secret")
	rotated, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("7"), Access: harness.access(rotateGrant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: created.Summary.Generation, Secret: secret,
	})
	if !errors.Is(err, ErrRecoveryRequired) || rotated.Phase != PhaseCredentialStored || !allZero(secret) {
		t.Fatalf("RotateCredential()=(%+v, %v)", rotated, err)
	}
	rotated, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: operationID("7"), Access: harness.access(rotateGrant)})
	if err != nil || rotated.Status != StatusCompleted || rotated.Summary == nil {
		t.Fatalf("Resume(rotate)=(%+v, %v)", rotated, err)
	}

	forgetGrant := harness.grant(t, "forget-recovery", []string{authority.OpProfileForget}, created.Summary.ProfileID)
	forgotten, err := harness.service.Forget(context.Background(), ForgetRequest{
		OperationID: operationID("8"), Access: harness.access(forgetGrant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: rotated.Summary.Generation,
	})
	if !errors.Is(err, ErrRecoveryRequired) || forgotten.Phase != PhaseCredentialDeleted {
		t.Fatalf("Forget()=(%+v, %v)", forgotten, err)
	}
	forgotten, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: operationID("8"), Access: harness.access(forgetGrant)})
	if err != nil || forgotten.Status != StatusCompleted {
		t.Fatalf("Resume(forget)=(%+v, %v)", forgotten, err)
	}
}

func TestRotationReceiptRecoversJournalCrashAndAcknowledgementFailure(t *testing.T) {
	journalFaults := &faultJournal{failPhase: PhaseCredentialStored}
	harness := newHarness(t, nil, nil, journalFaults)
	created, oldRef := harness.create(t, "9", "10.20.30.70", "old-secret")
	journalFaults.remaining = 1
	grant := harness.grant(t, "rotate-journal", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, created.Summary.ProfileID)
	secret := []byte("replacement")
	result, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("a"), Access: harness.access(grant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: created.Summary.Generation, Secret: secret,
	})
	if !errors.Is(err, ErrRecoveryRequired) || result.Status != StatusRecoverable || result.Phase != PhaseProfileRotating || !allZero(secret) {
		t.Fatalf("receipt journal failure=(%+v, %v) secretCleared=%v", result, err, allZero(secret))
	}
	current, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, created.Summary.ProfileID)
	if err != nil || current.CredentialState != profile.CredentialRotating || current.CredentialRef != oldRef {
		t.Fatalf("durable recovery marker missing: %+v err=%v", current.BusinessSummary(), err)
	}
	receipt, err := harness.credentials.RotationByOldRef(context.Background(), oldRef)
	if err != nil || receipt.Phase != credential.RotationCommitted {
		t.Fatalf("durable rotation receipt=(%+v, %v)", receipt, err)
	}
	result, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: operationID("a"), Access: harness.access(grant)})
	if err != nil || result.Status != StatusCompleted || result.Summary == nil {
		t.Fatalf("Resume(receipt)=(%+v, %v)", result, err)
	}
	if _, err := harness.credentials.RotationByOldRef(context.Background(), oldRef); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("committed receipt was not acknowledged: %v", err)
	}

	credentialFaults := &faultCredentialStore{failAck: 1}
	ackHarness := newHarness(t, nil, credentialFaults, nil)
	ackCreated, ackOldRef := ackHarness.create(t, "b", "10.20.30.71", "old-secret")
	ackGrant := ackHarness.grant(t, "rotate-ack", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, ackCreated.Summary.ProfileID)
	ackSecret := []byte("replacement")
	result, err = ackHarness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("c"), Access: ackHarness.access(ackGrant), ProfileID: ackCreated.Summary.ProfileID,
		ExpectedGeneration: ackCreated.Summary.Generation, Secret: ackSecret,
	})
	if !errors.Is(err, ErrRecoveryRequired) || result.Status != StatusRecoverable || result.Phase != PhaseProfileSwitched {
		t.Fatalf("acknowledgement failure=(%+v, %v)", result, err)
	}
	if _, err := ackHarness.credentials.RotationByOldRef(context.Background(), ackOldRef); err != nil {
		t.Fatalf("receipt disappeared before acknowledgement retry: %v", err)
	}
	result, err = ackHarness.service.Resume(context.Background(), ResumeRequest{OperationID: operationID("c"), Access: ackHarness.access(ackGrant)})
	if err != nil || result.Status != StatusCompleted {
		t.Fatalf("Resume(acknowledgement)=(%+v, %v)", result, err)
	}
}

func TestUnknownRotationReceiptIsPersistedAndRecovered(t *testing.T) {
	credentialFaults := &faultCredentialStore{forceUnknownRotate: 1, forceUnknownRecover: 1}
	harness := newHarness(t, nil, credentialFaults, nil)
	created, oldRef := harness.create(t, "7", "10.20.30.72", "old-secret")
	grant := harness.grant(t, "rotate-unknown", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, created.Summary.ProfileID)
	secret := []byte("replacement")
	result, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("8"), Access: harness.access(grant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: created.Summary.Generation, Secret: secret,
	})
	if !errors.Is(err, ErrOutcomeUnknown) || result.Status != StatusOutcomeUnknown || result.Phase != PhaseCredentialStored || !allZero(secret) {
		t.Fatalf("unknown rotation=(%+v, %v) secretCleared=%v", result, err, allZero(secret))
	}
	record, err := harness.journal.Get(context.Background(), operationID("8"))
	if err != nil || !record.CredentialRotationID.Valid() || record.CredentialRotationPhase != credential.RotationUnknown || record.NewCredentialRef == "" {
		t.Fatalf("unknown receipt was not persisted: %+v err=%v", record, err)
	}
	result, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: operationID("8"), Access: harness.access(grant)})
	if err != nil || result.Status != StatusCompleted || result.Summary == nil {
		t.Fatalf("Resume(unknown rotation)=(%+v, %v)", result, err)
	}
	if _, err := harness.credentials.Get(context.Background(), oldRef); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("old ref still resolves after unknown recovery: %v", err)
	}
}

func TestActiveSagaPreventsCredentialRotationReceiptHijack(t *testing.T) {
	profileFaults := &faultProfileStore{failUpdate: 1}
	harness := newHarness(t, profileFaults, nil, nil)
	created, oldRef := harness.create(t, "a", "10.20.30.73", "old-secret")
	firstGrant := harness.grant(t, "first-rotation", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, created.Summary.ProfileID)
	firstSecret := []byte("first-new-secret")
	first, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("b"), Access: harness.access(firstGrant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: created.Summary.Generation, Secret: firstSecret,
	})
	if !errors.Is(err, ErrRecoveryRequired) || first.Phase != PhaseCredentialStored || !allZero(firstSecret) {
		t.Fatalf("first rotation=(%+v, %v)", first, err)
	}
	current, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, created.Summary.ProfileID)
	if err != nil || current.CredentialState != profile.CredentialRotating {
		t.Fatalf("profile did not retain first rotation marker: %+v err=%v", current.BusinessSummary(), err)
	}
	receipt, err := harness.credentials.RotationByOldRef(context.Background(), oldRef)
	if err != nil || receipt.Phase != credential.RotationCommitted {
		t.Fatalf("first rotation receipt=(%+v, %v)", receipt, err)
	}

	secondGrant := harness.grant(t, "second-rotation", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, created.Summary.ProfileID)
	secondSecret := []byte("must-not-replace-first")
	second, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("c"), Access: harness.access(secondGrant), ProfileID: created.Summary.ProfileID,
		ExpectedGeneration: current.Generation, Secret: secondSecret,
	})
	if !errors.Is(err, ErrOperationConflict) || second.Status == StatusCompleted || !allZero(secondSecret) {
		t.Fatalf("second rotation hijacked active saga: (%+v, %v) secretCleared=%v", second, err, allZero(secondSecret))
	}
	if _, err := harness.journal.Get(context.Background(), operationID("c")); !errors.Is(err, ErrSagaNotFound) {
		t.Fatalf("conflicting saga was persisted: %v", err)
	}
	unchanged, err := harness.credentials.RotationByOldRef(context.Background(), oldRef)
	if err != nil || unchanged.OperationID != receipt.OperationID || unchanged.NewRef != receipt.NewRef {
		t.Fatalf("first receipt changed after conflict: (%+v, %v)", unchanged, err)
	}
	first, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: operationID("b"), Access: harness.access(firstGrant)})
	if err != nil || first.Status != StatusCompleted {
		t.Fatalf("Resume(first rotation)=(%+v, %v)", first, err)
	}
}

func TestIdentityDriftCrossTenantAndAuthorityMismatchAreBlocked(t *testing.T) {
	harness := newHarness(t, nil, nil, nil)
	created, _ := harness.create(t, "d", "10.20.30.80", "old-secret")
	item, err := harness.profiles.Get(context.Background(), harness.tenant, harness.site, created.Summary.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	item, err = harness.profiles.MarkIdentityDrift(context.Background(), harness.tenant, harness.site, item.ProfileID, item.Generation)
	if err != nil {
		t.Fatal(err)
	}
	grant := harness.grant(t, "rotate-drift", []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, item.ProfileID)
	secret := []byte("must-be-cleared")
	blocked, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("e"), Access: harness.access(grant), ProfileID: item.ProfileID,
		ExpectedGeneration: item.Generation, Secret: secret,
	})
	if !errors.Is(err, ErrIdentityDrift) || blocked.Status != StatusBlocked || !allZero(secret) {
		t.Fatalf("identity drift result=(%+v, %v)", blocked, err)
	}

	wrongTenantGrant := harness.grantFor(t, "wrong-tenant", harness.principal, "tenant-b", harness.site, []string{authority.OpCredentialRotate, authority.OpProfileUpdate}, item.ProfileID, authority.ConnectionProfileWrite)
	wrongTenant := harness.access(wrongTenantGrant)
	wrongTenant.TenantID = "tenant-b"
	secret = []byte("cross-tenant")
	result, err := harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("f"), Access: wrongTenant, ProfileID: item.ProfileID,
		ExpectedGeneration: item.Generation, Secret: secret,
	})
	if err == nil || result.Status == StatusCompleted || !allZero(secret) {
		t.Fatalf("cross-tenant operation=(%+v, %v)", result, err)
	}

	forbiddenGrant := harness.grantFor(t, "forbidden-class", harness.principal, harness.tenant, harness.site,
		[]string{authority.OpTaskEnable}, item.ProfileID, authority.PersistentDeviceWrite)
	secret = []byte("forbidden")
	result, err = harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("0"), Access: harness.access(forbiddenGrant), ProfileID: item.ProfileID,
		ExpectedGeneration: item.Generation, Secret: secret,
	})
	if !errors.Is(err, ErrAuthorityDenied) || result.Status != StatusFailed || !allZero(secret) {
		t.Fatalf("persistent-write grant was accepted: (%+v, %v)", result, err)
	}

	tampered := grant
	tampered.ProofSHA256 = strings.Repeat("0", 64)
	secret = []byte("tampered")
	result, err = harness.service.RotateCredential(context.Background(), RotateCredentialRequest{
		OperationID: operationID("1"), Access: harness.access(tampered), ProfileID: item.ProfileID,
		ExpectedGeneration: item.Generation, Secret: secret,
	})
	if !errors.Is(err, ErrAuthorityDenied) || !allZero(secret) {
		t.Fatalf("forged grant was accepted: (%+v, %v)", result, err)
	}
}

func TestResumeRequiresExactTenantSiteAndPrincipalBinding(t *testing.T) {
	profileFaults := &faultProfileStore{failCreate: 1}
	harness := newHarness(t, profileFaults, nil, nil)
	grant := harness.grant(t, "resume-binding", []string{authority.OpProfileCreate}, "")
	secret := []byte("binding-secret")
	request := CreateRequest{
		OperationID: operationID("9"), Access: harness.access(grant), ProfileID: profileID("9"),
		Alias: "绑定设备", Endpoint: "10.20.30.90", Username: "admin", Secret: secret,
		PinnedSerial: "serial-binding", PinnedType: "edge",
	}
	result, err := harness.service.Create(context.Background(), request)
	if !errors.Is(err, ErrRecoveryRequired) || result.Phase != PhaseCredentialStored {
		t.Fatalf("Create(binding recovery)=(%+v, %v)", result, err)
	}
	cases := []struct {
		name   string
		mutate func(*Access)
	}{
		{name: "tenant", mutate: func(access *Access) { access.TenantID = "tenant-b" }},
		{name: "site", mutate: func(access *Access) { access.SiteID = "site-b" }},
		{name: "principal", mutate: func(access *Access) { access.PrincipalSHA256 = strings.Repeat("b", 64) }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			access := request.Access
			testCase.mutate(&access)
			blocked, resumeErr := harness.service.Resume(context.Background(), ResumeRequest{OperationID: request.OperationID, Access: access})
			if !errors.Is(resumeErr, ErrBindingMismatch) || blocked.Status == StatusCompleted {
				t.Fatalf("Resume(%s binding)=(%+v, %v)", testCase.name, blocked, resumeErr)
			}
		})
	}
	result, err = harness.service.Resume(context.Background(), ResumeRequest{OperationID: request.OperationID, Access: request.Access})
	if err != nil || result.Status != StatusCompleted {
		t.Fatalf("Resume(exact binding)=(%+v, %v)", result, err)
	}
}

type harness struct {
	t           *testing.T
	now         time.Time
	tenant      string
	site        string
	principal   string
	profiles    *profile.Store
	credentials credential.SecretStore
	journal     SagaJournal
	signer      *authority.Signer
	verifier    *recordingVerifier
	service     *Service
}

func newHarness(t *testing.T, profileFaults *faultProfileStore, credentialFaults *faultCredentialStore, journalFaults *faultJournal) *harness {
	t.Helper()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	profiles, err := profile.Open(filepath.Join(t.TempDir(), "state", "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = profiles.Close() })
	memoryCredentials := credential.NewMemoryStore()
	t.Cleanup(memoryCredentials.Purge)
	memoryJournal := NewMemoryJournal()
	memoryJournal.now = func() time.Time { return now }
	signer, err := authority.NewSigner("onboarding-test-issuer", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	verifier := &recordingVerifier{delegate: signer}

	var profileDependency ProfileStore = profiles
	if profileFaults != nil {
		profileFaults.delegate = profiles
		profileDependency = profileFaults
	}
	var credentialDependency credential.SecretStore = memoryCredentials
	if credentialFaults != nil {
		credentialFaults.delegate = memoryCredentials
		credentialDependency = credentialFaults
	}
	var journalDependency SagaJournal = memoryJournal
	if journalFaults != nil {
		journalFaults.delegate = memoryJournal
		journalDependency = journalFaults
	}
	service, err := NewService(profileDependency, credentialDependency, journalDependency, verifier, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return &harness{
		t: t, now: now, tenant: "tenant-a", site: "site-a", principal: strings.Repeat("a", 64),
		profiles: profiles, credentials: credentialDependency, journal: journalDependency,
		signer: signer, verifier: verifier, service: service,
	}
}

func (h *harness) create(t *testing.T, suffix, endpoint, secretText string) (Result, credential.Ref) {
	t.Helper()
	grant := h.grant(t, "create-"+suffix, []string{authority.OpProfileCreate}, "")
	secret := []byte(secretText)
	result, err := h.service.Create(context.Background(), CreateRequest{
		OperationID: operationID(suffix), Access: h.access(grant), ProfileID: profileID(suffix),
		Alias: "设备-" + suffix, Endpoint: endpoint, Username: "operator", Secret: secret,
		PinnedSerial: "serial-" + suffix, PinnedType: "edge-box",
	})
	if err != nil || result.Status != StatusCompleted || result.Summary == nil || !allZero(secret) {
		t.Fatalf("Create(%s)=(%+v, %v) secretCleared=%v", suffix, result, err, allZero(secret))
	}
	item, err := h.profiles.Get(context.Background(), h.tenant, h.site, result.Summary.ProfileID)
	if err != nil || !item.CredentialRef.Valid() {
		t.Fatalf("created profile=%+v err=%v", item.BusinessSummary(), err)
	}
	return result, item.CredentialRef
}

func (h *harness) grant(t *testing.T, suffix string, operations []string, profileID string) authority.Grant {
	t.Helper()
	return h.grantFor(t, "grant-"+suffix, h.principal, h.tenant, h.site, operations, profileID, authority.ConnectionProfileWrite)
}

func (h *harness) grantFor(t *testing.T, grantID, principal, tenant, site string, operations []string, profileID string, class authority.Class) authority.Grant {
	t.Helper()
	grant, err := h.signer.Issue(grantID, class, principal, authority.Scope{
		TenantID: tenant, SiteID: site, DeviceProfileID: profileID, OperationKinds: operations,
	}, h.now.Add(-time.Minute), h.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func (h *harness) access(grant authority.Grant) Access {
	return Access{TenantID: h.tenant, SiteID: h.site, PrincipalSHA256: h.principal, Grant: grant}
}

type recordingVerifier struct {
	mu       sync.Mutex
	delegate *authority.Signer
	demands  []authority.Demand
}

func (v *recordingVerifier) Verify(grant authority.Grant, demand authority.Demand, at time.Time) error {
	v.mu.Lock()
	v.demands = append(v.demands, demand)
	v.mu.Unlock()
	return v.delegate.Verify(grant, demand, at)
}

func (v *recordingVerifier) demandsSnapshot() []authority.Demand {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]authority.Demand(nil), v.demands...)
}

type faultProfileStore struct {
	mu                  sync.Mutex
	delegate            ProfileStore
	events              *eventRecorder
	failCreate          int
	failUpdate          int
	failForget          int
	failCredentialState map[profile.CredentialState]int
}

func (s *faultProfileStore) Create(ctx context.Context, input profile.NewDeviceProfile) (profile.DeviceProfile, error) {
	if s.consume(func() *int { return &s.failCreate }) {
		return profile.DeviceProfile{}, errInjected
	}
	return s.delegate.Create(ctx, input)
}

func (s *faultProfileStore) Get(ctx context.Context, tenantID, siteID, profileID string) (profile.DeviceProfile, error) {
	return s.delegate.Get(ctx, tenantID, siteID, profileID)
}

func (s *faultProfileStore) Update(ctx context.Context, input profile.UpdateDeviceProfile) (profile.DeviceProfile, error) {
	if s.consume(func() *int { return &s.failUpdate }) {
		return profile.DeviceProfile{}, errInjected
	}
	return s.delegate.Update(ctx, input)
}

func (s *faultProfileStore) SetCredentialState(ctx context.Context, tenantID, siteID, profileID string, generation uint64, state profile.CredentialState) (profile.DeviceProfile, error) {
	s.mu.Lock()
	if s.failCredentialState != nil && s.failCredentialState[state] > 0 {
		s.failCredentialState[state]--
		s.mu.Unlock()
		return profile.DeviceProfile{}, errInjected
	}
	s.mu.Unlock()
	item, err := s.delegate.SetCredentialState(ctx, tenantID, siteID, profileID, generation, state)
	if err == nil && s.events != nil {
		s.events.add("profile_" + string(state))
	}
	return item, err
}

func (s *faultProfileStore) Forget(ctx context.Context, tenantID, siteID, profileID string, generation uint64) error {
	if s.consume(func() *int { return &s.failForget }) {
		return errInjected
	}
	err := s.delegate.Forget(ctx, tenantID, siteID, profileID, generation)
	if err == nil && s.events != nil {
		s.events.add("profile_forgotten")
	}
	return err
}

func (s *faultProfileStore) consume(selectCounter func() *int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	counter := selectCounter()
	if *counter == 0 {
		return false
	}
	*counter--
	return true
}

type faultCredentialStore struct {
	mu                     sync.Mutex
	delegate               credential.SecretStore
	failPut                int
	failPutAck             int
	forceUnknownPut        int
	forceUnknownPutRecover int
	failDelete             int
	failAck                int
	forceUnknownRotate     int
	forceUnknownRecover    int
	lastPut                []byte
	lastRotation           []byte
	events                 *eventRecorder
}

func (s *faultCredentialStore) Put(ctx context.Context, operationID credential.PutOperationID, secret []byte) (credential.PutReceipt, error) {
	s.mu.Lock()
	s.lastPut = secret
	if s.failPut > 0 {
		s.failPut--
		s.mu.Unlock()
		return credential.PutReceipt{}, errInjected
	}
	forceUnknown := s.forceUnknownPut > 0
	if forceUnknown {
		s.forceUnknownPut--
	}
	s.mu.Unlock()
	receipt, err := s.delegate.Put(ctx, operationID, secret)
	if forceUnknown && receipt.Valid() {
		receipt.Phase = credential.PutUnknown
		return receipt, &credential.OutcomeUnknownError{Operation: "put", NewRef: receipt.Ref}
	}
	return receipt, err
}

func (s *faultCredentialStore) PutByOperationID(ctx context.Context, operationID credential.PutOperationID) (credential.PutReceipt, error) {
	return s.delegate.PutByOperationID(ctx, operationID)
}

func (s *faultCredentialStore) RecoverPut(ctx context.Context, operationID credential.PutOperationID) (credential.PutReceipt, error) {
	receipt, err := s.delegate.RecoverPut(ctx, operationID)
	s.mu.Lock()
	forceUnknown := s.forceUnknownPutRecover > 0
	if forceUnknown {
		s.forceUnknownPutRecover--
	}
	s.mu.Unlock()
	if forceUnknown && receipt.Valid() {
		receipt.Phase = credential.PutUnknown
		return receipt, &credential.OutcomeUnknownError{Operation: "put", NewRef: receipt.Ref}
	}
	return receipt, err
}

func (s *faultCredentialStore) CompensatePut(ctx context.Context, operationID credential.PutOperationID) (credential.PutReceipt, error) {
	return s.delegate.CompensatePut(ctx, operationID)
}

func (s *faultCredentialStore) AcknowledgePut(ctx context.Context, operationID credential.PutOperationID) error {
	s.mu.Lock()
	if s.failPutAck > 0 {
		s.failPutAck--
		s.mu.Unlock()
		return errInjected
	}
	s.mu.Unlock()
	return s.delegate.AcknowledgePut(ctx, operationID)
}

func (s *faultCredentialStore) Get(ctx context.Context, ref credential.Ref) ([]byte, error) {
	return s.delegate.Get(ctx, ref)
}

func (s *faultCredentialStore) Delete(ctx context.Context, ref credential.Ref) error {
	s.mu.Lock()
	if s.failDelete > 0 {
		s.failDelete--
		s.mu.Unlock()
		return errInjected
	}
	s.mu.Unlock()
	err := s.delegate.Delete(ctx, ref)
	if err == nil && s.events != nil {
		s.events.add("credential_deleted")
	}
	return err
}

func (s *faultCredentialStore) Rotate(ctx context.Context, ref credential.Ref, secret []byte) (credential.RotationReceipt, error) {
	s.mu.Lock()
	s.lastRotation = secret
	forceUnknown := s.forceUnknownRotate > 0
	if forceUnknown {
		s.forceUnknownRotate--
	}
	s.mu.Unlock()
	receipt, err := s.delegate.Rotate(ctx, ref, secret)
	if forceUnknown && receipt.Valid() {
		receipt.Phase = credential.RotationUnknown
		return receipt, &credential.OutcomeUnknownError{Operation: "rotate", OldRef: receipt.OldRef, NewRef: receipt.NewRef}
	}
	return receipt, err
}

func (s *faultCredentialStore) RotationByOldRef(ctx context.Context, ref credential.Ref) (credential.RotationReceipt, error) {
	return s.delegate.RotationByOldRef(ctx, ref)
}

func (s *faultCredentialStore) RecoverRotation(ctx context.Context, operationID credential.RotationID) (credential.RotationReceipt, error) {
	receipt, err := s.delegate.RecoverRotation(ctx, operationID)
	s.mu.Lock()
	forceUnknown := s.forceUnknownRecover > 0
	if forceUnknown {
		s.forceUnknownRecover--
	}
	s.mu.Unlock()
	if forceUnknown && receipt.Valid() {
		receipt.Phase = credential.RotationUnknown
		return receipt, &credential.OutcomeUnknownError{Operation: "rotate", OldRef: receipt.OldRef, NewRef: receipt.NewRef}
	}
	return receipt, err
}

func (s *faultCredentialStore) AcknowledgeRotation(ctx context.Context, operationID credential.RotationID) error {
	s.mu.Lock()
	if s.failAck > 0 {
		s.failAck--
		s.mu.Unlock()
		return errInjected
	}
	s.mu.Unlock()
	return s.delegate.AcknowledgeRotation(ctx, operationID)
}

func (s *faultCredentialStore) lastPutWasCleared() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lastRotation) > 0 && allZero(s.lastRotation)
}

type faultJournal struct {
	mu        sync.Mutex
	delegate  SagaJournal
	failPhase Phase
	remaining int
}

func (j *faultJournal) Begin(ctx context.Context, record SagaRecord) (SagaRecord, error) {
	return j.delegate.Begin(ctx, record)
}

func (j *faultJournal) Get(ctx context.Context, operationID string) (SagaRecord, error) {
	return j.delegate.Get(ctx, operationID)
}

func (j *faultJournal) Save(ctx context.Context, record SagaRecord) (SagaRecord, error) {
	j.mu.Lock()
	if record.Phase == j.failPhase && j.remaining > 0 {
		j.remaining--
		j.mu.Unlock()
		return SagaRecord{}, errInjected
	}
	j.mu.Unlock()
	return j.delegate.Save(ctx, record)
}

func operationID(value string) string {
	if len(value) != 1 {
		panic(fmt.Sprintf("test operation suffix %q must be one character", value))
	}
	return "onb_" + strings.Repeat(value, 32)
}

func profileID(value string) string {
	if len(value) != 1 {
		panic(fmt.Sprintf("test profile suffix %q must be one character", value))
	}
	return "dpf_" + strings.Repeat(value, 32)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

type eventRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *eventRecorder) add(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *eventRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

var _ ProfileStore = (*faultProfileStore)(nil)
var _ credential.SecretStore = (*faultCredentialStore)(nil)
var _ SagaJournal = (*faultJournal)(nil)
var _ AuthorityVerifier = (*recordingVerifier)(nil)
