package authority

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGrantClassesEnforceDistinctAuthority(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	principal := strings.Repeat("a", 64)
	signer := testSigner(t)
	tests := []struct {
		name  string
		class Class
		scope Scope
	}{
		{
			name: "connection profile", class: ConnectionProfileWrite,
			scope: Scope{TenantID: "tenant-a", SiteID: "site-a", OperationKinds: []string{OpProfileCreate}},
		},
		{
			name: "device read", class: DeviceRead,
			scope: Scope{TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "device-a", OperationKinds: []string{OpCatalogRead}},
		},
		{
			name: "inspection execution", class: InspectionExecution,
			scope: Scope{TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "device-a", SourceHandles: []string{"source-a"}, OperationKinds: []string{OpCleanup, OpAnalyze, OpSourceAcquire}, RunID: "run-a", MaxFrames: 4, MaxBytes: 1 << 20, MaxDurationSeconds: 60},
		},
		{
			name: "persistent device write", class: PersistentDeviceWrite,
			scope: Scope{TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "device-a", OperationKinds: []string{OpTaskEnable}},
		},
		{
			name: "service execution", class: ServiceExecution,
			scope: Scope{TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "device-a", SourceHandles: []string{"source-a"}, OperationKinds: []string{OpOccurrenceExecute, OpSourceAcquire}, ScheduleID: "schedule-a", PolicySHA256: strings.Repeat("b", 64), MaxFrames: 4, MaxBytes: 1 << 20, MaxDurationSeconds: 60},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant, err := signer.Issue("grant-a", test.class, principal, test.scope, now, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if err := grant.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInspectionGrantCannotAuthorizePersistentWrite(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	_, err := testSigner(t).Issue("grant-a", InspectionExecution, strings.Repeat("a", 64), Scope{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "device-a", RunID: "run-a",
		OperationKinds: []string{OpTaskEnable}, MaxFrames: 1, MaxBytes: 1024, MaxDurationSeconds: 10,
	}, now, now.Add(time.Minute))
	if err == nil {
		t.Fatal("inspection execution authorized a persistent device write")
	}
}

func TestGrantAndDemandCannotDropExactProfileOrSourceBindings(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	principal := strings.Repeat("a", 64)
	signer := testSigner(t)
	if _, err := signer.Issue("grant-unbound-update", ConnectionProfileWrite, principal, Scope{
		TenantID: "tenant-a", SiteID: "site-a", OperationKinds: []string{OpProfileUpdate},
	}, now, now.Add(time.Minute)); err == nil {
		t.Fatal("profile update grant omitted its exact profile binding")
	}
	grant, err := signer.Issue("grant-bound-run", InspectionExecution, principal, Scope{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "profile-a", RunID: "run-a",
		SourceHandles: []string{"source-a"}, OperationKinds: []string{OpAnalyze, OpSourceAcquire},
		MaxFrames: 2, MaxBytes: 2048, MaxDurationSeconds: 30,
	}, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	base := Demand{
		Class: InspectionExecution, OperationKind: OpSourceAcquire, PrincipalSHA256: principal,
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "profile-a", RunID: "run-a",
		SourceHandles: []string{"source-a"}, MaxFrames: 1, MaxBytes: 1024, MaxDurationSeconds: 10,
	}
	if err := signer.Verify(grant, base, now.Add(time.Second)); err != nil {
		t.Fatalf("bound demand rejected: %v", err)
	}
	missingProfile := base
	missingProfile.DeviceProfileID = ""
	if err := signer.Verify(grant, missingProfile, now.Add(time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("demand dropped grant profile binding: %v", err)
	}
	missingSource := base
	missingSource.SourceHandles = nil
	if err := signer.Verify(grant, missingSource, now.Add(time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("source acquisition demand omitted sources: %v", err)
	}
}

func TestSavedConnectionDoesNotManufactureServiceAuthority(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	_, err := testSigner(t).Issue("grant-a", ServiceExecution, strings.Repeat("a", 64), Scope{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "device-a",
		OperationKinds: []string{OpOccurrenceExecute}, PolicySHA256: strings.Repeat("b", 64), MaxFrames: 1, MaxBytes: 1024, MaxDurationSeconds: 10,
	}, now, now.Add(time.Minute))
	if err == nil {
		t.Fatal("service execution was admitted without a schedule binding")
	}
}

func TestScopeDigestIsStableAfterNormalization(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	principal := strings.Repeat("a", 64)
	signer := testSigner(t)
	first, err := signer.Issue("grant-a", InspectionExecution, principal, Scope{
		TenantID: "tenant-a", SiteID: "site-a", RunID: "run-a",
		SourceHandles:  []string{"source-b", "source-a", "source-a"},
		OperationKinds: []string{OpCleanup, OpAnalyze, OpSourceAcquire, OpAnalyze},
		MaxFrames:      2, MaxBytes: 2048, MaxDurationSeconds: 30,
	}, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.Issue("grant-b", InspectionExecution, principal, Scope{
		TenantID: "tenant-a", SiteID: "site-a", RunID: "run-a",
		SourceHandles:  []string{"source-a", "source-b"},
		OperationKinds: []string{OpAnalyze, OpCleanup, OpSourceAcquire},
		MaxFrames:      2, MaxBytes: 2048, MaxDurationSeconds: 30,
	}, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.ScopeSHA256 != second.ScopeSHA256 {
		t.Fatalf("normalized scope digest changed: %s != %s", first.ScopeSHA256, second.ScopeSHA256)
	}
}

func TestTamperedScopeDigestIsRejected(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	grant, err := testSigner(t).Issue("grant-a", DeviceRead, strings.Repeat("a", 64), Scope{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "device-a", OperationKinds: []string{OpStatusRead},
	}, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	grant.Scope.OperationKinds = []string{OpCatalogRead}
	if err := grant.Validate(); err == nil {
		t.Fatal("tampered authority scope was accepted")
	}
}

func TestSignedGrantRejectsForgeryTamperAndWrongDemand(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	principal := strings.Repeat("a", 64)
	signer := testSigner(t)
	grant, err := signer.Issue("grant-a", ConnectionProfileWrite, principal, Scope{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "profile-a",
		OperationKinds: []string{OpCredentialRotate, OpProfileUpdate},
	}, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	valid := Demand{
		Class: ConnectionProfileWrite, OperationKind: OpProfileUpdate,
		PrincipalSHA256: principal, TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "profile-a",
	}
	if err := signer.Verify(grant, valid, now.Add(time.Second)); err != nil {
		t.Fatalf("valid demand was rejected: %v", err)
	}

	other, err := NewSigner("issuer-a", []byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	if err := other.Verify(grant, valid, now.Add(time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("grant signed by another key was accepted: %v", err)
	}

	tampered := grant
	tampered.Scope.OperationKinds = []string{OpProfileForget, OpProfileUpdate}
	digest, err := scopeDigest(tampered.Scope)
	if err != nil {
		t.Fatal(err)
	}
	tampered.ScopeSHA256 = digest
	if err := signer.Verify(tampered, valid, now.Add(time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("grant with recomputed public digest was accepted: %v", err)
	}

	for name, mutate := range map[string]func(*Demand){
		"principal":       func(d *Demand) { d.PrincipalSHA256 = strings.Repeat("c", 64) },
		"tenant":          func(d *Demand) { d.TenantID = "tenant-b" },
		"site":            func(d *Demand) { d.SiteID = "site-b" },
		"profile":         func(d *Demand) { d.DeviceProfileID = "profile-b" },
		"operation":       func(d *Demand) { d.OperationKind = OpProfileForget },
		"class":           func(d *Demand) { d.Class = PersistentDeviceWrite },
		"missing profile": func(d *Demand) { d.DeviceProfileID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			demand := valid
			mutate(&demand)
			if err := signer.Verify(grant, demand, now.Add(time.Second)); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("mismatched demand was accepted: %v", err)
			}
		})
	}
	if err := signer.Verify(grant, valid, now.Add(time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired grant was accepted: %v", err)
	}
	if err := signer.Verify(grant, valid, now.Add(-time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("not-yet-valid grant was accepted: %v", err)
	}
}

func TestSignerCloseInvalidatesAuthority(t *testing.T) {
	signer := testSigner(t)
	signer.Close()
	if _, err := signer.Issue("grant-a", ConnectionProfileWrite, strings.Repeat("a", 64), Scope{
		TenantID: "tenant-a", SiteID: "site-a", OperationKinds: []string{OpProfileCreate},
	}, time.Now(), time.Now().Add(time.Minute)); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed signer issued a grant: %v", err)
	}
}

func testSigner(t *testing.T) *Signer {
	t.Helper()
	signer, err := NewSigner("issuer-a", []byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	return signer
}
