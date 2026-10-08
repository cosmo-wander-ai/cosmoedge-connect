package media

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRuntimeLeasePreservesIngestionOwnershipAndSurvivesReopen(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "media")
	store, err := New(Config{
		Root: root, MaxObjectBytes: 1 << 20, MaxTotalBytes: 8 << 20,
		MaxDescriptors: 64, DefaultTTL: time.Hour, MaximumTTL: 2 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	capturedAt := now.Add(-time.Minute)
	content := jpegFixture(t, 20, 12)
	original, err := store.Put(context.Background(), PutRequest{
		Kind: KindImage,
		Binding: Binding{
			TenantID: "tenant-gate", SiteID: "site-gate", SourceRef: "source-upload-alpha",
			RunID: "upload-session-alpha", StepID: "ingest-media", Attempt: 1,
		},
		Encoding: Encoding{MIMEType: "image/jpeg", WidthPixels: 20, HeightPixels: 12},
		Temporal: Temporal{WindowStart: &capturedAt, WindowEnd: &capturedAt, SampleOrdinal: 1},
		Governance: Governance{
			PrivacyClass: "internal", RetentionPolicyRef: "uploaded-media-v2",
			Audience: []string{"inspection-gate"}, ExpiresAt: now.Add(time.Hour),
		},
	}, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	originalFrozen := cloneDescriptor(original)
	now = now.Add(time.Minute)
	lease, err := store.LeaseForRun(context.Background(), RunLeaseRequest{
		SourceMediaRef: original.MediaRef,
		Binding: Binding{
			TenantID: "tenant-gate", SiteID: "site-gate", SourceRef: "source-upload-alpha",
			RunID: "run-gate-alpha", StepID: "open-media", Attempt: 1,
		},
		Governance: Governance{
			PrivacyClass: "internal", RetentionPolicyRef: "inspection-run-v2",
			Audience: []string{"inspection-gate"}, ExpiresAt: now.Add(30 * time.Minute),
		},
		PolicyRef: "inspection-run-lease-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Validate(); err != nil {
		t.Fatal(err)
	}
	if lease.MediaRef == original.MediaRef || lease.Binding.RunID != "run-gate-alpha" ||
		lease.RuntimeLease.SourceMediaRef != original.MediaRef ||
		lease.RuntimeLease.SourceSHA256 != original.Integrity.SHA256 ||
		lease.RuntimeLease.PolicyRef != "inspection-run-lease-v2" || lease.Lineage != (Lineage{}) ||
		lease.Integrity != original.Integrity || lease.Encoding != original.Encoding ||
		!equalTemporal(lease.Temporal, original.Temporal) {
		t.Fatalf("runtime lease=%+v original=%+v", lease, original)
	}
	unchanged, err := store.Describe(original.MediaRef)
	if err != nil || !reflect.DeepEqual(unchanged, originalFrozen) {
		t.Fatalf("source descriptor was rewritten: got=%+v want=%+v err=%v", unchanged, originalFrozen, err)
	}
	assertMediaContent(t, store, original.MediaRef, content)
	assertMediaContent(t, store, lease.MediaRef, content)

	reopened, err := New(Config{
		Root: root, MaxObjectBytes: 1 << 20, MaxTotalBytes: 8 << 20,
		MaxDescriptors: 64, DefaultTTL: time.Hour, MaximumTTL: 2 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Describe(lease.MediaRef)
	if err != nil || !reflect.DeepEqual(loaded, lease) {
		t.Fatalf("reopened runtime lease=%+v want=%+v err=%v", loaded, lease, err)
	}
	if _, err := reopened.Delete(context.Background(), lease.MediaRef); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Describe(original.MediaRef); err != nil {
		t.Fatalf("releasing run lease deleted source media: %v", err)
	}

	second, err := reopened.LeaseForRun(context.Background(), RunLeaseRequest{
		SourceMediaRef: original.MediaRef,
		Binding: Binding{
			TenantID: "tenant-gate", SiteID: "site-gate", SourceRef: "source-upload-alpha",
			RunID: "run-gate-beta", StepID: "open-media", Attempt: 1,
		},
		Governance: Governance{
			PrivacyClass: "internal", RetentionPolicyRef: "inspection-run-v2",
			Audience: []string{"inspection-gate"}, ExpiresAt: now.Add(20 * time.Minute),
		},
		PolicyRef: "inspection-run-lease-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Delete(context.Background(), original.MediaRef); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Describe(second.MediaRef); !errors.Is(err, ErrDeleted) {
		t.Fatalf("source deletion did not cascade to runtime lease: %v", err)
	}
}

func TestRuntimeLeaseFailsClosedOnScopeLifetimeAndChaining(t *testing.T) {
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	store, err := New(Config{
		Root: filepath.Join(t.TempDir(), "media"), MaxObjectBytes: 1 << 20, MaxTotalBytes: 8 << 20,
		MaxDescriptors: 64, DefaultTTL: time.Hour, MaximumTTL: 2 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	capturedAt := now
	original, err := store.Put(context.Background(), PutRequest{
		Kind: KindImage,
		Binding: Binding{
			TenantID: "tenant-gate", SiteID: "site-gate", SourceRef: "source-upload-alpha",
			RunID: "upload-session-alpha", StepID: "ingest-media", Attempt: 1,
		},
		Encoding: Encoding{MIMEType: "image/jpeg", WidthPixels: 20, HeightPixels: 12},
		Temporal: Temporal{WindowStart: &capturedAt, WindowEnd: &capturedAt, SampleOrdinal: 1},
		Governance: Governance{
			PrivacyClass: "internal", RetentionPolicyRef: "uploaded-media-v2",
			Audience: []string{"inspection-gate"}, ExpiresAt: now.Add(time.Hour),
		},
	}, bytes.NewReader(jpegFixture(t, 20, 12)))
	if err != nil {
		t.Fatal(err)
	}
	valid := RunLeaseRequest{
		SourceMediaRef: original.MediaRef,
		Binding: Binding{
			TenantID: "tenant-gate", SiteID: "site-gate", SourceRef: "source-upload-alpha",
			RunID: "run-gate-alpha", StepID: "open-media", Attempt: 1,
		},
		Governance: Governance{
			PrivacyClass: "internal", RetentionPolicyRef: "inspection-run-v2",
			Audience: []string{"inspection-gate"}, ExpiresAt: now.Add(30 * time.Minute),
		},
		PolicyRef: "inspection-run-lease-v2",
	}
	for name, mutate := range map[string]func(*RunLeaseRequest){
		"tenant":      func(value *RunLeaseRequest) { value.Binding.TenantID = "tenant-other" },
		"site":        func(value *RunLeaseRequest) { value.Binding.SiteID = "site-other" },
		"source":      func(value *RunLeaseRequest) { value.Binding.SourceRef = "source-other" },
		"same run":    func(value *RunLeaseRequest) { value.Binding.RunID = original.Binding.RunID },
		"extends ttl": func(value *RunLeaseRequest) { value.Governance.ExpiresAt = now.Add(90 * time.Minute) },
		"privacy":     func(value *RunLeaseRequest) { value.Governance.PrivacyClass = "public" },
		"audience":    func(value *RunLeaseRequest) { value.Governance.Audience = []string{"external"} },
		"bad policy":  func(value *RunLeaseRequest) { value.PolicyRef = "https://invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			request.Governance.Audience = append([]string(nil), valid.Governance.Audience...)
			mutate(&request)
			if _, err := store.LeaseForRun(context.Background(), request); !errors.Is(err, ErrLineageConflict) {
				t.Fatalf("LeaseForRun() error=%v", err)
			}
		})
	}
	leased, err := store.LeaseForRun(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	chained := valid
	chained.SourceMediaRef = leased.MediaRef
	chained.Binding.RunID = "run-gate-beta"
	if _, err := store.LeaseForRun(context.Background(), chained); !errors.Is(err, ErrLineageConflict) {
		t.Fatalf("chained runtime lease error=%v", err)
	}
}

func assertMediaContent(t *testing.T, store *Store, mediaRef string, expected []byte) {
	t.Helper()
	_, reader, err := store.Open(context.Background(), mediaRef)
	if err != nil {
		t.Fatal(err)
	}
	content, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(content, expected) {
		t.Fatalf("media content ref=%q read=%v close=%v equal=%v", mediaRef, readErr, closeErr, bytes.Equal(content, expected))
	}
}
