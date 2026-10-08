package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

var mp4Fixture = []byte{
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2',
	0x00, 0x00, 0x02, 0x00, 'm', 'p', '4', '2', 'i', 's', 'o', 'm',
}

func TestPutStreamsImageAndProjectsOnlyBusinessMetadata(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	content := pngFixture(t, 24, 16)
	descriptor, err := store.Put(context.Background(), imageRequest(now, 0), bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("Put() returned an invalid descriptor: %v", err)
	}
	if descriptor.FrameMembers == nil {
		t.Fatal("Put() collapsed the explicit empty frame member collection to null")
	}
	if !mediaRefPattern.MatchString(descriptor.MediaRef) || descriptor.Schema != Schema || descriptor.Kind != KindImage ||
		descriptor.Encoding.MIMEType != "image/png" || descriptor.Encoding.Container != "png" || descriptor.Encoding.Codec != "png" ||
		descriptor.Encoding.WidthPixels != 24 || descriptor.Encoding.HeightPixels != 16 ||
		descriptor.Integrity.SizeBytes != int64(len(content)) || descriptor.Integrity.SHA256 != sha(content) ||
		descriptor.Availability != AvailabilityAvailable || descriptor.Governance.ExpiresAt != now.Add(time.Hour) {
		t.Fatalf("descriptor=%+v", descriptor)
	}
	projected := descriptor.Business()
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"path", "url", "base64", "tenant", "source", "runId", "stepId", "sha256", store.Root()} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("business projection leaked %q: %s", forbidden, raw)
		}
	}
	assertNoForbiddenBusinessField(t, reflect.TypeOf(projected))
	persisted, err := os.ReadFile(store.descriptorPath(descriptor.MediaRef))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{store.Root(), "rtsp://", "rtsps://", "password", "base64"} {
		if strings.Contains(strings.ToLower(string(persisted)), strings.ToLower(forbidden)) {
			t.Fatalf("persisted descriptor leaked %q: %s", forbidden, persisted)
		}
	}

	opened, reader, err := store.Open(context.Background(), descriptor.MediaRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Validate(); err != nil {
		t.Fatalf("Open() returned an invalid descriptor: %v", err)
	}
	if opened.FrameMembers == nil {
		t.Fatal("Open() collapsed the explicit empty frame member collection to null")
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, content) || opened.MediaRef != descriptor.MediaRef {
		t.Fatalf("Open() descriptor=%+v bytes=%d read=%v close=%v", opened, len(got), readErr, closeErr)
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{store.root, store.objectsDir, store.descriptorsDir, store.tombstonesDir, store.idempotencyDir, store.tempDir} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("private directory %s: info=%v err=%v", path, info, err)
			}
		}
		for _, path := range []string{filepath.Join(store.root, rootMarkerName), store.objectPath(descriptor.MediaRef), store.descriptorPath(descriptor.MediaRef)} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("private file %s: info=%v err=%v", path, info, err)
			}
		}
	}
}

func TestPutSupportsJPEGMP4AndStructuredKinds(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	jpegBytes := jpegFixture(t, 12, 8)
	jpegRequest := imageRequest(now, 1)
	jpegRequest.Encoding.MIMEType = "image/jpeg"
	jpegDescriptor, err := store.Put(context.Background(), jpegRequest, bytes.NewReader(jpegBytes))
	if err != nil || jpegDescriptor.Encoding.Codec != "jpeg" || jpegDescriptor.Encoding.WidthPixels != 12 {
		t.Fatalf("JPEG Put() descriptor=%+v err=%v", jpegDescriptor, err)
	}

	videoRequest := imageRequest(now, 2)
	videoRequest.Kind = KindVideoClip
	videoRequest.Encoding = Encoding{MIMEType: "video/mp4", Container: "mp4", Codec: "h264", WidthPixels: 1920, HeightPixels: 1080, FrameRate: 25}
	videoRequest.Temporal.DurationMillis = 1_500
	videoDescriptor, err := store.Put(context.Background(), videoRequest, bytes.NewReader(mp4Fixture))
	if err != nil || videoDescriptor.Kind != KindVideoClip || videoDescriptor.Encoding.Codec != "h264" || videoDescriptor.Temporal.DurationMillis != 1_500 {
		t.Fatalf("MP4 Put() descriptor=%+v err=%v", videoDescriptor, err)
	}

	for index, kind := range []Kind{KindMetric, KindDetection, KindEvent} {
		request := imageRequest(now, index+3)
		request.Kind = kind
		request.Encoding = Encoding{MIMEType: "application/json"}
		descriptor, err := store.Put(context.Background(), request, strings.NewReader(`{"value":1}`))
		if err != nil || descriptor.Kind != kind || descriptor.Encoding.Container != "json" || descriptor.Encoding.Codec != "json" {
			t.Fatalf("%s Put() descriptor=%+v err=%v", kind, descriptor, err)
		}
	}
}

func TestPutRejectsHashMIMEQuotaAndNonOpaqueBinding(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	content := pngFixture(t, 4, 4)
	store := newTestStore(t, Config{
		Now: func() time.Time { return now }, MaxObjectBytes: int64(len(content)),
		MaxTotalBytes: int64(len(content)), MaxDescriptors: 1,
	})
	wrongHash := imageRequest(now, 0)
	wrongHash.ExpectedSHA256 = strings.Repeat("0", 64)
	if _, err := store.Put(context.Background(), wrongHash, bytes.NewReader(content)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash mismatch error=%v", err)
	}
	wrongMIME := imageRequest(now, 0)
	wrongMIME.Encoding.MIMEType = "image/jpeg"
	if _, err := store.Put(context.Background(), wrongMIME, bytes.NewReader(content)); !errors.Is(err, ErrMIMEMismatch) {
		t.Fatalf("MIME mismatch error=%v", err)
	}
	leaky := imageRequest(now, 0)
	leaky.Binding.SourceRef = "192.168.1.8"
	if _, err := store.Put(context.Background(), leaky, bytes.NewReader(content)); err == nil {
		t.Fatal("literal device IP was accepted as an opaque source reference")
	}
	if _, err := store.Put(context.Background(), imageRequest(now, 0), bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), imageRequest(now, 1), bytes.NewReader(content)); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota error=%v", err)
	}
	tooLarge := newTestStore(t, Config{MaxObjectBytes: int64(len(content) - 1), MaxTotalBytes: int64(len(content) - 1)})
	if _, err := tooLarge.Put(context.Background(), imageRequest(time.Now().UTC(), 0), bytes.NewReader(content)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("per-object limit error=%v", err)
	}
}

func TestRegisterOrderedFrameSetAndDeletionCascades(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	first := mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	second := mustPutImage(t, store, imageRequest(now, 1), pngFixture(t, 9, 8))
	set, err := store.RegisterFrameSet(context.Background(), FrameSetRequest{
		Binding:    imageRequest(now, 2).Binding,
		Temporal:   Temporal{DurationMillis: 500, SampleOrdinal: 2},
		Governance: governance(now.Add(30 * time.Minute)),
		Members: []FrameMemberInput{
			{MediaRef: first.MediaRef, Ordinal: 0, OffsetMillis: 0, TransformPolicyRef: "sample-frame-v2"},
			{MediaRef: second.MediaRef, Ordinal: 1, OffsetMillis: 500, TransformPolicyRef: "sample-frame-v2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if set.Kind != KindFrameSet || set.Integrity.SizeBytes != 0 || len(set.FrameMembers) != 2 || set.FrameMembers[1].OffsetMillis != 500 {
		t.Fatalf("frame set=%+v", set)
	}
	reopened, err := New(Config{Root: store.Root(), MaxObjectBytes: 1 << 20, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("healthy frame set did not survive restart: %v", err)
	}
	store = reopened
	for index, childRef := range []string{first.MediaRef, second.MediaRef} {
		child, err := store.Describe(childRef)
		if err != nil || child.Lineage.ParentMediaRef != set.MediaRef || child.Lineage.Ordinal != index {
			t.Fatalf("child %d=%+v err=%v", index, child, err)
		}
	}
	if _, reader, err := store.Open(context.Background(), set.MediaRef); !errors.Is(err, ErrNoContent) || reader != nil {
		t.Fatalf("frame set Open() reader=%v err=%v", reader, err)
	}
	deleted, err := store.Delete(context.Background(), set.MediaRef)
	if err != nil || deleted.Availability != AvailabilityDeleted || deleted.DeletionReason != "deleted" {
		t.Fatalf("Delete()=(%+v,%v)", deleted, err)
	}
	for _, ref := range []string{set.MediaRef, first.MediaRef, second.MediaRef} {
		descriptor, err := store.Describe(ref)
		if !errors.Is(err, ErrDeleted) || descriptor.Availability != AvailabilityDeleted {
			t.Fatalf("Describe(%s)=(%+v,%v)", ref, descriptor, err)
		}
	}
}

func TestParentExpiryCascadesToFrameMembers(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	clock := now
	store := newTestStore(t, Config{Now: func() time.Time { return clock }})
	first := mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	second := mustPutImage(t, store, imageRequest(now, 1), pngFixture(t, 9, 8))
	set, err := store.RegisterFrameSet(context.Background(), FrameSetRequest{
		Binding: imageRequest(now, 2).Binding, Temporal: Temporal{SampleOrdinal: 2},
		Governance: governance(now.Add(10 * time.Minute)),
		Members: []FrameMemberInput{
			{MediaRef: first.MediaRef, Ordinal: 0, TransformPolicyRef: "sample-frame-v2"},
			{MediaRef: second.MediaRef, Ordinal: 1, OffsetMillis: 100, TransformPolicyRef: "sample-frame-v2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	clock = now.Add(11 * time.Minute)
	count, err := store.GC(context.Background())
	if err != nil || count != 1 {
		t.Fatalf("GC() count=%d err=%v", count, err)
	}
	for _, ref := range []string{set.MediaRef, first.MediaRef, second.MediaRef} {
		if _, err := store.Describe(ref); !errors.Is(err, ErrDeleted) {
			t.Fatalf("%s survived parent expiry: %v", ref, err)
		}
	}
}

func TestOpenDetectsTamperAndRestartReconcilesResidues(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "media")
	config := Config{Root: root, MaxObjectBytes: 1 << 20, Now: func() time.Time { return now }}
	store, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	healthy := mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	tampered := mustPutImage(t, store, imageRequest(now, 1), pngFixture(t, 9, 8))
	content, err := os.ReadFile(store.objectPath(tampered.MediaRef))
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-1] ^= 0xff
	if err := os.WriteFile(store.objectPath(tampered.MediaRef), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reader, err := store.Open(context.Background(), tampered.MediaRef); !errors.Is(err, ErrIntegrityMismatch) || reader != nil {
		t.Fatalf("tampered Open() reader=%v err=%v", reader, err)
	}
	orphanRef := "media_11111111111111111111111111111111"
	if err := os.WriteFile(store.objectPath(orphanRef), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.tempDir, "put-crash.media"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Describe(healthy.MediaRef); err != nil {
		t.Fatalf("healthy descriptor lost: %v", err)
	}
	if descriptor, err := reopened.Describe(tampered.MediaRef); !errors.Is(err, ErrDeleted) || descriptor.DeletionReason != "recovery_hash_mismatch" {
		t.Fatalf("tampered descriptor=(%+v,%v)", descriptor, err)
	}
	for _, path := range []string{reopened.objectPath(orphanRef), filepath.Join(reopened.tempDir, "put-crash.media")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("crash residue %s remains: %v", path, err)
		}
	}
}

func TestRestartFailsClosedOnInterruptedFrameSetPublication(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "media")
	config := Config{Root: root, MaxObjectBytes: 1 << 20, Now: func() time.Time { return now }}
	store, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	first := mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	second := mustPutImage(t, store, imageRequest(now, 1), pngFixture(t, 9, 8))
	set, err := store.RegisterFrameSet(context.Background(), FrameSetRequest{
		Binding: imageRequest(now, 2).Binding, Temporal: Temporal{SampleOrdinal: 2}, Governance: governance(now.Add(30 * time.Minute)),
		Members: []FrameMemberInput{
			{MediaRef: first.MediaRef, Ordinal: 0, TransformPolicyRef: "sample-frame-v2"},
			{MediaRef: second.MediaRef, Ordinal: 1, OffsetMillis: 50, TransformPolicyRef: "sample-frame-v2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := store.readDescriptor(store.descriptorPath(first.MediaRef))
	if err != nil {
		t.Fatal(err)
	}
	interrupted.Lineage = Lineage{}
	if err := store.writeDescriptorAtomic(store.descriptorPath(first.MediaRef), interrupted); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{set.MediaRef, first.MediaRef, second.MediaRef} {
		if _, err := reopened.Describe(ref); !errors.Is(err, ErrDeleted) {
			t.Fatalf("incomplete frame set member %s survived reconciliation: %v", ref, err)
		}
	}
}

func TestOldRootAndUnknownDescriptorStateAreRejected(t *testing.T) {
	root := filepath.Join(t.TempDir(), "old")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, rootMarkerName), []byte("cosmoedge.inspection.media.v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Root: root}); !errors.Is(err, ErrIncompatibleStore) {
		t.Fatalf("old root error=%v", err)
	}

	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	root = filepath.Join(t.TempDir(), "unknown-state")
	config := Config{Root: root, MaxObjectBytes: 1 << 20, Now: func() time.Time { return now }}
	store, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	raw, err := os.ReadFile(store.descriptorPath(descriptor.MediaRef))
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"availability":"available"`), []byte(`"availability":"legacy_ready"`), 1)
	if err := os.WriteFile(store.descriptorPath(descriptor.MediaRef), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config); !errors.Is(err, ErrCorruptDescriptor) {
		t.Fatalf("unknown state error=%v", err)
	}

	root = filepath.Join(t.TempDir(), "unknown-field")
	config = Config{Root: root, MaxObjectBytes: 1 << 20, Now: func() time.Time { return now }}
	store, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	descriptor = mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	raw, err = os.ReadFile(store.descriptorPath(descriptor.MediaRef))
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("{"), []byte(`{"legacyPath":"/tmp/leak",`), 1)
	if err := os.WriteFile(store.descriptorPath(descriptor.MediaRef), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config); !errors.Is(err, ErrCorruptDescriptor) {
		t.Fatalf("unknown field error=%v", err)
	}
}

func TestOpenLeaseSerializesDeletionAndConcurrentPutsAreRaceSafe(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }, MaxDescriptors: 128})
	descriptor := mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	_, reader, err := store.Open(context.Background(), descriptor.MediaRef)
	if err != nil {
		t.Fatal(err)
	}
	deleted := make(chan error, 1)
	go func() {
		_, err := store.Delete(context.Background(), descriptor.MediaRef)
		deleted <- err
	}()
	select {
	case err := <-deleted:
		t.Fatalf("Delete returned before stream Close: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}

	const workers = 24
	payloads := make([][]byte, workers)
	for index := range payloads {
		payloads[index] = pngFixture(t, 8+index%3, 8)
	}
	var group sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			request := imageRequest(now, index+1)
			_, err := store.Put(context.Background(), request, bytes.NewReader(payloads[index]))
			errorsSeen <- err
		}(index)
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestKindsReuseInspectionDomainEnumeration(t *testing.T) {
	values := []inspection.MediaKind{KindImage, KindFrameSet, KindVideoClip, KindMetric, KindDetection, KindEvent}
	expected := []inspection.MediaKind{
		inspection.MediaImage, inspection.MediaFrameSet, inspection.MediaVideoClip,
		inspection.MediaMetric, inspection.MediaDetection, inspection.MediaEvent,
	}
	if !reflect.DeepEqual(values, expected) {
		t.Fatalf("media kinds drifted: got=%v want=%v", values, expected)
	}
	for _, value := range values {
		if !value.Valid() {
			t.Fatalf("inspection domain rejects media kind %q", value)
		}
	}
}

func TestFrameSetRejectsNonCanonicalOrder(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	first := mustPutImage(t, store, imageRequest(now, 0), pngFixture(t, 8, 8))
	second := mustPutImage(t, store, imageRequest(now, 1), pngFixture(t, 9, 8))
	_, err := store.RegisterFrameSet(context.Background(), FrameSetRequest{
		Binding: imageRequest(now, 2).Binding, Temporal: Temporal{SampleOrdinal: 2}, Governance: governance(now.Add(30 * time.Minute)),
		Members: []FrameMemberInput{
			{MediaRef: first.MediaRef, Ordinal: 1, TransformPolicyRef: "sample-frame-v2"},
			{MediaRef: second.MediaRef, Ordinal: 0, TransformPolicyRef: "sample-frame-v2"},
		},
	})
	if err == nil {
		t.Fatal("out-of-order frame set was accepted")
	}
}

func newTestStore(t *testing.T, config Config) *Store {
	t.Helper()
	if config.Root == "" {
		config.Root = filepath.Join(t.TempDir(), "media")
	}
	if config.MaxObjectBytes == 0 {
		config.MaxObjectBytes = 1 << 20
	}
	store, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func imageRequest(now time.Time, ordinal int) PutRequest {
	return PutRequest{
		Kind: KindImage,
		Binding: Binding{
			TenantID: "tenant-demo", SiteID: "site-demo", SourceRef: "source-camera-east",
			RunID: "run-demo", StepID: "capture-step", Attempt: 1,
		},
		Encoding:   Encoding{MIMEType: "image/png"},
		Temporal:   Temporal{SampleOrdinal: ordinal},
		Governance: governance(now.Add(time.Hour)),
	}
}

func governance(expiresAt time.Time) Governance {
	return Governance{
		PrivacyClass: "sensitive", RedactionPolicyRef: "faces-v2",
		RetentionPolicyRef: "inspection-short-v2", Audience: []string{"operator", "run-owner"},
		ExpiresAt: expiresAt,
	}
}

func mustPutImage(t *testing.T, store *Store, request PutRequest, content []byte) Descriptor {
	t.Helper()
	descriptor, err := store.Put(context.Background(), request, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func pngFixture(t *testing.T, width, height int) []byte {
	t.Helper()
	frame := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			frame.SetRGBA(x, y, color.RGBA{R: uint8(x + 20), G: uint8(y + 30), B: 90, A: 255})
		}
	}
	var output bytes.Buffer
	if err := png.Encode(&output, frame); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func jpegFixture(t *testing.T, width, height int) []byte {
	t.Helper()
	frame := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			frame.SetRGBA(x, y, color.RGBA{R: 50, G: uint8(x + 40), B: uint8(y + 60), A: 255})
		}
	}
	var output bytes.Buffer
	if err := jpeg.Encode(&output, frame, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func sha(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func assertNoForbiddenBusinessField(t *testing.T, value reflect.Type) {
	t.Helper()
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"path", "url", "base64", "bytes", "credential", "password", "token", "source", "tenant", "runid", "stepid", "sha256"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("business descriptor field %s exposes %s", field.Name, forbidden)
			}
		}
	}
}
