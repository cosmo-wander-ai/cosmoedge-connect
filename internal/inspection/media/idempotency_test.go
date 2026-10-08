package media

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPutIdempotentExactReplayReturnsOneStableMediaRef(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	content := pngFixture(t, 20, 12)
	request := idempotentImageRequest(now, content, "a")

	first, created, err := store.PutIdempotent(context.Background(), request, bytes.NewReader(content))
	if err != nil || !created {
		t.Fatalf("PutIdempotent(first) created=%v err=%v", created, err)
	}
	replayed, created, err := store.PutIdempotent(context.Background(), request, failOnRead{})
	if err != nil || created || replayed.MediaRef != first.MediaRef || replayed.Integrity != first.Integrity {
		t.Fatalf("PutIdempotent(replay) ref=%q created=%v err=%v", replayed.MediaRef, created, err)
	}
	entries, err := os.ReadDir(store.idempotencyDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("idempotency records=%d err=%v", len(entries), err)
	}
}

func TestPutIdempotentRejectsMissingDigestInvalidKeyAndChangedRequest(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	content := pngFixture(t, 10, 10)
	request := idempotentImageRequest(now, content, "b")

	missingDigest := request
	missingDigest.Media.ExpectedSHA256 = ""
	if _, _, err := store.PutIdempotent(context.Background(), missingDigest, bytes.NewReader(content)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("missing digest error=%v", err)
	}
	invalidKey := request
	invalidKey.IdempotencyKey = "caller-controlled/path"
	if _, _, err := store.PutIdempotent(context.Background(), invalidKey, bytes.NewReader(content)); !errors.Is(err, ErrInvalidIdempotencyKey) {
		t.Fatalf("invalid key error=%v", err)
	}
	if _, _, err := store.PutIdempotent(context.Background(), request, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Media.Binding.StepID = "different-step"
	if _, _, err := store.PutIdempotent(context.Background(), changed, bytes.NewReader(content)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed request error=%v", err)
	}
}

func TestIdempotentPutRequestCannotLeakThroughBusinessProjection(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	content := pngFixture(t, 6, 6)
	request := idempotentImageRequest(now, content, "1")
	if _, err := json.Marshal(request); !errors.Is(err, ErrProtectedPutProjection) {
		t.Fatalf("Marshal() error=%v", err)
	}
	if _, err := request.MarshalText(); !errors.Is(err, ErrProtectedPutProjection) {
		t.Fatalf("MarshalText() error=%v", err)
	}
	var output bytes.Buffer
	slog.New(slog.NewJSONHandler(&output, nil)).Info("protected", slog.Any("request", request))
	projection := fmt.Sprintf("%s %+v %#v", output.String(), request, request)
	for _, forbidden := range []string{request.IdempotencyKey, request.Media.Binding.TenantID, request.Media.Binding.SourceRef, request.Media.ExpectedSHA256} {
		if strings.Contains(projection, forbidden) {
			t.Fatalf("protected request leaked %q: %s", forbidden, projection)
		}
	}
}

func TestPutIdempotentConcurrentReplayPublishesExactlyOnce(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	content := pngFixture(t, 18, 11)
	request := idempotentImageRequest(now, content, "c")

	const workers = 24
	var wait sync.WaitGroup
	var createdCount atomic.Int32
	refs := make(chan string, workers)
	errorsFound := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			descriptor, created, err := store.PutIdempotent(context.Background(), request, bytes.NewReader(content))
			if err != nil {
				errorsFound <- err
				return
			}
			if created {
				createdCount.Add(1)
			}
			refs <- descriptor.MediaRef
		}()
	}
	wait.Wait()
	close(refs)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	if createdCount.Load() != 1 {
		t.Fatalf("created count=%d", createdCount.Load())
	}
	var exact string
	for ref := range refs {
		if exact == "" {
			exact = ref
		}
		if ref != exact {
			t.Fatalf("concurrent replay allocated %q and %q", exact, ref)
		}
	}
}

func TestPutIdempotentRestartRecoversReservedIdentityWithoutOrphan(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	content := pngFixture(t, 14, 9)
	request := idempotentImageRequest(now, content, "d")
	canonical, err := store.canonicalIdempotentRequest(request.Media, now)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := idempotentRequestDigest(canonical)
	if err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	mediaRef, err := store.unusedMediaRefLocked()
	if err == nil {
		err = store.writeIdempotencyRecordLocked(idempotencyRecord{
			Schema: idempotencySchema, IdempotencyKey: request.IdempotencyKey,
			RequestSHA256: digest, Request: canonical, MediaRef: mediaRef,
			State: idempotencyReserved, CreatedAt: now,
		})
	}
	if err == nil {
		err = os.WriteFile(store.objectPath(mediaRef), []byte("interrupted-object"), 0o600)
	}
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := New(Config{Root: store.root, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(reopened.objectPath(mediaRef)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved orphan survived recovery: %v", err)
	}
	descriptor, created, err := reopened.PutIdempotent(context.Background(), request, bytes.NewReader(content))
	if err != nil || !created || descriptor.MediaRef != mediaRef {
		t.Fatalf("recovered put ref=%q want=%q created=%v err=%v", descriptor.MediaRef, mediaRef, created, err)
	}
}

func TestPutIdempotentRestartPromotesDescriptorPublishedBeforeRecord(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	content := pngFixture(t, 15, 10)
	request := idempotentImageRequest(now, content, "e")
	canonical, err := store.canonicalIdempotentRequest(request.Media, now)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := idempotentRequestDigest(canonical)

	store.mu.Lock()
	mediaRef, err := store.unusedMediaRefLocked()
	if err == nil {
		err = store.writeIdempotencyRecordLocked(idempotencyRecord{
			Schema: idempotencySchema, IdempotencyKey: request.IdempotencyKey,
			RequestSHA256: digest, Request: canonical, MediaRef: mediaRef,
			State: idempotencyReserved, CreatedAt: now,
		})
	}
	if err == nil {
		_, err = store.putLocked(context.Background(), canonical, bytes.NewReader(content), now, mediaRef)
	}
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := New(Config{Root: store.root, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	record, err := reopened.readIdempotencyRecordLocked(reopened.idempotencyPath(request.IdempotencyKey))
	if err != nil || record.State != idempotencyPublished || record.MediaRef != mediaRef {
		t.Fatalf("recovered record=%+v err=%v", record, err)
	}
	descriptor, created, err := reopened.PutIdempotent(context.Background(), request, failOnRead{})
	if err != nil || created || descriptor.MediaRef != mediaRef {
		t.Fatalf("replay after promotion ref=%q created=%v err=%v", descriptor.MediaRef, created, err)
	}
}

func TestPutIdempotentDeletionNeverResurrectsAndTamperingFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	store := newTestStore(t, Config{Now: func() time.Time { return now }})
	content := pngFixture(t, 13, 8)
	request := idempotentImageRequest(now, content, "f")
	descriptor, _, err := store.PutIdempotent(context.Background(), request, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(context.Background(), descriptor.MediaRef); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(Config{Root: store.root, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reopened.PutIdempotent(context.Background(), request, failOnRead{}); !errors.Is(err, ErrDeleted) {
		t.Fatalf("deleted replay error=%v", err)
	}

	raw, err := os.ReadFile(reopened.idempotencyPath(request.IdempotencyKey))
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"state":"published"`), []byte(`"state":"reserved" `), 1)
	if err := os.WriteFile(reopened.idempotencyPath(request.IdempotencyKey), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Root: store.root, Now: func() time.Time { return now }}); !errors.Is(err, ErrCorruptIdempotency) {
		t.Fatalf("tampered idempotency state error=%v", err)
	}
}

func idempotentImageRequest(now time.Time, content []byte, suffix string) IdempotentPutRequest {
	request := imageRequest(now, 0)
	request.ExpectedSHA256 = sha(content)
	return IdempotentPutRequest{
		IdempotencyKey: "media_put_" + strings.Repeat(suffix, 64),
		Media:          request,
	}
}

type failOnRead struct{}

func (failOnRead) Read([]byte) (int, error) {
	return 0, fmt.Errorf("idempotent replay unexpectedly consumed source")
}
