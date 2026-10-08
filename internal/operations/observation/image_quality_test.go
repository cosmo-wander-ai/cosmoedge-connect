package observation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image/color"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

func TestObservationDarkImageRetainsUnableEvidenceWithoutDeviceAnalysis(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	ctx := context.Background()
	original := testJPEG(t, color.RGBA{R: 2, G: 2, B: 2, A: 255})
	digest := sha256.Sum256(original)
	wantSHA := hex.EncodeToString(digest[:])
	fake.mu.Lock()
	fake.images["camera-a"] = original
	fake.answer = "否" // A model response must not override the local quality limit.
	fake.mu.Unlock()

	request := Request{RequestID: "dark-image-quality", SourceName: "室内", Question: "画面中是否有人", Subject: "人员"}
	startedAt := time.Now().UTC()
	first, err := service.Observe(ctx, testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	first = awaitTerminal(t, service, testOwner, first.OperationRef)
	if first.ObservedAt == nil || first.ObservedAt.Before(startedAt) || first.ObservedAt.After(time.Now().UTC()) {
		t.Fatalf("quality result lost its image retrieval time: %v", first.ObservedAt)
	}
	if len(first.Attachments) != 1 {
		t.Fatalf("quality result attachments=%d, want the original image", len(first.Attachments))
	}
	mediaRef := first.Attachments[0].MediaRef
	observedAt := *first.ObservedAt
	expiresAt := first.Attachments[0].ExpiresAt

	assertRetained := func(label string, result Result) {
		t.Helper()
		limitations := strings.Join(result.Limitations, " ")
		if result.Pending || result.Status != "succeeded" || result.Answer != temporary.AnswerUnable || len(result.Facts) != 0 ||
			!strings.Contains(limitations, "过暗") || !strings.Contains(limitations, "细节") || result.CleanupStatus != "not_started" {
			t.Fatalf("%s: quality limit was not retained: %+v", label, result)
		}
		if result.OperationRef != first.OperationRef || result.RequestID != request.RequestID || result.Question != request.Question ||
			result.SourceName != "室内" || result.SourceKind != "network_camera" || result.TimeMeaning != "image_retrieved_at" ||
			result.ObservedAt == nil || !result.ObservedAt.Equal(observedAt) || len(result.Attachments) != 1 {
			t.Fatalf("%s: result changed source, identity, or retrieval time: %+v", label, result)
		}
		attachment := result.Attachments[0]
		if attachment.MediaRef != mediaRef || attachment.Status != "available" || attachment.MIMEType != "image/jpeg" ||
			attachment.SHA256 != wantSHA || attachment.SizeBytes != int64(len(original)) || !attachment.ExpiresAt.Equal(expiresAt) {
			t.Fatalf("%s: original image metadata changed: %+v", label, attachment)
		}
		content, err := service.ReadMedia(ctx, testOwner, mediaRef)
		if err != nil || content.MIMEType != "image/jpeg" || content.SHA256 != wantSHA || !bytes.Equal(content.Content, original) {
			t.Fatalf("%s: original image bytes are unavailable or changed: %v", label, err)
		}
		if _, err := service.ReadMedia(ctx, otherOwner, mediaRef); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: another owner could read the quality-limited image: %v", label, err)
		}
		if _, err := service.Get(ctx, otherOwner, first.OperationRef); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: another owner could read the quality-limited result: %v", label, err)
		}
		if _, err := service.GetByRequest(ctx, otherOwner, request.RequestID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: another owner could resolve the quality-limited request: %v", label, err)
		}

		operation, err := service.resource.operations.get(ctx, testOwner, first.OperationRef)
		if err != nil {
			t.Fatalf("%s: read persisted operation: %v", label, err)
		}
		record, err := service.resource.runner.Get(ctx, operation.RunID)
		if err != nil || record.Validate() != nil || record.State != temporary.StateSucceeded || record.Reason != temporary.ReasonCompleted ||
			record.Binding.PrincipalSHA256 != testOwner || record.Binding.PublicRunRef != first.OperationRef ||
			record.MediaRef != mediaRef || record.Media == nil || record.Media.SHA256 != wantSHA ||
			record.Media.Temporal.WindowEnd == nil || !record.Media.Temporal.WindowEnd.Equal(observedAt) ||
			record.Observation == nil || record.Observation.Answer != temporary.AnswerUnable || len(record.Observation.VisibleFacts) != 0 {
			t.Fatalf("%s: persisted unable result or media binding is invalid: %v", label, err)
		}
		descriptor, err := service.resource.media.Describe(mediaRef)
		if err != nil || !matchesMedia(operation, descriptor) || descriptor.Binding.RunID != operation.RunID ||
			descriptor.Binding.SourceRef != operation.Source.SourceRef || descriptor.Integrity.SHA256 != wantSHA ||
			descriptor.Temporal.WindowEnd == nil || !descriptor.Temporal.WindowEnd.Equal(observedAt) {
			t.Fatalf("%s: persisted image lost its source, owner, or time binding: %v", label, err)
		}
		var tasks int
		if err := service.resource.operations.db.QueryRowContext(ctx, "SELECT count(*) FROM temporary_tasks").Scan(&tasks); err != nil || tasks != 0 {
			t.Fatalf("%s: quality limit reserved temporary tasks=%d: %v", label, tasks, err)
		}
		fake.mu.Lock()
		captures := append([]string(nil), fake.captures...)
		creates, detects, cancels := len(fake.creates), fake.detects, len(fake.cancels)
		fake.mu.Unlock()
		if len(captures) != 1 || captures[0] != "camera-a" || creates != 0 || detects != 0 || cancels != 0 {
			t.Fatalf("%s: unexpected device work: captures=%v create=%d detect=%d cancel=%d", label, captures, creates, detects, cancels)
		}
	}
	assertRetained("initial", first)

	// A later camera image must not replace the evidence or trigger model work
	// when the original request is read again, including after reopening stores.
	replacement := testJPEG(t, color.RGBA{R: 255, A: 255})
	fake.mu.Lock()
	fake.images["camera-a"] = replacement
	fake.mu.Unlock()
	for _, phase := range []string{"repeat", "restart"} {
		if phase == "restart" {
			if err := service.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := service.Start(ctx); err != nil {
				t.Fatal(err)
			}
		}
		byRequest, err := service.GetByRequest(ctx, testOwner, request.RequestID)
		if err != nil {
			t.Fatalf("%s: read original request: %v", phase, err)
		}
		assertRetained(phase+" by-request", byRequest)
		duplicate, err := service.Observe(ctx, testOwner, request)
		if err != nil {
			t.Fatalf("%s: repeat original observation: %v", phase, err)
		}
		assertRetained(phase+" observe", duplicate)
	}
}
