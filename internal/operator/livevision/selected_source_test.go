package livevision

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestSelectedSourcesCaptureExactCameraAndFailOnDriftWithoutFallback(t *testing.T) {
	harness := newConnectionHarness(t)
	vault := harness.provider.(*vaultConnections).vault
	harness.device.mutateSnapshot(func(snapshot *device.Snapshot) {
		snapshot.Cameras = append(snapshot.Cameras, device.Camera{ID: "native-second-camera", Name: "另一现场", SourceFingerprint: liveDigest("second-camera")})
	})
	snapshot, _ := harness.device.Read(context.Background())
	firstBinding, err := BindSource(snapshot, snapshot.Cameras[0], "source-first")
	if err != nil {
		t.Fatal(err)
	}
	secondBinding, err := BindSource(snapshot, snapshot.Cameras[1], "source-second")
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewVaultConnectionsForSource(vault, firstBinding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewVaultConnectionsForSource(vault, secondBinding)
	if err != nil {
		t.Fatal(err)
	}
	firstAcquirer := NewTemporaryAcquirer(first)
	secondAcquirer := NewTemporaryAcquirer(second)
	consume := func(acquirer mediaprep.Acquirer, request mediaprep.AcquisitionRequest, want mediaprep.AcquisitionOutcome) {
		t.Helper()
		result, err := acquirer.Acquire(context.Background(), request)
		if err != nil || result.Outcome != want {
			t.Fatalf("acquire: %v %v, want %v", result.Outcome, err, want)
		}
		if result.Content != nil {
			if _, err := io.Copy(io.Discard, result.Content); err != nil {
				t.Fatal(err)
			}
			if err := result.Content.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	firstRequest := selectedAcquisitionRequest("source-first", 1)
	consume(firstAcquirer, firstRequest, mediaprep.AcquisitionReady)
	consume(secondAcquirer, selectedAcquisitionRequest("source-second", 2), mediaprep.AcquisitionReady)
	// A repeated request reuses the exact acquisition and never takes a new picture.
	consume(firstAcquirer, firstRequest, mediaprep.AcquisitionReady)
	consume(secondAcquirer, selectedAcquisitionRequest("source-first", 3), mediaprep.AcquisitionFailed)
	harness.device.mutateSnapshot(func(snapshot *device.Snapshot) { snapshot.Cameras[1].SourceFingerprint = liveDigest("drifted-second") })
	consume(secondAcquirer, selectedAcquisitionRequest("source-second", 4), mediaprep.AcquisitionFailed)
	// The unaffected source remains usable while the second source fails.
	consume(firstAcquirer, selectedAcquisitionRequest("source-first", 5), mediaprep.AcquisitionReady)
	harness.device.mu.Lock()
	got := append([]string(nil), harness.device.pictures...)
	harness.device.mu.Unlock()
	want := []string{snapshot.Cameras[0].ID, snapshot.Cameras[1].ID, snapshot.Cameras[0].ID}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("camera captures %v, want %v", got, want)
	}
}

func TestBindSourceRejectsMissingDuplicateAndStaleSelection(t *testing.T) {
	original := device.Camera{ID: "one", Name: "One", SourceFingerprint: liveDigest("one")}
	snapshot := device.Snapshot{Identity: device.Identity{Serial: "device"}, Cameras: []device.Camera{original}}
	if _, err := BindSource(snapshot, original, "source-one"); err != nil {
		t.Fatal(err)
	}
	stale := original
	stale.SourceFingerprint = liveDigest("old")
	if _, err := BindSource(snapshot, stale, "source-one"); err == nil {
		t.Fatal("stale source accepted")
	}
	if _, err := BindSource(snapshot, device.Camera{ID: "missing"}, "source-one"); err == nil {
		t.Fatal("missing source accepted")
	}
	snapshot.Cameras = append(snapshot.Cameras, original)
	if _, err := BindSource(snapshot, original, "source-one"); err == nil {
		t.Fatal("duplicate source accepted")
	}
}

func selectedAcquisitionRequest(source string, ordinal int) mediaprep.AcquisitionRequest {
	at := time.Now().UTC().Add(-time.Second)
	return mediaprep.AcquisitionRequest{
		PreparationRef: fmt.Sprintf("media_prep_%032x", ordinal), OperationKey: fmt.Sprintf("media_acquire_%064x", ordinal),
		TenantID: TenantID, SiteID: SiteID, SourceRef: source, CapabilityRef: SnapshotCapability, Kind: media.KindImage,
		TimeScope: mediaprep.TimeScope{WindowStart: at, WindowEnd: at}, AudienceSHA256: strings.Repeat("a", 64), EvidenceExpiresAt: at.Add(10 * time.Minute),
	}
}
