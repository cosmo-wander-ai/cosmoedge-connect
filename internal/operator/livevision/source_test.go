package livevision

import (
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"strings"
	"testing"
)

func TestSelectCameraPrefersVLMTaskChannel(t *testing.T) {
	snapshot := device.Snapshot{
		Cameras: []device.Camera{{ID: "1", Name: "A"}, {ID: "5", Name: "Z"}},
		Tasks:   []device.Task{{ChannelID: "5", AlgorithmName: "视觉语言大模型", DisplayName: "现场观察"}},
	}
	selected, ok := SelectCamera(snapshot)
	if !ok || selected.ID != "5" {
		t.Fatalf("selected = %#v, %t", selected, ok)
	}
}

func TestSelectCameraUsesStableFallback(t *testing.T) {
	snapshot := device.Snapshot{Cameras: []device.Camera{{ID: "2", Name: "西侧"}, {ID: "1", Name: "东侧"}}}
	selected, ok := SelectCamera(snapshot)
	if !ok || selected.ID != "1" {
		t.Fatalf("selected = %#v, %t", selected, ok)
	}
}

func TestSourceFingerprintFallsBackForLocalSource(t *testing.T) {
	snapshot := device.Snapshot{Identity: device.Identity{Serial: "serial-private"}}
	camera := device.Camera{ID: "usb-1"}
	got := SourceFingerprint(snapshot, camera)
	if !digestPattern.MatchString(got) || strings.Contains(got, snapshot.Identity.Serial) || strings.Contains(got, camera.ID) {
		t.Fatalf("unsafe fallback fingerprint %q", got)
	}
	if SourceFingerprint(device.Snapshot{}, camera) != "" || SourceFingerprint(snapshot, device.Camera{}) != "" {
		t.Fatal("incomplete source identity must not produce a fingerprint")
	}
}

func TestConnectionClassificationRespectsFrozenOutputPolicy(t *testing.T) {
	allowed := []inspection.Assessment{
		inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention,
		inspection.AssessmentUncertain, inspection.AssessmentNotObservable,
	}
	for label, wanted := range map[string]inspection.Assessment{
		"是": inspection.AssessmentNeedsAttention, "否": inspection.AssessmentMeetsRule,
		"无法判断": inspection.AssessmentUncertain, "不可见": inspection.AssessmentNotObservable,
	} {
		got, err := assessmentForLabel(label, allowed)
		if err != nil || got != wanted {
			t.Fatalf("label %q = %q, %v; want %q", label, got, err, wanted)
		}
	}
	got, err := assessmentForLabel("否", []inspection.Assessment{
		inspection.AssessmentNeedsAttention, inspection.AssessmentUncertain,
	})
	if err != nil || got != inspection.AssessmentUncertain {
		t.Fatalf("negative answer escaped non-compliance policy: %q, %v", got, err)
	}
	if _, err := assessmentForLabel("一切合规", allowed); err == nil {
		t.Fatal("unbounded model label must be rejected")
	}
}

func TestCurrentCameraUsesSharedFingerprintRule(t *testing.T) {
	snapshot := device.Snapshot{
		Identity: device.Identity{Serial: "serial-private"},
		Cameras:  []device.Camera{{ID: "5", Name: "现场"}},
	}
	fingerprint := SourceFingerprint(snapshot, snapshot.Cameras[0])
	got, _, ok := currentCamera(snapshot, "5", fingerprint)
	if !ok || got.ID != "5" {
		t.Fatalf("current camera = %#v, %t", got, ok)
	}
	if _, _, ok := currentCamera(snapshot, "5", strings.Repeat("a", 64)); ok {
		t.Fatal("stale camera fingerprint was accepted")
	}
}
