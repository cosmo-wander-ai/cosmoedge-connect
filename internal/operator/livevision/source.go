// Package livevision adapts an identity-checked session Vault to snapshot and
// temporary picture analysis. It owns no persistent connection or product lifecycle.
package livevision

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"regexp"
	"sort"
)

const (
	TenantID           = "tenant-cosmoedge-live"
	SiteID             = "site-current-device"
	DeviceProfileID    = "dpf_86ada3d536c17b313c52b04502050804"
	SourceHandle       = "source-current-camera"
	SnapshotCapability = "snapshot-current"
	snapshotCapability = SnapshotCapability
	fullFrameROI       = "full-frame"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SourceFingerprint returns the stable source identity shared by catalog sync
// and the foreground connection adapter. Device-provided fingerprints are
// accepted only when non-empty and non-trivial; local/USB sources fall back to
// a digest of the protected device serial and camera identifier.
func SourceFingerprint(snapshot device.Snapshot, camera device.Camera) string {
	if snapshot.Identity.Serial == "" || camera.ID == "" {
		return ""
	}
	empty := sha256.Sum256(nil)
	emptyDigest := hex.EncodeToString(empty[:])
	if digestPattern.MatchString(camera.SourceFingerprint) && camera.SourceFingerprint != emptyDigest {
		return camera.SourceFingerprint
	}
	value := sha256.Sum256([]byte("cosmoedge.inspection.live-source.v1\x00" + snapshot.Identity.Serial + "\x00" + camera.ID))
	return hex.EncodeToString(value[:])
}

// SelectCamera prefers a camera already bound to a device task explicitly
// identified as VLM. This keeps the snapshot and picture-analysis path on the
// same channel. Devices without such a task use a stable name/ID fallback.
func SelectCamera(snapshot device.Snapshot) (device.Camera, bool) {
	cameras := append([]device.Camera(nil), snapshot.Cameras...)
	sort.Slice(cameras, func(i, j int) bool {
		if cameras[i].Name != cameras[j].Name {
			return cameras[i].Name < cameras[j].Name
		}
		return cameras[i].ID < cameras[j].ID
	})
	vlmChannels := make(map[string]struct{})
	for _, task := range snapshot.Tasks {
		name := task.AlgorithmName + " " + task.DisplayName
		if task.ChannelID != "" && isVLMName(name) {
			vlmChannels[task.ChannelID] = struct{}{}
		}
	}
	for _, camera := range cameras {
		if camera.ID == "" {
			continue
		}
		if _, preferred := vlmChannels[camera.ID]; preferred {
			return camera, true
		}
	}
	for _, camera := range cameras {
		if camera.ID != "" {
			return camera, true
		}
	}
	return device.Camera{}, false
}

// PublicSourceRef is the catalog reference accepted by business source selection.
// Native camera identifiers remain inside the adapter and frozen operation state.
func PublicSourceRef(camera device.Camera) string {
	if camera.ID == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(camera.ID + ":" + camera.SourceFingerprint))
	return "source_" + hex.EncodeToString(digest[:12])
}
