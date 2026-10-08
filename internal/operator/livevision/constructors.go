package livevision

import (
	"errors"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

// SourceBinding pins a public source reference to one exact camera identity.
// CameraID is a device locator; keep this object inside the service.
// A changed identity is rejected and never replaced by the default camera.
type SourceBinding struct {
	SourceRef            string
	CameraID             string
	IdentityFingerprint  string
	DeviceIdentitySHA256 string `json:"DeviceIdentitySHA256,omitempty"`
	ConnectionEpoch      string `json:"ConnectionEpoch,omitempty"`
}

// BindSource constructs a frozen binding from an independently selected camera
// in the current snapshot. It rejects duplicate, absent, or changed identities.
func BindSource(snapshot device.Snapshot, camera device.Camera, sourceRef string) (SourceBinding, error) {
	fingerprint := SourceFingerprint(snapshot, camera)
	selected, _, ok := currentCamera(snapshot, camera.ID, fingerprint)
	if !ok || selected != camera || sourceRef == "" || strings.TrimSpace(sourceRef) != sourceRef || len(sourceRef) > 128 {
		return SourceBinding{}, inspectionadapter.ErrBindingStale
	}
	return SourceBinding{SourceRef: sourceRef, CameraID: camera.ID, IdentityFingerprint: fingerprint, DeviceIdentitySHA256: deviceIdentityDigest(snapshot)}, nil
}

// BindConnectionSource additionally pins the explicit admission generation.
// The physical device and source may be identical after an A-to-B-to-A switch.
func BindConnectionSource(connection session.InspectionConnection, camera device.Camera, sourceRef string) (SourceBinding, error) {
	binding, err := BindSource(connection.Snapshot(), camera, sourceRef)
	if err != nil {
		return SourceBinding{}, err
	}
	binding.ConnectionEpoch = connectionEpoch(connection)
	return binding, nil
}

// NewVaultConnectionsForSource uses one immutable source binding. Each operation
// reacquires the same shared Vault and verifies the camera's current identity.
// NewVaultConnections preserves the legacy default selection instead.
func NewVaultConnectionsForSource(vault *session.Vault, source SourceBinding, options ...ConnectionOption) (inspectionadapter.ConnectionProvider, error) {
	if vault == nil || source.SourceRef == "" || strings.TrimSpace(source.SourceRef) != source.SourceRef || len(source.SourceRef) > 128 || source.CameraID == "" || !digestPattern.MatchString(source.IdentityFingerprint) || source.DeviceIdentitySHA256 != "" && !digestPattern.MatchString(source.DeviceIdentitySHA256) || source.ConnectionEpoch != "" && !digestPattern.MatchString(source.ConnectionEpoch) {
		return nil, errors.New("live vision source binding is invalid")
	}
	p := &vaultConnections{vault: vault, now: time.Now, source: &source, tasks: make(map[string]*temporaryPictureTask)}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("live vision option is invalid")
		}
		if err := option(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func NewTemporaryAcquirer(connections inspectionadapter.ConnectionProvider) mediaprep.Acquirer {
	return newLiveTemporaryAcquirer(connections)
}
func NewTemporaryAnalyzer(connections inspectionadapter.ConnectionProvider) temporary.Analyzer {
	return liveTemporaryAnalyzer{connections: connections}
}
func NewTemporaryMediaReader(store *media.Store) temporary.MediaReader {
	return temporaryMediaReader{store: store}
}

func (p *vaultConnections) sourceRef() string {
	if p != nil && p.source != nil {
		return p.source.SourceRef
	}
	return SourceHandle
}
func (p *vaultConnections) matchesSource(camera device.Camera, fingerprint string) bool {
	return p.source == nil || (p.source.CameraID == camera.ID && p.source.IdentityFingerprint == fingerprint)
}
func (p *vaultConnections) selectCamera(snapshot device.Snapshot) (device.Camera, bool) {
	if p.source == nil {
		return SelectCamera(snapshot)
	}
	camera, _, ok := currentCamera(snapshot, p.source.CameraID, p.source.IdentityFingerprint)
	return camera, ok
}
