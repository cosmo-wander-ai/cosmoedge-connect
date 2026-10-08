package inspectionfixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const (
	snapshotAssetName  = "scene.jpg"
	clipAssetName      = "scene.mp4"
	clipFrameAssetName = "scene-frame.jpg"
	eventAssetName     = "event.json"
	manifestAssetName  = "manifest.json"
	maxFixtureAsset    = 8 << 20
	fixtureAssetSchema = "cosmoedge.inspection.fixture.assets.v1"
)

var lowercaseToken = regexp.MustCompile(`^[0-9a-f]{64}$`)

type assets struct {
	snapshot        []byte
	clip            []byte
	clipFrame       []byte
	event           []byte
	manifest        []byte
	snapshotWidth   int
	snapshotHeight  int
	clipWidth       int
	clipHeight      int
	clipFrameRate   float64
	clipDuration    int64
	clipFrameOffset int64
}

type assetManifest struct {
	Schema    string             `json:"schema"`
	Snapshot  imageAssetManifest `json:"snapshot"`
	Clip      clipAssetManifest  `json:"clip"`
	ClipFrame frameAssetManifest `json:"clipFrame"`
	Event     eventAssetManifest `json:"event"`
}

type imageAssetManifest struct {
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	MIMEType string `json:"mimeType"`
}

type clipAssetManifest struct {
	File           string  `json:"file"`
	SHA256         string  `json:"sha256"`
	Width          int     `json:"width"`
	Height         int     `json:"height"`
	MIMEType       string  `json:"mimeType"`
	Codec          string  `json:"codec"`
	FrameRate      float64 `json:"frameRate"`
	DurationMillis int64   `json:"durationMillis"`
}

type frameAssetManifest struct {
	File         string `json:"file"`
	SHA256       string `json:"sha256"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	MIMEType     string `json:"mimeType"`
	OffsetMillis int64  `json:"offsetMillis"`
}

type eventAssetManifest struct {
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	MIMEType string `json:"mimeType"`
}

func loadAssets(root string) (assets, error) {
	absolute, err := filepath.Abs(root)
	if err != nil || absolute == string(os.PathSeparator) {
		return assets{}, errors.New("fixture asset root is invalid")
	}
	if err := localstate.ValidateStateRoot(absolute); err != nil {
		return assets{}, errors.Join(errors.New("fixture asset root must be owner-only"), err)
	}
	read := func(name string) ([]byte, error) {
		path := filepath.Join(absolute, name)
		if filepath.Dir(path) != absolute {
			return nil, errors.New("fixture asset path escaped its root")
		}
		if err := localstate.ValidateFile(path); err != nil {
			return nil, errors.Join(errors.New("fixture asset must be an owner-only regular file"), err)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		payload, err := io.ReadAll(io.LimitReader(file, maxFixtureAsset+1))
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 || len(payload) > maxFixtureAsset {
			return nil, errors.New("fixture asset size is outside the allowed bound")
		}
		return payload, nil
	}
	manifestRaw, err := read(manifestAssetName)
	if err != nil {
		return assets{}, err
	}
	var manifest assetManifest
	if err := strictjson.ValidateExactFields(manifestRaw, &manifest, 4); err != nil {
		return assets{}, errors.Join(errors.New("fixture manifest is not exact JSON"), err)
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return assets{}, err
	}
	snapshot, err := read(snapshotAssetName)
	if err != nil {
		return assets{}, err
	}
	clip, err := read(clipAssetName)
	if err != nil {
		return assets{}, err
	}
	clipFrame, err := read(clipFrameAssetName)
	if err != nil {
		return assets{}, err
	}
	event, err := read(eventAssetName)
	if err != nil {
		return assets{}, err
	}
	if err := validateAssetManifest(manifest, snapshot, clip, clipFrame, event); err != nil {
		return assets{}, err
	}
	snapshotConfig, format, err := image.DecodeConfig(bytes.NewReader(snapshot))
	if err != nil || format != "jpeg" || snapshotConfig.Width != manifest.Snapshot.Width || snapshotConfig.Height != manifest.Snapshot.Height {
		return assets{}, errors.New("fixture scene.jpg is not a valid JPEG")
	}
	frameConfig, frameFormat, err := image.DecodeConfig(bytes.NewReader(clipFrame))
	if err != nil || frameFormat != "jpeg" || frameConfig.Width != manifest.ClipFrame.Width || frameConfig.Height != manifest.ClipFrame.Height ||
		frameConfig.Width != manifest.Clip.Width || frameConfig.Height != manifest.Clip.Height {
		return assets{}, errors.New("fixture scene-frame.jpg does not match the clip geometry")
	}
	if len(clip) < 12 || string(clip[4:8]) != "ftyp" {
		return assets{}, errors.New("fixture scene.mp4 is not an MP4 asset")
	}
	trimmed := bytes.TrimSpace(event)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || !json.Valid(trimmed) {
		return assets{}, errors.New("fixture event.json is not a bounded JSON object")
	}
	return assets{
		snapshot: snapshot, clip: clip, clipFrame: clipFrame, event: event, manifest: manifestRaw,
		snapshotWidth: manifest.Snapshot.Width, snapshotHeight: manifest.Snapshot.Height,
		clipWidth: manifest.Clip.Width, clipHeight: manifest.Clip.Height, clipFrameRate: manifest.Clip.FrameRate,
		clipDuration: manifest.Clip.DurationMillis, clipFrameOffset: manifest.ClipFrame.OffsetMillis,
	}, nil
}

func (a assets) validate() error {
	if len(a.snapshot) == 0 || len(a.clip) == 0 || len(a.clipFrame) == 0 || len(a.event) == 0 || len(a.manifest) == 0 ||
		a.snapshotWidth < 1 || a.snapshotHeight < 1 || a.clipWidth < 1 || a.clipHeight < 1 ||
		a.clipFrameRate <= 0 || a.clipDuration < 1 || a.clipFrameOffset < 0 || a.clipFrameOffset > a.clipDuration {
		return errors.New("fixture asset set is incomplete")
	}
	return nil
}

func validateAssetManifest(manifest assetManifest, snapshot, clip, clipFrame, event []byte) error {
	validDigest := func(value string) bool { return lowercaseToken.MatchString(value) }
	if manifest.Schema != fixtureAssetSchema ||
		manifest.Snapshot.File != snapshotAssetName || manifest.Snapshot.MIMEType != "image/jpeg" || !validDigest(manifest.Snapshot.SHA256) ||
		manifest.Clip.File != clipAssetName || manifest.Clip.MIMEType != "video/mp4" || manifest.Clip.Codec != "h264" || !validDigest(manifest.Clip.SHA256) ||
		manifest.ClipFrame.File != clipFrameAssetName || manifest.ClipFrame.MIMEType != "image/jpeg" || !validDigest(manifest.ClipFrame.SHA256) ||
		manifest.Event.File != eventAssetName || manifest.Event.MIMEType != "application/json" || !validDigest(manifest.Event.SHA256) {
		return errors.New("fixture manifest contract is invalid")
	}
	if manifest.Snapshot.Width < 1 || manifest.Snapshot.Width > 8192 || manifest.Snapshot.Height < 1 || manifest.Snapshot.Height > 8192 ||
		manifest.Clip.Width < 1 || manifest.Clip.Width > 8192 || manifest.Clip.Height < 1 || manifest.Clip.Height > 8192 ||
		manifest.ClipFrame.Width < 1 || manifest.ClipFrame.Width > 8192 || manifest.ClipFrame.Height < 1 || manifest.ClipFrame.Height > 8192 ||
		manifest.Clip.FrameRate <= 0 || manifest.Clip.FrameRate > 240 || manifest.Clip.DurationMillis < 1 || manifest.Clip.DurationMillis > 60_000 || manifest.Clip.DurationMillis%1000 != 0 ||
		manifest.ClipFrame.OffsetMillis < 0 || manifest.ClipFrame.OffsetMillis > manifest.Clip.DurationMillis {
		return errors.New("fixture manifest media metadata is outside its bounds")
	}
	for _, item := range []struct {
		payload []byte
		sha256  string
	}{{snapshot, manifest.Snapshot.SHA256}, {clip, manifest.Clip.SHA256}, {clipFrame, manifest.ClipFrame.SHA256}, {event, manifest.Event.SHA256}} {
		if digest(string(item.payload)) != item.sha256 {
			return errors.New("fixture asset digest does not match its manifest")
		}
	}
	return nil
}

type tokenMaterial struct {
	digest        string
	credentialKey []byte
}

func readTokenMaterial(path string) (tokenMaterial, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || absolute == string(os.PathSeparator) {
		return tokenMaterial{}, errors.New("fixture token path is invalid")
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		return tokenMaterial{}, errors.Join(errors.New("fixture token must be owner-only"), err)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return tokenMaterial{}, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 66))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		clear(raw)
		return tokenMaterial{}, errors.Join(readErr, closeErr)
	}
	if len(raw) == 65 && raw[64] == '\n' {
		raw = raw[:64]
	}
	if len(raw) != 64 || !lowercaseToken.Match(raw) {
		clear(raw)
		return tokenMaterial{}, errors.New("fixture token file must contain exactly 64 lowercase hexadecimal characters")
	}
	if err := validateTokenEntropy(raw); err != nil {
		clear(raw)
		return tokenMaterial{}, err
	}
	digestBytes := sha256.Sum256(raw)
	credentialInput := make([]byte, 0, len("cosmoedge.fixture.credentials.v1\x00")+len(raw))
	credentialInput = append(credentialInput, []byte("cosmoedge.fixture.credentials.v1\x00")...)
	credentialInput = append(credentialInput, raw...)
	credentialKey := sha256.Sum256(credentialInput)
	clear(credentialInput)
	clear(raw)
	return tokenMaterial{
		digest: hex.EncodeToString(digestBytes[:]), credentialKey: append([]byte(nil), credentialKey[:]...),
	}, nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
