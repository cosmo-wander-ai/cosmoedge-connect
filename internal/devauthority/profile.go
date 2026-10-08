package devauthority

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const (
	profileVersion            = "cosmoedge-dev-authority/v1"
	profileFilename           = "authority.json"
	ActionRead                = "read"
	ActionTaskSwitchRoundTrip = "task_switch_roundtrip"
)

type Profile struct {
	Version           string    `json:"version"`
	Endpoint          string    `json:"endpoint"`
	Username          string    `json:"username"`
	DeviceFingerprint string    `json:"deviceFingerprint"`
	DeviceHint        string    `json:"deviceHint"`
	DeviceType        string    `json:"deviceType"`
	AllowedActions    []string  `json:"allowedActions"`
	EncryptedPassword string    `json:"encryptedPassword"`
	CreatedAt         time.Time `json:"createdAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

type Store struct {
	root string
}

func NewStore(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = DefaultRoot()
		if err != nil {
			return nil, err
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Store{root: filepath.Clean(root)}, nil
}

func DefaultRoot() (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("development device authority is supported only on Windows")
	}
	base := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if base == "" {
		return "", errors.New("LOCALAPPDATA is unavailable")
	}
	return filepath.Join(base, "CosmoEdge", "DevAuthority"), nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) Path() string { return filepath.Join(s.root, profileFilename) }

func (s *Store) Save(profile Profile) error {
	if err := validateProfile(profile, time.Time{}); err != nil {
		return err
	}
	if err := localstate.PrepareStateRoot(s.root); err != nil {
		return err
	}
	path := s.Path()
	if _, err := os.Lstat(path); err == nil {
		if err := localstate.ValidateFile(path); err != nil {
			return fmt.Errorf("reject existing development authority: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.root, "authority-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := localstate.ProtectFile(temporaryPath); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return localstate.ProtectFile(path)
}

func (s *Store) Load(now time.Time) (Profile, error) {
	if err := localstate.ValidateStateRoot(s.root); err != nil {
		return Profile{}, err
	}
	path := s.Path()
	if err := localstate.ValidateFile(path); err != nil {
		return Profile{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	var profile Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return Profile{}, errors.New("development authority is malformed")
	}
	if err := validateProfile(profile, now); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func (s *Store) Revoke() error {
	if _, err := os.Lstat(s.root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := localstate.ValidateStateRoot(s.root); err != nil {
		return err
	}
	path := s.Path()
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := localstate.ValidateFile(path); err != nil {
		return err
	}
	return os.Remove(path)
}

func (p Profile) Allows(action string) bool {
	for _, candidate := range p.AllowedActions {
		if candidate == action {
			return true
		}
	}
	return false
}

func validateProfile(profile Profile, now time.Time) error {
	if profile.Version != profileVersion {
		return errors.New("development authority version is unsupported")
	}
	endpoint, err := session.NormalizeDeviceAddress(profile.Endpoint)
	if err != nil || endpoint.URL != profile.Endpoint {
		return errors.New("development authority endpoint is invalid")
	}
	if strings.TrimSpace(profile.Username) == "" || len(profile.Username) > 256 {
		return errors.New("development authority account is invalid")
	}
	if len(profile.DeviceFingerprint) != sha256.Size*2 {
		return errors.New("development authority device binding is invalid")
	}
	if _, err := hex.DecodeString(profile.DeviceFingerprint); err != nil {
		return errors.New("development authority device binding is invalid")
	}
	if profile.DeviceHint == "" || profile.DeviceType == "" || profile.EncryptedPassword == "" {
		return errors.New("development authority is incomplete")
	}
	if encrypted, err := base64.StdEncoding.DecodeString(profile.EncryptedPassword); err != nil || len(encrypted) == 0 || len(encrypted) > 64<<10 {
		return errors.New("development authority credential envelope is invalid")
	}
	if profile.CreatedAt.IsZero() || profile.ExpiresAt.IsZero() || !profile.CreatedAt.Before(profile.ExpiresAt) {
		return errors.New("development authority lifetime is invalid")
	}
	if !now.IsZero() && !now.Before(profile.ExpiresAt) {
		return errors.New("development authority has expired")
	}
	actions := append([]string(nil), profile.AllowedActions...)
	sort.Strings(actions)
	if len(actions) == 0 || actions[0] != ActionRead {
		return errors.New("development authority read permission is missing")
	}
	for index, action := range actions {
		if action != ActionRead && action != ActionTaskSwitchRoundTrip {
			return errors.New("development authority contains an unsupported action")
		}
		if index > 0 && action == actions[index-1] {
			return errors.New("development authority contains duplicate actions")
		}
	}
	return nil
}

func deviceFingerprint(serial string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(serial)))
	return hex.EncodeToString(sum[:])
}

func maskDevice(serial string) string {
	serial = strings.TrimSpace(serial)
	if len(serial) <= 4 {
		return "***"
	}
	return "***" + serial[len(serial)-4:]
}

func randomID(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
