package agentcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

var (
	conversationAssertionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern                = regexp.MustCompile(`^[0-9a-f]{64}$`)
	publicRefPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type clientConfig struct {
	Endpoint                    string `json:"endpoint"`
	TokenFile                   string `json:"tokenFile"`
	ConversationAssertionSHA256 string `json:"conversationAssertionSha256"`
	InspectWaitMillis           int    `json:"inspectWaitMillis,omitempty"`
	ContinueWaitMillis          int    `json:"continueWaitMillis,omitempty"`
}

func loadClientConfig() (clientConfig, error) {
	stateRoot, err := localstate.DefaultStateRoot()
	if err != nil {
		return clientConfig{}, err
	}
	root := filepath.Join(stateRoot, "codex-inspection")
	if err := localstate.ValidateStateRoot(root); err != nil {
		return clientConfig{}, err
	}
	path := filepath.Join(root, "client.json")
	if err := localstate.ValidateFile(path); err != nil {
		return clientConfig{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 16<<10 {
		return clientConfig{}, errors.New("inspection client configuration is unavailable")
	}
	var config clientConfig
	if strictjson.ValidateExactFields(raw, &config, 2) != nil || json.Unmarshal(raw, &config) != nil {
		return clientConfig{}, errors.New("inspection client configuration is invalid")
	}
	if config.InspectWaitMillis == 0 {
		config.InspectWaitMillis = 10_000
	}
	if config.ContinueWaitMillis == 0 {
		config.ContinueWaitMillis = 20_000
	}
	if config.validate() != nil {
		return clientConfig{}, errors.New("inspection client configuration is invalid")
	}
	return config, nil
}

func (c clientConfig) validate() error {
	parsed, err := url.Parse(c.Endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
		return errors.New("inspection Product endpoint is invalid")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || port == "0" || port == "" {
		return errors.New("inspection Product endpoint is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || host != ip.String() {
		return errors.New("inspection Product endpoint must be literal loopback")
	}
	if !filepath.IsAbs(c.TokenFile) || strings.ContainsRune(c.TokenFile, '\x00') || !digestPattern.MatchString(c.ConversationAssertionSHA256) ||
		c.InspectWaitMillis < 1 || c.InspectWaitMillis > 10_000 {
		return errors.New("inspection client binding is invalid")
	}
	if c.ContinueWaitMillis < 1 || c.ContinueWaitMillis > 20_000 {
		return errors.New("inspection client binding is invalid")
	}
	return nil
}

func (c clientConfig) authorizeConversation(assertion string) error {
	if !conversationAssertionPattern.MatchString(assertion) {
		return errors.New("trusted conversation assertion is unavailable")
	}
	digest := sha256.Sum256([]byte(assertion))
	if hex.EncodeToString(digest[:]) != c.ConversationAssertionSHA256 {
		return errors.New("trusted conversation assertion does not match the provisioned binding")
	}
	return nil
}
