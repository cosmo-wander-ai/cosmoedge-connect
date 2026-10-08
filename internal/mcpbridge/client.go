// Package mcpbridge adapts CosmoEdge Connect's local operations API to MCP. It never
// connects to a device or owns business-confirmation authority.
package mcpbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const (
	APIVersion = "cosmoedge.mcp.v1"
	apiPrefix  = "/operations/v1/"
	maxJSON    = 512 << 10
	maxImage   = 8 << 20
	maxReport  = 256 << 10
)

var referencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var sessionPattern = regexp.MustCompile(`^[0-9a-f]{32}\.[0-9]+\.[0-9a-f]{64}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Identity struct {
	Product  string `json:"product"`
	Version  string `json:"version"`
	Revision string `json:"revision"`
	Modified bool   `json:"modified"`
	Platform string `json:"platform"`
}

func identity(v buildinfo.Info) Identity {
	return Identity{v.Product, v.Version, v.Revision, v.Modified, v.Platform}
}

type Config struct {
	BaseURL       string
	TokenFile     string
	StateRoot     string
	CandidateFile string
}

type apiClient struct {
	base, token string
	identity    Identity
	http        *http.Client
	serverTime  string
}

func (i Identity) pairingKey() string {
	return (buildinfo.Info{Product: i.Product, Version: i.Version, Revision: i.Revision, Modified: i.Modified, Platform: i.Platform}).PairingKey()
}

// readChecked pins and compares the checked file identity. Private credentials
// require the existing cross-platform current-user permission checks.
func readChecked(path string, limit int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, errors.New("local_file_unavailable")
	}
	if private {
		if err := localstate.ValidateFile(path); err != nil {
			return nil, errors.New("local_file_not_private")
		}
	} else if runtime.GOOS == "windows" {
		if localstate.ValidateFile(path) != nil {
			return nil, errors.New("candidate_acl_unavailable")
		}
	} else if before.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("local_file_writable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("local_file_unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("local_file_changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || int64(len(raw)) > limit || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, errors.New("local_file_changed")
	}
	return raw, nil
}

func newClient(c Config) (*apiClient, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Hostname() == "" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Port() == "" {
		return nil, errors.New("literal_loopback_url_required")
	}
	raw, err := readChecked(c.TokenFile, 4096, true)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("invalid_local_token")
	}
	raw, err = readChecked(c.CandidateFile, 65536, false)
	if err != nil {
		return nil, err
	}
	var candidate map[string]any
	if err := decodeStrict(raw, &candidate); err != nil {
		return nil, errors.New("invalid_candidate")
	}
	var expected Identity
	if json.Unmarshal(raw, &expected) != nil {
		return nil, errors.New("invalid_candidate")
	}
	if expected.Product == "" {
		expected.Product = "cosmoedge-connect"
	}
	if _, ok := candidate["modified"].(bool); !ok || expected.Version == "" || expected.Revision == "" || expected.Platform == "" || expected != identity(buildinfo.Current()) {
		return nil, errors.New("adapter_candidate_mismatch")
	}
	return &apiClient{base: c.BaseURL, token: token, identity: expected, http: &http.Client{
		Timeout:       55 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: 15 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// decodeStrict rejects duplicate keys rather than accepting ambiguous security
// metadata or an alternate request identity through last-key-wins parsing.
func decodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting limit")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				seen := map[string]bool{}
				for dec.More() {
					k, e := dec.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return errors.New("duplicate key")
					}
					seen[key] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for dec.More() {
					if e := walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return errors.New("invalid JSON")
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return json.Unmarshal(raw, out)
}

func (c *apiClient) read(ctx context.Context, session, path string, body any, limit int64) (int, http.Header, []byte, error) {
	if !strings.HasPrefix(path, apiPrefix) || strings.ContainsAny(path, "?#\\") || strings.Contains(path, "..") {
		return 0, nil, nil, errors.New("invalid_service_path")
	}
	method := http.MethodGet
	var reader io.Reader
	if body != nil {
		raw, e := json.Marshal(body)
		if e != nil {
			return 0, nil, nil, errors.New("invalid_request")
		}
		method = http.MethodPost
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, nil, errors.New("invalid_request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-CosmoEdge-Candidate", c.identity.pairingKey())
	if session != "" {
		req.Header.Set("X-CosmoEdge-Session", session)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, errors.New("service_unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return 0, nil, nil, errors.New("service_redirect_rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return 0, nil, nil, errors.New("invalid_service_response")
	}
	return res.StatusCode, res.Header, raw, nil
}

func (c *apiClient) request(ctx context.Context, session, path string, body any) (map[string]any, error) {
	status, header, raw, err := c.read(ctx, session, path, body, maxJSON)
	if err != nil {
		return nil, err
	}
	media, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, errors.New("invalid_service_response")
	}
	var data map[string]any
	if decodeStrict(raw, &data) != nil || data == nil {
		return nil, errors.New("invalid_service_response")
	}
	ok, valid := data["ok"].(bool)
	if !valid || status < 200 || status >= 600 || (status >= 400 && ok) || containsAuthority(data) {
		return nil, errors.New("invalid_service_response")
	}
	return data, nil
}

func containsAuthority(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if k == "confirmationToken" || k == "confirmationReceipt" || k == "token" || k == "password" {
				return true
			}
			if containsAuthority(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if containsAuthority(v) {
				return true
			}
		}
	}
	return false
}

func (c *apiClient) verify(ctx context.Context) error {
	d, err := c.request(ctx, "", apiPrefix+"version", nil)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(d["version"])
	var got Identity
	if d["ok"] != true || d["protocol"] != "cosmoedge.operations.v1" || json.Unmarshal(raw, &got) != nil || got != c.identity || d["candidateKey"] != c.identity.pairingKey() {
		return errors.New("service_candidate_mismatch")
	}
	c.serverTime = ""
	if stamp := stringField(d, "serverTime"); stamp != "" {
		if _, err := time.Parse(time.RFC3339, stamp); err == nil {
			c.serverTime = stamp
		}
	}
	return nil
}

func sha(raw []byte) string { d := sha256.Sum256(raw); return hex.EncodeToString(d[:]) }
