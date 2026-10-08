package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

type unavailableConnection struct{ reads int }

func (c *unavailableConnection) InspectionConnection(context.Context) (session.InspectionConnection, error) {
	c.reads++
	return session.InspectionConnection{}, errors.New("private endpoint unavailable")
}
func TestSessionScopeAndTransportFailClosed(t *testing.T) {
	token := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(token))
	now := time.Now()
	connection := &unavailableConnection{}
	h, err := New(Config{TokenDigest: hex.EncodeToString(sum[:]), Connections: connection, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, ref, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:37789"+Prefix+path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-CosmoEdge-Session", ref)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	first, second := call("session", "", ""), call("session", "", "")
	var a, b struct {
		SessionRef string `json:"sessionRef"`
		ServerTime string `json:"serverTime"`
	}
	json.Unmarshal(first.Body.Bytes(), &a)
	json.Unmarshal(second.Body.Bytes(), &b)
	if first.Code != 200 || a.SessionRef == "" || a.SessionRef == b.SessionRef {
		t.Fatal("new conversations did not receive distinct capabilities")
	}
	if a.ServerTime != now.UTC().Format(time.RFC3339) {
		t.Fatal("conversation lacks the service clock for interpreting calendar dates")
	}
	if !h.validSession(a.SessionRef) || !h.validSession(b.SessionRef) {
		t.Fatal("issued capability invalid")
	}
	if w := call("connection", a.SessionRef, "https://example.invalid"); w.Code != 403 {
		t.Fatal("cross-origin accepted")
	}
	if w := call("connection", a.SessionRef[:len(a.SessionRef)-1]+"z", ""); w.Code != 403 {
		t.Fatal("tampered session accepted")
	}
	now = now.Add(8 * 24 * time.Hour)
	if h.validSession(a.SessionRef) {
		t.Fatal("expired session accepted")
	}
	if connection.reads != 0 {
		t.Fatal("rejected input reached device")
	}
}

// Relative-date queries in long-lived MCP connections need a fresh clock
// without creating a new business context or touching the device.
func TestVersionRefreshesServerClockWithoutDeviceRead(t *testing.T) {
	token := strings.Repeat("a", 64)
	digest := sha256.Sum256([]byte(token))
	now := time.Date(2026, 9, 28, 15, 59, 59, 0, time.UTC)
	connection := &unavailableConnection{}
	h, err := New(Config{TokenDigest: hex.EncodeToString(digest[:]), Connections: connection, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "http://127.0.0.1"+Prefix+"version", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var data struct {
			ServerTime string `json:"serverTime"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || data.ServerTime != now.Format(time.RFC3339) {
			t.Fatal("version did not return fresh service clock", w.Code)
		}
		now = now.Add(2 * time.Second)
	}
	if connection.reads != 0 {
		t.Fatal("clock refresh touched device")
	}
}

func TestInvalidSummaryDoesNotReachDeviceOrLeakError(t *testing.T) {
	token := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(token))
	connection := &unavailableConnection{}
	h, _ := New(Config{TokenDigest: hex.EncodeToString(sum[:]), Connections: connection})
	// Use the public issuance route rather than forging a test capability.
	r := httptest.NewRequest("POST", "http://127.0.0.1"+Prefix+"session", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var issued struct {
		SessionRef string `json:"sessionRef"`
	}
	json.Unmarshal(w.Body.Bytes(), &issued)
	data := issued.SessionRef
	for _, body := range []string{`{}`, `{"start":"bad"}`, `{"unexpected":"value"}`, `{} {}`} {
		r := httptest.NewRequest("POST", "http://127.0.0.1"+Prefix+"summary", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-CosmoEdge-Session", data)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || strings.Contains(w.Body.String(), "private endpoint") {
			t.Fatal("invalid request response", w.Code, w.Body.String())
		}
	}
	if connection.reads != 0 {
		t.Fatal("invalid summary reached device")
	}
}

func TestCandidatePinRejectsUpgradeRaceBeforeDispatch(t *testing.T) {
	token := strings.Repeat("a", 64)
	digest := sha256.Sum256([]byte(token))
	connection := &unavailableConnection{}
	h, err := New(Config{TokenDigest: hex.EncodeToString(digest[:]), Connections: connection})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"version", "session", "catalog", "captures", "deployments", "media/example"} {
		method := "GET"
		if path == "session" || path == "captures" || path == "deployments" {
			method = "POST"
		}
		r := httptest.NewRequest(method, "http://127.0.0.1"+Prefix+path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-CosmoEdge-Candidate", strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "candidate_mismatch") {
			t.Fatalf("%s accepted stale adapter: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1"+Prefix+"version", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-CosmoEdge-Candidate", buildinfo.Current().PairingKey())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), buildinfo.Current().PairingKey()) {
		t.Fatal("matching adapter was not accepted")
	}
	if connection.reads != 0 {
		t.Fatal("mismatched candidate reached device")
	}
}
