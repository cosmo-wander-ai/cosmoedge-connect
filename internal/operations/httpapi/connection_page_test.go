package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectionPageRequiresAuthorityAndOnlyReportsDispatch(t *testing.T) {
	for _, test := range []struct {
		name, origin, bearer, session, candidate, body string
		expired, openFailure                           bool
		wantStatus, wantOpens                          int
	}{
		{name: "valid", wantStatus: 200, wantOpens: 1},
		{name: "cross origin", origin: "https://example.invalid", wantStatus: 403},
		{name: "bad bearer", bearer: "wrong", wantStatus: 401},
		{name: "missing session", session: "missing", wantStatus: 403},
		{name: "bad session", session: "tampered", wantStatus: 403},
		{name: "expired session", expired: true, wantStatus: 403},
		{name: "candidate mismatch", candidate: strings.Repeat("0", 64), wantStatus: 409},
		{name: "invalid body", body: `{"endpoint":"must-not-be-used"}`, wantStatus: 400},
		{name: "launcher failed", openFailure: true, wantStatus: 503, wantOpens: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := strings.Repeat("a", 64)
			digest := sha256.Sum256([]byte(token))
			now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
			connection := &unavailableConnection{}
			opens := 0
			h, err := New(Config{TokenDigest: hex.EncodeToString(digest[:]), Connections: connection,
				Now: func() time.Time { return now }, OpenConnection: func() error {
					opens++
					if test.openFailure {
						return errors.New("private launcher failure")
					}
					return nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+Prefix+"session", strings.NewReader("{}"))
			request.Header.Set("Authorization", "Bearer "+token)
			issued := httptest.NewRecorder()
			h.ServeHTTP(issued, request)
			var data struct{ SessionRef string }
			if err := json.Unmarshal(issued.Body.Bytes(), &data); err != nil || data.SessionRef == "" {
				t.Fatal("session issuance failed", err)
			}
			if test.session == "missing" {
				data.SessionRef = ""
			} else if test.session == "tampered" {
				data.SessionRef += "x"
			}
			if test.expired {
				now = now.Add(8 * 24 * time.Hour)
			}
			body := test.body
			if body == "" {
				body = "{}"
			}
			request = httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+Prefix+"connection", strings.NewReader(body))
			if test.bearer != "" {
				token = test.bearer
			}
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("X-CosmoEdge-Session", data.SessionRef)
			if test.candidate != "" {
				request.Header.Set("X-CosmoEdge-Candidate", test.candidate)
			}
			request.Header.Set("Origin", test.origin)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != test.wantStatus || opens != test.wantOpens || connection.reads != 0 {
				t.Fatalf("status=%d opens=%d device reads=%d", response.Code, opens, connection.reads)
			}
			var result map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if test.wantStatus == http.StatusOK {
				if result["ok"] != true || result["pageState"] != "dispatched" || result["interactionRequired"] != true || result["supportedInteraction"] != "connection_only" {
					t.Fatalf("incorrect dispatch receipt: %v", result)
				}
				for _, key := range []string{"rendered", "connected", "pending", "pollPath", "pageOpened"} {
					if _, exists := result[key]; exists {
						t.Fatalf("dispatch receipt claims %s", key)
					}
				}
			} else if result["ok"] != false || result["pageState"] != nil {
				t.Fatal("failed request claimed successful page dispatch")
			}
			if strings.Contains(response.Body.String(), "private launcher") {
				t.Fatal("private launcher error leaked")
			}
		})
	}
}
