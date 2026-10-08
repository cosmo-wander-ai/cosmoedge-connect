package connectionowner

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectiondiagnostic"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

// Exercise the real encrypted owner -> registry -> Vault -> V1 client chain.
// The injected factory redirects only these synthetic private bindings to a
// local test server. No device address or credential comes from live state.
func TestRestoreDiagnosticsThroughEncryptedOwnerAndV1Client(t *testing.T) {
	for _, scenario := range []struct {
		name, stage, class string
		mode               int32
	}{
		{"success", "commit", "ok", 0},
		{"login throttle", "login", "login_throttled", 1},
		{"login malformed", "login", "response_invalid", 2},
		{"read malformed", "device_read", "response_invalid", 3},
		{"identity drift", "commit", "identity_mismatch", 4},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var mode, loginCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/gtw/cwai/login/DoLogin":
					loginCalls.Add(1)
					var request map[string]string
					if json.NewDecoder(r.Body).Decode(&request) != nil || request["account"] != "operator" || request["pwd"] != fmt.Sprintf("%X", md5.Sum([]byte("synthetic-owner-secret"))) {
						t.Error("persisted secret did not survive until real adapter login")
						http.Error(w, "invalid synthetic login", http.StatusUnauthorized)
						return
					}
					if mode.Load() == 1 {
						fmt.Fprint(w, `{"resCode":2,"resMsg":[{"msgCode":"10009","msgText":"private-response-token"}]}`)
					} else if mode.Load() == 2 {
						fmt.Fprint(w, `private-response-token`)
					} else {
						fmt.Fprint(w, `{"resCode":1,"resData":{"mtk":"private-response-token"}}`)
					}
				case "/gtw/cwai/System/QueryDeviceInfo":
					if mode.Load() == 3 {
						fmt.Fprint(w, `private-response-token`)
					} else if mode.Load() == 4 {
						fmt.Fprint(w, `{"resCode":1,"resData":{"deviceSn":"private-other-serial","productModel":"test-box"}}`)
					} else {
						fmt.Fprint(w, `{"resCode":1,"resData":{"deviceSn":"private-original-serial","productModel":"test-box"}}`)
					}
				case "/gtw/cwai/Camera/Page", "/gtw/cwai/Algorithm/Page", "/gtw/cwai/atomic/Model/Page", "/gtw/cwai/algorithm/layout/list", "/gtw/cwai/System/QueryHardwareResource":
					fmt.Fprint(w, `{"resCode":1,"resData":{"total":0,"rows":[]}}`)
				default:
					t.Error("unexpected test device operation")
					http.Error(w, "unexpected", http.StatusNotFound)
				}
			}))
			defer server.Close()
			root := t.TempDir()
			vault := session.New(func(endpoint, username, password string) device.Client {
				if endpoint != "http://10.20.30.40:8000" {
					t.Fatal("unexpected synthetic binding")
				}
				return device.NewV1Client(server.URL, username, password)
			})
			owner, err := New(Config{StateRoot: filepath.Join(root, "state"), TokenFile: writeTestToken(t, root), Vault: vault})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Stop()
			if _, err = owner.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			connectOwnerVault(t, vault)
			if err = owner.Stop(); err != nil {
				t.Fatal(err)
			}
			mode.Store(scenario.mode)
			var output bytes.Buffer
			ctx := connectiondiagnostic.WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&output, nil)))
			state, err := owner.Start(ctx)
			wantState := connectionregistry.RestoreNeedsAttention
			if scenario.mode == 0 {
				wantState = connectionregistry.RestoreConnected
			}
			if err != nil || state != wantState {
				t.Fatalf("restore=%s error=%v", state, err)
			}
			var stages []string
			for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
				var event map[string]any
				if err = json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatal(err)
				}
				stages = append(stages, event["stage"].(string)+":"+event["class"].(string))
			}
			want := []string{"selection:ok", "credential_read:ok"}
			if scenario.stage != "login" {
				want = append(want, "login:ok")
			}
			if scenario.stage == "commit" {
				want = append(want, "device_read:ok")
			}
			want = append(want, scenario.stage+":"+scenario.class)
			if scenario.mode == 0 {
				want = append(want, "total:ok")
			} else {
				want = append(want, "total:needs_attention")
			}
			if !reflect.DeepEqual(stages, want) {
				t.Fatalf("stages=%v want=%v", stages, want)
			}
			for _, secret := range []string{"synthetic-owner-secret", "private-response-token", "private-original-serial", "private-other-serial", "10.20.30.40", server.URL} {
				if strings.Contains(output.String(), secret) {
					t.Fatal("protected material escaped startup diagnostics")
				}
			}
			if scenario.mode != 4 {
				if err = owner.VerifyCurrent(context.Background()); err != nil {
					t.Fatal("non-identity failure damaged saved profile or credential")
				}
				if err = owner.Stop(); err != nil {
					t.Fatal(err)
				}
				mode.Store(0)
				if state, err = owner.Start(ctx); err != nil || state != connectionregistry.RestoreConnected {
					t.Fatalf("fresh startup did not automatically recover: %s %v", state, err)
				}
				if loginCalls.Load() != 3 {
					t.Fatal("restore unexpectedly retried or omitted a fresh login")
				}
			}
		})
	}
}
