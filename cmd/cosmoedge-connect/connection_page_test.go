package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestOperationsConnectionDispatchesDedicatedConnectionView(t *testing.T) {
	parent := t.TempDir()
	token := strings.Repeat("a", 64)
	tokenFile := filepath.Join(parent, "access.token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(tokenFile); err != nil {
		t.Fatal(err)
	}
	var opened []string
	p := &provider{
		config: config{stateRoot: filepath.Join(parent, "private-state"), tokenFile: tokenFile},
		vault:  session.New(nil), opener: func(raw string) error { opened = append(opened, raw); return nil },
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	})
	handler, err := p.Handler()
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, ref string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:37789/operations/v1/"+path, strings.NewReader("{}"))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-CosmoEdge-Session", ref)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	var issued struct{ SessionRef string }
	if err := json.Unmarshal(call("session", "").Body.Bytes(), &issued); err != nil || issued.SessionRef == "" {
		t.Fatal("session issuance failed", err)
	}
	response := call("connection", issued.SessionRef)
	if response.Code != http.StatusOK || len(opened) != 1 {
		t.Fatalf("connection status=%d opens=%d", response.Code, len(opened))
	}
	location, err := url.Parse(opened[0])
	if err != nil || location.Hostname() != "127.0.0.1" {
		t.Fatal("page was not dispatched to a local browser URL")
	}
	auth, err := p.vault.ConsumeBootstrap(location.Query().Get("bootstrap"))
	if err != nil || auth.View != session.ViewConnection {
		t.Fatalf("operations dispatched view=%q err=%v", auth.View, err)
	}
	if _, _, connected := p.vault.ConnectedIdentity(); connected {
		t.Fatal("opening the page changed the device connection")
	}
}
