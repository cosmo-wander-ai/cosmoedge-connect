package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

type mockService struct {
	mu               sync.Mutex
	version          buildinfo.Info
	sessions         map[string]bool
	operations       map[string]map[string]any
	owners           map[string]string
	image            []byte
	captures, writes int
}

func digest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func newMock(ctx context.Context, executable string) (*mockService, []string, func(), error) {
	raw, err := exec.CommandContext(ctx, executable, "--version-json").Output()
	if err != nil {
		return nil, nil, nil, errors.New("cannot read adapter identity")
	}
	var version buildinfo.Info
	if json.Unmarshal(raw, &version) != nil || version.Revision == "" {
		return nil, nil, nil, errors.New("adapter must have a source identity; use the paired build flags")
	}
	root, err := os.MkdirTemp("", "cosmoedge-mcp-example-")
	if err != nil {
		return nil, nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	private := filepath.Join(root, "private")
	if err = localstate.PrepareStateRoot(private); err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	token := filepath.Join(private, "access.token")
	candidate := filepath.Join(private, "candidate.json")
	for path, data := range map[string][]byte{token: []byte(strings.Repeat("b", 64)), candidate: raw} {
		if err = os.WriteFile(path, data, 0600); err == nil {
			err = localstate.ProtectFile(path)
		}
		if err != nil {
			cleanup()
			return nil, nil, nil, err
		}
	}
	pic, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j5V8AAAAASUVORK5CYII=")
	f := &mockService{version: version, sessions: map[string]bool{}, operations: map[string]map[string]any{}, owners: map[string]string{}, image: pic}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	return f, []string{"--base-url", server.URL, "--token-file", token, "--candidate-file", candidate, "--state-root", filepath.Join(private, "journal")}, func() { server.Close(); cleanup() }, nil
}
func (f *mockService) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) || r.Header.Get("X-CosmoEdge-Candidate") != f.version.PairingKey() {
		w.WriteHeader(403)
		reply(map[string]any{"ok": false, "code": "unauthorized"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/operations/v1/")
	if path == "version" {
		reply(map[string]any{"ok": true, "protocol": "cosmoedge.operations.v1", "version": f.version, "candidateKey": f.version.PairingKey(), "serverTime": time.Now().UTC().Format(time.RFC3339)})
		return
	}
	if path == "session" {
		session := fmt.Sprintf("%032x.%d.%s", len(f.sessions)+1, time.Now().Unix(), strings.Repeat("c", 64))
		f.sessions[session] = true
		reply(map[string]any{"ok": true, "sessionRef": session, "serverTime": time.Now().UTC().Format(time.RFC3339)})
		return
	}
	owner := r.Header.Get("X-CosmoEdge-Session")
	if !f.sessions[owner] {
		w.WriteHeader(403)
		reply(map[string]any{"ok": false, "code": "session_required"})
		return
	}
	var input map[string]any
	if r.Method == "POST" {
		_ = json.NewDecoder(r.Body).Decode(&input)
	}
	switch path {
	case "captures":
		f.captures++
		id, _ := input["requestId"].(string)
		ref := "capture_" + id
		media := "media_" + id
		data := map[string]any{"ok": true, "operationRef": ref, "requestId": id, "pending": false, "observation": map[string]any{"kind": "capture", "status": "captured", "sourceName": "Synthetic Gate", "frameTimeKnown": false}, "attachments": []any{map[string]any{"mediaRef": media, "path": "/operations/v1/media/" + media, "contentType": "image/png", "sha256": digest(f.image), "sizeBytes": len(f.image)}}}
		f.operations[ref] = data
		f.owners[ref] = owner
		f.owners[media] = owner
		reply(data)
		return
	case "summary":
		report := "# Synthetic retained alarms\n\n3 records.\n"
		reply(map[string]any{"ok": true, "summary": map[string]any{"count": 3}, "userMessage": report, "summaryReport": map[string]any{"schemaVersion": 1, "contentType": "text/markdown; charset=utf-8", "sha256": digest([]byte(report)), "sizeBytes": len(report), "candidate": f.version, "headline": "Three synthetic retained alarms."}})
		return
	case "deployments":
		id, _ := input["requestId"].(string)
		ref := "deployment_" + id
		data := map[string]any{"ok": true, "operationRef": ref, "requestId": id, "proposal": map[string]any{"state": "proposed", "sourceName": "Synthetic Gate", "algorithmName": "Synthetic People"}, "confirmationMode": "local_page", "interactionRequired": true, "supportedInteraction": "deployment_confirmation"}
		f.operations[ref] = data
		f.owners[ref] = owner
		reply(data)
		return
	case "deployments/review", "deployments/cancel":
		ref, _ := input["operationRef"].(string)
		if f.owners[ref] != owner {
			break
		}
		if path == "deployments/review" {
			reply(map[string]any{"ok": true, "operationRef": ref, "interactionRequired": true, "confirmationMode": "local_page", "supportedInteraction": "deployment_confirmation", "pageOpened": true})
			return
		}
		reply(map[string]any{"ok": true, "operationRef": ref, "cancelled": true, "deployment": map[string]any{"state": "blocked", "class": "blocked", "reason": "cancelled_by_user", "dispatches": 0, "deviceWrites": 0}})
		return
	case "deployments/confirm":
		f.writes++
		w.WriteHeader(409)
		reply(map[string]any{"ok": false, "code": "forbidden"})
		return
	}
	if strings.HasPrefix(path, "media/") && f.owners[strings.TrimPrefix(path, "media/")] == owner {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Content-SHA256", digest(f.image))
		_, _ = w.Write(f.image)
		return
	}
	for ref, data := range f.operations {
		if f.owners[ref] == owner && (path == "observations/"+ref || path == "deployments/"+ref) {
			reply(data)
			return
		}
	}
	w.WriteHeader(404)
	reply(map[string]any{"ok": false, "code": "operation_not_found"})
}
