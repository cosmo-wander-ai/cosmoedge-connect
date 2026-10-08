package mcpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMain(m *testing.M) {
	buildinfo.Version = "mcp-test"
	buildinfo.SourceRevision = strings.Repeat("a", 40)
	buildinfo.SourceModified = "false"
	os.Exit(m.Run())
}

type fakeOperation struct{ owner, id, ref, kind, state string }
type fixture struct {
	mu               sync.Mutex
	server           *httptest.Server
	identity         Identity
	sessions         map[string]bool
	ops              map[string]*fakeOperation
	posts            map[string]int
	gets             map[string]int
	image            []byte
	dropCapture      bool
	corruptImage     bool
	corruptReport    bool
	wrongBinding     bool
	rejectCapture    bool
	rejectConnection bool
	dropConnection   bool
	connectionReply  map[string]any
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pic, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j5V8AAAAASUVORK5CYII=")
	f := &fixture{identity: identity(buildinfo.Current()), sessions: map[string]bool{}, ops: map[string]*fakeOperation{}, posts: map[string]int{}, gets: map[string]int{}, image: pic}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(data any) { _ = json.NewEncoder(w).Encode(data) }
	if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
		w.WriteHeader(401)
		write(map[string]any{"ok": false, "code": "unauthenticated"})
		return
	}
	if r.Header.Get("X-CosmoEdge-Candidate") != f.identity.pairingKey() {
		w.WriteHeader(409)
		write(map[string]any{"ok": false, "code": "candidate_mismatch"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, apiPrefix)
	if r.Method == "POST" {
		f.posts[path]++
	} else {
		f.gets[path]++
	}
	if path == "version" {
		write(map[string]any{"ok": true, "protocol": "cosmoedge.operations.v1", "version": f.identity, "candidateKey": f.identity.pairingKey(), "serverTime": "2026-09-28T05:06:07Z"})
		return
	}
	if path == "session" {
		s := fmt.Sprintf("%032x.%d.%s", len(f.sessions)+1, time.Now().Unix(), strings.Repeat("c", 64))
		f.sessions[s] = true
		write(map[string]any{"ok": true, "sessionRef": s, "serverTime": time.Now().UTC().Format(time.RFC3339), "binding": "desktop_conversation_capability"})
		return
	}
	owner := r.Header.Get("X-CosmoEdge-Session")
	if !f.sessions[owner] {
		w.WriteHeader(403)
		write(map[string]any{"ok": false, "code": "session_required"})
		return
	}
	var in map[string]any
	if r.Method == "POST" {
		_ = json.NewDecoder(r.Body).Decode(&in)
	}
	switch path {
	case "catalog":
		write(map[string]any{"ok": true, "sources": []any{map[string]any{"name": "Gate", "sourceRef": "source_gate", "kind": "network_camera"}}, "algorithms": []any{map[string]any{"name": "People"}}, "tasks": []any{}, "totals": map[string]any{"sourceCount": 1, "sourcesByKind": map[string]int{"network_camera": 1, "test_video": 0, "usb_camera": 0, "unknown": 0}, "algorithmCount": 1, "taskCount": 0, "runningTaskCount": 0, "stoppedTaskCount": 0, "unknownRuntimeTaskCount": 0}, "userMessage": "Current directory."})
		return
	case "connection":
		if f.connectionReply != nil {
			write(f.connectionReply)
			return
		}
		if f.dropConnection {
			f.dropConnection = false
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		if f.rejectConnection {
			write(map[string]any{"ok": false, "code": "page_open_failed", "interactionRequired": true, "supportedInteraction": "connection_only"})
			return
		}
		write(map[string]any{"ok": true, "pageState": "dispatched", "interactionRequired": true, "supportedInteraction": "connection_only", "userMessage": "Local connection page dispatched."})
		return
	case "summary":
		if _, single := in["sourceName"]; single {
			if _, multi := in["sourceNames"]; multi {
				w.WriteHeader(400)
				write(map[string]any{"ok": false, "code": "conflicting_source_filters"})
				return
			}
		}
		report := "# Retained alarms\n\nGate: 3\n"
		digest := sha([]byte(report))
		if f.corruptReport {
			digest = strings.Repeat("0", 64)
		}
		write(map[string]any{"ok": true, "summary": map[string]any{"count": 3, "coverage": map[string]any{"retrievalComplete": false}}, "partial": true, "userMessage": report, "summaryReport": map[string]any{"schemaVersion": 1, "contentType": "text/markdown; charset=utf-8", "sizeBytes": len(report), "sha256": digest, "candidate": f.identity, "headline": "Read 3 retained alarms; incomplete coverage.", "filters": map[string]string{"sourceName": "Gate", "algorithmName": ""}}})
		return
	case "captures", "deployments":
		if path == "captures" && f.rejectCapture {
			w.WriteHeader(400)
			write(map[string]any{"ok": false, "code": "invalid_observation", "userMessage": "Refused before capture."})
			return
		}
		id, _ := in["requestId"].(string)
		key := owner + "/" + id
		op := f.ops[key]
		if op == nil {
			kind := "observation"
			state := "captured"
			if path == "deployments" {
				kind = "deployment"
				state = "proposed"
			}
			op = &fakeOperation{owner, id, "svc_" + id, kind, state}
			f.ops[key] = op
		}
		if path == "captures" && f.dropCapture {
			f.dropCapture = false
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		write(f.receipt(op))
		return
	case "deployments/review":
		for _, op := range f.ops {
			if op.owner == owner && op.ref == in["operationRef"] {
				write(map[string]any{"ok": true, "interactionRequired": true, "operationRef": op.ref, "confirmationMode": "local_page", "supportedInteraction": "deployment_confirmation", "pageOpened": true, "userMessage": "Review opened."})
				return
			}
		}
	case "deployments/cancel":
		for _, op := range f.ops {
			if op.owner == owner && op.ref == in["operationRef"] {
				op.state = "blocked"
				data := f.receipt(op)
				data["ok"] = true
				data["cancelled"] = true
				write(data)
				return
			}
		}
	}
	for _, op := range f.ops {
		if op.owner != owner {
			continue
		}
		if path == op.kind+"s/"+op.ref || path == op.kind+"s/by-request/"+op.id {
			write(f.receipt(op))
			return
		}
		if path == "media/media_"+op.id {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("X-Content-SHA256", sha(f.image))
			raw := append([]byte(nil), f.image...)
			if f.corruptImage {
				raw[len(raw)-1] ^= 1
			}
			_, _ = w.Write(raw)
			return
		}
	}
	w.WriteHeader(404)
	write(map[string]any{"ok": false, "code": "observation_not_found"})
}
func (f *fixture) receipt(op *fakeOperation) map[string]any {
	ref := op.ref
	if f.wrongBinding {
		ref = "wrong_ref"
	}
	d := map[string]any{"ok": true, "operationRef": ref, "requestId": op.id, "pending": false, "userMessage": "Original operation receipt."}
	if op.kind == "deployment" {
		if op.state == "proposed" {
			d["proposal"] = map[string]any{"state": "proposed", "sourceName": "Gate", "algorithmName": "People", "enabled": true}
			d["confirmationMode"] = "local_page"
			d["supportedInteraction"] = "deployment_confirmation"
			d["interactionRequired"] = true
		} else {
			d["deployment"] = map[string]any{"state": op.state, "class": op.state, "target": map[string]any{"sourceName": "Gate", "algorithmName": "People"}, "originalVerification": map[string]any{"observedAt": "2026-09-01T00:00:00Z"}, "current": map[string]any{"observedAt": "2026-09-02T00:00:00Z"}}
			d["ok"] = op.state == "completed"
		}
	} else {
		d["observation"] = map[string]any{"status": op.state, "kind": "capture", "analysisSource": "none", "sourceName": "Gate", "observedAt": "2026-09-28T00:00:00Z", "frameTimeKnown": false}
		d["attachments"] = []any{map[string]any{"mediaRef": "media_" + op.id, "path": apiPrefix + "media/media_" + op.id, "contentType": "image/png", "sha256": sha(f.image), "sizeBytes": len(f.image)}}
	}
	return d
}
func configFor(t *testing.T, f *fixture) Config {
	t.Helper()
	root := t.TempDir()
	if err := localstate.PrepareStateRoot(filepath.Join(root, "private")); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "private", "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("b", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(root, "private", "candidate.json")
	raw, _ := json.Marshal(identity(buildinfo.Current()))
	if err := os.WriteFile(candidate, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(candidate); err != nil {
		t.Fatal(err)
	}
	return Config{f.server.URL, token, filepath.Join(root, "private", "journal"), candidate}
}
func bridgeFor(t *testing.T, f *fixture) (*Bridge, Config) {
	t.Helper()
	c := configFor(t, f)
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, c
}
func beginFor(t *testing.T, b *Bridge) string {
	t.Helper()
	r, _ := b.begin(context.Background())
	if !r.OK {
		t.Fatalf("begin: %+v", r)
	}
	return r.ContextRef
}

func TestOneMCPConnectionSeparateContextsAndNativeContent(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, z := mcp.NewInMemoryTransports()
	ss, err := b.Server().Connect(ctx, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "no-skill-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, z, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	call := func(name string, args any) (Result, *mcp.CallToolResult) {
		t.Helper()
		out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(out.StructuredContent)
		var r Result
		if json.Unmarshal(raw, &r) != nil {
			t.Fatalf("bad output %s", raw)
		}
		return r, out
	}
	one, _ := call("cosmoedge_begin_context", map[string]any{})
	two, _ := call("cosmoedge_begin_context", map[string]any{})
	if !one.OK || !two.OK || one.ContextRef == two.ContextRef {
		t.Fatal("distinct contexts required")
	}
	catalog, _ := call("cosmoedge_catalog", ContextInput{ContextRef: one.ContextRef})
	var wantTotals map[string]any
	_ = json.Unmarshal([]byte(`{"sourceCount":1,"sourcesByKind":{"network_camera":1,"test_video":0,"usb_camera":0,"unknown":0},"algorithmCount":1,"taskCount":0,"runningTaskCount":0,"stoppedTaskCount":0,"unknownRuntimeTaskCount":0}`), &wantTotals)
	if !catalog.OK || !reflect.DeepEqual(catalog.Data["totals"], wantTotals) {
		t.Fatalf("native MCP did not preserve service catalog totals: %+v", catalog)
	}
	shot, content := call("cosmoedge_capture", CaptureInput{ContextRef: one.ContextRef, RequestKey: "shot-1", SourceName: "Gate"})
	if !shot.OK || shot.State != "captured" || len(shot.Artifacts) != 1 {
		t.Fatalf("capture %+v", shot)
	}
	if len(content.Content) != 2 {
		t.Fatalf("image missing: %+v", content.Content)
	}
	if _, ok := content.Content[1].(*mcp.ImageContent); !ok {
		t.Fatal("not image content")
	}
	denied, _ := call("cosmoedge_get_artifact", ArtifactInput{two.ContextRef, shot.Artifacts[0].Ref})
	if denied.OK || denied.Code != "artifact_not_found" {
		t.Fatalf("cross-context artifact %+v", denied)
	}
	denied, _ = call("cosmoedge_get_operation", OperationInput{ContextRef: two.ContextRef, OperationRef: shot.OperationRef})
	if denied.OK || denied.Code != "operation_not_found" {
		t.Fatalf("cross-context operation %+v", denied)
	}
	repeat, original := call("cosmoedge_get_artifact", ArtifactInput{one.ContextRef, shot.Artifacts[0].Ref})
	if !repeat.OK || len(original.Content) != 2 {
		t.Fatal("original reread failed")
	}
	summary, report := call("cosmoedge_summary", SummaryInput{ContextRef: one.ContextRef, Start: "2026-09-01T00:00:00+08:00", End: "2026-09-02T00:00:00+08:00", TimeZone: "Asia/Shanghai", SourceNames: []string{"Gate"}})
	if !summary.OK || len(summary.Artifacts) != 1 || summary.Data["partial"] != true {
		t.Fatalf("summary %+v", summary)
	}
	if _, ok := report.Content[1].(*mcp.EmbeddedResource); !ok {
		t.Fatal("report not embedded original")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts["captures"] != 1 {
		t.Fatal("artifact reread recaptured")
	}
}

func TestLostOutputRestartOnlyRecoversOriginalRequest(t *testing.T) {
	f := newFixture(t)
	c := configFor(t, f)
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ref := beginFor(t, b)
	f.dropCapture = true
	in := CaptureInput{ContextRef: ref, RequestKey: "lost-first-output", SourceName: "Gate"}
	lost, _ := b.capture(context.Background(), in)
	if !lost.Unknown || lost.OperationRef == "" || lost.Pending {
		t.Fatalf("lost %+v", lost)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	list, _ := b.pending(ContextInput{ref})
	ops := list.Data["operations"].([]operation)
	if len(ops) != 1 || ops[0].RequestKey != in.RequestKey {
		t.Fatalf("lost request not recoverable: %+v", list)
	}
	recovered, _ := b.capture(context.Background(), in)
	if !recovered.OK || recovered.State != "captured" || recovered.OperationRef != lost.OperationRef {
		t.Fatalf("recovery %+v", recovered)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts["captures"] != 1 {
		t.Fatalf("replayed POST %d", f.posts["captures"])
	}
}

func TestReviewIsNotConfirmationAndUnknownRemainsRecoverable(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ref := beginFor(t, b)
	p, _ := b.prepare(context.Background(), ChangeInput{ref, "change-1", "Gate", "People", true})
	if !p.OK || p.State != "proposed" {
		t.Fatalf("prepare %+v", p)
	}
	r, _ := b.review(context.Background(), ReviewInput{ContextRef: ref, OperationRef: p.OperationRef})
	if !r.OK || r.State != "proposed" {
		t.Fatalf("page-open became completion %+v", r)
	}
	list, _ := b.pending(ContextInput{ref})
	if len(list.Data["operations"].([]operation)) != 1 {
		t.Fatal("unconfirmed proposal vanished")
	}
	f.mu.Lock()
	for _, op := range f.ops {
		op.state = "unknown"
	}
	f.mu.Unlock()
	u, _ := b.get(context.Background(), OperationInput{ContextRef: ref, OperationRef: p.OperationRef})
	if !u.Unknown || u.State != "unknown" {
		t.Fatalf("unknown %+v", u)
	}
	list, _ = b.pending(ContextInput{ref})
	if len(list.Data["operations"].([]operation)) != 1 {
		t.Fatal("unknown vanished")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts["deployments/confirm"] != 0 || f.posts["deployments"] != 1 {
		t.Fatal("confirmation authority bypass")
	}
}

func TestIntegrityFailureKeepsFactsAndRejectsMedia(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ref := beginFor(t, b)
	f.corruptImage = true
	r, content := b.capture(context.Background(), CaptureInput{ContextRef: ref, RequestKey: "bad-image", SourceName: "Gate"})
	if !r.OK || len(r.Artifacts) != 0 || len(content) != 0 || len(r.ArtifactErrors) != 1 {
		t.Fatalf("bad image %+v", r)
	}
	f.corruptReport = true
	r, content = b.summary(context.Background(), SummaryInput{ContextRef: ref, Start: "2026-09-01T00:00:00Z", End: "2026-09-02T00:00:00Z", TimeZone: "UTC"})
	if !r.OK || r.Data["summary"] == nil || len(content) != 0 || len(r.ArtifactErrors) != 1 {
		t.Fatalf("bad report %+v", r)
	}
}

func TestPairingLoopbackAndPrivateStateAdmission(t *testing.T) {
	f := newFixture(t)
	c := configFor(t, f)
	bad := c
	bad.BaseURL = "http://example.com:37789"
	if _, err := New(bad); err == nil {
		t.Fatal("non-loopback admitted")
	}
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	second, err := New(c)
	if err != nil {
		t.Fatal("shared journal admission:", err)
	}
	defer second.Close()
	f.identity.Revision = strings.Repeat("d", 40)
	r, _ := b.begin(context.Background())
	if r.OK || r.Code != "service_candidate_mismatch" {
		t.Fatalf("mismatch %+v", r)
	}
}

func TestMaintenanceRetainsUnknownAndRecentEvidence(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	old := beginFor(t, b)
	unknown := beginFor(t, b)
	recent := beginFor(t, b)
	b.capture(context.Background(), CaptureInput{ContextRef: old, RequestKey: "settled", SourceName: "Gate"})
	f.dropCapture = true
	b.capture(context.Background(), CaptureInput{ContextRef: unknown, RequestKey: "uncertain", SourceName: "Gate"})
	b.summary(context.Background(), SummaryInput{ContextRef: recent, Start: "2026-09-01T00:00:00Z", End: "2026-09-02T00:00:00Z", TimeZone: "UTC"})
	stamp := time.Now().Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	for _, table := range []string{"contexts", "operations", "artifacts"} {
		if _, err := b.journal.db.Exec("UPDATE "+table+" SET created_at=?", stamp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.journal.db.Exec("UPDATE artifacts SET created_at=? WHERE context_ref=?", time.Now().UTC().Format(time.RFC3339Nano), recent); err != nil {
		t.Fatal(err)
	}
	preview, err := b.Maintain(30, false)
	if err != nil || preview.Contexts != 1 || preview.Artifacts != 1 {
		t.Fatalf("preview %+v %v", preview, err)
	}
	if _, err = b.journal.context(old); err != nil {
		t.Fatal("dry run deleted context")
	}
	applied, err := b.Maintain(30, true)
	if err != nil || applied.Contexts != 1 {
		t.Fatalf("apply %+v %v", applied, err)
	}
	if _, err = b.journal.context(old); err == nil {
		t.Fatal("old settled context retained")
	}
	if _, err = b.journal.context(unknown); err != nil {
		t.Fatal("unknown context lost")
	}
	if _, err = b.journal.context(recent); err != nil {
		t.Fatal("recent evidence lost")
	}
}

func TestDuplicateJSONAndAuthorityMaterialRejected(t *testing.T) {
	var out map[string]any
	if decodeStrict([]byte(`{"ok":true,"ok":false}`), &out) == nil {
		t.Fatal("duplicate accepted")
	}
	if !containsAuthority(map[string]any{"nested": []any{map[string]any{"confirmationToken": "secret"}}}) {
		t.Fatal("confirmation material accepted")
	}
}

func TestConcurrentSharedJournalClaimsOneSubmission(t *testing.T) {
	f := newFixture(t)
	c := configFor(t, f)
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ref := beginFor(t, a)
	in := CaptureInput{ContextRef: ref, RequestKey: "concurrent-intent", SourceName: "Gate"}
	ready := make(chan struct{})
	results := make(chan Result, 2)
	for _, bridge := range []*Bridge{a, b} {
		go func(bridge *Bridge) { <-ready; r, _ := bridge.capture(context.Background(), in); results <- r }(bridge)
	}
	close(ready)
	one, two := <-results, <-results
	if one.OperationRef == "" || one.OperationRef != two.OperationRef {
		t.Fatalf("claim identity diverged: %+v %+v", one, two)
	}
	final, _ := b.get(context.Background(), OperationInput{ContextRef: ref, RequestKey: in.RequestKey})
	if !final.OK {
		t.Fatalf("recover shared claim: %+v", final)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts["captures"] != 1 {
		t.Fatalf("duplicate POST %d", f.posts["captures"])
	}
}

func TestStaleReceiptCannotOverwriteNewerConcurrentReceipt(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ref := beginFor(t, b)
	op, _, err := b.journal.prepare(ref, "revision-test", "deployment", map[string]any{"sourceName": "Gate"})
	if err != nil {
		t.Fatal(err)
	}
	stale := op
	newer := op
	newer.State = "completed"
	newer.Result = map[string]any{"ok": true, "userMessage": "new"}
	if err = b.journal.save(&newer); err != nil {
		t.Fatal(err)
	}
	stale.State = "pending"
	stale.Result = map[string]any{"ok": true, "userMessage": "old"}
	if err = b.journal.save(&stale); err != nil {
		t.Fatal(err)
	}
	if stale.State != "completed" || stale.Result["userMessage"] != "new" {
		t.Fatalf("stale result won %+v", stale)
	}
}

func TestRepeatedRejectedKeyReturnsOriginalRefusal(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ref := beginFor(t, b)
	f.rejectCapture = true
	in := CaptureInput{ContextRef: ref, RequestKey: "refused", SourceName: "Gate"}
	one, _ := b.capture(context.Background(), in)
	two, _ := b.capture(context.Background(), in)
	if one.State != "rejected" || two.State != "rejected" || one.Code != "invalid_observation" || two.Code != one.Code || two.Unknown {
		t.Fatalf("refusal changed %+v %+v", one, two)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts["captures"] != 1 {
		t.Fatal("refused request replayed")
	}
}

func TestServerClockComesFromService(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	r, _ := b.capabilities(context.Background())
	if r.Data["serverTime"] != "2026-09-28T05:06:07Z" || r.Data["serverTimeAvailable"] != true {
		t.Fatalf("wrong clock %+v", r)
	}
}

func TestPendingInventoryReportsTruncationAndRevealsNextAfterResolution(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ref := beginFor(t, b)
	other := beginFor(t, b)
	for i := 0; i < 105; i++ {
		if _, _, err := b.journal.prepare(ref, fmt.Sprintf("pending-%03d", i), "observation", map[string]any{"sourceName": "Gate"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := b.journal.prepare(other, "other-context", "observation", map[string]any{"sourceName": "Gate"}); err != nil {
		t.Fatal(err)
	}
	first, _ := b.pending(ContextInput{ref})
	ops := first.Data["operations"].([]operation)
	if first.Data["totalPending"] != 105 || first.Data["returned"] != 100 || first.Data["truncated"] != true || len(ops) != 100 || !strings.Contains(first.Message, "first 100") {
		t.Fatalf("truncation not explicit: %+v", first)
	}
	for _, op := range ops {
		op.State = "captured"
		op.Result = map[string]any{"ok": true}
		if err := b.journal.save(&op); err != nil {
			t.Fatal(err)
		}
	}
	next, _ := b.pending(ContextInput{ref})
	if next.Data["totalPending"] != 5 || next.Data["returned"] != 5 || next.Data["truncated"] != false {
		t.Fatalf("remaining inventory: %+v", next)
	}
}
