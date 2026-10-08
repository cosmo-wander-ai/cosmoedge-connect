package mcpbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connectionTestClient(t *testing.T, b *Bridge) (context.Context, *mcp.ClientSession) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server, err := b.Server().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := mcp.NewClient(&mcp.Implementation{Name: "connection-test", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return ctx, client
}

func connectionTestCall(t *testing.T, ctx context.Context, client *mcp.ClientSession, args any) (Result, *mcp.CallToolResult) {
	t.Helper()
	out, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "cosmoedge_open_connection", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var r Result
	if out.StructuredContent != nil {
		raw, err := json.Marshal(out.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
	}
	return r, out
}

func TestOpenConnectionDirectCreatesAndReusesWorkflow(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ctx, client := connectionTestClient(t, b)
	first, out := connectionTestCall(t, ctx, client, map[string]any{})
	if !first.OK || out.IsError || first.ContextRef == "" || first.Data["pageState"] != "dispatched" || first.Data["interactionRequired"] != true || first.Data["supportedInteraction"] != "connection_only" {
		t.Fatalf("direct open: %+v", first)
	}
	if _, leaked := first.Data["sessionRef"]; leaked {
		t.Fatal("service session leaked")
	}
	f.mu.Lock()
	if f.posts["session"] != 1 || f.posts["connection"] != 1 || f.gets["version"] != 1 || f.gets["catalog"] != 0 || len(f.posts) != 2 || len(f.gets) != 1 {
		t.Errorf("unexpected direct-open requests: posts=%v gets=%v", f.posts, f.gets)
	}
	f.mu.Unlock()
	reused, out := connectionTestCall(t, ctx, client, map[string]any{"contextRef": first.ContextRef})
	if !reused.OK || out.IsError || reused.ContextRef != first.ContextRef {
		t.Fatalf("reuse: %+v", reused)
	}
	second, out := connectionTestCall(t, ctx, client, map[string]any{})
	if !second.OK || out.IsError || second.ContextRef == first.ContextRef || second.ContextRef == "" {
		t.Fatalf("new workflow: %+v", second)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts["session"] != 2 || f.posts["connection"] != 3 || f.gets["version"] != 3 {
		t.Fatalf("unexpected reused/new workflow requests: posts=%v gets=%v", f.posts, f.gets)
	}
}

func TestOpenConnectionSchemaAndExplicitInvalidReferences(t *testing.T) {
	f := newFixture(t)
	b, _ := bridgeFor(t, f)
	ctx, client := connectionTestClient(t, b)
	tools, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Required   []string `json:"required"`
			Properties map[string]struct {
				Type json.RawMessage `json:"type"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		property, hasContext := schema.Properties["contextRef"]
		if tool.Name == "cosmoedge_open_connection" {
			if !hasContext || string(property.Type) != `"string"` || slices.Contains(schema.Required, "contextRef") {
				t.Fatalf("open schema must allow omission, not null: %s", raw)
			}
		} else if hasContext && !slices.Contains(schema.Required, "contextRef") {
			t.Fatalf("%s lost its required contextRef", tool.Name)
		}
	}
	for _, value := range []any{"", " ", "ctx_missing", "../invalid", nil, 7} {
		r, out := connectionTestCall(t, ctx, client, map[string]any{"contextRef": value})
		if r.OK || !out.IsError || r.ContextRef != "" {
			t.Fatalf("explicit invalid reference accepted (%v): %+v", value, r)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.posts) != 0 || len(f.gets) != 0 {
		t.Fatalf("invalid references must not dispatch or create replacement sessions: posts=%v gets=%v", f.posts, f.gets)
	}
}

func TestOpenConnectionExpiredReferencesNeverCreateReplacement(t *testing.T) {
	for _, localExpired := range []bool{false, true} {
		t.Run(map[bool]string{false: "service_session_expired", true: "local_context_pruned"}[localExpired], func(t *testing.T) {
			f := newFixture(t)
			b, _ := bridgeFor(t, f)
			ref := beginFor(t, b)
			c, err := b.journal.context(ref)
			if err != nil {
				t.Fatal(err)
			}
			if localExpired {
				if _, err := b.journal.db.Exec("DELETE FROM contexts WHERE ref=?", ref); err != nil {
					t.Fatal(err)
				}
			} else {
				f.mu.Lock()
				delete(f.sessions, c.Session)
				f.mu.Unlock()
			}
			ctx, client := connectionTestClient(t, b)
			r, out := connectionTestCall(t, ctx, client, map[string]any{"contextRef": ref})
			if r.OK || !out.IsError {
				t.Fatalf("expired reference accepted: %+v", r)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.posts["session"] != 1 {
				t.Fatalf("replacement session created: %v", f.posts)
			}
		})
	}
}

func TestOpenConnectionFailureRetainsCreatedContext(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(map[bool]string{false: "service_rejection", true: "lost_response"}[drop], func(t *testing.T) {
			f := newFixture(t)
			b, _ := bridgeFor(t, f)
			f.mu.Lock()
			f.dropConnection, f.rejectConnection = drop, !drop
			f.mu.Unlock()
			ctx, client := connectionTestClient(t, b)
			r, out := connectionTestCall(t, ctx, client, map[string]any{})
			if r.OK || !out.IsError || r.ContextRef == "" {
				t.Fatalf("failure lost created context: %+v", r)
			}
			if _, err := b.journal.context(r.ContextRef); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.rejectConnection = false
			f.mu.Unlock()
			retried, out := connectionTestCall(t, ctx, client, map[string]any{"contextRef": r.ContextRef})
			if !retried.OK || out.IsError || retried.ContextRef != r.ContextRef {
				t.Fatalf("retry: %+v", retried)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.posts["session"] != 1 || f.posts["connection"] != 2 {
				t.Fatalf("retry replaced context: %v", f.posts)
			}
		})
	}
}

func TestOpenConnectionRetainsPairingAndAuthenticationChecks(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, authFailure := range []bool{false, true} {
			name := map[bool]string{false: "new", true: "existing"}[existing] + "/" + map[bool]string{false: "pairing", true: "authentication"}[authFailure]
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				b, _ := bridgeFor(t, f)
				args := map[string]any{}
				wantSessions := 0
				if existing {
					args["contextRef"] = beginFor(t, b)
					wantSessions = 1
				}
				if authFailure {
					b.client.token = strings.Repeat("x", 64)
				} else {
					f.mu.Lock()
					f.identity.Version = "different-candidate"
					f.mu.Unlock()
				}
				ctx, client := connectionTestClient(t, b)
				r, out := connectionTestCall(t, ctx, client, args)
				if r.OK || !out.IsError {
					t.Fatalf("verification bypassed: %+v", r)
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.posts["session"] != wantSessions || f.posts["connection"] != 0 {
					t.Fatalf("dispatch before verification: %v", f.posts)
				}
			})
		}
	}
}

func TestOpenConnectionInvalidSuccessReceiptRetainsContext(t *testing.T) {
	for _, field := range []string{"pageState", "interactionRequired", "supportedInteraction"} {
		for _, missing := range []bool{false, true} {
			t.Run(field+map[bool]string{false: "/wrong", true: "/missing"}[missing], func(t *testing.T) {
				f := newFixture(t)
				b, _ := bridgeFor(t, f)
				reply := map[string]any{"ok": true, "pageState": "dispatched", "interactionRequired": true, "supportedInteraction": "connection_only"}
				if missing {
					delete(reply, field)
				} else {
					reply[field] = map[string]any{"pageState": "rendered", "interactionRequired": false, "supportedInteraction": "deployment_confirmation"}[field]
				}
				f.mu.Lock()
				f.connectionReply = reply
				f.mu.Unlock()
				ctx, client := connectionTestClient(t, b)
				r, out := connectionTestCall(t, ctx, client, map[string]any{})
				if r.OK || !out.IsError || r.Code != "invalid_connection_response" || r.ContextRef == "" {
					t.Fatalf("invalid page-dispatch receipt accepted or context lost: %+v", r)
				}
				if _, err := b.journal.context(r.ContextRef); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				f.connectionReply = nil
				f.mu.Unlock()
				retried, out := connectionTestCall(t, ctx, client, map[string]any{"contextRef": r.ContextRef})
				if !retried.OK || out.IsError || retried.ContextRef != r.ContextRef {
					t.Fatalf("retry replaced context: %+v", retried)
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.posts["session"] != 1 || f.posts["connection"] != 2 {
					t.Fatalf("unexpected retry requests: %v", f.posts)
				}
			})
		}
	}
}

type connectionRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn connectionRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestOpenConnectionUsesOneDeadlineAcrossRequests(t *testing.T) {
	for _, shorterParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "default_cap", true: "shorter_parent"}[shorterParent], func(t *testing.T) {
			f := newFixture(t)
			b, _ := bridgeFor(t, f)
			ctx := context.Background()
			if shorterParent {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
				defer cancel()
			}
			transport := b.client.http.Transport
			var deadlines []time.Time
			var paths []string
			b.client.http.Transport = connectionRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				deadline, ok := req.Context().Deadline()
				if !ok {
					t.Fatal("request has no shared deadline")
				}
				deadlines = append(deadlines, deadline)
				paths = append(paths, strings.TrimPrefix(req.URL.Path, apiPrefix))
				if shorterParent && strings.HasSuffix(req.URL.Path, "/session") {
					// The session spends part of the caller's budget before open.
					timer := time.NewTimer(25 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-req.Context().Done():
						return nil, req.Context().Err()
					}
				}
				if shorterParent && strings.HasSuffix(req.URL.Path, "/connection") {
					<-req.Context().Done()
					return nil, req.Context().Err()
				}
				return transport.RoundTrip(req)
			})
			started := time.Now()
			r, _ := b.openConnection(ctx, OpenConnectionInput{})
			if !slices.Equal(paths, []string{"version", "session", "connection"}) || r.ContextRef == "" {
				t.Fatalf("combined request did not reach open with a retained context: %v %+v", paths, r)
			}
			for _, deadline := range deadlines {
				if !deadline.Equal(deadlines[0]) || deadline.After(started.Add(55*time.Second+time.Second)) {
					t.Fatalf("request reset the shared deadline: %v", deadlines)
				}
			}
			if shorterParent {
				parentDeadline, _ := ctx.Deadline()
				if r.OK || !deadlines[0].Equal(parentDeadline) || ctx.Err() != context.DeadlineExceeded {
					t.Fatalf("shorter caller deadline was not preserved: %+v", r)
				}
			} else if !r.OK {
				t.Fatalf("default budget: %+v", r)
			}
		})
	}
}
