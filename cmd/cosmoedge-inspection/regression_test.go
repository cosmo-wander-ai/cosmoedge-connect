package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/agentcli"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectionfixture"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

// The subprocess and its protected configuration exercise the installed CLI
// contract. Only the external Product HTTP responses are controlled by a test.
func regressionCLI(t *testing.T, handler http.Handler, options map[string]any) (string, []string) {
	t.Helper()
	binary := buildInspectionCLI(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	stateHome := t.TempDir()
	root := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(root, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	assertion := "codex-regression-task"
	digest := sha256.Sum256([]byte(assertion))
	config := map[string]any{"endpoint": server.URL, "tokenFile": tokenPath, "conversationAssertionSha256": hex.EncodeToString(digest[:])}
	for key, value := range options {
		config[key] = value
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "client.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	return binary, cliProcessEnv(stateHome, assertion)
}

func invokeRegressionCLI(t *testing.T, binary string, environment []string, goal, input string) agentcli.Envelope {
	t.Helper()
	return invokeRegressionCLIContext(t, context.Background(), binary, environment, goal, input)
}

func invokeRegressionCLIContext(t *testing.T, ctx context.Context, binary string, environment []string, goal, input string) agentcli.Envelope {
	t.Helper()
	command := exec.CommandContext(ctx, binary, goal)
	command.Env, command.Stdin = environment, strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s: %v stderr=%q", goal, err, stderr.String())
	}
	var envelope agentcli.Envelope
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("stdout has trailing data: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("handled response wrote stderr=%q", stderr.String())
	}
	return envelope
}

func regressionRun(status httpapi.RunStatus) httpapi.RunView {
	now := time.Now().UTC()
	return httpapi.RunView{RunRef: "run-regression-one", Status: status, Message: "正在查看现场", SubmittedAt: now, UpdatedAt: now}
}

func TestInspectRejectsRedirectWithoutForwardingAuthorityOrBusinessInput(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"created": true, "run": regressionRun(httpapi.RunWorking)})
	}))
	defer target.Close()
	binary, environment := regressionCLI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/unbound", http.StatusTemporaryRedirect)
	}), nil)
	envelope := invokeRegressionCLI(t, binary, environment, "inspect", `{"instruction":"查看入口情况"}`)
	if forwarded.Load() != 0 {
		t.Fatalf("unbound endpoint received %d requests", forwarded.Load())
	}
	if envelope.State != "unable" || envelope.RunRef != "" {
		t.Fatalf("unexpected rejected redirect: %+v", envelope)
	}
}

func TestCLIRejectsUnsafeOrInvalidProductProjections(t *testing.T) {
	for _, test := range []struct {
		name, goal, input string
		response          func(*http.Request) any
	}{
		{"capability-text", "capabilities", "", func(*http.Request) any {
			return httpapi.CapabilitySet{ContextLabel: "当前现场", Capabilities: []httpapi.CapabilityView{{CapabilityRef: "offering-one", Title: "rtsp://review.invalid/synthetic", Description: "现场查看", Examples: []string{"查看入口"}}}}
		}},
		{"missing-capability-examples", "capabilities", "", func(*http.Request) any {
			return httpapi.CapabilitySet{ContextLabel: "当前现场", Capabilities: []httpapi.CapabilityView{{CapabilityRef: "offering-one", Title: "现场巡检", Description: "现场查看"}}}
		}},
		{"run-state", "inspect", `{"instruction":"查看入口"}`, func(*http.Request) any {
			run := regressionRun("invented-state")
			return map[string]any{"created": true, "run": run}
		}},
		{"run-text", "continue", `{"runRef":"run-regression-one"}`, func(*http.Request) any {
			run := regressionRun(httpapi.RunWorking)
			run.Message = "rtsp://review.invalid/synthetic"
			return run
		}},
		{"result-text", "continue", `{"runRef":"run-regression-one"}`, func(r *http.Request) any {
			if strings.HasSuffix(r.URL.Path, "/result") {
				return httpapi.ResultView{RunRef: "run-regression-one", Summary: "rtsp://review.invalid/synthetic", CompletedAt: time.Now().UTC()}
			}
			return regressionRun(httpapi.RunReady)
		}},
		{"empty-result", "continue", `{"runRef":"run-regression-one"}`, func(r *http.Request) any {
			if strings.HasSuffix(r.URL.Path, "/result") {
				return httpapi.ResultView{RunRef: "run-regression-one"}
			}
			return regressionRun(httpapi.RunReady)
		}},
		{"missing-candidate-reference", "continue", `{}`, func(*http.Request) any {
			return httpapi.ContinuationResolution{Status: httpapi.ContinuationAmbiguous, Candidates: []httpapi.ContinuationCandidate{
				{Area: "入口", Goal: "查看通行", StartedAt: time.Now().UTC()},
				{RunRef: "run-second", Area: "出口", Goal: "查看通行", StartedAt: time.Now().UTC()},
			}}
		}},
		{"unsafe-candidate-description", "continue", `{}`, func(*http.Request) any {
			return httpapi.ContinuationResolution{Status: httpapi.ContinuationAmbiguous, Candidates: []httpapi.ContinuationCandidate{
				{RunRef: "run-first", Area: "入口", Goal: "rtsp://review.invalid/synthetic", StartedAt: time.Now().UTC()},
				{RunRef: "run-second", Area: "出口", Goal: "查看通行", StartedAt: time.Now().UTC()},
			}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			binary, environment := regressionCLI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(test.response(r))
			}), nil)
			envelope := invokeRegressionCLI(t, binary, environment, test.goal, test.input)
			raw, _ := json.Marshal(envelope)
			if strings.Contains(string(raw), "review.invalid") || envelope.State == "invented-state" || envelope.Result != nil || len(envelope.Offerings) != 0 || len(envelope.Candidates) != 0 {
				t.Fatalf("untrusted Product projection reached CLI output: %s", raw)
			}
		})
	}
}

func TestInspectPreservesAcceptedRunWhenProgressReadFails(t *testing.T) {
	binary, environment := regressionCLI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"created": true, "run": regressionRun(httpapi.RunAccepted)})
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}), nil)
	envelope := invokeRegressionCLI(t, binary, environment, "inspect", `{"instruction":"查看入口情况"}`)
	if envelope.RunRef != "run-regression-one" || envelope.Result != nil {
		t.Fatalf("accepted run lost after progress failure: %+v", envelope)
	}
}

func TestCLIWaitBudgetIncludesProgressAndResultHTTPReads(t *testing.T) {
	for _, goal := range []string{"inspect", "continue"} {
		for _, phase := range []string{"progress", "result"} {
			t.Run(goal+"/"+phase, func(t *testing.T) {
				var reads atomic.Int32
				var cancelled atomic.Bool
				finished := make(chan time.Duration, 1)
				run := regressionRun(httpapi.RunWorking)
				if phase == "result" {
					run.Status = httpapi.RunReady
				}
				binary, environment := regressionCLI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						w.WriteHeader(http.StatusCreated)
						_ = json.NewEncoder(w).Encode(map[string]any{"created": true, "run": run})
						return
					}
					isResult := strings.HasSuffix(r.URL.Path, "/result")
					if !isResult && (phase == "result" || goal == "continue" && reads.Add(1) == 1) {
						_ = json.NewEncoder(w).Encode(run)
						return
					}
					// The wait budget starts inside the CLI after bootstrap. Measure
					// the blocked HTTP read, excluding process launch and exit.
					requestStarted := time.Now()
					defer func() {
						select {
						case finished <- time.Since(requestStarted):
						default: // Preserve the first blocked read if a broken client polls again.
						}
					}()
					select {
					case <-r.Context().Done():
						cancelled.Store(true)
						return
					case <-time.After(2 * time.Second):
					}
					if isResult {
						_ = json.NewEncoder(w).Encode(httpapi.ResultView{RunRef: run.RunRef, Summary: "现场查看已完成", CompletedAt: time.Now().UTC()})
					} else {
						_ = json.NewEncoder(w).Encode(run)
					}
				}), map[string]any{"inspectWaitMillis": 100, "continueWaitMillis": 100})
				input := `{"instruction":"查看入口"}`
				if goal == "continue" {
					input = `{"runRef":"run-regression-one"}`
				}
				// Keep a separate process watchdog so a startup or exit hang is
				// bounded without mistaking that overhead for the HTTP budget.
				processContext, cancelProcess := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancelProcess()
				envelope := invokeRegressionCLIContext(t, processContext, binary, environment, goal, input)
				var elapsed time.Duration
				select {
				case elapsed = <-finished:
				case <-processContext.Done():
					t.Fatal("CLI did not complete the blocked HTTP read within the process watchdog")
				}
				if elapsed > time.Second || !cancelled.Load() || envelope.State != "working" || envelope.RunRef != run.RunRef || envelope.Result != nil {
					t.Fatalf("HTTP exceeded wait budget: elapsed=%s cancelled=%v envelope=%+v", elapsed, cancelled.Load(), envelope)
				}
			})
		}
	}
}
