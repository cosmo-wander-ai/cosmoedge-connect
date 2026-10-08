package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectionfixture"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestCapabilitiesProcessReturnsOneSafeEnvelopeFromProtectedFixture(t *testing.T) {
	binary := buildInspectionCLI(t)
	stateRoot := filepath.Join(t.TempDir(), "fixture-state")
	assetRoot := filepath.Join(stateRoot, "assets")
	if err := inspectionfixture.PrepareAssetRoot(filepath.Join("..", "..", "internal", "inspectionfixture", "testdata", "assets"), assetRoot); err != nil {
		t.Fatalf("prepare fixture assets: %v", err)
	}
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatalf("provision fixture token: %v", err)
	}
	address := freeLoopbackAddress(t)
	threadID := "codex-thread-fixture-a"
	service, err := inspectionfixture.New(inspectionfixture.Config{
		StateRoot: stateRoot, AssetRoot: assetRoot, TokenFile: tokenFile, Address: address,
		ConversationRef: threadID, WorkerInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("construct fixture Product: %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("start fixture Product: %v", err)
	}
	t.Cleanup(func() { _ = service.Stop() })

	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatalf("prepare client state: %v", err)
	}
	assertionDigest := sha256.Sum256([]byte(threadID))
	config := map[string]string{
		"endpoint":                    "http://" + address,
		"tokenFile":                   tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]),
	}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatalf("protect client config: %v", err)
	}

	command := exec.Command(binary, "capabilities")
	command.Env = cliProcessEnv(stateHome, threadID)
	command.Stdin = bytes.NewReader(nil)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("capabilities process: %v; stderr=%q", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("handled invocation wrote stderr %q", stderr.String())
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var envelope struct {
		Schema       string `json:"schema"`
		Command      string `json:"command"`
		State        string `json:"state"`
		ContextLabel string `json:"contextLabel"`
		Offerings    []struct {
			Title       string   `json:"title"`
			Description string   `json:"description"`
			Examples    []string `json:"examples"`
		} `json:"offerings"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("decode stdout envelope %q: %v", stdout.String(), err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		t.Fatalf("stdout contains more than one JSON value: %q", stdout.String())
	}
	if envelope.Schema != "cosmoedge.inspection.agent.v1" || envelope.Command != "capabilities" || envelope.State != "ready" || envelope.ContextLabel == "" || len(envelope.Offerings) == 0 {
		t.Fatalf("unexpected capabilities envelope: %+v", envelope)
	}
	for _, offering := range envelope.Offerings {
		if offering.Title == "" || offering.Description == "" || len(offering.Examples) == 0 {
			t.Fatalf("incomplete audience-safe offering: %+v", offering)
		}
	}
	if stats := service.RuntimeStats(); stats.DeviceWriteCalls != 0 {
		t.Fatalf("capability read crossed persistent device write seam: %+v", stats)
	}
}

func TestCapabilitiesInvalidConversationAssertionReturnsSafeHandoffBeforeProductRequest(t *testing.T) {
	binary := buildInspectionCLI(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	stateRoot := filepath.Join(t.TempDir(), "client-state")
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	boundThreadID := "codex-thread-bound"
	assertionDigest := sha256.Sum256([]byte(boundThreadID))
	configRaw, err := json.Marshal(map[string]string{
		"endpoint": server.URL, "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	for _, assertion := range []string{"", "invalid assertion", "codex-thread-other"} {
		command := exec.Command(binary, "capabilities")
		command.Env = cliProcessEnv(stateHome, assertion)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		if err := command.Run(); err != nil {
			t.Fatalf("assertion %q returned process failure: %v; stderr=%q", assertion, err, stderr.String())
		}
		var envelope struct {
			Schema      string `json:"schema"`
			Command     string `json:"command"`
			State       string `json:"state"`
			Interaction struct {
				Title       string `json:"title"`
				Message     string `json:"message"`
				ActionLabel string `json:"actionLabel"`
				Capability  string `json:"capability"`
			} `json:"interaction"`
		}
		decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		if err := decoder.Decode(&envelope); err != nil {
			t.Fatalf("assertion %q stdout=%q: %v", assertion, stdout.String(), err)
		}
		if decoder.Decode(&struct{}{}) == nil {
			t.Fatalf("assertion %q returned multiple stdout values: %q", assertion, stdout.String())
		}
		if envelope.Schema != "cosmoedge.inspection.agent.v1" || envelope.Command != "capabilities" || envelope.State != "interaction_required" ||
			envelope.Interaction.Title == "" || envelope.Interaction.Message == "" || envelope.Interaction.ActionLabel == "" || envelope.Interaction.Capability != "operator.codex_binding" {
			t.Fatalf("assertion %q unsafe handoff envelope: %+v", assertion, envelope)
		}
		if stderr.Len() != 0 {
			t.Fatalf("assertion %q handled response wrote stderr %q", assertion, stderr.String())
		}
	}
	if requests != 0 {
		t.Fatalf("invalid assertions reached Product %d times", requests)
	}
}

func TestCapabilitiesRejectsEveryNonEmptyStdinBeforeProductRequest(t *testing.T) {
	binary := buildInspectionCLI(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		response.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	stateRoot := filepath.Join(t.TempDir(), "client-state")
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	threadID := "codex-thread-input-contract"
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]string{
		"endpoint": server.URL, "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{" ", "\n", "{}"} {
		command := exec.Command(binary, "capabilities")
		command.Env = cliProcessEnv(stateHome, threadID)
		command.Stdin = strings.NewReader(input)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 2 {
			t.Fatalf("stdin %q exit error=%v, want contract exit 2", input, err)
		}
		if stdout.Len() != 0 || stderr.String() != "inspection command could not produce a trusted response\n" {
			t.Fatalf("stdin %q stdout=%q stderr=%q", input, stdout.String(), stderr.String())
		}
	}
	if requests != 0 {
		t.Fatalf("non-empty capabilities stdin reached Product %d times", requests)
	}
}

func TestCapabilitiesMissingScopeReturnsSafeUnableEnvelope(t *testing.T) {
	binary := buildInspectionCLI(t)
	stateRoot := filepath.Join(t.TempDir(), "fixture-state")
	assetRoot := filepath.Join(stateRoot, "assets")
	if err := inspectionfixture.PrepareAssetRoot(filepath.Join("..", "..", "internal", "inspectionfixture", "testdata", "assets"), assetRoot); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	address := freeLoopbackAddress(t)
	threadID := "codex-thread-missing-scope"
	service, err := inspectionfixture.New(inspectionfixture.Config{
		StateRoot: stateRoot, AssetRoot: assetRoot, TokenFile: tokenFile, Address: address,
		ConversationRef: threadID, WorkerInterval: 10 * time.Millisecond,
		ChannelScopes: []httpapi.Scope{httpapi.ScopeRunRead},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Stop() })

	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]string{
		"endpoint": "http://" + address, "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(binary, "capabilities")
	command.Env = cliProcessEnv(stateHome, threadID)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("missing-scope invocation returned process failure: %v; stderr=%q", err, stderr.String())
	}
	var envelope struct {
		Schema  string `json:"schema"`
		Command string `json:"command"`
		State   string `json:"state"`
		Message string `json:"message"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) == nil {
		t.Fatalf("missing-scope stdout=%q decode=%v", stdout.String(), err)
	}
	if envelope.Schema != "cosmoedge.inspection.agent.v1" || envelope.Command != "capabilities" || envelope.State != "unable" || envelope.Message == "" {
		t.Fatalf("missing-scope envelope=%+v", envelope)
	}
	if strings.Contains(stdout.String(), "forbidden") || strings.Contains(stdout.String(), "scope") || strings.Contains(stdout.String(), "403") || stderr.Len() != 0 {
		t.Fatalf("missing-scope response leaked transport details: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if stats := service.RuntimeStats(); stats.DeviceWriteCalls != 0 {
		t.Fatalf("missing-scope read crossed persistent device write seam: %+v", stats)
	}
}

func TestInspectProcessReturnsReadyTextResultFromProtectedFixture(t *testing.T) {
	binary := buildInspectionCLI(t)
	stateRoot := filepath.Join(t.TempDir(), "fixture-state")
	assetRoot := filepath.Join(stateRoot, "assets")
	if err := inspectionfixture.PrepareAssetRoot(filepath.Join("..", "..", "internal", "inspectionfixture", "testdata", "assets"), assetRoot); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	address := freeLoopbackAddress(t)
	threadID := "codex-thread-inspect-text"
	service, err := inspectionfixture.New(inspectionfixture.Config{
		StateRoot: stateRoot, AssetRoot: assetRoot, TokenFile: tokenFile, Address: address,
		ConversationRef: threadID, WorkerInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Stop() })

	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]string{
		"endpoint": "http://" + address, "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "inspect")
	command.Env = cliProcessEnv(stateHome, threadID)
	command.Stdin = strings.NewReader(`{"instruction":"帮我查看公共区域的现场状态"}`)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("inspect process: %v; stderr=%q", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("handled inspect wrote stderr %q", stderr.String())
	}
	var envelope struct {
		Schema  string             `json:"schema"`
		Command string             `json:"command"`
		State   string             `json:"state"`
		Message string             `json:"message"`
		RunRef  string             `json:"runRef"`
		Result  httpapi.ResultView `json:"result"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) == nil {
		t.Fatalf("inspect stdout=%q decode=%v", stdout.String(), err)
	}
	if envelope.Schema != "cosmoedge.inspection.agent.v1" || envelope.Command != "inspect" || envelope.State != "ready" ||
		envelope.Message == "" || envelope.RunRef == "" || envelope.Result.RunRef != envelope.RunRef || envelope.Result.Summary == "" || len(envelope.Result.Sections) == 0 {
		t.Fatalf("inspect envelope=%+v", envelope)
	}
	if stats := service.RuntimeStats(); stats.DeviceWriteCalls != 0 {
		t.Fatalf("inspect crossed persistent device write seam: %+v", stats)
	}
}

func TestInspectRejectsNonCanonicalInputBeforeProductDispatch(t *testing.T) {
	binary := buildInspectionCLI(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		response.WriteHeader(http.StatusInternalServerError)
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	stateRoot := filepath.Join(t.TempDir(), "client-state")
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	threadID := "codex-thread-strict-input"
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]string{
		"endpoint": server.URL, "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"unknown field":       []byte(`{"instruction":"查看现场","timeout":30}`),
		"protected field":     []byte(`{"instruction":"查看现场","siteId":"other"}`),
		"duplicate key":       []byte(`{"instruction":"查看现场","instruction":"再次查看"}`),
		"case alias":          []byte(`{"Instruction":"查看现场"}`),
		"trailing JSON":       []byte(`{"instruction":"查看现场"}{}`),
		"invalid UTF-8":       append([]byte(`{"instruction":"`), 0xff, '"', '}'),
		"duplicate context":   []byte(`{"instruction":"查看现场","context":[{"name":"班次","value":"早"},{"name":"班次","value":"晚"}]}`),
		"case-folded context": []byte(`{"instruction":"查看现场","context":[{"name":"Shift","value":"早"},{"name":"shift","value":"晚"}]}`),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			command := exec.Command(binary, "inspect")
			command.Env = cliProcessEnv(stateHome, threadID)
			command.Stdin = bytes.NewReader(input)
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			err := command.Run()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 2 {
				t.Fatalf("exit error=%v, want contract exit 2; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || stderr.String() != "inspection command could not produce a trusted response\n" {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
	if requests != 0 {
		t.Fatalf("invalid inspect inputs reached Product %d times", requests)
	}
}

func TestInspectInteractionRequiredIsHandledWithoutRun(t *testing.T) {
	binary := buildInspectionCLI(t)
	stateRoot := filepath.Join(t.TempDir(), "fixture-state")
	assetRoot := filepath.Join(stateRoot, "assets")
	if err := inspectionfixture.PrepareAssetRoot(filepath.Join("..", "..", "internal", "inspectionfixture", "testdata", "assets"), assetRoot); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	address := freeLoopbackAddress(t)
	threadID := "codex-thread-interaction"
	service, err := inspectionfixture.New(inspectionfixture.Config{
		StateRoot: stateRoot, AssetRoot: assetRoot, TokenFile: tokenFile, Address: address,
		ConversationRef: threadID, WorkerInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Stop() })

	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]string{
		"endpoint": "http://" + address, "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(binary, "inspect")
	command.Env = cliProcessEnv(stateHome, threadID)
	command.Stdin = strings.NewReader(`{"instruction":"准备现场接入"}`)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("interaction inspect: %v; stderr=%q", err, stderr.String())
	}
	var envelope struct {
		State       string `json:"state"`
		RunRef      string `json:"runRef"`
		Interaction struct {
			Title       string `json:"title"`
			Message     string `json:"message"`
			ActionLabel string `json:"actionLabel"`
			Capability  string `json:"capability"`
			HandoffRef  string `json:"handoffRef"`
		} `json:"interaction"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) == nil {
		t.Fatalf("interaction stdout=%q decode=%v", stdout.String(), err)
	}
	if envelope.State != "interaction_required" || envelope.RunRef != "" || envelope.Interaction.Title == "" ||
		envelope.Interaction.Message == "" || envelope.Interaction.ActionLabel == "" || envelope.Interaction.Capability != httpapi.InteractionCapabilityOnboarding || envelope.Interaction.HandoffRef == "" {
		t.Fatalf("interaction envelope=%+v", envelope)
	}
	if stderr.Len() != 0 || strings.Contains(stdout.String(), `"runRef"`) {
		t.Fatalf("interaction response invented a run: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if stats := service.RuntimeStats(); stats.DeviceWriteCalls != 0 {
		t.Fatalf("interaction crossed persistent device write seam: %+v", stats)
	}
}

func TestInspectTrustedShorterWaitReturnsWorkingWithoutCancellingRun(t *testing.T) {
	binary := buildInspectionCLI(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	starts, reads, cancels := 0, 0, 0
	now := time.Now().UTC()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/inspection/requests":
			starts++
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"created":true,"run":{"runRef":"run-working-1","status":"working","message":"正在查看现场情况","submittedAt":"` + now.Format(time.RFC3339Nano) + `","updatedAt":"` + now.Format(time.RFC3339Nano) + `"}}`))
		case request.Method == http.MethodGet && request.URL.Path == "/api/inspection/runs/run-working-1":
			reads++
			_, _ = response.Write([]byte(`{"runRef":"run-working-1","status":"working","message":"正在查看现场情况","submittedAt":"` + now.Format(time.RFC3339Nano) + `","updatedAt":"` + now.Format(time.RFC3339Nano) + `"}`))
		default:
			cancels++
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	stateRoot := filepath.Join(t.TempDir(), "client-state")
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	threadID := "codex-thread-short-wait"
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]any{
		"endpoint": "http://" + listener.Addr().String(), "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]), "inspectWaitMillis": 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(binary, "inspect")
	command.Env = cliProcessEnv(stateHome, threadID)
	command.Stdin = strings.NewReader(`{"instruction":"查看现场状态"}`)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	startedAt := time.Now()
	if err := command.Run(); err != nil {
		t.Fatalf("short-wait inspect: %v; stderr=%q", err, stderr.String())
	}
	elapsed := time.Since(startedAt)
	var envelope struct {
		State  string `json:"state"`
		RunRef string `json:"runRef"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("working stdout=%q: %v", stdout.String(), err)
	}
	if envelope.State != "working" || envelope.RunRef != "run-working-1" || elapsed > time.Second || starts != 1 || reads < 1 || cancels != 0 || stderr.Len() != 0 {
		t.Fatalf("working envelope=%+v elapsed=%v starts=%d reads=%d unexpected=%d stderr=%q", envelope, elapsed, starts, reads, cancels, stderr.String())
	}
}

func TestInspectTransportRetryReusesOneStableIdempotencyKey(t *testing.T) {
	binary := buildInspectionCLI(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var keys, bodies []string
	now := time.Now().UTC()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/api/inspection/runs/run-idempotent-1" {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"runRef":"run-idempotent-1","status":"working","message":"正在查看现场情况","submittedAt":"` + now.Format(time.RFC3339Nano) + `","updatedAt":"` + now.Format(time.RFC3339Nano) + `"}`))
			return
		}
		body, _ := io.ReadAll(request.Body)
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		bodies = append(bodies, string(body))
		if len(keys) == 1 {
			connection, _, hijackErr := response.(http.Hijacker).Hijack()
			if hijackErr != nil {
				t.Errorf("hijack first transport attempt: %v", hijackErr)
				return
			}
			_ = connection.Close()
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{"created":true,"run":{"runRef":"run-idempotent-1","status":"working","message":"正在查看现场情况","submittedAt":"` + now.Format(time.RFC3339Nano) + `","updatedAt":"` + now.Format(time.RFC3339Nano) + `"}}`))
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	stateRoot := filepath.Join(t.TempDir(), "client-state")
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	threadID := "codex-thread-idempotent-retry"
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]any{
		"endpoint": "http://" + listener.Addr().String(), "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]), "inspectWaitMillis": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(binary, "inspect")
	command.Env = cliProcessEnv(stateHome, threadID)
	command.Stdin = strings.NewReader(`{"instruction":"查看公共区域状态"}`)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("retry inspect: %v; stderr=%q", err, stderr.String())
	}
	var envelope struct {
		State  string `json:"state"`
		RunRef string `json:"runRef"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.State != "working" || envelope.RunRef != "run-idempotent-1" || len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] || bodies[0] != bodies[1] || stderr.Len() != 0 {
		t.Fatalf("envelope=%+v keys=%v bodies=%v stderr=%q", envelope, keys, bodies, stderr.String())
	}
}

func TestContinueProcessReadsAcceptedRunAfterInspectProcessExits(t *testing.T) {
	binary := buildInspectionCLI(t)
	stateRoot := filepath.Join(t.TempDir(), "fixture-state")
	assetRoot := filepath.Join(stateRoot, "assets")
	if err := inspectionfixture.PrepareAssetRoot(filepath.Join("..", "..", "internal", "inspectionfixture", "testdata", "assets"), assetRoot); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(stateRoot, "channel.token")
	if err := inspectionfixture.ProvisionToken(tokenFile); err != nil {
		t.Fatal(err)
	}
	address := freeLoopbackAddress(t)
	threadID := "codex-thread-explicit-continue"
	service, err := inspectionfixture.New(inspectionfixture.Config{
		StateRoot: stateRoot, AssetRoot: assetRoot, TokenFile: tokenFile, Address: address,
		ConversationRef: threadID, WorkerInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Stop() })

	stateHome := t.TempDir()
	clientRoot := cliClientRoot(stateHome)
	if err := localstate.PrepareStateRoot(clientRoot); err != nil {
		t.Fatal(err)
	}
	assertionDigest := sha256.Sum256([]byte(threadID))
	configRaw, err := json.Marshal(map[string]any{
		"endpoint": "http://" + address, "tokenFile": tokenFile,
		"conversationAssertionSha256": hex.EncodeToString(assertionDigest[:]), "inspectWaitMillis": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientRoot, "client.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(configPath); err != nil {
		t.Fatal(err)
	}

	inspect := exec.Command(binary, "inspect")
	inspect.Env = cliProcessEnv(stateHome, threadID)
	inspect.Stdin = strings.NewReader(`{"instruction":"帮我查看公共区域的现场状态"}`)
	var inspectOut, inspectErr bytes.Buffer
	inspect.Stdout, inspect.Stderr = &inspectOut, &inspectErr
	if err := inspect.Run(); err != nil {
		t.Fatalf("inspect: %v; stderr=%q", err, inspectErr.String())
	}
	var started struct {
		RunRef string `json:"runRef"`
	}
	if err := json.Unmarshal(inspectOut.Bytes(), &started); err != nil || started.RunRef == "" {
		t.Fatalf("inspect envelope=%q err=%v", inspectOut.String(), err)
	}

	continuation := exec.Command(binary, "continue")
	continuation.Env = cliProcessEnv(stateHome, threadID)
	continuation.Stdin = strings.NewReader(`{"runRef":"` + started.RunRef + `"}`)
	var stdout, stderr bytes.Buffer
	continuation.Stdout, continuation.Stderr = &stdout, &stderr
	if err := continuation.Run(); err != nil {
		t.Fatalf("continue: %v; stderr=%q", err, stderr.String())
	}
	var envelope struct {
		Command string `json:"command"`
		State   string `json:"state"`
		RunRef  string `json:"runRef"`
		Result  *struct {
			Summary string `json:"summary"`
		} `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Command != "continue" || envelope.State != "ready" || envelope.RunRef != started.RunRef || envelope.Result == nil || envelope.Result.Summary == "" || stderr.Len() != 0 {
		t.Fatalf("continue envelope=%+v stderr=%q", envelope, stderr.String())
	}

	automatic := exec.Command(binary, "continue")
	automatic.Env = cliProcessEnv(stateHome, threadID)
	automatic.Stdin = strings.NewReader(`{}`)
	var automaticOut, automaticErr bytes.Buffer
	automatic.Stdout, automatic.Stderr = &automaticOut, &automaticErr
	if err := automatic.Run(); err != nil {
		t.Fatalf("automatic continue: %v; stderr=%q", err, automaticErr.String())
	}
	var resolved struct {
		State  string `json:"state"`
		RunRef string `json:"runRef"`
	}
	if err := json.Unmarshal(automaticOut.Bytes(), &resolved); err != nil || resolved.State != "ready" || resolved.RunRef != started.RunRef || automaticErr.Len() != 0 {
		t.Fatalf("automatic continue envelope=%q decoded=%+v err=%v stderr=%q", automaticOut.String(), resolved, err, automaticErr.String())
	}

	second := exec.Command(binary, "inspect")
	second.Env = cliProcessEnv(stateHome, threadID)
	second.Stdin = strings.NewReader(`{"instruction":"帮我查看公共区域的现场状态"}`)
	var secondOut, secondErr bytes.Buffer
	second.Stdout, second.Stderr = &secondOut, &secondErr
	if err := second.Run(); err != nil {
		t.Fatalf("second inspect: %v stderr=%q", err, secondErr.String())
	}
	var secondRun struct {
		RunRef string `json:"runRef"`
	}
	if err := json.Unmarshal(secondOut.Bytes(), &secondRun); err != nil || secondRun.RunRef == "" || secondRun.RunRef == started.RunRef {
		t.Fatalf("second inspection did not create a distinct run: %q err=%v", secondOut.String(), err)
	}
	clarification := invokeRegressionCLI(t, binary, cliProcessEnv(stateHome, threadID), "continue", `{}`)
	raw, _ := json.Marshal(clarification)
	var choice struct {
		Candidates []struct {
			RunRef string `json:"runRef"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &choice); err != nil {
		t.Fatal(err)
	}
	if clarification.State != "clarification" || len(choice.Candidates) != 2 {
		t.Fatalf("expected two choices: %s", raw)
	}
	selected := ""
	for _, candidate := range choice.Candidates {
		if candidate.RunRef == secondRun.RunRef {
			selected = candidate.RunRef
		}
	}
	if selected == "" {
		t.Fatalf("clarification omitted the hidden selection reference: %s", raw)
	}
	selectedInput, _ := json.Marshal(map[string]string{"runRef": selected})
	selectedResult := invokeRegressionCLI(t, binary, cliProcessEnv(stateHome, threadID), "continue", string(selectedInput))
	if selectedResult.State != "ready" || selectedResult.RunRef != secondRun.RunRef || selectedResult.Result == nil {
		t.Fatalf("explicit choice did not continue the selected inspection: %+v", selectedResult)
	}
	if stats := service.RuntimeStats(); stats.DeviceWriteCalls != 0 {
		t.Fatalf("continue crossed persistent device write seam: %+v", stats)
	}
}

func buildInspectionCLI(t *testing.T) string {
	t.Helper()
	name := "cosmoedge-inspection"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-o", binary, ".")
	command.Dir = filepath.Join(".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build inspection CLI: %v\n%s", err, output)
	}
	return binary
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func processEnv(pairs ...string) []string {
	values := make(map[string]string, len(pairs)/2)
	for index := 0; index < len(pairs); index += 2 {
		values[pairs[index]] = pairs[index+1]
	}
	environment := make([]string, 0, len(os.Environ())+len(values))
	for _, item := range os.Environ() {
		key, _, ok := strings.Cut(item, "=")
		if _, replaced := values[key]; ok && replaced {
			continue
		}
		environment = append(environment, item)
	}
	for key, value := range values {
		environment = append(environment, key+"="+value)
	}
	return environment
}

// cliClientRoot mirrors the installed platform layout inside an isolated home.
func cliClientRoot(stateHome string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(stateHome, "CosmoEdge", "Operator", "codex-inspection")
	case "darwin":
		return filepath.Join(stateHome, "Library", "Application Support", "CosmoEdge", "Operator", "codex-inspection")
	default:
		return filepath.Join(stateHome, "cosmoedge", "operator", "codex-inspection")
	}
}

func cliProcessEnv(stateHome, assertion string) []string {
	return processEnv("HOME", stateHome, "USERPROFILE", stateHome,
		"LOCALAPPDATA", stateHome, "XDG_STATE_HOME", stateHome, "CODEX_THREAD_ID", assertion)
}
