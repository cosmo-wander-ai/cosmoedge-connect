package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestBootstrapIsOneTimeAndCreatesDistinctBrowserSessions(t *testing.T) {
	t.Parallel()
	vault := New(nil)
	firstToken, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	first, err := vault.ConsumeBootstrap(firstToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ConsumeBootstrap(firstToken); !errors.Is(err, ErrConflict) {
		t.Fatalf("consumed bootstrap err=%v", err)
	}
	secondToken, _ := vault.IssueBootstrap()
	second, err := vault.ConsumeBootstrap(secondToken)
	if err != nil {
		t.Fatal(err)
	}
	if first.SessionID == second.SessionID || first.CSRF == second.CSRF {
		t.Fatal("browser sessions reused private bindings")
	}
}

func TestBootstrapCarriesOnlyValidatedFriendlyTaskIntent(t *testing.T) {
	t.Parallel()
	vault := New(nil)
	token, err := vault.IssueBootstrapForIntent(OpenIntent{
		View: "manage_tasks", TaskName: "入口安全帽分析", TaskAction: "disable",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	if auth.View != "manage_tasks" || auth.TaskName != "入口安全帽分析" || auth.TaskAction != "disable" {
		t.Fatalf("task bootstrap=%#v", auth)
	}
	for _, invalid := range []OpenIntent{
		{View: "home", TaskName: "入口安全帽分析", TaskAction: "disable"},
		{View: "manage_tasks", TaskName: "入口安全帽分析", TaskAction: "delete"},
		{View: "manage_tasks", TaskAction: "enable"},
	} {
		if _, err := vault.IssueBootstrapForIntent(invalid); err == nil {
			t.Fatalf("invalid open intent accepted: %#v", invalid)
		}
	}
}

func TestInspectionBootstrapSealsOneExactHandoffIntoLiveBrowser(t *testing.T) {
	t.Parallel()
	current := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	vault := New(nil)
	vault.now = func() time.Time { return current }
	token, err := vault.IssueBootstrapForIntent(OpenIntent{
		View: ViewInspectionInteraction, HandoffRef: "inspection_handoff_exact",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	if auth.View != ViewInspectionInteraction || auth.inspectionHandoffRef != "inspection_handoff_exact" {
		t.Fatal("inspection browser did not inherit the exact protected handoff")
	}
	if handoffRef, err := vault.InspectionHandoff(auth); err != nil || handoffRef != "inspection_handoff_exact" {
		t.Fatalf("InspectionHandoff() ref=%q err=%v", handoffRef, err)
	}

	for name, mutate := range map[string]func(*BrowserAuth){
		"csrf":        func(value *BrowserAuth) { value.CSRF = strings.Repeat("0", 64) },
		"session":     func(value *BrowserAuth) { value.SessionID = strings.Repeat("1", 64) },
		"handoff":     func(value *BrowserAuth) { value.inspectionHandoffRef = "inspection_handoff_other" },
		"seal":        func(value *BrowserAuth) { value.seal = [32]byte{} },
		"session-pad": func(value *BrowserAuth) { value.SessionID += " " },
	} {
		t.Run(name, func(t *testing.T) {
			forged := auth
			mutate(&forged)
			if _, err := vault.InspectionHandoff(forged); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("InspectionHandoff(forged %s) error=%v", name, err)
			}
		})
	}

	current = current.Add(browserTTL)
	if _, err := vault.Authenticate(auth.SessionID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate(expired) error=%v", err)
	}
	if _, err := vault.InspectionHandoff(auth); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("InspectionHandoff(expired) error=%v", err)
	}
}

func TestInspectionIntentRejectsMissingCrossViewOrInvalidHandoff(t *testing.T) {
	t.Parallel()
	vault := New(nil)
	for _, intent := range []OpenIntent{
		{View: ViewInspectionInteraction},
		{View: ViewInspectionInteraction, HandoffRef: "invalid handoff"},
		{View: ViewInspectionInteraction, HandoffRef: " padded_handoff"},
		{View: ViewInspectionInteraction, HandoffRef: "valid_handoff", TaskName: "task"},
		{View: "home", HandoffRef: "valid_handoff"},
		{View: "manage_tasks", HandoffRef: "valid_handoff", TaskName: "task", TaskAction: "disable"},
	} {
		if _, err := vault.IssueBootstrapForIntent(intent); err == nil {
			t.Fatalf("invalid inspection intent accepted: %#v", intent)
		}
	}
}

func TestInspectionBrowserAuthIsBoundToItsIssuingVault(t *testing.T) {
	t.Parallel()
	issuer := New(nil)
	other := New(nil)
	token, err := issuer.IssueBootstrapForIntent(OpenIntent{
		View: ViewInspectionInteraction, HandoffRef: "issuing_vault_handoff",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := issuer.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.InspectionHandoff(auth); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("other Vault accepted foreign BrowserAuth: %v", err)
	}
	if ref, err := issuer.InspectionHandoff(auth); err != nil || ref != "issuing_vault_handoff" {
		t.Fatalf("issuing Vault ref=%q err=%v", ref, err)
	}
}

func TestInspectionBootstrapConcurrentConsumeHasExactlyOneBoundWinner(t *testing.T) {
	t.Parallel()
	vault := New(nil)
	token, err := vault.IssueBootstrapForIntent(OpenIntent{
		View: ViewInspectionInteraction, HandoffRef: "single_consumer_handoff",
	})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	type outcome struct {
		auth BrowserAuth
		err  error
	}
	results := make(chan outcome, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			auth, consumeErr := vault.ConsumeBootstrap(token)
			results <- outcome{auth: auth, err: consumeErr}
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.err != nil {
			if !errors.Is(result.err, ErrConflict) {
				t.Fatalf("ConsumeBootstrap(loser) error=%v", result.err)
			}
			continue
		}
		winners++
		if ref, err := vault.InspectionHandoff(result.auth); err != nil || ref != "single_consumer_handoff" {
			t.Fatalf("winning browser ref=%q err=%v", ref, err)
		}
	}
	if winners != 1 {
		t.Fatalf("ConsumeBootstrap winners=%d, want exactly 1", winners)
	}
}

func TestInspectionAuthenticationIsRaceSafeUnderConcurrentReads(t *testing.T) {
	t.Parallel()
	vault := New(nil)
	token, err := vault.IssueBootstrapForIntent(OpenIntent{
		View: ViewInspectionInteraction, HandoffRef: "inspection_handoff_concurrent",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 24
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for attempt := 0; attempt < 100; attempt++ {
				current, authenticateErr := vault.Authenticate(auth.SessionID)
				if authenticateErr != nil {
					errorsFound <- authenticateErr
					return
				}
				if ref, inspectErr := vault.InspectionHandoff(current); inspectErr != nil || ref != "inspection_handoff_concurrent" {
					errorsFound <- fmt.Errorf("inspection ref=%q: %w", ref, inspectErr)
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}

func TestBrowserAuthAndOpenIntentBlockJSONTextAndLogProjection(t *testing.T) {
	t.Parallel()
	vault := New(nil)
	intent := OpenIntent{View: ViewInspectionInteraction, HandoffRef: "private_handoff_ref"}
	token, err := vault.IssueBootstrapForIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{intent, auth} {
		if _, err := json.Marshal(value); !errors.Is(err, credential.ErrProtectedProjection) {
			t.Fatalf("Marshal(%T) error=%v", value, err)
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, credential.ErrProtectedProjection) {
			t.Fatalf("MarshalText(%T) error=%v", value, err)
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("protected", slog.Any("value", value))
		projection := fmt.Sprintf("%+v %#v %s", value, value, output.String())
		for _, forbidden := range []string{intent.HandoffRef, auth.SessionID, auth.CSRF} {
			if strings.Contains(projection, forbidden) {
				t.Fatalf("%T leaked protected value %q", value, forbidden)
			}
		}
	}
}

func TestConnectionCandidateIsBrowserBoundAndConsumedOnce(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{snapshots: []device.Snapshot{testSnapshot("SN-ONE-739184")}}
	var factoryCalls int
	vault := New(func(_, _, _ string) device.Client {
		factoryCalls++
		return fake
	})
	browserA := newBrowser(t, vault)
	browserB := newBrowser(t, vault)
	preview, err := vault.PrepareConnection(browserA.SessionID, "10.20.30.40", "admin")
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("private-password")
	if _, err := vault.Connect(context.Background(), browserB.SessionID, preview.Token, password); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-browser candidate err=%v", err)
	}
	for _, value := range password {
		if value != 0 {
			t.Fatal("rejected password buffer was not cleared")
		}
	}
	if fake.logins != 0 || factoryCalls != 0 {
		t.Fatal("cross-browser candidate reached the device")
	}
	if _, err := vault.Connect(context.Background(), browserA.SessionID, preview.Token, []byte("private-password")); !errors.Is(err, ErrConflict) {
		t.Fatalf("consumed candidate was reusable: %v", err)
	}
}

func TestConnectAndReadEnforceIdentityContinuity(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{snapshots: []device.Snapshot{
		testSnapshot("SN-ONE-739184"),
		testSnapshot("SN-ONE-739184"),
		testSnapshot("SN-DRIFTED-111111"),
	}}
	vault := New(func(_, _, _ string) device.Client { return fake })
	browser := newBrowser(t, vault)
	preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", "admin")
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("private-password")
	connected, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, password)
	if err != nil || connected.State != "connecting" || connected.MaskedID != "***9184" {
		t.Fatalf("connect=%#v err=%v", connected, err)
	}
	for _, value := range password {
		if value != 0 {
			t.Fatal("accepted password buffer was not cleared")
		}
	}
	if _, err := vault.Read(context.Background()); err != nil {
		t.Fatalf("stable identity read: %v", err)
	}
	if _, err := vault.Read(context.Background()); !errors.Is(err, ErrIdentityDrift) {
		t.Fatalf("identity drift err=%v", err)
	}
}

func TestConnectionCandidateExpiresWithoutDeviceIO(t *testing.T) {
	t.Parallel()
	current := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	fake := &fakeClient{snapshots: []device.Snapshot{testSnapshot("SN-ONE-739184")}}
	var factoryCalls int
	vault := New(func(_, _, _ string) device.Client {
		factoryCalls++
		return fake
	})
	vault.now = func() time.Time { return current }
	browser := newBrowser(t, vault)
	preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", "admin")
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(candidateTTL + time.Second)
	password := []byte("private-password")
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, password); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired candidate err=%v", err)
	}
	if factoryCalls != 0 || fake.logins != 0 {
		t.Fatal("expired candidate reached the device")
	}
	for _, value := range password {
		if value != 0 {
			t.Fatal("expired password buffer was not cleared")
		}
	}
}

func newBrowser(t *testing.T, vault *Vault) BrowserAuth {
	t.Helper()
	token, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := vault.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	return browser
}

func testSnapshot(serial string) device.Snapshot {
	return device.Snapshot{Identity: device.Identity{Serial: serial, Type: "edge"}, Cameras: []device.Camera{}, Tasks: []device.Task{}}
}

type fakeClient struct {
	mu        sync.Mutex
	logins    int
	snapshots []device.Snapshot
}

func (f *fakeClient) Login(context.Context) error {
	f.mu.Lock()
	f.logins++
	f.mu.Unlock()
	return nil
}

func (f *fakeClient) Read(context.Context) (device.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.snapshots) == 0 {
		return device.Snapshot{}, errors.New("no snapshot")
	}
	snapshot := f.snapshots[0]
	if len(f.snapshots) > 1 {
		f.snapshots = f.snapshots[1:]
	}
	return snapshot, nil
}

func (f *fakeClient) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{ByTask: map[string]device.TaskEventObservation{}}
}
