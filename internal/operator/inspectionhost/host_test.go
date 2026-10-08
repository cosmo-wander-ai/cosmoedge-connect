package inspectionhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDisabledHostHasNoEffects(t *testing.T) {
	provider := &recordingProvider{}
	host, err := New(Config{Enabled: false, Address: "0.0.0.0:0"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := host.Stop(); err != nil {
		t.Fatal(err)
	}
	if starts, handlers, stops := provider.counts(); starts != 0 || handlers != 0 || stops != 0 {
		t.Fatalf("disabled host touched provider: starts=%d handlers=%d stops=%d", starts, handlers, stops)
	}
	if readiness := host.Readiness(); readiness.Enabled || readiness.Ready || readiness.State != StateDisabled || readiness.Generation != 0 || readiness.Address != "" || readiness.Failure != "" {
		t.Fatalf("disabled readiness=%+v", readiness)
	}
}

func TestHostRejectsEveryNonLiteralOrNonLoopbackAddressBeforeProviderStart(t *testing.T) {
	for _, address := range []string{
		"", "localhost:37789", "0.0.0.0:37789", "192.168.1.10:37789", ":37789",
		"127.0.0.1:0", "127.0.0.1:http", " 127.0.0.1:37789", "[::]:37789", "[fe80::1]:37789",
	} {
		t.Run(strings.ReplaceAll(address, "/", "_"), func(t *testing.T) {
			provider := &recordingProvider{}
			host, err := New(Config{Enabled: true, Address: address}, provider)
			if err != nil {
				t.Fatal(err)
			}
			if err := host.Start(context.Background()); err == nil {
				t.Fatalf("unsafe address %q was accepted", address)
			}
			if starts, handlers, stops := provider.counts(); starts != 0 || handlers != 0 || stops != 0 {
				t.Fatalf("unsafe address touched provider: starts=%d handlers=%d stops=%d", starts, handlers, stops)
			}
			if readiness := host.Readiness(); readiness.State != StateFailed || readiness.Ready || readiness.Failure != "address_invalid" {
				t.Fatalf("unsafe address readiness=%+v", readiness)
			}
		})
	}
}

func TestAddressValidationCanonicalizesLiteralLoopbackOnly(t *testing.T) {
	for _, testCase := range []struct {
		raw         string
		wantNetwork string
		wantAddress string
	}{
		{raw: "127.0.0.1:37789", wantNetwork: "tcp4", wantAddress: "127.0.0.1:37789"},
		{raw: "127.0.0.2:37789", wantNetwork: "tcp4", wantAddress: "127.0.0.2:37789"},
		{raw: "[0:0:0:0:0:0:0:1]:37789", wantNetwork: "tcp6", wantAddress: "[::1]:37789"},
	} {
		network, address, err := validateLoopbackAddress(testCase.raw)
		if err != nil {
			t.Fatalf("validate %q: %v", testCase.raw, err)
		}
		if network != testCase.wantNetwork || address != testCase.wantAddress {
			t.Fatalf("validate %q=(%q,%q), want (%q,%q)", testCase.raw, network, address, testCase.wantNetwork, testCase.wantAddress)
		}
	}
}

func TestHostStartsStopsAndRestartsWithFreshProviderHandler(t *testing.T) {
	address := availableAddress(t)
	provider := &recordingProvider{}
	host := newTestHost(t, address, provider)
	client := &http.Client{Timeout: time.Second}

	for generation := uint64(1); generation <= 2; generation++ {
		if err := host.Start(context.Background()); err != nil {
			t.Fatalf("start generation %d: %v", generation, err)
		}
		readiness := host.Readiness()
		if !readiness.Enabled || !readiness.Ready || readiness.State != StateReady || readiness.Generation != generation || readiness.Address != address || readiness.Failure != "" {
			t.Fatalf("generation %d readiness=%+v", generation, readiness)
		}
		response, body := get(t, client, address, "")
		if response.StatusCode != http.StatusOK || body != fmt.Sprintf("provider-generation-%d", generation) {
			t.Fatalf("generation %d response status=%d body=%q", generation, response.StatusCode, body)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("security headers=%v", response.Header)
		}
		if err := host.Stop(); err != nil {
			t.Fatalf("stop generation %d: %v", generation, err)
		}
		if readiness := host.Readiness(); readiness.Ready || readiness.State != StateStopped || readiness.Generation != generation {
			t.Fatalf("stopped generation %d readiness=%+v", generation, readiness)
		}
	}
	if starts, handlers, stops := provider.counts(); starts != 2 || handlers != 2 || stops != 2 {
		t.Fatalf("provider lifecycle starts=%d handlers=%d stops=%d", starts, handlers, stops)
	}
}

func TestBindConflictRollsBackProviderAndCanRetry(t *testing.T) {
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := blocker.Addr().String()
	provider := &recordingProvider{}
	host := newTestHost(t, address, provider)
	if err := host.Start(context.Background()); err == nil {
		t.Fatal("host accepted an occupied address")
	}
	if starts, handlers, stops := provider.counts(); starts != 1 || handlers != 1 || stops != 1 {
		t.Fatalf("bind rollback starts=%d handlers=%d stops=%d", starts, handlers, stops)
	}
	if readiness := host.Readiness(); readiness.State != StateFailed || readiness.Failure != "listen_failed" || readiness.Generation != 0 {
		t.Fatalf("bind failure readiness=%+v", readiness)
	}
	if err := blocker.Close(); err != nil {
		t.Fatal(err)
	}
	if err := host.Start(context.Background()); err != nil {
		t.Fatalf("retry after released bind: %v", err)
	}
	if readiness := host.Readiness(); !readiness.Ready || readiness.Generation != 1 {
		t.Fatalf("retry readiness=%+v", readiness)
	}
	if err := host.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderAndHandlerStartupFailuresRollbackCompletely(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		provider    *recordingProvider
		wantFailure string
		wantCounts  [3]int
	}{
		{name: "provider start", provider: &recordingProvider{startErr: errors.New("start failed")}, wantFailure: "provider_start_failed", wantCounts: [3]int{1, 0, 1}},
		{name: "handler", provider: &recordingProvider{handlerErr: errors.New("handler failed")}, wantFailure: "handler_unavailable", wantCounts: [3]int{1, 1, 1}},
		{name: "typed nil handler", provider: &recordingProvider{typedNilHandler: true}, wantFailure: "handler_unavailable", wantCounts: [3]int{1, 1, 1}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			host := newTestHost(t, availableAddress(t), testCase.provider)
			if err := host.Start(context.Background()); err == nil {
				t.Fatal("startup failure was accepted")
			}
			starts, handlers, stops := testCase.provider.counts()
			if [3]int{starts, handlers, stops} != testCase.wantCounts {
				t.Fatalf("provider lifecycle=%v, want %v", [3]int{starts, handlers, stops}, testCase.wantCounts)
			}
			if readiness := host.Readiness(); readiness.State != StateFailed || readiness.Ready || readiness.Failure != testCase.wantFailure || readiness.Generation != 0 {
				t.Fatalf("startup failure readiness=%+v", readiness)
			}
		})
	}
}

func TestContextCanceledDuringStartupRollsBackProviderBeforeListen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := &recordingProvider{handlerFactory: func(uint64) http.Handler {
		cancel()
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}}
	host := newTestHost(t, availableAddress(t), provider)
	if err := host.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation error=%v", err)
	}
	if starts, handlers, stops := provider.counts(); starts != 1 || handlers != 1 || stops != 1 {
		t.Fatalf("startup cancellation lifecycle starts=%d handlers=%d stops=%d", starts, handlers, stops)
	}
	if readiness := host.Readiness(); readiness.State != StateFailed || readiness.Failure != "startup_context_closed" || readiness.Generation != 0 {
		t.Fatalf("startup cancellation readiness=%+v", readiness)
	}
}

func TestStopRejectsNewRequestsAndDrainsAdmittedRequestBeforeProviderStop(t *testing.T) {
	address := availableAddress(t)
	started := make(chan struct{})
	release := make(chan struct{})
	provider := &recordingProvider{handlerFactory: func(uint64) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			response.WriteHeader(http.StatusNoContent)
		})
	}}
	host := newTestHost(t, address, provider)
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		response, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + address + "/api/inspection")
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				err = fmt.Errorf("status=%d", response.StatusCode)
			}
		}
		requestDone <- err
	}()
	<-started
	stopDone := make(chan error, 1)
	go func() { stopDone <- host.Stop() }()
	waitFor(t, func() bool { return host.Readiness().State == StateStopping })
	if _, _, stops := provider.counts(); stops != 0 {
		t.Fatalf("provider stopped before HTTP drain: %d", stops)
	}
	select {
	case err := <-stopDone:
		t.Fatalf("stop returned before request drain: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if _, _, stops := provider.counts(); stops != 1 {
		t.Fatalf("provider stop count=%d", stops)
	}
}

func TestUnexpectedServeFailureFailsClosedAndPreservesFailureAfterCleanup(t *testing.T) {
	address := availableAddress(t)
	provider := &recordingProvider{}
	host := newTestHost(t, address, provider)
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	host.mu.RLock()
	listener := host.listener
	host.mu.RUnlock()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return host.Readiness().State == StateFailed })
	if readiness := host.Readiness(); readiness.Ready || readiness.Failure != "serve_failed" {
		t.Fatalf("serve failure readiness=%+v", readiness)
	}
	provider.waitContextCanceled(t)
	if err := host.Stop(); err == nil {
		t.Fatal("cleanup hid unexpected serve failure")
	}
	if readiness := host.Readiness(); readiness.State != StateFailed || readiness.Failure != "serve_failed" {
		t.Fatalf("cleaned serve failure readiness=%+v", readiness)
	}
	if _, _, stops := provider.counts(); stops != 1 {
		t.Fatalf("provider stop count=%d", stops)
	}
}

func TestParentCancellationFailsClosedUntilExplicitCleanup(t *testing.T) {
	address := availableAddress(t)
	provider := &recordingProvider{}
	host := newTestHost(t, address, provider)
	ctx, cancel := context.WithCancel(context.Background())
	if err := host.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitFor(t, func() bool { return host.Readiness().State == StateFailed })
	if readiness := host.Readiness(); readiness.Ready || readiness.Failure != "lifecycle_context_closed" {
		t.Fatalf("canceled lifecycle readiness=%+v", readiness)
	}
	provider.waitContextCanceled(t)
	if err := host.Stop(); err != nil {
		t.Fatal(err)
	}
	if readiness := host.Readiness(); readiness.State != StateFailed || readiness.Failure != "lifecycle_context_closed" {
		t.Fatalf("cleaned canceled lifecycle readiness=%+v", readiness)
	}
}

func TestHostHeaderMustMatchConfiguredLoopbackLiteral(t *testing.T) {
	address := availableAddress(t)
	host := newTestHost(t, address, &recordingProvider{})
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Stop() })
	request, err := http.NewRequest(http.MethodGet, "http://"+address+"/api/inspection", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "attacker.example"
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("mismatched Host status=%d", response.StatusCode)
	}
}

func TestEnabledHostRejectsUnboundedTimeouts(t *testing.T) {
	if host, err := New(Config{
		Enabled: true, Address: "127.0.0.1:37789", ReadHeaderTimeout: -time.Second,
	}, &recordingProvider{}); err == nil || host != nil {
		t.Fatalf("negative timeout accepted: host=%v err=%v", host, err)
	}
	if host, err := New(Config{
		Enabled: true, Address: "127.0.0.1:37789", ShutdownTimeout: maxServerTimeout + time.Second,
	}, &recordingProvider{}); err == nil || host != nil {
		t.Fatalf("unbounded timeout accepted: host=%v err=%v", host, err)
	}
}

type recordingProvider struct {
	mu              sync.Mutex
	starts          int
	handlers        int
	stops           int
	current         uint64
	contexts        []context.Context
	startErr        error
	handlerErr      error
	typedNilHandler bool
	handlerFactory  func(uint64) http.Handler
}

func (p *recordingProvider) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.starts++
	p.current++
	p.contexts = append(p.contexts, ctx)
	return p.startErr
}

func (p *recordingProvider) Stop() error {
	p.mu.Lock()
	p.stops++
	p.mu.Unlock()
	return nil
}

func (p *recordingProvider) Handler() (http.Handler, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers++
	if p.handlerErr != nil {
		return nil, p.handlerErr
	}
	if p.typedNilHandler {
		var handler *nilHandler
		return handler, nil
	}
	generation := p.current
	if p.handlerFactory != nil {
		return p.handlerFactory(generation), nil
	}
	return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(response, "provider-generation-%d", generation)
	}), nil
}

func (p *recordingProvider) counts() (int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.starts, p.handlers, p.stops
}

func (p *recordingProvider) waitContextCanceled(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	ctx := p.contexts[len(p.contexts)-1]
	p.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("provider context was not canceled")
	}
}

type nilHandler struct{}

func (*nilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func newTestHost(t *testing.T, address string, provider Provider) *Host {
	t.Helper()
	host, err := New(Config{
		Enabled: true, Address: address,
		ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 2 * time.Second,
		IdleTimeout: time.Second, ShutdownTimeout: time.Second,
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func availableAddress(t *testing.T) string {
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

func get(t *testing.T, client *http.Client, address, hostOverride string) (*http.Response, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://"+address+"/api/inspection", nil)
	if err != nil {
		t.Fatal(err)
	}
	if hostOverride != "" {
		request.Host = hostOverride
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not reached before timeout")
}
