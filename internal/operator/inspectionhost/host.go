// Package inspectionhost owns the explicit loopback HTTP lifecycle for an
// enabled Inspection v2 product. It never enables or assembles a product by
// itself and never listens on a non-loopback interface.
package inspectionhost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 90 * time.Second
	defaultIdleTimeout       = 90 * time.Second
	defaultShutdownTimeout   = 10 * time.Second
	maxServerTimeout         = 10 * time.Minute
	maxHeaderBytes           = 64 << 10
)

var numericPortPattern = regexp.MustCompile(`^[0-9]{1,5}$`)

type State string

const (
	StateDisabled State = "disabled"
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateReady    State = "ready"
	StateStopping State = "stopping"
	StateFailed   State = "failed"
)

type Config struct {
	Enabled           bool
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// Provider is the exact lifecycle and handler boundary implemented by the
// Inspection v2 product. Handler must return a gate for the current successful
// Start generation; Host asks for it again on every restart.
type Provider interface {
	Start(context.Context) error
	Stop() error
	Handler() (http.Handler, error)
}

type Readiness struct {
	Enabled    bool
	Ready      bool
	State      State
	Generation uint64
	Address    string
	Failure    string
}

type Host struct {
	config   Config
	provider Provider

	lifecycle  sync.Mutex
	mu         sync.RWMutex
	state      State
	generation uint64
	failure    string
	active     bool
	address    string
	cancel     context.CancelFunc
	server     *http.Server
	listener   net.Listener
	serveDone  chan error
	watchDone  chan struct{}
}

func New(config Config, provider Provider) (*Host, error) {
	host := &Host{config: config, provider: provider, state: StateDisabled}
	if !config.Enabled {
		return host, nil
	}
	if isNil(provider) {
		return nil, errors.New("enabled inspection host requires a lifecycle provider")
	}
	normalized, err := normalizeTimeouts(config)
	if err != nil {
		return nil, err
	}
	host.config = normalized
	host.state = StateStopped
	return host, nil
}

func (h *Host) Start(parent context.Context) error {
	if h == nil {
		return errors.New("inspection host is required")
	}
	if !h.config.Enabled {
		return nil
	}
	if parent == nil {
		return errors.New("inspection host parent context is required")
	}
	if err := parent.Err(); err != nil {
		return fmt.Errorf("inspection host parent context is unavailable: %w", err)
	}

	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	h.mu.Lock()
	if h.active || h.state == StateStarting || h.state == StateStopping {
		h.mu.Unlock()
		return errors.New("inspection host lifecycle is already active")
	}
	h.state = StateStarting
	h.failure = ""
	h.mu.Unlock()

	network, address, err := validateLoopbackAddress(h.config.Address)
	if err != nil {
		h.failStartup("address_invalid")
		return err
	}
	lifecycleContext, cancel := context.WithCancel(parent)
	if err := h.provider.Start(lifecycleContext); err != nil {
		cancel()
		stopErr := h.provider.Stop()
		h.failStartup("provider_start_failed")
		return errors.Join(fmt.Errorf("start inspection provider: %w", err), stopErr)
	}
	rollbackProvider := func(stage, failure string, stageErr error) error {
		cancel()
		stopErr := h.provider.Stop()
		h.failStartup(failure)
		return errors.Join(fmt.Errorf("start inspection host %s: %w", stage, stageErr), stopErr)
	}

	handler, err := h.provider.Handler()
	if err != nil || isNil(handler) {
		if err == nil {
			err = errors.New("provider returned a nil handler")
		}
		return rollbackProvider("handler", "handler_unavailable", err)
	}
	if err := lifecycleContext.Err(); err != nil {
		return rollbackProvider("lifecycle context", "startup_context_closed", err)
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return rollbackProvider("listener", "listen_failed", err)
	}
	if err := lifecycleContext.Err(); err != nil {
		closeErr := listener.Close()
		return errors.Join(rollbackProvider("lifecycle context", "startup_context_closed", err), closeErr)
	}
	h.mu.RLock()
	generation := h.generation + 1
	h.mu.RUnlock()

	server := &http.Server{
		Handler:           hostHTTPGate{host: h, generation: generation, expectedHost: address, target: handler},
		ReadHeaderTimeout: h.config.ReadHeaderTimeout,
		ReadTimeout:       h.config.ReadTimeout,
		WriteTimeout:      h.config.WriteTimeout,
		IdleTimeout:       h.config.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return lifecycleContext
		},
	}
	serveDone := make(chan error, 1)
	watchDone := make(chan struct{})

	h.mu.Lock()
	h.active = true
	h.generation = generation
	h.address = address
	h.cancel = cancel
	h.server = server
	h.listener = listener
	h.serveDone = serveDone
	h.watchDone = watchDone
	h.state = StateReady
	h.mu.Unlock()

	go h.serve(generation, server, listener, serveDone)
	go h.watchContext(generation, lifecycleContext, server, watchDone)
	return nil
}

func (h *Host) Stop() error {
	if h == nil || !h.config.Enabled {
		return nil
	}
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()

	h.mu.Lock()
	if !h.active {
		h.mu.Unlock()
		return nil
	}
	failed := h.state == StateFailed
	priorFailure := h.failure
	h.state = StateStopping
	server, cancel := h.server, h.cancel
	serveDone, watchDone := h.serveDone, h.watchDone
	h.mu.Unlock()

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), h.config.ShutdownTimeout)
	shutdownErr := server.Shutdown(shutdownContext)
	shutdownCancel()
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	serveErr := <-serveDone
	cancel()
	<-watchDone
	providerErr := h.provider.Stop()
	stopErr := errors.Join(shutdownErr, serveErr, providerErr)

	h.mu.Lock()
	h.active = false
	h.cancel = nil
	h.server = nil
	h.listener = nil
	h.serveDone = nil
	h.watchDone = nil
	if failed {
		h.state = StateFailed
		h.failure = priorFailure
	} else if stopErr != nil {
		h.state = StateFailed
		h.failure = "shutdown_failed"
	} else {
		h.state = StateStopped
		h.failure = ""
	}
	h.mu.Unlock()
	return stopErr
}

func (h *Host) Readiness() Readiness {
	if h == nil {
		return Readiness{State: StateFailed, Failure: "host_unavailable"}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return Readiness{
		Enabled: h.config.Enabled, Ready: h.state == StateReady, State: h.state,
		Generation: h.generation, Address: h.address, Failure: h.failure,
	}
}

func (h *Host) serve(generation uint64, server *http.Server, listener net.Listener, done chan<- error) {
	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if err != nil {
		h.failRuntime(generation, "serve_failed", server)
	}
	done <- err
}

func (h *Host) watchContext(generation uint64, ctx context.Context, server *http.Server, done chan<- struct{}) {
	defer close(done)
	<-ctx.Done()
	h.failRuntime(generation, "lifecycle_context_closed", server)
}

func (h *Host) failRuntime(generation uint64, failure string, server *http.Server) {
	h.mu.Lock()
	if !h.active || h.generation != generation || h.state != StateReady || h.server != server {
		h.mu.Unlock()
		return
	}
	h.state = StateFailed
	h.failure = failure
	cancel := h.cancel
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = server.Close()
}

func (h *Host) failStartup(failure string) {
	h.mu.Lock()
	h.state = StateFailed
	h.failure = failure
	h.mu.Unlock()
}

func normalizeTimeouts(config Config) (Config, error) {
	for target, fallback := range map[*time.Duration]time.Duration{
		&config.ReadHeaderTimeout: defaultReadHeaderTimeout,
		&config.ReadTimeout:       defaultReadTimeout,
		&config.WriteTimeout:      defaultWriteTimeout,
		&config.IdleTimeout:       defaultIdleTimeout,
		&config.ShutdownTimeout:   defaultShutdownTimeout,
	} {
		if *target == 0 {
			*target = fallback
		}
		if *target <= 0 || *target > maxServerTimeout {
			return Config{}, errors.New("inspection host timeouts must be positive and bounded")
		}
	}
	return config, nil
}

func validateLoopbackAddress(raw string) (string, string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00/?#") {
		return "", "", errors.New("inspection host requires a literal loopback address")
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil || host == "" || !numericPortPattern.MatchString(portText) {
		return "", "", errors.New("inspection host requires a literal loopback address and fixed port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", errors.New("inspection host port must be fixed and valid")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || !address.IsLoopback() {
		return "", "", errors.New("inspection host address must be a loopback IP literal")
	}
	network := "tcp6"
	if address.Is4() {
		network = "tcp4"
	}
	return network, net.JoinHostPort(address.String(), strconv.Itoa(port)), nil
}

type hostHTTPGate struct {
	host         *Host
	generation   uint64
	expectedHost string
	target       http.Handler
}

func (g hostHTTPGate) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Frame-Options", "DENY")
	if request.Host != g.expectedHost || request.URL.IsAbs() {
		http.Error(response, "loopback host unavailable", http.StatusMisdirectedRequest)
		return
	}
	if g.host == nil || isNil(g.target) {
		http.Error(response, "inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	g.host.mu.RLock()
	available := g.host.active && g.host.state == StateReady && g.host.generation == g.generation
	g.host.mu.RUnlock()
	if !available {
		http.Error(response, "inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	g.target.ServeHTTP(response, request)
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
