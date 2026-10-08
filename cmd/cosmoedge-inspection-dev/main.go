package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	ordinaryapp "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/app"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionlive"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
	ordinaryweb "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/web"
)

type config struct {
	stateRoot    string
	tokenFile    string
	listen       string
	openOperator bool
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version-json" {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], openBrowser); err != nil {
		fmt.Fprintln(os.Stderr, "CosmoEdge 现场巡检开发服务启动失败")
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, opener func(string) error) error {
	config, err := parseConfig(args)
	if err != nil {
		return err
	}
	if ctx == nil {
		return errors.New("service context is required")
	}
	if opener == nil {
		return errors.New("operator page opener is required")
	}
	if err := localstate.PrepareStateRoot(config.stateRoot); err != nil {
		return err
	}
	if err := localstate.ValidateExistingStateFiles(config.stateRoot); err != nil {
		return err
	}

	vault := session.New(nil)
	connections, err := inspectionlive.NewVaultConnections(vault)
	if err != nil {
		return err
	}
	operatorRoot := filepath.Join(config.stateRoot, "operator")
	if err := localstate.PrepareStateRoot(operatorRoot); err != nil {
		return err
	}
	store, err := ledger.Open(filepath.Join(operatorRoot, "operator.db"))
	if err != nil {
		return err
	}
	defer store.Close()
	actionManager, err := actions.New(store, vault)
	if err != nil {
		return err
	}
	if err := actionManager.Start(ctx); err != nil {
		return err
	}
	defer actionManager.Stop()

	interactionOpener := &localInteractionOpener{}
	inspectionService, err := inspectionlive.New(inspectionlive.Config{
		StateRoot: config.stateRoot, TokenFile: config.tokenFile, Address: config.listen,
		Snapshots: vault, Connections: connections, Sessions: vault, OpenInteraction: interactionOpener.Open,
	})
	if err != nil {
		return err
	}
	if err := inspectionService.Start(ctx); err != nil {
		_ = inspectionService.Stop()
		return err
	}
	defer inspectionService.Stop()
	restoreState, err := inspectionService.ConnectionRestoreState()
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	baseURL := "http://" + listener.Addr().String()
	controlToken, err := randomHex(32)
	if err != nil {
		_ = listener.Close()
		return err
	}
	host := ordinaryweb.New(baseURL, controlToken, ordinaryapp.New(vault, actionManager), vault, opener)
	localHandler, err := inspectionService.LocalInteractionHandler(baseURL, ordinaryweb.SessionCookieName, vault)
	if err != nil {
		_ = listener.Close()
		return err
	}
	if err := host.MountInspectionLocal(localHandler); err != nil {
		_ = listener.Close()
		return err
	}
	interactionOpener.Set(host)
	defer interactionOpener.Set(nil)
	server := &http.Server{Handler: host, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	if shouldOpenOperator(config.openOperator, restoreState) {
		bootstrap, bootstrapErr := host.BootstrapURL("home")
		if bootstrapErr != nil {
			_ = server.Close()
			return bootstrapErr
		}
		// Opening the page is a convenience, not service authority. A desktop
		// opener failure must not tear down the already-ready loopback service.
		_ = opener(bootstrap)
	}

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := server.Shutdown(shutdownContext)
		cancel()
		serveErr := <-serveErrors
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		return errors.Join(shutdownErr, serveErr)
	case serveErr := <-serveErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	}
}

func shouldOpenOperator(requested bool, restoreState connectionregistry.RestoreState) bool {
	return requested && restoreState != connectionregistry.RestoreConnected
}

type localInteractionOpener struct {
	mu   sync.RWMutex
	host *ordinaryweb.Host
}

func (o *localInteractionOpener) Set(host *ordinaryweb.Host) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.host = host
	o.mu.Unlock()
}

func (o *localInteractionOpener) Open(capability, handoffRef string) error {
	if o == nil || !httpapi.ValidInteractionCapability(capability) {
		return errors.New("local interaction opener is unavailable")
	}
	o.mu.RLock()
	host := o.host
	o.mu.RUnlock()
	if host == nil {
		return errors.New("local interaction opener is unavailable")
	}
	return host.OpenInspectionInteraction(handoffRef)
}

func parseConfig(args []string) (config, error) {
	flags := flag.NewFlagSet("cosmoedge-inspection-dev", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var result config
	flags.StringVar(&result.stateRoot, "state-root", "", "private runtime state directory")
	flags.StringVar(&result.tokenFile, "token-file", "", "owner-only WorkBuddy token")
	flags.StringVar(&result.listen, "listen", inspectionlive.DefaultAddress, "inspection loopback listener")
	flags.BoolVar(&result.openOperator, "open-operator", true, "open the local Operator connection page")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return config{}, errors.New("invalid command arguments")
	}
	if result.stateRoot == "" || result.tokenFile == "" || result.listen == "" {
		return config{}, errors.New("--state-root, --token-file, and --listen are required")
	}
	stateRoot, err := filepath.Abs(result.stateRoot)
	if err != nil {
		return config{}, err
	}
	tokenFile, err := filepath.Abs(result.tokenFile)
	if err != nil {
		return config{}, err
	}
	result.stateRoot, result.tokenFile = stateRoot, tokenFile
	return result, nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
