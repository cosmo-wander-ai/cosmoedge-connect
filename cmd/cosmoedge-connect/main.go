// CosmoEdge Connect runs the three operations in one process, with one connection owner.
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
	"syscall"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deployment"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deploymentlocal"
	operationsapi "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/observation"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	ordinaryapp "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/app"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionowner"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionhost"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/kernel"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
	ordinaryweb "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/web"
)

type config struct {
	stateRoot, tokenFile, listen string
	openOperator                 bool
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version-json" {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], openBrowser); err != nil {
		fmt.Fprintln(os.Stderr, "CosmoEdge Connect 服务未能启动或已停止；请检查安装状态。")
		os.Exit(1)
	}
}
func parseConfig(args []string) (config, error) {
	var c config
	flags := flag.NewFlagSet("cosmoedge-connect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&c.stateRoot, "state-root", "", "private runtime state directory")
	flags.StringVar(&c.tokenFile, "token-file", "", "private access token")
	flags.StringVar(&c.listen, "listen", "127.0.0.1:37789", "loopback listener")
	flags.BoolVar(&c.openOperator, "open-operator", true, "open device connection page when needed")
	if flags.Parse(args) != nil || flags.NArg() != 0 || c.stateRoot == "" || c.tokenFile == "" {
		return c, errors.New("invalid service arguments")
	}
	return c, nil
}
func run(ctx context.Context, args []string, opener func(string) error) error {
	c, err := parseConfig(args)
	if err != nil {
		return err
	}
	if ctx == nil || opener == nil {
		return errors.New("service context and opener required")
	}
	p := &provider{config: c, opener: opener, vault: session.New(nil)}
	host, err := inspectionhost.New(inspectionhost.Config{Enabled: true, Address: c.listen}, p)
	if err != nil {
		return err
	}
	if err = host.Start(ctx); err != nil {
		return err
	}
	defer host.Stop()
	<-ctx.Done()
	return nil
}

type provider struct {
	config       config
	opener       func(string) error
	vault        *session.Vault
	owner        *connectionowner.Owner
	actions      *actions.Manager
	deployments  *deployment.Service
	observations *observation.Service
	ledger       *ledger.Store
	handler      http.Handler
	local        *http.Server
	localDone    chan error
	localReview  *deploymentlocal.Handler
}

func (p *provider) Start(ctx context.Context) error {
	var err error
	p.owner, err = connectionowner.New(connectionowner.Config{StateRoot: p.config.stateRoot, TokenFile: p.config.tokenFile, Vault: p.vault})
	if err != nil {
		return err
	}
	restored, err := p.owner.Start(ctx)
	if err != nil {
		return err
	}
	fail := func(err error) error { return errors.Join(err, p.Stop()) }
	opRoot := filepath.Join(p.config.stateRoot, "operator")
	if err = localstate.PrepareStateRoot(opRoot); err != nil {
		return fail(err)
	}
	p.ledger, err = ledger.Open(filepath.Join(opRoot, "operator.db"))
	if err != nil {
		return fail(err)
	}
	p.deployments, err = deployment.New(p.ledger, p.vault)
	if err != nil {
		return fail(err)
	}
	p.actions, err = actions.NewWithHandlers(p.ledger, p.vault, map[string]kernel.Handler{deployment.Kind: p.deployments})
	if err != nil {
		return fail(err)
	}
	if err = p.actions.Start(ctx); err != nil {
		return fail(err)
	}
	p.observations, err = observation.New(observation.Config{StateRoot: p.config.stateRoot, Vault: p.vault})
	if err != nil {
		return fail(err)
	}
	if err = p.observations.Start(ctx); err != nil {
		return fail(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fail(err)
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		listener.Close()
		return fail(err)
	}
	localBase := "http://" + listener.Addr().String()
	localHost := ordinaryweb.New(localBase, hex.EncodeToString(random), ordinaryapp.New(p.vault, p.actions), p.vault, p.opener)
	clear(random)
	openConnection := func() error {
		url, err := localHost.BootstrapURL(session.ViewConnection)
		if err != nil {
			return err
		}
		return p.opener(url)
	}
	localReview, err := deploymentlocal.New(deploymentlocal.Config{BaseURL: localBase, SessionCookie: ordinaryweb.SessionCookieName, Vault: p.vault, Deployments: p.deployments, Open: localHost.OpenDeploymentReview})
	if err != nil {
		listener.Close()
		return fail(err)
	}
	if err = localHost.MountDeploymentReview(localReview); err != nil {
		listener.Close()
		return fail(err)
	}
	p.localReview = localReview
	digest, err := p.owner.TokenDigest()
	if err != nil {
		listener.Close()
		return fail(err)
	}
	p.handler, err = operationsapi.New(operationsapi.Config{TokenDigest: digest, Connections: p.vault, OpenConnection: openConnection, OpenDeploymentReview: localReview.OpenReview, Deployments: p.deployments, Observations: p.observations})
	if err != nil {
		listener.Close()
		return fail(err)
	}
	localServer := &http.Server{Handler: localHost, ReadHeaderTimeout: 5 * time.Second}
	localDone := make(chan error, 1)
	p.local, p.localDone = localServer, localDone
	// Stop may run before this goroutine is scheduled. Keep this generation's
	// server and completion channel even after the provider clears its fields.
	go func() { localDone <- localServer.Serve(listener) }()
	// This contains only local discovery and build identity, never an auth token.
	discovery, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "version": buildinfo.Current(), "operatorBaseURL": localBase, "connectionRestoreState": restored})
	if err = os.WriteFile(filepath.Join(p.config.stateRoot, "service.json"), discovery, 0600); err != nil {
		return fail(err)
	}
	if p.config.openOperator && restored != connectionregistry.RestoreConnected {
		_ = openConnection()
	}
	return nil
}
func (p *provider) Handler() (http.Handler, error) {
	if p.handler == nil {
		return nil, errors.New("operations handler unavailable")
	}
	return p.handler, nil
}
func (p *provider) Stop() error {
	var err error
	if p.localReview != nil {
		p.localReview.Close()
		p.localReview = nil
	}
	if p.local != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = errors.Join(err, p.local.Shutdown(ctx))
		cancel()
		p.local = nil
		if p.localDone != nil {
			if e := <-p.localDone; !errors.Is(e, http.ErrServerClosed) {
				err = errors.Join(err, e)
			}
			p.localDone = nil
		}
	}
	if p.observations != nil {
		err = errors.Join(err, p.observations.Stop())
		p.observations = nil
	}
	if p.actions != nil {
		p.actions.Stop()
		p.actions = nil
	}
	if p.deployments != nil {
		p.deployments.Close()
		p.deployments = nil
	}
	if p.ledger != nil {
		err = errors.Join(err, p.ledger.Close())
		p.ledger = nil
	}
	if p.owner != nil {
		err = errors.Join(err, p.owner.Stop())
		p.owner = nil
	}
	return err
}
