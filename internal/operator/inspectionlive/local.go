package inspectionlive

import (
	"context"
	"errors"
	"net/http"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionlocal"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

type localBrowserSessions struct{ vault *session.Vault }

func (s localBrowserSessions) ResolveInspectionSession(sessionID string) (inspectionlocal.BrowserSession, error) {
	auth, err := s.vault.Authenticate(sessionID)
	if err != nil {
		return inspectionlocal.BrowserSession{}, err
	}
	handoffRef, err := s.vault.InspectionHandoff(auth)
	if err != nil {
		return inspectionlocal.BrowserSession{}, err
	}
	return inspectionlocal.BrowserSession{
		SessionID: auth.SessionID, CSRF: auth.CSRF, View: auth.View,
		TaskName: auth.TaskName, TaskAction: auth.TaskAction, HandoffRef: handoffRef,
	}, nil
}

type localConnectionProbe struct{ vault *session.Vault }

func (p localConnectionProbe) PrepareConnection(sessionID, endpoint, username string) (string, error) {
	preview, err := p.vault.PrepareConnection(sessionID, endpoint, username)
	return preview.Token, err
}

func (p localConnectionProbe) Connect(ctx context.Context, sessionID, candidateToken string, password []byte) error {
	_, err := p.vault.Connect(ctx, sessionID, candidateToken, password)
	return sanitizeLocalConnectionError(err)
}

func sanitizeLocalConnectionError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, session.ErrConnectionLoginRejected):
		return inspectionlocal.ErrConnectionRejected
	case errors.Is(err, session.ErrConnectionLoginThrottled):
		return inspectionlocal.ErrConnectionThrottled
	case errors.Is(err, session.ErrConnectionLoginUnavailable):
		return inspectionlocal.ErrConnectionUnavailable
	case errors.Is(err, session.ErrConnectionReadUnavailable):
		return inspectionlocal.ErrConnectionReadUnavailable
	case errors.Is(err, session.ErrConnectionPersistenceFailure):
		return inspectionlocal.ErrConnectionPersistenceFailed
	default:
		return inspectionlocal.ErrConnectionRequestUnavailable
	}
}

// LocalInteractionHandler composes the existing foreground Vault with the
// current Product-owned handoff/onboarding generation. It exposes no private
// store and cannot outlive the Product generation gate.
func (s *Service) LocalInteractionHandler(baseURL, sessionCookie string, vault *session.Vault) (http.Handler, error) {
	if s == nil || s.product == nil || vault == nil {
		return nil, errors.New("live local interaction service is unavailable")
	}
	binder, err := inspectionlocal.NewSessionBinder(inspectionlocal.SessionBinderConfig{Sessions: localBrowserSessions{vault: vault}})
	if err != nil {
		return nil, err
	}
	application, err := s.product.LocalInteractions(binder)
	if err != nil {
		return nil, err
	}
	return inspectionlocal.NewHTTPHandler(inspectionlocal.HTTPConfig{
		BaseURL: baseURL, SessionCookie: sessionCookie, Sessions: binder,
		Application: application, Connections: localConnectionProbe{vault: vault},
	})
}
