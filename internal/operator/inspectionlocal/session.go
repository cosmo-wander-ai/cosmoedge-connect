package inspectionlocal

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

const localSessionBindingDomain = "cosmoedge.operator.inspection-local.browser-binding.v1\x00"

// BrowserSession is the least-privilege projection required to bind one local
// page to one already-authenticated Operator browser and one exact handoff.
// The Operator session seal and all bootstrap authority remain in the caller's
// session implementation.
type BrowserSession struct {
	SessionID  string
	CSRF       string
	View       string
	TaskName   string
	TaskAction string
	HandoffRef string
}

type BrowserSessionReader interface {
	ResolveInspectionSession(string) (BrowserSession, error)
}

type SessionBinderConfig struct {
	Sessions BrowserSessionReader
}

// SessionBinder is the only LocalSession mint. It re-authenticates against the
// existing operator session Vault on every application call and accepts only
// the handoff privately sealed into that browser during bootstrap.
type SessionBinder struct {
	sessions BrowserSessionReader
}

func NewSessionBinder(config SessionBinderConfig) (*SessionBinder, error) {
	if config.Sessions == nil {
		return nil, ErrUnavailable
	}
	return newSessionBinder(config.Sessions)
}

func newSessionBinder(sessions BrowserSessionReader) (*SessionBinder, error) {
	if sessions == nil {
		return nil, ErrUnavailable
	}
	return &SessionBinder{sessions: sessions}, nil
}

// Authenticate creates a read-only local application session. It is suitable
// for resolving the closed local-page state but cannot authorize a mutation.
func (b *SessionBinder) Authenticate(sessionID string) (BrowserSession, LocalSession, error) {
	return b.authenticate(sessionID)
}

// AuthorizePost creates a write-authorized local session only after exact CSRF
// validation against the current authenticated browser record.
func (b *SessionBinder) AuthorizePost(sessionID, presentedCSRF string) (BrowserSession, LocalSession, error) {
	auth, local, err := b.authenticate(sessionID)
	if err != nil {
		return BrowserSession{}, LocalSession{}, err
	}
	if !browserRefPattern.MatchString(presentedCSRF) ||
		subtle.ConstantTimeCompare([]byte(presentedCSRF), []byte(auth.CSRF)) != 1 {
		return BrowserSession{}, LocalSession{}, ErrDenied
	}
	local.writeAuthorized = true
	return auth, local, nil
}

func (b *SessionBinder) authenticate(sessionID string) (BrowserSession, LocalSession, error) {
	if b == nil || b.sessions == nil || !browserRefPattern.MatchString(sessionID) {
		return BrowserSession{}, LocalSession{}, ErrInvalidSession
	}
	auth, err := b.sessions.ResolveInspectionSession(sessionID)
	if err != nil {
		return BrowserSession{}, LocalSession{}, ErrInvalidSession
	}
	if auth.SessionID != sessionID || !browserRefPattern.MatchString(auth.SessionID) || !browserRefPattern.MatchString(auth.CSRF) {
		return BrowserSession{}, LocalSession{}, ErrInvalidSession
	}
	handoffRef := auth.HandoffRef
	if !validHandoffRef(handoffRef) {
		return BrowserSession{}, LocalSession{}, ErrInvalidSession
	}
	local := LocalSession{
		sessionID: sessionID, handoffRef: handoffRef,
		browserBindingSHA256: browserBindingDigest(auth, handoffRef),
	}
	if !local.valid() {
		return BrowserSession{}, LocalSession{}, ErrInvalidSession
	}
	return auth, local, nil
}

func (b *SessionBinder) validate(local LocalSession, requireWrite bool) (LocalSession, error) {
	if b == nil || b.sessions == nil || !local.valid() {
		return LocalSession{}, ErrInvalidSession
	}
	_, current, err := b.authenticate(local.sessionID)
	if err != nil || current.handoffRef != local.handoffRef ||
		subtle.ConstantTimeCompare([]byte(current.browserBindingSHA256), []byte(local.browserBindingSHA256)) != 1 {
		return LocalSession{}, ErrInvalidSession
	}
	if requireWrite && !local.writeAuthorized {
		return LocalSession{}, ErrDenied
	}
	current.writeAuthorized = local.writeAuthorized
	return current, nil
}

func browserBindingDigest(auth BrowserSession, handoffRef string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(localSessionBindingDomain))
	for _, value := range []string{auth.SessionID, auth.CSRF, auth.View, auth.TaskName, auth.TaskAction, handoffRef} {
		writeDigestString(digest, value)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeDigestString(digest hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write([]byte(value))
}
