package kernel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

var ErrWorkerUnavailable = errors.New("action worker is owned by another process")

const (
	workerName     = "operator"
	workerLeaseTTL = 15 * time.Second
	workerRenewal  = 3 * time.Second
)

type Dispatch struct {
	Outcome          string
	DeviceWriteCount int
	Diagnostic       *safediagnostic.Diagnostic `json:"diagnostic,omitempty"`
}

type Handler interface {
	Validate(context.Context, ledger.Action) error
	Dispatch(context.Context, ledger.Action) Dispatch
	Verify(context.Context, ledger.Action, Dispatch) result.Trusted
}

type Kernel struct {
	store    *ledger.Store
	now      func() time.Time
	ownerID  string
	handlers map[string]Handler
	wake     chan struct{}

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func New(store *ledger.Store, handlers map[string]Handler) (*Kernel, error) {
	if store == nil {
		return nil, errors.New("action ledger is required")
	}
	ownerID, err := randomID(16)
	if err != nil {
		return nil, err
	}
	return &Kernel{store: store, now: time.Now, ownerID: ownerID, handlers: handlers, wake: make(chan struct{}, 1)}, nil
}

func (k *Kernel) Propose(ctx context.Context, input ledger.NewAction) (ledger.Action, error) {
	if input.ID == "" {
		id, err := randomID(16)
		if err != nil {
			return ledger.Action{}, err
		}
		input.ID = "act_" + id
	}
	if input.CreatedAt.IsZero() {
		input.CreatedAt = k.now().UTC()
	}
	if err := k.store.Create(ctx, input); err != nil {
		return ledger.Action{}, err
	}
	return k.store.Get(ctx, input.ID)
}

func (k *Kernel) Confirm(ctx context.Context, id, sessionBinding string) error {
	if err := k.store.Confirm(ctx, id, sessionBinding, k.now().UTC()); err != nil {
		return err
	}
	k.Wake()
	return nil
}

func (k *Kernel) Cancel(ctx context.Context, id, sessionBinding string) error {
	return k.store.Cancel(ctx, id, sessionBinding, k.now().UTC())
}

func (k *Kernel) Start(parent context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cancel != nil {
		return errors.New("action kernel is already running")
	}
	now := k.now().UTC()
	acquired, err := k.store.AcquireWorker(parent, workerName, k.ownerID, now, workerLeaseTTL)
	if err != nil {
		return err
	}
	if !acquired {
		return ErrWorkerUnavailable
	}
	if err := k.store.RecoverInterrupted(parent, now); err != nil {
		_ = k.store.ReleaseWorker(context.Background(), workerName, k.ownerID)
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	k.cancel, k.done = cancel, make(chan struct{})
	go k.run(ctx)
	k.Wake()
	return nil
}

func (k *Kernel) Stop() {
	k.mu.Lock()
	cancel, done := k.cancel, k.done
	k.cancel = nil
	k.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (k *Kernel) Wake() {
	select {
	case k.wake <- struct{}{}:
	default:
	}
}

func (k *Kernel) run(ctx context.Context) {
	defer func() {
		_ = k.store.ReleaseWorker(context.Background(), workerName, k.ownerID)
		close(k.done)
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-k.wake:
			k.drain(ctx)
		case <-ticker.C:
			k.drain(ctx)
		}
	}
}

func (k *Kernel) drain(ctx context.Context) {
	now := k.now().UTC()
	acquired, err := k.store.AcquireWorker(ctx, workerName, k.ownerID, now, workerLeaseTTL)
	if err != nil || !acquired {
		return
	}
	for {
		action, ok, err := k.store.ClaimNext(ctx, k.now().UTC())
		if err != nil || !ok {
			return
		}
		k.executeWithHeartbeat(ctx, action)
	}
}

func (k *Kernel) executeWithHeartbeat(ctx context.Context, action ledger.Action) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(workerRenewal)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				acquired, err := k.store.AcquireWorker(ctx, workerName, k.ownerID, k.now().UTC(), workerLeaseTTL)
				if err != nil || !acquired {
					return
				}
			}
		}
	}()
	k.execute(ctx, action)
	close(done)
}

func (k *Kernel) execute(ctx context.Context, action ledger.Action) {
	handler := k.handlers[action.Kind]
	if handler == nil {
		_ = k.finishClaimed(ctx, action.ID, "action_handler_unavailable")
		return
	}
	if err := safeValidate(ctx, handler, action); err != nil {
		_ = k.finishClaimed(ctx, action.ID, "foreground_action_material_unavailable")
		return
	}
	if err := k.store.MarkDispatch(ctx, action.ID, k.now().UTC()); err != nil {
		return
	}
	dispatch, dispatchPanicked := safeDispatch(ctx, handler, action)
	if dispatch.Outcome != "accepted" && dispatch.Outcome != "known_failed" && dispatch.Outcome != "outcome_unknown" {
		dispatch.Outcome = "outcome_unknown"
	}
	if dispatch.DeviceWriteCount < 0 {
		dispatch.Outcome, dispatch.DeviceWriteCount = "outcome_unknown", 0
	}
	// A handler may only persist the closed safe diagnostic contract. Invalid optional
	// metadata must not discard the already-observed dispatch outcome or skip verification.
	if dispatch.Diagnostic != nil && dispatch.Diagnostic.Validate() != nil {
		dispatch.Diagnostic = nil
	}
	if err := k.store.RecordDispatch(ctx, action.ID, ledger.DispatchObservation{
		Outcome: dispatch.Outcome, DeviceWriteCount: dispatch.DeviceWriteCount, FinishedAt: k.now().UTC(), Diagnostic: dispatch.Diagnostic,
	}); err != nil {
		return
	}
	if dispatchPanicked {
		_ = k.finishVerifyingUnknown(ctx, action.ID, "dispatch_handler_panicked")
		return
	}
	trusted, verifyPanicked := safeVerify(ctx, handler, action, dispatch)
	if verifyPanicked || trusted.Validate() != nil {
		_ = k.finishVerifyingUnknown(ctx, action.ID, "verification_contract_invalid")
		return
	}
	if err := k.store.Finish(ctx, action.ID, trusted); err != nil {
		_ = k.finishVerifyingUnknown(ctx, action.ID, "trusted_result_rejected")
	}
}

func (k *Kernel) finishClaimed(ctx context.Context, id, reason string) error {
	now := k.now().UTC()
	return k.store.Finish(ctx, id, result.Trusted{
		Class: result.Blocked, EvidenceStatus: result.EvidencePending,
		Conclusion: "操作未进入设备写入。", Reason: reason, EvidenceJSON: `{}`, ObservedAt: now,
	})
}

func (k *Kernel) finishVerifyingUnknown(ctx context.Context, id, reason string) error {
	now := k.now().UTC()
	return k.store.Finish(ctx, id, result.Trusted{
		Class: result.Unknown, EvidenceStatus: result.EvidencePending,
		Conclusion: "Dispatch result could not be verified.", Reason: reason, EvidenceJSON: `{}`, ObservedAt: now,
	})
}

func safeValidate(ctx context.Context, handler Handler, action ledger.Action) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("validation handler panicked")
		}
	}()
	return handler.Validate(ctx, action)
}

func safeDispatch(ctx context.Context, handler Handler, action ledger.Action) (dispatch Dispatch, panicked bool) {
	defer func() {
		if recover() != nil {
			dispatch, panicked = Dispatch{Outcome: "outcome_unknown"}, true
		}
	}()
	return handler.Dispatch(ctx, action), false
}

func safeVerify(ctx context.Context, handler Handler, action ledger.Action, dispatch Dispatch) (trusted result.Trusted, panicked bool) {
	defer func() {
		if recover() != nil {
			trusted, panicked = result.Trusted{}, true
		}
	}()
	return handler.Verify(ctx, action, dispatch), false
}

func randomID(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
