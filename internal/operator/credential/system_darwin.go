//go:build darwin

package credential

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"unicode/utf8"
)

const (
	securityBinary       = "/usr/bin/security"
	securityItemNotFound = 44
)

type commandResult struct {
	stdout   []byte
	exitCode int
	started  bool
	err      error
}

type commandRunner interface {
	Run(context.Context, string, []string, []byte) commandResult
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, path string, args []string, stdin []byte) commandResult {
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = io.Discard
	err := command.Run()
	result := commandResult{stdout: stdout.Bytes(), exitCode: -1, started: command.ProcessState != nil, err: err}
	if err == nil {
		result.exitCode = 0
	} else if exitError := new(exec.ExitError); errors.As(err, &exitError) {
		result.exitCode = exitError.ExitCode()
		result.started = true
	}
	return result
}

type darwinStore struct {
	mu      sync.Mutex
	service string
	runner  commandRunner
	puts    *putJournal
	journal *rotationJournal
}

func OpenSystemStore(stateRoot string) (SecretStore, error) {
	return newDarwinStore(stateRoot, execCommandRunner{})
}

func newDarwinStore(stateRoot string, runner commandRunner) (*darwinStore, error) {
	root, err := prepareSystemRoot(stateRoot)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, errors.New("Keychain command runner is required")
	}
	service, err := namespaceForRoot(root)
	if err != nil {
		return nil, err
	}
	journal, err := openRotationJournal(root)
	if err != nil {
		return nil, err
	}
	puts, err := openPutJournal(root)
	if err != nil {
		return nil, err
	}
	return &darwinStore{service: service, runner: runner, puts: puts, journal: journal}, nil
}

func (s *darwinStore) Put(ctx context.Context, operationID PutOperationID, secret []byte) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	if err := validateDarwinSecret(secret); err != nil {
		return PutReceipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, err := s.puts.Get(operationID); err == nil {
		return s.recoverPutLocked(ctx, existing)
	} else if !errors.Is(err, ErrNotFound) {
		return PutReceipt{}, err
	}
	ref, err := newRef()
	if err != nil {
		return PutReceipt{}, err
	}
	receipt, err := s.puts.Create(operationID, ref)
	if err != nil {
		return PutReceipt{}, err
	}
	if err := s.putAtLocked(ctx, ref, secret); err != nil {
		phase := PutRolledBack
		if errors.Is(err, ErrOutcomeUnknown) {
			phase = PutUnknown
		}
		updated, updateErr := s.puts.Update(receipt, phase)
		if updateErr != nil {
			return receipt, unknown("put", "", ref)
		}
		return updated, err
	}
	updated, err := s.puts.Update(receipt, PutCommitted)
	if err != nil {
		return receipt, unknown("put", "", ref)
	}
	return updated, nil
}

func (s *darwinStore) PutByOperationID(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts.Get(operationID)
}

func (s *darwinStore) RecoverPut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.puts.Get(operationID)
	if err != nil {
		return PutReceipt{}, err
	}
	return s.recoverPutLocked(ctx, receipt)
}

func (s *darwinStore) CompensatePut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.puts.Get(operationID)
	if err != nil {
		return PutReceipt{}, err
	}
	if receipt.Phase == PutRolledBack {
		return receipt, nil
	}
	if err := s.deleteLocked(ctx, receipt.Ref); err != nil {
		updated, _ := s.puts.Update(receipt, PutUnknown)
		if updated.Valid() {
			receipt = updated
		}
		return receipt, unknown("put", "", receipt.Ref)
	}
	updated, err := s.puts.Update(receipt, PutRolledBack)
	if err != nil {
		return receipt, unknown("put", "", receipt.Ref)
	}
	return updated, nil
}

func (s *darwinStore) AcknowledgePut(ctx context.Context, operationID PutOperationID) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.puts.Get(operationID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !receipt.Phase.terminal() {
		return unknown("put", "", receipt.Ref)
	}
	return s.puts.Delete(operationID)
}

func (s *darwinStore) recoverPutLocked(ctx context.Context, receipt PutReceipt) (PutReceipt, error) {
	secret, found, err := s.lookupLocked(ctx, receipt.Ref)
	clear(secret)
	if err != nil {
		updated, _ := s.puts.Update(receipt, PutUnknown)
		if updated.Valid() {
			receipt = updated
		}
		return receipt, unknown("put", "", receipt.Ref)
	}
	phase := PutRolledBack
	if found && receipt.Phase == PutRolledBack {
		if err := s.deleteLocked(ctx, receipt.Ref); err != nil {
			updated, _ := s.puts.Update(receipt, PutUnknown)
			if updated.Valid() {
				receipt = updated
			}
			return receipt, unknown("put", "", receipt.Ref)
		}
	} else if found {
		phase = PutCommitted
	}
	updated, err := s.puts.Update(receipt, phase)
	if err != nil {
		return receipt, unknown("put", "", receipt.Ref)
	}
	return updated, nil
}

func (s *darwinStore) Get(ctx context.Context, ref Ref) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !ref.Valid() {
		return nil, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, found, err := s.lookupLocked(ctx, ref)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return secret, nil
}

func (s *darwinStore) Delete(ctx context.Context, ref Ref) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !ref.Valid() {
		return ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(ctx, ref)
}

func (s *darwinStore) Rotate(ctx context.Context, old Ref, secret []byte) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !old.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	if err := validateDarwinSecret(secret); err != nil {
		return RotationReceipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, err := s.journal.ByOldRef(old); err == nil {
		return s.recoverRotationLocked(ctx, existing)
	} else if !errors.Is(err, ErrNotFound) {
		return RotationReceipt{}, err
	}
	oldSecret, found, err := s.lookupLocked(ctx, old)
	clear(oldSecret)
	if err != nil {
		return RotationReceipt{}, err
	}
	if !found {
		return RotationReceipt{}, ErrNotFound
	}
	newReference, err := newRef()
	if err != nil {
		return RotationReceipt{}, err
	}
	receipt, err := s.journal.Create(old, newReference)
	if err != nil {
		return RotationReceipt{}, err
	}
	// A second process can win the durable receipt creation between the
	// ByOldRef lookup above and Create. In that case the winning receipt is the
	// only operation we may resume; using our locally allocated reference would
	// fork the rotation and could orphan a Keychain item.
	if receipt.NewRef != newReference {
		return s.recoverRotationLocked(ctx, receipt)
	}
	if err := s.putAtLocked(ctx, newReference, secret); err != nil {
		phase := RotationRolledBack
		if errors.Is(err, ErrOutcomeUnknown) {
			phase = RotationUnknown
		}
		updated, updateErr := s.journal.Update(receipt, phase)
		if updateErr != nil {
			return receipt, unknown("rotate", old, newReference)
		}
		return updated, err
	}
	deleted := s.runDelete(ctx, old)
	if commandSucceeded(deleted) || commandMissing(deleted) {
		updated, err := s.journal.Update(receipt, RotationCommitted)
		if err != nil {
			return receipt, unknown("rotate", old, newReference)
		}
		return updated, nil
	}
	oldSecret, oldFound, lookupErr := s.lookupLocked(ctx, old)
	clear(oldSecret)
	if lookupErr != nil {
		updated, _ := s.journal.Update(receipt, RotationUnknown)
		if updated.Valid() {
			receipt = updated
		}
		return receipt, unknown("rotate", old, newReference)
	}
	if !oldFound {
		updated, err := s.journal.Update(receipt, RotationCommitted)
		if err != nil {
			return receipt, unknown("rotate", old, newReference)
		}
		return updated, nil
	}
	if cleanupErr := s.deleteLocked(ctx, newReference); cleanupErr == nil {
		updated, err := s.journal.Update(receipt, RotationRolledBack)
		if err != nil {
			return receipt, unknown("rotate", old, newReference)
		}
		return updated, sanitizeCommandError("rotate-delete-old", deleted)
	}
	updated, _ := s.journal.Update(receipt, RotationUnknown)
	if updated.Valid() {
		receipt = updated
	}
	return receipt, unknown("rotate", old, newReference)
}

func (s *darwinStore) RotationByOldRef(ctx context.Context, old Ref) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !old.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.journal.ByOldRef(old)
}

func (s *darwinStore) RecoverRotation(ctx context.Context, operationID RotationID) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !operationID.Valid() {
		return RotationReceipt{}, ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.journal.Get(operationID)
	if err != nil {
		return RotationReceipt{}, err
	}
	return s.recoverRotationLocked(ctx, receipt)
}

func (s *darwinStore) AcknowledgeRotation(ctx context.Context, operationID RotationID) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.journal.Get(operationID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !receipt.Phase.terminal() {
		return unknown("rotate", receipt.OldRef, receipt.NewRef)
	}
	return s.journal.Delete(operationID)
}

func (s *darwinStore) recoverRotationLocked(ctx context.Context, receipt RotationReceipt) (RotationReceipt, error) {
	if receipt.Phase.terminal() {
		return receipt, nil
	}
	oldSecret, oldFound, oldErr := s.lookupLocked(ctx, receipt.OldRef)
	clear(oldSecret)
	newSecret, newFound, newErr := s.lookupLocked(ctx, receipt.NewRef)
	clear(newSecret)
	if oldErr != nil || newErr != nil {
		updated, _ := s.journal.Update(receipt, RotationUnknown)
		if updated.Valid() {
			receipt = updated
		}
		return receipt, unknown("rotate", receipt.OldRef, receipt.NewRef)
	}
	phase := RotationUnknown
	switch {
	case oldFound && !newFound:
		phase = RotationRolledBack
	case !oldFound && newFound:
		phase = RotationCommitted
	case oldFound && newFound:
		if err := s.deleteLocked(ctx, receipt.NewRef); err == nil {
			phase = RotationRolledBack
		}
	}
	updated, err := s.journal.Update(receipt, phase)
	if err != nil {
		return receipt, unknown("rotate", receipt.OldRef, receipt.NewRef)
	}
	if phase == RotationUnknown {
		return updated, unknown("rotate", receipt.OldRef, receipt.NewRef)
	}
	return updated, nil
}

func (s *darwinStore) putAtLocked(ctx context.Context, ref Ref, secret []byte) error {
	stdin := make([]byte, len(secret)+1)
	copy(stdin, secret)
	stdin[len(stdin)-1] = '\n'
	result := s.runner.Run(ctx, securityBinary, []string{
		"add-generic-password", "-a", ref.ProtectedValue(), "-s", s.service, "-w",
	}, stdin)
	clear(stdin)
	clear(result.stdout)
	if commandSucceeded(result) {
		return nil
	}
	stored, found, lookupErr := s.lookupLocked(ctx, ref)
	if lookupErr != nil {
		clear(stored)
		return unknown("put", "", ref)
	}
	matches := found && bytes.Equal(stored, secret)
	clear(stored)
	if matches {
		return nil
	}
	if found {
		return unknown("put", "", ref)
	}
	return sanitizeCommandError("put", result)
}

func (s *darwinStore) lookupLocked(ctx context.Context, ref Ref) ([]byte, bool, error) {
	result := s.runner.Run(ctx, securityBinary, []string{
		"find-generic-password", "-a", ref.ProtectedValue(), "-s", s.service, "-w",
	}, nil)
	if commandMissing(result) {
		clear(result.stdout)
		return nil, false, nil
	}
	if !commandSucceeded(result) {
		clear(result.stdout)
		return nil, false, sanitizeCommandError("get", result)
	}
	secret := append([]byte(nil), result.stdout...)
	clear(result.stdout)
	secret = bytes.TrimSuffix(secret, []byte("\n"))
	secret = bytes.TrimSuffix(secret, []byte("\r"))
	if err := validateDarwinSecret(secret); err != nil {
		clear(secret)
		return nil, false, errors.New("Keychain returned an invalid credential payload")
	}
	return secret, true, nil
}

func (s *darwinStore) deleteLocked(ctx context.Context, ref Ref) error {
	result := s.runDelete(ctx, ref)
	if commandSucceeded(result) || commandMissing(result) {
		return nil
	}
	secret, found, lookupErr := s.lookupLocked(ctx, ref)
	clear(secret)
	if lookupErr != nil {
		return unknown("delete", ref, "")
	}
	if !found {
		return nil
	}
	return sanitizeCommandError("delete", result)
}

func (s *darwinStore) runDelete(ctx context.Context, ref Ref) commandResult {
	result := s.runner.Run(ctx, securityBinary, []string{
		"delete-generic-password", "-a", ref.ProtectedValue(), "-s", s.service,
	}, nil)
	clear(result.stdout)
	return result
}

func validateDarwinSecret(secret []byte) error {
	if err := validateSecret(secret); err != nil {
		return err
	}
	if !utf8.Valid(secret) || bytes.IndexByte(secret, 0) >= 0 || bytes.ContainsAny(secret, "\r\n") {
		return ErrInvalidSecret
	}
	return nil
}

func commandSucceeded(result commandResult) bool {
	return result.started && result.err == nil && result.exitCode == 0
}

func commandMissing(result commandResult) bool {
	return result.started && result.exitCode == securityItemNotFound
}

type keychainCommandError struct {
	operation string
	exitCode  int
	started   bool
}

func (e *keychainCommandError) Error() string {
	if e.exitCode >= 0 {
		return "Keychain " + e.operation + " failed with status " + strconv.Itoa(e.exitCode)
	}
	if e.started {
		return "Keychain " + e.operation + " did not report a reliable result"
	}
	return "Keychain " + e.operation + " could not start"
}

func sanitizeCommandError(operation string, result commandResult) error {
	return &keychainCommandError{operation: operation, exitCode: result.exitCode, started: result.started}
}

func unknown(operation string, old, new Ref) error {
	return &OutcomeUnknownError{Operation: operation, OldRef: old, NewRef: new}
}

var _ SecretStore = (*darwinStore)(nil)
