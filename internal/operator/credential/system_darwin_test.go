//go:build darwin

package credential

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestDarwinKeychainStoreUsesStdinAndNoLocalSecretFile(t *testing.T) {
	root := newCredentialStateRoot(t)
	runner := newFakeKeychainRunner()
	store, err := newDarwinStore(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("darwin-private-password")
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	putReceipt, err := store.Put(context.Background(), putID, secret)
	if err != nil {
		t.Fatal(err)
	}
	ref := putReceipt.Ref
	calls := runner.snapshotCalls()
	if len(calls) != 1 || calls[0].path != securityBinary || calls[0].args[len(calls[0].args)-1] != "-w" {
		t.Fatalf("unexpected add command: %#v", calls)
	}
	if !bytes.Equal(calls[0].stdin, append(append([]byte(nil), secret...), '\n')) {
		t.Fatalf("secret was not supplied through stdin: %#v", calls[0].stdin)
	}
	for _, argument := range calls[0].args {
		if strings.Contains(argument, string(secret)) {
			t.Fatalf("secret entered argv: %#v", calls[0].args)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 3 || entries[0].Name() != ".credential-puts" || entries[1].Name() != ".credential-rotations" || entries[2].Name() != namespaceMarkerName {
		t.Fatalf("Keychain backend wrote unexpected local files: %#v, %v", entries, err)
	}
	opened, err := store.Get(context.Background(), ref)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	clear(opened)
	if recovered, err := store.PutByOperationID(context.Background(), putID); err != nil || recovered != putReceipt {
		t.Fatalf("durable Keychain Put receipt=%v err=%v", recovered, err)
	}
	if err := store.AcknowledgePut(context.Background(), putID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted Keychain reference still resolves: %v", err)
	}
}

func TestDarwinKeychainRotateSuccessAndKnownRollback(t *testing.T) {
	runner := newFakeKeychainRunner()
	root := newCredentialStateRoot(t)
	store, err := newDarwinStore(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	old := putTestSecretAndAcknowledge(t, store, []byte("old-secret"))
	rotation, err := store.Rotate(context.Background(), old, []byte("new-secret"))
	if err != nil {
		t.Fatal(err)
	}
	rotated := rotation.NewRef
	if rotated == old {
		t.Fatal("rotation did not replace the opaque reference")
	}
	if _, err := store.Get(context.Background(), old); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old reference survived successful rotation: %v", err)
	}
	opened, err := store.Get(context.Background(), rotated)
	if err != nil || string(opened) != "new-secret" {
		t.Fatalf("rotated secret=%q err=%v", opened, err)
	}
	clear(opened)
	if recovered, err := store.RotationByOldRef(context.Background(), old); err != nil || recovered != rotation {
		t.Fatalf("durable Keychain receipt=%v err=%v", recovered, err)
	}
	retried, err := store.Rotate(context.Background(), old, []byte("must-not-start-second-rotation"))
	if err != nil || retried != rotation || runner.itemCount() != 1 {
		t.Fatalf("same old ref opened a second rotation: %v, %v", retried, err)
	}
	reopened, err := newDarwinStore(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := reopened.RecoverRotation(context.Background(), rotation.OperationID); err != nil || recovered != rotation {
		t.Fatalf("reopened Keychain rotation receipt=%v err=%v", recovered, err)
	}
	if err := reopened.AcknowledgeRotation(context.Background(), rotation.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := reopened.AcknowledgeRotation(context.Background(), rotation.OperationID); err != nil {
		t.Fatalf("Keychain rotation acknowledgement is not idempotent: %v", err)
	}

	runner = newFakeKeychainRunner()
	store, err = newDarwinStore(newCredentialStateRoot(t), runner)
	if err != nil {
		t.Fatal(err)
	}
	old = putTestSecretAndAcknowledge(t, store, []byte("preserved-old-secret"))
	runner.failDeleteRefs[old] = true
	rolledBack, err := store.Rotate(context.Background(), old, []byte("must-be-rolled-back"))
	if err == nil || errors.Is(err, ErrOutcomeUnknown) || rolledBack.Phase != RotationRolledBack {
		t.Fatalf("known rollback receipt=%v err=%v", rolledBack, err)
	}
	opened, err = store.Get(context.Background(), old)
	if err != nil || string(opened) != "preserved-old-secret" {
		t.Fatalf("old reference was not preserved: %q, %v", opened, err)
	}
	clear(opened)
	if runner.itemCount() != 1 {
		t.Fatalf("known rollback left multiple valid references: %d", runner.itemCount())
	}
}

func TestDarwinKeychainRotateReportsOutcomeUnknownWhenRollbackCannotBeProven(t *testing.T) {
	runner := newFakeKeychainRunner()
	store, err := newDarwinStore(newCredentialStateRoot(t), runner)
	if err != nil {
		t.Fatal(err)
	}
	old := putTestSecretAndAcknowledge(t, store, []byte("old-secret"))
	runner.failAllDeletes = true
	unknownReceipt, err := store.Rotate(context.Background(), old, []byte("new-secret"))
	if !errors.Is(err, ErrOutcomeUnknown) || unknownReceipt.Phase != RotationUnknown {
		t.Fatalf("ambiguous rotation receipt=%v err=%v", unknownReceipt, err)
	}
	var unknownResult *OutcomeUnknownError
	if !errors.As(err, &unknownResult) || unknownResult.OldRef != old || unknownResult.NewRef != unknownReceipt.NewRef {
		t.Fatalf("outcome-unknown binding=%#v", unknownResult)
	}
	if runner.itemCount() != 2 {
		t.Fatalf("ambiguous fake state not represented truthfully: %d", runner.itemCount())
	}
	runner.failAllDeletes = false
	recovered, err := store.RecoverRotation(context.Background(), unknownReceipt.OperationID)
	if err != nil || recovered.Phase != RotationRolledBack || runner.itemCount() != 1 {
		t.Fatalf("ambiguous Keychain state did not recover deterministically: %v, %v", recovered, err)
	}
	if err := store.AcknowledgeRotation(context.Background(), recovered.OperationID); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinKeychainRejectsUnsafeSecretAndSanitizesCommandErrors(t *testing.T) {
	runner := newFakeKeychainRunner()
	store, err := newDarwinStore(newCredentialStateRoot(t), runner)
	if err != nil {
		t.Fatal(err)
	}
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), putID, []byte("line-one\nline-two")); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("multiline secret error=%v", err)
	}
	if len(runner.snapshotCalls()) != 0 {
		t.Fatal("invalid secret reached the Keychain command runner")
	}
	secret := "must-not-appear-in-command-error"
	runner.failAdds = true
	_, err = store.Put(context.Background(), putID, []byte(secret))
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), runner.failureText) {
		t.Fatalf("command error leaked protected output: %v", err)
	}
}

func TestDarwinKeychainClearsCommandOutputAndRequiresStartedProcess(t *testing.T) {
	ref, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	output := []byte("transient-keychain-secret\n")
	runner := &staticCommandRunner{result: commandResult{stdout: output, exitCode: 0, started: true}}
	store, err := newDarwinStore(newCredentialStateRoot(t), runner)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := store.Get(context.Background(), ref)
	if err != nil || string(opened) != "transient-keychain-secret" {
		t.Fatalf("Keychain output=%q err=%v", opened, err)
	}
	clear(opened)
	for _, value := range output {
		if value != 0 {
			t.Fatal("Keychain stdout buffer was not cleared")
		}
	}
	notStartedOutput := []byte("must-be-cleared")
	notStarted := &staticCommandRunner{result: commandResult{
		stdout: notStartedOutput, exitCode: securityItemNotFound, started: false, err: errors.New("not started"),
	}}
	store, err = newDarwinStore(newCredentialStateRoot(t), notStarted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), ref); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unstarted command was mistaken for not-found: %v", err)
	}
	for _, value := range notStartedOutput {
		if value != 0 {
			t.Fatal("failed Keychain stdout buffer was not cleared")
		}
	}
}

func TestDarwinKeychainRecoversAndCompensatesInterruptedPut(t *testing.T) {
	root := newCredentialStateRoot(t)
	runner := newFakeKeychainRunner()
	store, err := newDarwinStore(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.puts.Create(operationID, ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.putAtLocked(context.Background(), ref, []byte("installed-before-phase-update")); err != nil {
		t.Fatal(err)
	}
	reopened, err := newDarwinStore(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.RecoverPut(context.Background(), receipt.OperationID)
	if err != nil || recovered.Phase != PutCommitted || recovered.Ref != ref {
		t.Fatalf("interrupted Keychain Put recovery=%v err=%v", recovered, err)
	}
	compensated, err := reopened.CompensatePut(context.Background(), receipt.OperationID)
	if err != nil || compensated.Phase != PutRolledBack || runner.itemCount() != 0 {
		t.Fatalf("Keychain Put compensation=%v err=%v items=%d", compensated, err, runner.itemCount())
	}
	if err := reopened.AcknowledgePut(context.Background(), receipt.OperationID); err != nil {
		t.Fatal(err)
	}
}

type staticCommandRunner struct {
	result commandResult
}

func (runner *staticCommandRunner) Run(context.Context, string, []string, []byte) commandResult {
	return runner.result
}

type fakeKeychainCall struct {
	path  string
	args  []string
	stdin []byte
}

type fakeKeychainRunner struct {
	mu             sync.Mutex
	items          map[string][]byte
	calls          []fakeKeychainCall
	failAdds       bool
	failAllDeletes bool
	failDeleteRefs map[Ref]bool
	failureText    string
}

func newFakeKeychainRunner() *fakeKeychainRunner {
	return &fakeKeychainRunner{
		items: map[string][]byte{}, failDeleteRefs: map[Ref]bool{},
		failureText: "fake stderr contains protected material",
	}
}

func (r *fakeKeychainRunner) Run(_ context.Context, path string, args []string, stdin []byte) commandResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fakeKeychainCall{path: path, args: append([]string(nil), args...), stdin: append([]byte(nil), stdin...)})
	account, service := option(args, "-a"), option(args, "-s")
	key := service + "\x00" + account
	switch first(args) {
	case "add-generic-password":
		if r.failAdds {
			return fakeFailure(r.failureText)
		}
		if _, exists := r.items[key]; exists {
			return commandResult{exitCode: 45, started: true, err: errors.New("duplicate")}
		}
		value := append([]byte(nil), stdin...)
		value = bytes.TrimSuffix(value, []byte("\n"))
		r.items[key] = value
		return commandResult{exitCode: 0, started: true}
	case "find-generic-password":
		value, exists := r.items[key]
		if !exists {
			return commandResult{exitCode: securityItemNotFound, started: true, err: errors.New("missing")}
		}
		stdout := append([]byte(nil), value...)
		stdout = append(stdout, '\n')
		return commandResult{stdout: stdout, exitCode: 0, started: true}
	case "delete-generic-password":
		ref := Ref(account)
		if r.failAllDeletes || r.failDeleteRefs[ref] {
			return fakeFailure(r.failureText)
		}
		if _, exists := r.items[key]; !exists {
			return commandResult{exitCode: securityItemNotFound, started: true, err: errors.New("missing")}
		}
		delete(r.items, key)
		return commandResult{exitCode: 0, started: true}
	default:
		return fakeFailure("unsupported")
	}
}

func (r *fakeKeychainRunner) snapshotCalls() []fakeKeychainCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]fakeKeychainCall, len(r.calls))
	copy(result, r.calls)
	return result
}

func (r *fakeKeychainRunner) itemCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}

func fakeFailure(text string) commandResult {
	return commandResult{exitCode: 1, started: true, err: errors.New(text)}
}

func option(args []string, name string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name {
			return args[index+1]
		}
	}
	return ""
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
