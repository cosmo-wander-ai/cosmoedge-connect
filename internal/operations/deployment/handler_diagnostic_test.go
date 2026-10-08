package deployment

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

type nativeRejectedError struct{}

func (nativeRejectedError) Error() string {
	return "device raw rejection password=do-not-persist rtsp://private.invalid/feed answer=do-not-persist"
}
func (nativeRejectedError) KnownFailure() bool { return true }

func TestNativeDeploymentRejectionKeepsCodesAfterVerifyAndReopen(t *testing.T) {
	h := newHarness(t, true)
	code := 0
	diagnostic := safediagnostic.Diagnostic{Operation: safediagnostic.OperationTaskSwitch, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassNativeRejected, HTTPStatus: 200, ResCode: &code, MsgCode: "12314"}
	h.client.writeErr = fmt.Errorf("switch failed: %w", safediagnostic.Wrap(nativeRejectedError{}, diagnostic))
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	record := confirmAndWait(t, h, proposal)
	if record.State != "blocked" || record.DispatchOutcome != "known_failed" || record.Reason != "deployment_rejected" || record.Dispatches != 1 || record.DeviceWrites != 0 || !reflect.DeepEqual(record.Diagnostic, diagnostic.Clone()) {
		t.Fatalf("rejection lost native facts: %+v", record)
	}
	// A native HTTP 200 business rejection has zero device-write accounting even
	// though one client switch request was sent. These are different observations.
	h.client.mu.Lock()
	switches, writes := h.client.switches, h.client.writes
	h.client.mu.Unlock()
	if switches != 1 || writes != 1 {
		t.Fatalf("requests switches=%d writes=%d, expected exactly one despite DeviceWrites=0", switches, writes)
	}
	if err = h.service.Confirm(context.Background(), "session-a", proposal.ActionRef, proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	if _, err = h.service.GetByRequest(context.Background(), "session-a", "request-one"); err != nil {
		t.Fatal(err)
	}
	status, err := h.service.Status(context.Background(), "session-a", proposal.ActionRef)
	if err != nil || !reflect.DeepEqual(status.Diagnostic, record.Diagnostic) || status.DiagnosticMessage != "" || status.Target.State != "" {
		t.Fatalf("public status lost codes or inferred an unknown code: %+v %v", status, err)
	}
	raw, err := json.Marshal(status)
	if err != nil || strings.Contains(string(raw), "do-not-persist") || strings.Contains(string(raw), "private.invalid") {
		t.Fatalf("public diagnostic leaked native error text: %v", err)
	}
	var original metadata
	if err := json.Unmarshal([]byte(record.PublicJSON), &original); err != nil || original.Target.State != "proposed" {
		t.Fatal("status projection changed the original proposal")
	}
	if foreign, err := h.service.Status(context.Background(), "session-b", proposal.ActionRef); err == nil || foreign.Diagnostic != nil {
		t.Fatal("another session read diagnostic facts")
	}
	h.worker.Stop()
	if err = h.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ledger.Open(h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.Inspect(context.Background(), proposal.ActionRef)
	if err != nil || !reflect.DeepEqual(after, record) {
		t.Fatalf("read-only reopen changed verified rejection: after=%+v before=%+v err=%v", after, record, err)
	}
	h.client.mu.Lock()
	writes = h.client.writes
	h.client.mu.Unlock()
	if writes != 1 {
		t.Fatalf("rejection replayed: writes=%d", writes)
	}
	assertNotDurable(t, h.dbPath, "do-not-persist", "private.invalid", "password=", "answer=")
}
