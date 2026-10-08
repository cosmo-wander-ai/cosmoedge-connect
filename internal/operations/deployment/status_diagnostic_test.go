package deployment

import (
	"reflect"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

func TestDispatchDiagnosticUsesOnlyKnownNativeCodeSemantics(t *testing.T) {
	zero := 0
	base := safediagnostic.Diagnostic{Operation: safediagnostic.OperationTaskSwitch, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassNativeRejected, HTTPStatus: 200, ResCode: &zero, MsgCode: "8"}
	for _, tc := range []struct {
		name    string
		modify  func(*ledger.Record)
		present bool
		meaning bool
	}{
		{"resource admission", func(*ledger.Record) {}, true, true},
		{"new binding resource admission", func(r *ledger.Record) { r.Diagnostic.Operation = safediagnostic.OperationDeploymentSave }, true, true},
		{"unknown native code", func(r *ledger.Record) { r.Diagnostic.MsgCode = "987654" }, true, false},
		{"transport uncertainty", func(r *ledger.Record) {
			r.DispatchOutcome = "outcome_unknown"
			r.Diagnostic.Phase = safediagnostic.PhaseTransport
			r.Diagnostic.Class = safediagnostic.ClassOutcomeUnknown
		}, true, false},
		{"HTTP code is not a native code", func(r *ledger.Record) { r.Diagnostic.MsgCode = ""; *r.Diagnostic.ResCode = 8 }, true, false},
		{"legacy no diagnostic", func(r *ledger.Record) { r.Diagnostic = nil }, false, false},
		{"no dispatch", func(r *ledger.Record) { r.Dispatches = 0 }, false, false},
		{"wrong operation", func(r *ledger.Record) { r.Diagnostic.Operation = safediagnostic.OperationPictureDetect }, false, false},
		{"unbounded native text", func(r *ledger.Record) { r.Diagnostic.MsgCode = "rtsp://credential@private.invalid" }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ledger.Record{Dispatches: 1, DispatchOutcome: "known_failed", Diagnostic: base.Clone()}
			tc.modify(&r)
			d, message := dispatchDiagnostic(r)
			if (d != nil) != tc.present || (message != "") != tc.meaning {
				t.Fatalf("projection=%+v meaning=%q", d, message)
			}
			if d != nil {
				if !reflect.DeepEqual(d, r.Diagnostic) {
					t.Fatal("changed native diagnostic")
				}
				*d.ResCode = 42
				if *r.Diagnostic.ResCode == 42 {
					t.Fatal("projection aliases retained diagnostic")
				}
			}
		})
	}
}
