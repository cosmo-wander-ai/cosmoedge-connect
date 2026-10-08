package deployment

import (
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

func dispatchDiagnostic(record ledger.Record) (*safediagnostic.Diagnostic, string) {
	d := record.Diagnostic
	if record.Dispatches == 0 || d == nil || d.Validate() != nil ||
		(d.Operation != safediagnostic.OperationTaskSwitch && d.Operation != safediagnostic.OperationDeploymentSave) {
		return nil, ""
	}
	message := ""
	// CosmoEdge v1.1's native task API uses ErrorEnum::ResourceLimit (8).
	// The code identifies resource admission, not which resource triggered it.
	// Other codes and uncertain transport outcomes carry no inferred cause.
	if record.DispatchOutcome == "known_failed" && d.Phase == safediagnostic.PhaseNativeResponse &&
		d.Class == safediagnostic.ClassNativeRejected && d.MsgCode == "8" {
		message = "设备报告资源不足，未接受本次操作。"
	}
	return d.Clone(), message
}
