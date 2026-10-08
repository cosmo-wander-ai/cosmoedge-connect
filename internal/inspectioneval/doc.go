// Package inspectioneval provides deterministic, offline-only validation and
// evaluation of direct-v3 inspection result projections.
//
// It has no dependency on device clients, credentials, or ordinary Operator
// entrypoints. AssembleRecord accepts repository-verified evidence through
// read-only standard-runtime, temporary-runtime, application-binding, dataset,
// delivery, feedback, and review ports; adapters in this package connect the
// existing runtime/application/feedback repositories and leave the
// independently governed temporary-review projection as an explicit Product
// composition seam. Direct JSONL loading remains a synthetic fixture path.
// Synthetic scores are contract checks, never real-scene accuracy, production
// provenance, or reliability claims.
package inspectioneval
