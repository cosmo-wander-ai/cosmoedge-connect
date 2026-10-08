# Offline inspection evaluation v3

`inspection-eval` validates, evaluates, and gates metadata-only inspection
projections. The direct JSONL commands and checked-in golden files are
synthetic contract-regression fixtures only: their unhashed business fields
are caller-authored and do not prove production evidence provenance. The tool
does not open an Operator session, read media, contact a device, deliver a
message, or train a model.

V3 directly replaces V2. Old schemas, flags, field names, and dual parsing are
rejected.

## Trusted assembly boundary

Production adapters must build records through `inspectioneval.AssembleRecord`:

- the caller supplies a dataset `CreateReceipt`, not a dataset object;
- assembly requires `ResolveCreate == committed`, then reads an active
  admitted projection; the dataset repository verifies the projection, private
  split-leakage ledgers, frozen review set, and composite receipt digest, while
  a trusted clock rejects the wrong purpose, future-created, or expired data;
- a runtime-evidence verifier must prove that the exact `inspection.Run`, frozen
  `ExecutionPlan`, typed `AnalysisResult`, or temporary runtime record came from
  the authoritative store; standard run identity, output-contract digest,
  zero-write/cleanup state, strategy, source, target, step, schema, media, and
  capture time are then cross-checked;
- a protected application-state verifier must bind the public run, internal
  run, run kind, tenant/site, plan, and complete delivery audience;
- delivery must bind both the public run and the sole
  `delivery.ResultRefForRun` identity; it is loaded by ID from the delivery
  repository, its complete persisted terminal state is validated, and its
  actual delivery/reconciliation attempt counts are retained;
- feedback is read through a narrow trusted repository and is bound to the
  run, result, audience, receipt time, and trusted adapter projection digest;
- temporary observations require exactly one independently verified review
  that binds the admitted item/annotation and the runtime run, result, media,
  spec, observation, policy, reviewer, and completion time.

Missing, duplicated, early, unverifiable, cross-run, or digest-mismatched
evidence fails closed.

`NewAuthoritativeRuntimeEvidenceAdapter` accepts the read-only subsets already
implemented by the persistent standard inspection store and temporary runtime
store. `NewApplicationRunBindingAdapter` accepts the protected read-only subset
already implemented by `application.StateStore`. Dataset and delivery stores
implement their assembly ports directly, and `ClockFunc` adapts a Product-owned
trusted clock. None of these adapters can mutate runtime, application, media,
delivery, or device state.

`application.StateStore` also supplies the exact, comment-free feedback read
projection consumed by `NewFeedbackProjectionAdapter`; the adapter verifies the
derived result reference and creates the evaluation-owned canonical digest.
The one final Product composition input is the independently governed
temporary-review service, which must provide the list and verification
functions for `NewTemporaryReviewAdapters`. The evaluation package does not
invent that authority or open its store. Dataset activity is evaluated at the
validated repository snapshot; a future persisted evaluation pipeline must
also define retention/purge handling for its own projections. Direct JSONL
remains a synthetic contract-regression channel, not a production evidence
channel.

## V3 record and metric rules

Each JSONL record uses `cosmoedge.inspection.eval.record.v3`. It carries only
keyed pseudonyms and bounded typed values. Its annotation contract includes
criterion ID/version, result schema/kind, and the complete canonical scene
taxonomy; no first-taxonomy fallback exists.

Unknown fields, duplicate keys, case aliases, raw locators, non-finite values,
oversized unions, invalid result combinations, and old schemas fail before
scoring. Test records cannot be used for threshold calibration.

`overall` and the primary strategy/criterion/source/media/site/scene slices are
computed from the test split only. Train and validation records appear only in
their explicit split slices and calibration summary. Criterion slices retain
ID, version, result schema, and result kind. Delivery and feedback metrics are
counted once per unique delivery evidence, not once per criterion row.
Detection scoring uses a
fixed IoU threshold of 0.5 and deterministic maximum-cardinality bipartite
matching, with total IoU as the secondary objective.

## Commands

```sh
go run ./tools/inspection-eval validate --manifest evaluation-v3.jsonl
go run ./tools/inspection-eval evaluate --manifest evaluation-v3.jsonl
go run ./tools/inspection-eval gate \
  --manifest internal/inspectioneval/testdata/synthetic.jsonl \
  --thresholds internal/inspectioneval/testdata/golden-thresholds-v3.json \
  --golden-report internal/inspectioneval/testdata/golden-report-v3.json \
  --golden-sha256 internal/inspectioneval/testdata/golden-report-v3.sha256
```

`gate` exits nonzero for any threshold failure, report regression, or golden
digest mismatch. The checked-in fixture covers two sites, all four strategies,
all result kinds, helpful/unhelpful/missing feedback, unknown/failed delivery,
and actual retry counts. Its scores verify contracts only; they are not
real-scene accuracy, production reliability, or latency evidence.
