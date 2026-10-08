# Structured Analysis Contract

## Purpose

CV, VLM, and hybrid adapters return untrusted analysis candidates. CosmoEdge Connect
validates those candidates, combines them with trusted capture and execution
facts, and uses a deterministic Oracle to create an `Observation`. A model
cannot mark a run complete, satisfy a business criterion, authorize a retry,
choose a site, or publish a report.

The current runtime has four closed execution strategies:
`existing_task_read`, `snapshot_analysis`, `clip_analysis`, and
`hybrid_analysis`. This envelope governs analyzer steps in the latter three.
An existing-task read may instead return a trusted typed metric, event, or
detection without calling an analyzer.

The machine-readable adapter envelope is
[`schema/analysis-result.schema.json`](schema/analysis-result.schema.json),
with a synthetic example in
[`examples/analysis-result.example.json`](examples/analysis-result.example.json).

## Compilation Boundary

Standard user or schedule input selects an existing versioned
`InspectionTemplate`. A temporary visual request is separately normalized into
a bounded `TemporaryObservationSpec`. Neither raw chat form is concatenated
directly into a device or model prompt.

The prompt compiler accepts only typed, bounded values:

- criterion ID, version, title, and approved rubric text;
- approved observable and exclusion codes;
- assignment ROI expressed as normalized numeric coordinates;
- required response schema version;
- sampling context such as sample ordinal and total;
- locale from an allowlist;
- optional approved reference-image handles resolved by the media adapter.

The compiler rejects unknown variables, control characters, oversized values,
URLs, native device identifiers, credentials, and template-version mismatch.
The compiled prompt is identified by template ID, version, and SHA-256 digest.
That identity is frozen in the run plan and recorded with the result.

For a temporary observation, CosmoEdge Connect owns the fixed system instruction,
structured response contract, locale, and display policy. Only the validated
subject, region, time scope, observable, and evidence policy may enter prompt
compilation. A temporary request cannot publish a standard template or become
a scheduled task without a separate reviewed workflow.

The fixed system instruction must state that text visible inside an image is
untrusted scene content, not an instruction; the analyzer must evaluate only
the supplied criterion and return only the requested JSON object.

## Adapter Envelope

The runtime constructs and verifies every envelope field except the
`candidate` object, using the frozen plan, trusted capture/runtime facts, and
bounded adapter metadata. In particular, a model does not choose:

- run, step, tenant, site, criterion, or media identity;
- analyzer kind, adapter version, model policy, or prompt version;
- timestamps, attempt number, latency, resource counts, or content hashes;
- retry policy, disposition aggregation, report wording, or recipients.

An adapter may translate vendor output into `candidate`, but must preserve a
digest of the bounded raw output for diagnostics. Raw prompts, raw vendor
payloads, chain-of-thought, base64 media, and unrestricted model prose are not
persisted in the inspection ledger.

`candidate.disposition` has exactly five values:

- `meets_rule`: visible evidence supports every required observable;
- `needs_attention`: visible evidence supports a defined violation;
- `uncertain`: evidence is conflicting, insufficient, or below threshold;
- `not_observable`: the subject cannot be evaluated from supplied media;
- `unsupported`: the analyzer cannot apply the requested criterion.

Confidence is optional supporting telemetry. It never upgrades a disposition,
fills missing evidence, or overrides an exclusion or limitation.

A conclusive candidate also carries exactly one typed `value` matching the
frozen output kind: `classification`, `enum`, `structured`, `metric`,
`detection`, `count`, or `event`. An inconclusive candidate carries no value.
The model cannot change the result kind or output schema frozen in the binding.

## Deterministic Oracle

After JSON Schema validation, the Go Oracle derives the trusted Observation.
At minimum it checks:

1. envelope bindings match the frozen run plan;
2. every media reference belongs to this tenant, site, run, and attempt;
3. content hashes and capture times match trusted media metadata;
4. evidence is inside freshness, frame-count, and byte budgets;
5. criterion, prompt, adapter, and contract versions match the plan;
6. every finding and region references supplied evidence;
7. required observables and exclusions are represented;
8. limitations and observability are compatible with the proposed disposition;
9. analyzer execution did not exceed its deadline or finish after a terminal
   run transition;
10. persistent device configuration writes equal zero.

The Oracle may preserve or downgrade an adapter disposition. It can never
upgrade `uncertain`, `not_observable`, or `unsupported` to a clear result. A
clear result with missing required evidence becomes `uncertain`; no usable
evidence becomes `not_observable`; an unsupported criterion remains
`unsupported`.

Multi-sample aggregation is deterministic and criterion-specific. Until a
template supplies an accepted rule, conflicting clear samples aggregate to
`uncertain`, not majority vote. `needs_attention` cannot be hidden by averaging
free-form confidence values.

## Malformed and Failed Output

The parser accepts one bounded JSON object only. Markdown fences, trailing
prose, duplicate keys, non-finite numbers, unknown fields, invalid UTF-8,
schema mismatch, excessive nesting, and oversized strings are invalid.

Failure handling is fail-closed:

| Condition | Trusted handling |
| --- | --- |
| Malformed or schema-invalid output | Record bounded failure facts; observation is `uncertain` with `invalid_model_output` when usable media exists. |
| Analyzer timeout before known dispatch | Retry only if the plan permits and budget remains. |
| Timeout after dispatch or unknown vendor outcome | Do not blind-retry; mark the step outcome `unknown` and reconcile if the adapter supports a typed read. |
| Adapter/model version differs from plan | `blocked`; do not silently upgrade. |
| Media stale, missing, hash-mismatched, or wrong scope | Reject the candidate and quarantine the reference. |
| Result arrives after cancellation, expiry, or another terminal attempt | Preserve a bounded audit fact; do not change or deliver the terminal result. |
| Unsupported criterion | Return `unsupported`; do not substitute a general-purpose prompt. |

Retries use a stable step identity plus a new attempt identity. Retrying
capture creates a new sample with a new media digest; it must not replace the
old evidence in place. Attempt count, elapsed time, frames, inference calls,
and temporary bytes share the run's finite budget.

## Rendering Contract

Human-facing text is rendered from trusted typed observations, not copied from
model prose. The enum names below are internal mappings; WorkBuddy and other
business channels send only the corresponding Chinese wording. Required
rendering distinctions include:

- `meets_rule`: “在本次可见范围内，未发现违反该项标准的证据。”
- `needs_attention`: “发现需要关注的可见情况，并附证据。”
- `uncertain`: “现有证据不足，无法判断。”
- `not_observable`: “该项在本次画面中不可观察。”
- `unsupported`: “当前分析能力不支持该项判断。”

Reports must include coverage, capture time, criterion version, limitations,
and evidence expiry. “未发现异常” must never be rendered as “卫生合格”、
“符合监管要求” or “整店正常”.

Temporary observation text is allowed only under its trusted display policy,
must be presented as a bounded model observation with evidence and limitations,
and must not be reused as standard-report wording.
