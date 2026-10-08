# Decision: preserve operation identity across failures

Status: accepted for local capture and algorithm-change workflows.

## Problem

A disconnected client cannot tell whether its last request reached the service.
A service interrupted during a device write cannot tell whether the device
accepted that write. Repeating either request with a new identity can acquire a
different image or change a task twice. A current device snapshot cannot prove
which earlier request caused its state.

## Decision

Persist one request identity before submission. MCP maps a caller's
`contextRef` and `requestKey` to a durable service request ID. Reusing the key
with the same normalized input returns the original operation; different input
is a conflict. When adapter processes share a journal, its unique constraint
selects the submitter and revision checks prevent stale results from replacing
newer ones. Continuation queries the original operation or request ID.

This provides duplicate-submission prevention and explicit uncertainty. It does
not promise exactly-once execution across an arbitrary device API and a local
database.

### Device-write boundary

An algorithm change first becomes a durable proposal. Its exact local business
confirmation queues it. Opening the review page and granting an MCP tool
permission do not supply that confirmation.

The Action Kernel commits a dispatch marker before calling the device. Recovery
uses that boundary rather than guessing from a timeout:

| State at service interruption | Recovered result | Reason |
| --- | --- | --- |
| `proposed`, `queued`, `claimed` | `blocked` | Foreground confirmation material is no longer available; no automatic write |
| `dispatching`, `verifying` | `unknown` | A write may have reached the device; no replay |
| Terminal result | Retained | Later reads do not replace the original outcome |

Confirmation tokens and native configuration material stay in process memory;
reopening the ledger does not recreate write authority. Cancellation invalidates
an unexecuted proposal. A later inverse change requires a separate proposal,
confirmation and verification; it is not cancellation of the earlier write.

### Bind the target, then verify it again

A proposal freezes the selected device, connection epoch, source fingerprint,
algorithm, original task and intended configuration. Confirmation and execution
check these bindings again. Returning to a previously selected device is still
a new selection epoch. Source or configuration drift blocks the stale proposal.

After an accepted write, completion requires configuration and enable-state
readback. Enabling also requires two fresh runtime samples with progress for
the expected processing nodes, followed by another configuration check. A
successful switch or a cumulative counter alone is insufficient. An ambiguous
write remains unknown even if a later snapshot shows processing.

### Preserve evidence separately from current state

The original verification and a fresh status observation have different times
and meanings. A later stopped task does not erase a verified earlier start or
identify who stopped it. A failed current read must not invent absence from
default values.

Capture uses the same request-identity rule. Result lookup and artifact resend
must not start another capture. A retained original keeps its digest, source
binding and ownership. Missing or expired bytes remain unavailable; a newly
captured image is a new operation. Artifact integrity, model access and visible
delivery in a host client are separately verified outcomes.

## Implementation and regression checks

Keep these rules in the shared service and journal, so every client has the same
execution boundary. Skills explain the workflow but are not its only guard.
Use the existing closed diagnostic fields rather than persisting raw device
responses or transport error strings.

| Contract | Implementation | Regression coverage |
| --- | --- | --- |
| Shared request claims and continuation | [MCP journal](../../internal/mcpbridge/store.go), [bridge](../../internal/mcpbridge/bridge.go) | [Lost output, shared contexts and restart tests](../../internal/mcpbridge/bridge_test.go) |
| Durable dispatch and restart outcomes | [Action Kernel](../../internal/operator/kernel/kernel.go), [ledger](../../internal/operator/ledger/store.go) | [Ledger restart and concurrent-claim tests](../../internal/operator/ledger/store_test.go) |
| Target identity and local confirmation | [Deployment service](../../internal/operations/deployment/service.go), [handler](../../internal/operations/deployment/handler.go) | [Selection-epoch tests](../../internal/operations/deployment/confirmation_binding_test.go) |
| Original verification versus current state | [Deployment evidence](../../internal/operations/deployment/evidence.go) | [Evidence regression tests](../../internal/operations/deployment/evidence_test.go) |
| Capture continuation without recapture | [Capture progress](../../internal/operations/observation/capture.go) | [Interrupted download and retained-original tests](../../internal/operations/observation/capture_test.go) |

Changes to these boundaries need failure tests around submission, dispatch,
restart and stale reads, not only successful requests. See the
[operations contract](../operations.md), [troubleshooting guide](../troubleshooting.md)
and [release acceptance cases](../testing.md).
