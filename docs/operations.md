# Operations contract

These business rules apply across MCP and WorkBuddy. Host-specific invocation
is documented in [MCP](mcp.md) and the [WorkBuddy client contract](../integrations/workbuddy/skills/cosmoedge-operations/references/api-contract.md).

## Open a connection page

Opening the local connection page is one client action. WorkBuddy `connect` and
MCP `cosmoedge_open_connection` create a session or context when it is omitted,
and return that reference for the current workflow. An explicitly supplied
reference must be valid; it is never silently replaced. Pairing and HTTP
authorization remain part of the internal call sequence.

The opening receipt reports `ok: true`, `pageState: dispatched` and
`interactionRequired: true`. This means browser launch was requested, not that
the page rendered, the user saw it or a device connected. The dedicated page
shows its connection form without querying the device. Enter credentials and
confirm replacement of an existing device there.

## Retained-alarm summaries

A summary uses a fixed start, end and timezone, optionally filtered by selected
sources and algorithm. Source and algorithm filters are independent. The
service resolves every requested source before querying; it never treats a
camera whose name contains an algorithm name as an algorithm restriction.

The result supplies counts, date/source/algorithm groupings, shares, original
report and coverage. Day/source zero cells are explicit. Shares use matching
retrieved records as their denominator; a zero denominator is null. A partial
read describes its retrieved subset, not an estimate of unread records.

The maximum window is 31 days. A query through today ends at the actual available
server time. Retention can change during pagination, including for past dates;
coverage and drift indicators remain part of the result. Counts do not establish
historical uptime, algorithm enable history, incident causes or accuracy.

Reuse the original summary and report for questions already covered by its
breakdowns. A new window or filter creates a new query. Failure to deliver a
report does not erase the returned statistics or justify silently querying a
different window.

## Images

Capture selects exactly one source from the current catalog and freezes its
identity. Ambiguous names return choices. A changed, removed or mismatched
source fails rather than falling back to a default camera.

One capture produces an original image for the host model. The ordinary capture
path does not create an edge analysis task or supply a service-generated visual
answer. The separate internal edge-observation path retains its own typed
analysis and unknown-result semantics.

The retrieval timestamp is not independent proof of camera exposure or OSD
time. Preserve source type, including test-video provenance. Read the image
before answering visual questions; missing evidence cannot be replaced by an
invented scene description. Reuse the same original for follow-ups unless a
fresh image is explicitly requested.

Integrity-verified bytes, model access and user-visible display are three
separate outcomes. An attachment failure leaves the operation result available
and can be retried for the same artifact. It does not authorize another capture.

## Device changes

A source/algorithm proposal preserves its target and intended change. Existing
parameters, region and plan are retained. Local confirmation displays the exact
change; opening the page alone never authorizes execution. General MCP tool
approval is not that business confirmation.

Each operation has its own dispatch/write counts and original verification.
Readback distinguishes enabled, configured and actually processing states.
A successful enabled switch alone does not prove progress. A later stopped
state does not rewrite the original result or establish why it changed.

Cancel invalidates an unexecuted proposal without a device write. Once dispatch
has started, inspect the original operation; use a separately prepared operation
for any subsequent change. A failed or unknown result is not automatically
replayed.

## Recovery and scope

Persist the request identity before submitting capture or a device-change
proposal. Reusing it with the same normalized input recovers the original
request; using it with different input is a conflict. After uncertain submission,
query that identity or its operation reference. Do not create a new identity to
make a failed-looking response disappear.

Contexts, operations and artifacts remain scoped to their owning local client
context. A context reference is not a verified host conversation identity or
remote-user authentication. Keep independent conversations' references separate.
Artifact retention is bounded by service and client storage behavior; expired
or missing originals remain unavailable rather than being silently regenerated.

Original completion and current state carry distinct observation times. Local
process timeout, installation success, HTTP success and successful model prose
are not substitutes for the operation's verified outcome.
