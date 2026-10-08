# Troubleshooting

Start with the affected operation, its original result and a fresh observation.
Record service/client versions, package identity, request identity, timestamps,
operation state and safe diagnostic fields. Keep credentials, device addresses,
raw responses and original media in private evidence storage. Public reports
should contain a sanitized reproduction, observed behavior and remaining limits.

## Read the failure boundary

The [safe diagnostic contract](../internal/safediagnostic/diagnostic.go) separates
operation, phase, class, HTTP status, native response codes and local validation
codes. An HTTP 200 can carry a native rejection; native business codes are not
HTTP statuses. A transport failure after a write may mean an unknown outcome.
Preserve those distinctions instead of parsing a localized error message or
retrying every failed-looking response.

Regression coverage: [adapter diagnostic tests](../internal/adapter/diagnostic_test.go)
and [deployment diagnostic tests](../internal/operations/deployment/handler_diagnostic_test.go).

## The connection page takes a long time to open

Separate prompt-to-first-tool time, client preparation, service response and
first observation of the usable form. Earlier workflows added script discovery,
explicit session creation and request-file preparation before opening the page.
The current workflow exposes one `cosmoedge_open_connection` call, or WorkBuddy
`connect`; the client handles pairing and context creation internally.

Check that the installed client and Skill use that direct path. The initial
connection form must render without a device catalog query. Retain an explicitly
supplied context: an invalid or expired reference must fail instead of silently
creating a replacement. After executable changes, check the host's current
trust/enablement state and regenerate installed MCP configuration when required.

Measure comparable prompts, host/model versions and cold/warm conditions.
`pageState: dispatched` means the browser launch was requested. It does not
measure first paint or establish a completed device login.

Regression coverage: [MCP connection tests](../internal/mcpbridge/open_connection_test.go)
and [connection-page tests](../internal/operations/httpapi/connection_page_test.go).

## Capture succeeds but downloading the picture fails

Check the diagnostic phase before changing capture behavior. The device's API
listener and its static media Web origin can use different ports. A diagnostic
client built directly with `adapter.NewClientWithHTTPClient` can omit the media
origin configured by the product's `device.NewV1Client`; downloading a valid
`/web/...` reference from the API listener can then fail with HTTP 400.

Compare the diagnostic client's configured media origin with the
[product constructor](../internal/operator/device/device.go). For a controlled
reproduction, retain the same capture reference and compare only the download
configuration. Do not acquire another picture to hide the failed download, send
credentials to a different origin, or relax origin/path/redirect checks. If the
reference no longer exists, report that limitation.

A successful JPEG download proves retrieval of those bytes. Retrieval time and
camera OSD time alone do not establish exposure time or freshness; use advancing
frames and independent source observations for a freshness claim.

Regression coverage: [media-origin tests](../internal/operator/device/device_test.go)
and [bounded download tests](../internal/adapter/inspection_test.go).

## A task is enabled but processing is unconfirmed, or later stops

Inspect the exact source/algorithm binding, configuration and runtime samples.
An enabled switch and a `running` catalog row do not prove that the expected
nodes are making progress. The verifier requires two increasing-time samples
with matching node sets and increasing counters, then rechecks the task's
configuration. Counter resets, stalled nodes or a changed task require new
observations; see [verification logic](../internal/operations/deployment/verification.go).

Compare the original operation's dispatch/write counts and verification with
the later current-state observation. A closed review page or expired proposal
does not by itself explain a later device stop. Check target-specific device
logs, source continuity and other writers. End-of-file on a finite test video
is one possible cause; do not assert it without evidence or assume a local
firmware fix is present on the installed device.

For disconnect/recovery testing, first establish healthy frames and processing,
then interrupt a controlled source and verify recovery of the same binding.
Record any manual restart. A failed initial source connection cannot demonstrate
healthy-to-disconnected behavior, and a short run cannot establish long-term
stability. Restore the actual pre-test configuration and verify it afterwards.

Regression coverage: [deployment behavior tests](../internal/operations/deployment/service_test.go)
and [original/current evidence tests](../internal/operations/deployment/evidence_test.go).

## A request timed out, the client restarted, or an attachment is missing

For MCP, recover the original `contextRef` and `requestKey`, then query the
existing operation. `cosmoedge_list_pending_operations` helps locate unfinished
local requests; it does not itself prove service acceptance.

For WorkBuddy, retain the original request file with its `sessionRef`,
`requestId` and `operationKind`. Use `recover-observation` or
`recover-deployment` with that file for read-only recovery. If an `operationRef`
is already known, query it in the original session and omit `requestId`.
See the [WorkBuddy recovery contract](../integrations/workbuddy/skills/cosmoedge-operations/references/api-contract.md).

For either client, do not create a new identity to make an uncertain write or
capture appear successful. A recovered pre-dispatch operation can be blocked;
one interrupted after dispatch can remain unknown. See
[the recovery decision](decisions/0002-operation-recovery.md).

If only attachment delivery failed, retrieve the retained artifact in its owning
context and compare its digest. Verify separately that the host model received
the image and the user can see the attachment. Resending an original does not
require another capture or summary. Expired artifacts stay unavailable, and
retained client journals do not extend the service session's authorization
window; see [MCP recovery and retention](mcp.md).

## A saved connection does not restore

Treat `connectionRestoreState` as the startup attempt's result. Current liveness
requires a fresh observation. Inspect the typed transport/authentication cause
and the selected device binding; a transport failure is not proof that saved
credentials are invalid. Avoid deleting the selector or credential store as a
first response: they preserve the selected identity and replacement boundary.
Use the local connection page's supported retry or replacement flow.

Also check that only one service owns the installation's state root. Business
workers must stop before connection resources and their ownership lease are
released. Regression coverage: [restore diagnostics](../internal/operator/connectionowner/restore_diagnostic_test.go),
[transport restoration tests](../internal/operator/session/restore_transport_test.go)
and [connection ownership](../internal/operator/connectionowner/owner.go).

## A clean check or package build differs from the working directory

Git-ignored experiment code can still be discovered by `go test ./...`, causing
errors such as duplicate `main` declarations. Preserve the initial error and
reproduce source checks in a clean checkout. Keep private experiments and
generated outputs outside the source package tree; deleting a failing file
without understanding its origin is not a reproducible fix.

Package builders reject output inside the worktree. Resolve the intended output
directory before building and verify the actual package manifest afterwards.
A rebuilt package has its own identity and must not inherit another package's
installation or device acceptance. See [development](development.md) and
[testing](testing.md).

For CI failures, first check whether a runner actually started and test steps
executed. A job with no runner or steps may be blocked by account, quota or
scheduling conditions; inspect its annotations before attributing it to code.
Local passing checks do not turn an unexecuted CI job or a skipped native
platform test into a pass.
