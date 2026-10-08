# Local MCP integration

**English** | [简体中文](mcp.zh-CN.md)

[Home](../README.md) · [Installation](installation.md) · [Quickstart](getting-started.md)

`cosmoedge-mcp` exposes the CosmoEdge Connect operations service over stdio. The AI client
launches this adapter as a child process; the CosmoEdge Connect service must already be
installed and running. The adapter does not provision a device connection or
start the service itself.

This is a trusted local-user integration. Remote Streamable HTTP, cloud hosting
and multi-user authentication are not part of this release. Client acceptance is
recorded separately in [compatibility](compatibility.md).

## Install and configure

Build the paired package with MCP included:

```sh
make package-macos VERSION=cosmoedge-connect-dev-local PACKAGE_DIR=../cosmoedge-connect-dev-local
```

The underlying macOS builder supports `--with-mcp`; the Windows package target
includes it as well. Install the package using [installation](installation.md),
then generate configuration from the actual installed candidate. The bundle
contains the WorkBuddy `cosmoedge-operations` Skill, but MCP-only use does not require
WorkBuddy or native Skill import.

For a complete first-use walkthrough, see [getting started](getting-started.md).

On macOS:

```sh
/path/to/bundle/install.command mcp-config --client-id codex
```

On Windows:

```powershell
& "$env:LOCALAPPDATA/CosmoEdgeConnect/cosmoedge-connect-control.ps1" -Action McpConfig -ClientId codex
```

Choose a client ID such as `codex` or `claude` to organize its private journal.
IDs begin with a lowercase letter and contain up to 40 lowercase letters, digits
or hyphens. Multiple stdio processes may share one configured journal root: a
persisted request is claimed once, and competing processes recover it by reading
instead of submitting a duplicate. Separate client IDs produce separate roots
when that organization is useful. Neither arrangement automatically establishes
trusted host conversation identity; keep business contexts explicit.

The output is a `mcpServers.cosmoedge` entry with `command` and `args`. Copy those
values into the client's local stdio MCP configuration. Some clients use JSON,
others use a settings page or another file format; the executable and argument
values are the same. Do not paste token contents into client configuration.
Regenerate configuration after upgrade or rollback, since it points to the
installed candidate.

The command shape is:

```sh
cosmoedge-mcp --base-url http://127.0.0.1:37789 --token-file /private/install/access.token --state-root /private/install/mcp-state/client-a --candidate-file /private/package/mcp-candidate.json
```

These paths are placeholders. Use installer output for real paths. The private
MCP journal is separate from service runtime state. `--candidate-file` identifies
the matching release; service, adapter and candidate identity must agree.
`--version-json` reports build identity without connecting to a device. On
Windows the candidate JSON must have the current-user DACL supplied by the
installer; saving an unprotected manual copy is not a supported setup route.

For source development:

```sh
go build -buildvcs=false -o cosmoedge-mcp ./cmd/cosmoedge-mcp
```

An arbitrary standalone build will not inherit an installed candidate's identity.
Use the paired builder when connecting to an installed service. A generic
third-party MCP client does not need the same source revision; only the official
adapter/service pair does.

### Codex CLI startup troubleshooting

If Codex reports that `codex-code-mode-host` is missing before any CosmoEdge Connect tool
call, check whether the `codex` launcher is a symlink. On macOS,
`ls -l "$(command -v codex)"` shows the launcher target. Invoke the original
installed Codex executable beside its bundled companion runtime, or repair the
Codex installation through its installer. Keep the executable and companion
from the same client installation; do not copy an unrelated runtime.

This client-packaging issue was observed with Codex CLI 0.155.0-alpha.16.3 and
resolved by invoking its existing executable directly. It does not establish a
CosmoEdge Connect service failure and does not require disabling sandbox or approval
controls. Client troubleshooting does not qualify a new package; see the
[current validation status](compatibility.md).

## Tools

Discover the complete JSON input schema through MCP `tools/list`. Tool names and
fields are the integration interface; do not parse localized human summaries.

| Tool | Purpose |
| --- | --- |
| `cosmoedge_capabilities` | Report adapter/service capabilities, availability and fresh `data.serverTime` |
| `cosmoedge_begin_context` | Create an explicit business context for this client's work |
| `cosmoedge_open_connection` | Open the local connection page; create a context when omitted |
| `cosmoedge_catalog` | Read current sources, installed algorithms, task bindings and service-computed `data.totals` |
| `cosmoedge_summary` | Query a fixed retained-alarm window and return statistics/report content |
| `cosmoedge_capture` | Acquire one source image for host-model analysis |
| `cosmoedge_get_operation` | Read the original operation and continue pending work |
| `cosmoedge_list_pending_operations` | Recover unfinished work for the context |
| `cosmoedge_prepare_algorithm_change` | Prepare an enable/disable proposal using an existing algorithm |
| `cosmoedge_open_review` | Open the proposal's local business-confirmation page |
| `cosmoedge_cancel` | Cancel an unexecuted proposal |
| `cosmoedge_get_artifact` | Retrieve the exact retained original image or report |

Catalog `data.totals` counts the returned lists: `sourceCount`, `sourcesByKind`,
`algorithmCount`, `taskCount`, `runningTaskCount`, `stoppedTaskCount`, and
`unknownRuntimeTaskCount`. Prefer these values to counting long lists. Source
groups are `network_camera`, `test_video`, `usb_camera`, and `unknown`; other or
missing kinds remain unknown, with the original entries unchanged. Runtime
counts use exact `running`/`stopped` states and keep other states unknown. They
do not infer runtime from enabled switches or prove processing-counter progress.

To connect or change a device, call `cosmoedge_open_connection` directly with
`{}`. The adapter verifies the paired service and creates a context internally;
retain the returned `contextRef` for this workflow. An existing `contextRef`
may be supplied instead. Explicit invalid or expired references are rejected
rather than replaced. If opening fails after context creation, retain the
returned reference. Other business tools still require a context.

A successful opening receipt has `ok: true`, `data.pageState: dispatched` and
`data.interactionRequired: true`. It means the browser launch was requested,
not that the page rendered or a device logged in. The dedicated page displays
its form and saved-connection options without a device catalog read. Credentials
and any device replacement confirmation stay on that local page.

For other business requests, the ordinary workflow is capabilities → context → catalog → the requested
business operation. Keep `contextRef` with the application's conversation or
job state. It is an adapter-generated scope reference, not a verified host-chat
identity. Do not share references between unrelated conversations. Before each
new relative-date summary, refresh `cosmoedge_capabilities` and derive the window
from its current server time. Continuations retain their original window.

`start` and `end` are absolute RFC3339 instants: UTC `Z` values can be passed
directly. `timeZone` controls calendar-day grouping and display; it does not
reinterpret those endpoints. For the past 24 hours, use fresh `serverTime` as
`end` and subtract 24 hours in UTC for `start`. Never replace `Z` with `+08:00`
while keeping the same clock time. A representation change must preserve the
instant: `2026-05-06T12:00:00Z` equals `2026-05-06T20:00:00+08:00`, not
`2026-05-06T12:00:00+08:00`. For calendar-date requests, calculate the requested
local midnight boundaries in the business timezone before encoding them.

## Request recovery

Capture and algorithm-change preparation require a `requestKey` in addition to
`contextRef`. The caller creates a stable key for one user intent and saves it
before calling the tool. This key is separate from the MCP JSON-RPC request ID.
The adapter persists its mapped service request before submitting it.

If the transport disconnects, resume with the same context and request key.
Recovery queries the original operation rather than submitting another request.
Changed business input under the same key is a conflict. A not-yet-confirmed
proposal, a pending operation and an unknown outcome are distinct states.

Completed contexts use a default 30-day retention window, evaluated when a new
context is created. Unresolved operations are retained. Maintenance is a local
CLI action: the normal connection flags plus `--maintenance` report a dry-run;
`--retention-days` selects a window and `--apply` applies eligible cleanup.
There is no tool that clears all pending work. Expired artifacts cannot be
regenerated as if they were the original.

The service session has a separate seven-day online authorization window.
Keeping a journal for 30 days does not extend it. After session expiry, offline
`cosmoedge_get_artifact` may still return a retained original, but online operation
reads require their original valid service session. Do not create a new context
and resubmit an unknown device change to work around expiration.

Preserve the private journal across ordinary restarts. Start with
`cosmoedge_list_pending_operations` when reconnecting, then use `cosmoedge_get_operation`. Do not
create a new context or request key just to hide a failed-looking response.
A client may implement bounded polling and resume later without asking the user
to issue the same instruction again.

## Images and reports

Images are returned as native MCP image content. Reports are returned as embedded
text resources. Artifacts include opaque references and integrity metadata;
`cosmoedge_get_artifact` retrieves the same original in the same context. No public local
file path or arbitrary fetch URL is required by this interface.

The host must actually pass the image to its model before answering visual
questions. A client must separately expose the attachment to its user. A native
MCP image/content response alone does not prove that every client's UI displayed
or saved it. An unavailable or expired artifact does not authorize a fresh
capture or summary query.

## Algorithm changes

`cosmoedge_prepare_algorithm_change` prepares the exact source/algorithm change.
`cosmoedge_open_review` opens the local page; it does not confirm the change. After the
user confirms, query the same operation until a real outcome is available.
MCP tool permissions do not substitute for the business confirmation.

Use `cosmoedge_cancel` if the user withdraws an unexecuted proposal. Check the
returned cancellation flag and actual state before reporting cancellation. If
confirmation raced with cancellation and the operation is queued or running,
reconcile it before preparing a conflicting replacement. Once an action has
executed, an opposite change is a new proposal. Preserve original outcome and
current readback separately; do not infer processing from enable state alone.

## Minimal client example

A source example can exercise the interface without a Skill:

```sh
go run ./examples/mcp-client --server /absolute/path/to/paired/cosmoedge-mcp --mock
```

`--mock` starts a synthetic loopback service and demonstrates the tools and
content/recovery flow, including multiple stdio processes sharing a journal.
It does not connect to a device, invoke a model or establish host UI delivery.
The server executable must be the adapter built from this source or a compatible
paired package. Run the example from the source checkout.

Without `--mock`, the example lists tools and calls capabilities only; it does
not capture an image or change a device. See the [example source](../examples/mcp-client/main.go)
for accepted flags and lifecycle handling.

## Third-party client checklist

A minimal client can use the tools without an official Skill. The optional
[operations Skill (Chinese)](../skills/cosmoedge-operations/SKILL.md) adds workflow guidance;
it does not implement credentials, confirmation or device execution.
A client needs to:

1. Initialize stdio MCP and discover tool schemas.
2. Persist context references and request keys before mutating calls.
3. Handle tool errors, pending results and uncertain submission explicitly.
4. Consume image and resource content, and offer originals to its user.
5. Open local connection/review flows and read back the same operation.
6. Keep independent conversations' references separate.

See [operations](operations.md) for data meaning and [testing](testing.md) for
acceptance cases. Schema or semantic changes must be called out in release
notes; unreleased development builds have no promised cross-version API stability.
