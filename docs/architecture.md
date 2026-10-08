# Architecture

CosmoEdge Connect is a local single-device service. Its active business domains are
retained-alarm summaries, camera-image capture and changes to installed
algorithms. The MCP adapter exposes these domains to local AI clients; the
WorkBuddy integration uses its paired Python client and Skill.

```text
AI client / third-party MCP client
  -> cosmoedge-mcp (stdio, context/request journal, content conversion)
  -> CosmoEdge Connect loopback operations API
  -> summary / observation / deployment services
  -> shared connection owner, session, device adapter
  -> CosmoEdge

WorkBuddy Skill -> paired Python client -> same operations API
```

## Responsibilities

| Layer | Owns |
| --- | --- |
| AI host and its configured integration | Task planning, model-based preliminary review, task policy and any scheduling, notifications or escalation |
| Skill | Interpreting dates and names, asking useful clarification, same-image follow-ups, explaining evidence |
| MCP adapter / host tool client | Tool arguments, explicit business contexts, persisted request identity, bounded continuation, native content delivery |
| Operations service | Business calculations, frozen target selection, durable operation state, artifact integrity, execution and readback |
| Connection owner | One selected device, protected connection persistence, startup restoration and exclusive state-root ownership |
| Action Kernel | Accepted dispatch, immutable proposed target, exact confirmation and verification of device writes |
| Platform installer | Paired package identity, current-user installation, managed process lifecycle and file recovery |

A user can delegate a whole handover task: the host coordinates alarm queries,
requested source images and a brief with follow-up items and originals. Connect
supplies the tool operations, device access and recoverable evidence. Its durable
operation records are not a business task log, ticketing system or alarm-closure
workflow. The host retains responsibility for the task and its delivery.

Scheduled checks and authorized preliminary review can be built by a capable
host using these tools. Connect has no built-in scheduler or notification service;
those host integrations need separate validation. Integration includes keeping
the local service available, launching the local stdio adapter, maintaining valid
service-session authorization, and defining each run's task scope and state.
The host must handle missed runs, unavailable devices, expired sessions and
failed delivery. After an uncertain submission it must recover the original
operation using its saved context and request identity, rather than start a
duplicate run. See [MCP recovery](mcp.md#request-recovery) for session and journal
lifetimes. Host policy cannot authorize a device write in place of local
confirmation: each pause or resume still uses its own proposal, confirmation
and result verification.

The public integration contract is [MCP](mcp.md). Internal HTTP routes and Go
packages may change with their paired adapter. The Go module is
`github.com/cosmo-wander-ai/cosmoedge-connect`; the product entrypoints are
`cmd/cosmoedge-connect` and `cmd/cosmoedge-mcp`.

## State and lifecycle

Start the connection owner before business workers. Stop admission and business
workers before releasing connection resources. The installation's state root
has one owner; a second service instance must not share it. The connection owner has a bounded startup restore, while current
status always comes from fresh device observations.

The current selector, profiles and encrypted credential stores survive a normal
restart. Replacing a device advances its selection boundary. An old operation
must not silently rebind to the new device, source or algorithm. A startup
`connectionRestoreState` field is a startup result, not continuous liveness.

Observation owns its operation, acquisition, temporary-task cleanup and media
state under its own namespace. It does not start the internal Inspection schedule
or delivery workers. Reading a result does not acknowledge external delivery,
restart acquisition or dispatch another write.

Deployment persists the proposal and original verification, then samples current
state separately. Cancellation applies only before execution; restoring an
already changed task creates its own proposal and verified operation.

The [operation recovery decision](decisions/0002-operation-recovery.md) explains
the durable dispatch boundary, target binding and behavior after interruption.
Use [troubleshooting](troubleshooting.md) to distinguish transport failures,
device outcomes and unavailable evidence.

## Shared and retained code

`internal/operator` is still an active shared dependency: CosmoEdge Connect uses its
connection owner, sessions, web confirmation, Action Kernel and ledger.
`internal/inspection` supplies internal media/runtime/contract pieces and
regression surfaces. These internal modules do not add public product entrypoints.

Schema and example paths under [inspection](inspection/README.md) remain stable
because tests consume them. Test fixtures, golden cases and failure regressions
are maintained with the code. Maintained design rationale is recorded in the
[local integration decision](decisions/0001-local-integration.md) and
[operation recovery decision](decisions/0002-operation-recovery.md); reusable
diagnostic lessons are in [troubleshooting](troubleshooting.md).

## Distribution boundary

Official service, adapter and WorkBuddy payloads carry matched candidate
identities. Third-party MCP clients implement the protocol without matching the
repository revision. Installation integrity, runtime behavior, image delivery
and device acceptance are separate checks; see [testing](testing.md).

Remote HTTP MCP, multi-user authentication, multi-device routing and phone
confirmation are outside this local release. Extending those requires explicit
identity, artifact-access and confirmation designs. A host that schedules local
stdio calls must preserve the same context, request-recovery and confirmation
contracts; scheduled execution is not an additional Connect service.
