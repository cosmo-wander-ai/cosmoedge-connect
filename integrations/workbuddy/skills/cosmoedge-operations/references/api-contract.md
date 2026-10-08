# CosmoEdge Connect operations client

These are tool details, not phrases to recite to operators. Use the installed launcher. Business requests use a private JSON request file and the current conversation's `sessionRef`; `session` and the direct `connect` entry do not need a file.

## Commands

| Command | Request fields beyond sessionRef | Purpose |
| --- | --- | --- |
| session | none | Create this conversation's identity; returns serverTime |
| catalog | none | Current sources, installed algorithms and bindings |
| connect | optional sessionRef | Dispatch the local connection page; create a conversation identity when omitted |
| summary | start, end, timeZone; optional sourceName or sourceNames, algorithmName | Deterministic retained-alarm statistics and original report |
| capture | sourceName; optional sourceRef, question, requestId | Capture evidence for host multimodal analysis; no edge analysis task |
| observe | sourceName, subject, question; optional sourceRef, requestId | Explicit edge analysis of a captured image |
| observation | exactly one of operationRef or requestId | Read the same capture or edge observation |
| deploy / stop | sourceName, algorithmName; optional requestId | Prepare a change for local user confirmation |
| confirm | operationRef | Open that proposal's local confirmation page |
| cancel | operationRef | Cancel an unconfirmed proposal without device writes |
| deployment | exactly one of operationRef or requestId | Read original result and separately sampled current state |
| recover-observation / recover-deployment | original request file | GET by the originally persisted request identity after lost output |

`sourceRef` may be selected only from this session's real directory or ambiguity choices. Omit a new requestId to let the client generate one. Explicit IDs use 1–128 ASCII letters, digits, dot, underscore or hyphen, starting with a letter/digit. Business query references are not new request IDs. `deploy/stop` cannot accept operationRef or confirmationToken; `confirm` cannot contain source/algorithm fields or client-generated tokens.

## Direct connection

Run `connect` without a request file or `sessionRef` for first connection. After
normal pairing verification, the client creates one session and requests the
connection page within the same total deadline. It returns the new `sessionRef`
for this conversation, including when a later page request fails or times out
after the session was received. The new session's `serverTime` is also retained
when available; reusing an existing session does not invent or refresh its clock.
It does not call `catalog`, inspect saved device state, connect to the device,
or wait for login.

Use `connect --session-ref "<current-sessionRef>"` to reuse this conversation's
identity. A private request file containing `sessionRef` remains supported.
An explicitly empty or malformed reference is rejected before any HTTP;
an expired or rejected reference is sent unchanged and is never silently
replaced. Other business commands still require a session.

A successful page request returns `ok: true`, `interactionRequired: true`,
`supportedInteraction: connection_only` and `pageState: dispatched`. This means
the browser-opening request was dispatched, not that the page was rendered or
the device was connected. Report that distinction without reading local state
or retrying the opening request to manufacture stronger evidence.

## Catalog totals

`catalog.totals` counts the exact returned directory: `sourceCount`, `sourcesByKind`, `algorithmCount`, `taskCount`, `runningTaskCount`, `stoppedTaskCount`, and `unknownRuntimeTaskCount`. Source kind buckets are `network_camera`, `test_video`, `usb_camera`, and `unknown`; missing or unrecognized kinds count as unknown while original entries remain unchanged. Runtime counts use only exact `running`/`stopped` values; every other value is unknown, regardless of the enabled switch. Running here preserves catalog runtime semantics and does not prove processing-counter progress. Use these computed totals instead of counting the lists yourself.

## Capture and edge observation

`capture` uses POST `/operations/v1/captures`; `observe` uses POST `/operations/v1/observations`. Both use the existing owner-bound observation queries and media routes. Capture results have `observation.kind: capture`, `analysisSource: none`, and terminal status `captured` when the original image is available. There is no service-generated visual answer for capture; the host must read the image to answer. Edge results retain yes/no/unable and their original unknown semantics.

`observedAt` is the image retrieval timestamp, not independent proof of camera frame time. A Z timestamp is UTC; convert it before labeling it Beijing time. Preserve source type and original operation when replying to follow-ups. A failed download does not authorize recapture. A different source or an explicit request for a fresh image creates a new capture. A different question about the same scene reuses the original image unless the user requests a refresh.

`attachmentFiles` lists hash-verified local originals. For images use native Read and then native present_files with those original paths and the current task's cwd. Read proves model access; a successful present_files receipt listing the path proves delivery. Neither guarantees the visual answer is correct. Available images should still be delivered when analysis is unknown. If no image could be read, do not supply a new host visual conclusion.

## Summary facts and reports

Camera selection and algorithm selection are independent filters. A request about one camera uses `sourceName`; several cameras use one nonempty `sourceNames` array. The service resolves all requested names before reading and combines their retained records in one summary/report. Use `algorithmName` only for an algorithm restriction actually requested by the user; a camera named after an algorithm is still a camera. Omitting it includes all algorithms recorded for the selected cameras. The report's `filters.sourceName` displays the resolved camera names together, while `summary.sourceIds` identifies the selected references.

`summary` contains the fixed window, timezone, count, byDay, byDaySource, bySource, byAlgorithm, bySourceAlgorithm, bySourceKind and coverage. `peak` describes the most frequent retained-alarm date for the queried window. Groups are independently computed by the service. byDaySource directly supplies each date/source count, including zero cells for known sources. Its source IDs include observed history and the explicitly selected sources, or the current catalog when unfiltered. Whole-window source/algorithm groupings do not establish each day's algorithm distribution. `summaryEvidence` identifies which breakdowns and historical facts were actually supplied. Follow-ups reuse `summaryContext` unless the user changes the window or filter.

Each group includes computed `sharePercent`. `shareBasis` identifies the selected window's retrieved-record denominator and numerator fields; sourceKind uses retainedRecordCount, not sourceCount. Zero denominator yields null. Partial retrieval gives the share of retrieved records, not an estimate for unread records. Other derived comparisons may use local deterministic calculation with these same scoped counts.

Time errors identify missing bounds, reversed bounds, a window longer than 31 days, invalid timezone, or a future end. The response retains `requestedWindow`; a future end also returns `serverTime` and `availableEnd`. Correct the original intended interval using those facts. A query through today ends at server time, while its start remains the intended local midnight. Changing the queried dates to find an accepted request would change the user's question.

`userMessage` is a concise computed headline, not a mandatory reply template. Answer the actual question from the supplied statistics, including justified comparisons. Use byDaySource to answer day/source comparisons within the same window without another device query. A zero cell in partial data means no matching record was read, not that the day had no retained records. Algorithm composition for a particular day still needs an explicitly scoped query. The service has not supplied historical uptime, changes or incident causes; current status cannot establish them. Source types are classified from the current catalog, not a historical inventory.

Original report preparation checks content length, SHA256 and candidate identity. `reportDelivery.state: ready` means a local original is available, not that it was sent. Use present_files to deliver it. Failed report preparation/delivery leaves any successfully returned summary facts and partial coverage unchanged. Reuse the file to resend; do not regenerate statistics just to resend an attachment.

## Deployment semantics

A proposal describes a possible action. `confirmationMode: local_page` requires one actual user confirmation in that page; opening, closing, or a chat acknowledgement does not execute or cancel it. Do not use tools to click confirmation for the user. `cancel` POSTs to `/operations/v1/deployments/cancel` with the original operationRef. Only the owning session can cancel an unconfirmed proposal; inspect the returned `cancelled` flag and actual state. Cancellation invalidates the pending proposal without another user approval or device write. An already executing/executed action cannot be undone by cancellation; a separate stop proposal is needed if the user wants it stopped.

The client's stdout is a concise business receipt, produced after complete response validation, binding and polling. `userMessage` describes the verified action and current status. `deployment.state` and `class` describe the original operation; sourceName and algorithmName identify its target. `currentReadbackAvailable`, originalObservedAt/originalSealedAt and currentObservedAt distinguish historical completion from fresh readback. An unknown response can retain lastKnownObservedAt without presenting an older snapshot as current. `supportedInteraction: none` means no actionable configuration or confirmation page is supplied for that result.

`deploymentDetails.path` points to the full private JSON receipt and candidate identity; its size and SHA256 describe that file. Read it when the user's follow-up needs detailed verification or diagnostics. It is not a user attachment. A details-file failure changes only details availability, not the action result. The full receipt retains originalVerification, current, the original proposed target, safe diagnostics and counters. Unknown native codes do not establish a cause. A failed device read supplies no new current observation or observation time.

Proposal-only responses provide no fresh device readback. Query an executed operation or catalog for current status. A later stopped state does not invalidate earlier processing or explain why it stopped. Runtime evidence needs target progress, not merely enabled/configured; the complete receipt preserves that proof and the original configuration comparison.

Dispatch and device-write counts cover that original operation's lifetime. They are neither fresh writes caused by polling nor conversation totals. Accepted dispatch with zero writes can mean the desired switch was already satisfied; zero alone cannot prove this for a failed or unknown request. Do not replay uncertain changes or substitute a new request to get a successful result.

## Request identity and bounded waiting

Use a separate private file for each new capture/observe/deploy/stop. Before submission the client atomically stores sessionRef, requestId and operationKind in the file. The observation kind also covers captures. Persisted IDs do not prove service acceptance. Do not overwrite unresolved files, carry them across sessions, or change their IDs.

On lost output use the matching recover command with the original file. Recovery performs GET only, never creates a new ID or POST. If an operation reference is already known, query it directly and omit requestId. Missing/unprepared files do not authorize another submission.

JSON waitSeconds (0–55) overrides the CLI value. New edge observe defaults to 0 for an immediate real receipt; other commands default to a 45-second polling budget only when an actual pending operation or deployment confirmation exists. `session` and `connect` do not poll or wait out this budget. An immediately terminal response prepares attachments. Pending responses retain continuation, and the host should continue in the same task without requiring the user to trigger each poll. A process timeout is not an accepted receipt.

When executing the client with WorkBuddy Bash, allow at least 70 seconds (`timeout: 70000`) for the outer process. The client's default total deadline is 55 seconds; a shorter Bash timeout can kill it before it returns its result or continuation. This does not extend the confirmation window or authorize a retrying write.

`confirm` opens the review once and uses the same budget to GET the original operation while the user confirms, then follows execution. It never clicks or POSTs a business confirmation. If the budget ends before the user acts, the returned proposal remains unconfirmed with a read-only continuation; it is not a failed deployment or permission to create another proposal.

## Installation

Service, client and Skill are a paired candidate. Version mismatch requires the matching installation; do not bypass checks or use legacy device endpoints. The current report workflow does not require the development report hook. Keep credentials, internal addresses, raw IDs and request references in tool parameters and local connection/confirmation pages.
