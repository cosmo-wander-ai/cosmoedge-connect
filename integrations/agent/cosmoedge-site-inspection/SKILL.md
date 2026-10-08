---
name: cosmoedge-site-inspection
description: Query available Inspection Offerings or start a bounded observation at a bound physical-site. Use for an explicit Skill invocation or a clear request asking what can be inspected or visibly checked at the current site; exclude software inspection, repository work, deployment, device administration, and persistent configuration changes.
---

# CosmoEdge Site Inspection

## Query current offerings

For a request asking what the Bound Site can inspect:

1. Run `cosmoedge-inspection capabilities` with empty standard input.
2. Read exactly one JSON envelope from standard output.
3. When `state` is `ready`, present `contextLabel` and every item in `offerings` as concise business-facing options.
4. When `state` is `unable`, present `message` without adding a cause or claiming that an inspection ran.
5. When `state` is `interaction_required`, present `message` and the bounded `interaction` action as a local handoff. Treat it as setup still required.

Keep the returned business meaning intact. Ask one clarification and take no action when the request lacks a physical location or an offerings intent.

## Start an inspection

For a clear physical-site observation request:

1. Run `cosmoedge-inspection inspect` and write one JSON object to standard input.
2. Set `instruction` to the user's original bounded request. Add `context` only for business facts the user supplied as name/value pairs.
3. Read exactly one JSON envelope from standard output.
4. For `accepted` or `working`, state that the inspection is still running and wait for a later user follow-up.
5. For `ready`, present the Result Projection concisely while preserving its answer, certainty, limitations, and evidence relationships.
6. For `unable`, `cancelled`, or `expired`, present the returned `message` without inventing a result.
7. For `interaction_required`, present the bounded local handoff and make clear that the requested setup is not complete.

## Continue a prior inspection

For a follow-up asking for progress or the result:

1. Run `cosmoedge-inspection continue` with `{}` as the standard-input JSON object, unless the user has just chosen a returned candidate.
2. Read exactly one JSON envelope from standard output.
3. Present `accepted`, `working`, `ready`, `unable`, `cancelled`, or `expired` using the same meaning-preservation rules as a new inspection.
4. For `clarification`, ask the user to choose using each candidate's `area`, `goal`, and `startedAt` values. Keep the choice in business language and never display or ask the user to copy `runRef`.
5. Once the user clearly selects a candidate, call `cosmoedge-inspection continue` with `{"runRef":"<chosen candidate's runRef>"}` on standard input. Use only the matching value returned in that clarification; do not invent it or choose by recency. If the choice is still ambiguous, ask one clarification without calling the CLI.
