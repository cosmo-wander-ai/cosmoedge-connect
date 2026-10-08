---
name: cosmoedge-device-lab
description: Run high-frequency, model-directed, zero-write real-device probes against the currently authorized CosmoEdge development device. Use during repository development to test dynamic hypotheses about identity, health, camera/task catalogs, task state, and alarm observations while keeping credentials, endpoints, raw device IDs, success judgment, and write authority outside model control.
---

# CosmoEdge Device Lab

Use only in the CosmoEdge Connect development repository on an authorized Windows
machine. This is an engineering validation surface, not an ordinary product
capability.

## Start one bounded run

```powershell
./scripts/cosmoedge-device-lab.ps1 -Action Start
./scripts/cosmoedge-device-lab.ps1 -Action Begin
```

The begin result reports a masked device, expiry, and `deviceWrites: 0`.
Do not request credentials or inspect DevAuthority or DevLab state files.

## Generate probes

Send one typed JSON request at a time:

```powershell
./scripts/cosmoedge-device-lab.ps1 -Action Probe -RequestJson '{"kind":"task_catalog","repeat":3,"intervalMs":500,"hypothesis":"task catalog remains stable","assertions":[{"kind":"stable","path":"catalogFingerprint"},{"kind":"non_empty","path":"tasks"}]}'
```

Supported kinds are `identity`, `health`, `camera_catalog`, `task_catalog`,
`task_state`, `event_window`, and `snapshot`. Use only handles returned by the
current run. `task_state` and `event_window` require a task handle. Event
windows are `last_1h` and `last_24h`.

Supported assertions are `known`, `non_empty`, `stable`, and `equals`. Treat
the Go Oracle's assertion status as authoritative; never declare success from
the hypothesis text or from an unasserted visual impression. Adapt subsequent
probes to observations and failures instead of relying on a fixed suite.

Budgets are server-enforced: at most 10 minutes, 200 reads, 50 samples per
probe, and a 250 ms minimum repeated-sample interval. A stale handle requires a
fresh catalog probe. Never access the locator, token, endpoint, credential,
raw IDs, or evidence database directly.

## Finish

```powershell
./scripts/cosmoedge-device-lab.ps1 -Action Finish
./scripts/cosmoedge-device-lab.ps1 -Action Stop
```

Always finish a run and stop the daemon after validation. Report the run ID,
probe/assertion/read counts, Oracle failures, and `deviceWrites`; do not report
the run as passing unless the finish result and required assertions passed.
