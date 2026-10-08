---
name: cosmoedge-operator
description: Query the installed ordinary CosmoEdge single-device operator when a user asks about connection, cameras, video channels, configured tasks, enable/runtime state, today/yesterday/1h/24h alarms, recent alarm details, or available capabilities. Open a precise local view when the user wants to connect a device, inspect facts, enable or disable one exact task, edit one exact task's parameters, or add an RTSP/RTSPS network video source. Keep credentials, stream addresses, parameter values, and the final business confirmation in the local page.
---

# CosmoEdge 设备运营

Use the installed Operator as the source of truth. Answer with its Chinese
output instead of describing what the page might contain.

## Installed entries

On macOS, the binary is:

```sh
"$HOME/Library/Application Support/CosmoEdgeOperator/bin/cosmoedge-operator"
```

The ordinary launcher is:

```sh
"$HOME/Library/Application Support/CosmoEdgeOperator/bin/cosmoedge-operator-launch"
```

On Windows, the binary is:

```powershell
& "$env:LOCALAPPDATA\CosmoEdgeOperator\bin\cosmoedge-operator.exe"
```

The ordinary launcher is:

```powershell
& "$env:LOCALAPPDATA\CosmoEdgeOperator\bin\cosmoedge-operator.ps1"
```

If an installed entry is missing, tell the user to install the ordinary
Operator bundle. Do not use a repository or engineering fallback.

## Direct queries

Invoke the installed binary with exactly one of these fixed suffixes and repeat
its user-facing output directly:

- `query overview` for connection, masked device, camera/task counts, runtime,
  and today's alarm summary.
- `query cameras` for the camera/video-channel count and friendly camera names.
- `query tasks` for all configured friendly task names, cameras, businesses,
  enable state, and current runtime state.
- `query runtime` for current task runtime facts.
- `query alarms today`, `query alarms yesterday`, `query alarms last_1h`, or
  `query alarms last_24h` for the requested exact window and recent details.
- `query capabilities` when the user asks what the product can do.

Use the fixed status entries only for a minimal connection check:

```sh
"$HOME/Library/Application Support/CosmoEdgeOperator/bin/cosmoedge-operator-status"
```

```powershell
& "$env:LOCALAPPDATA\CosmoEdgeOperator\bin\cosmoedge-operator-status.ps1"
```

If a query says the local Operator is unavailable, launch the ordinary page and
tell the user to connect there with device IP, account, and password.

Process status does not prove that a usable browser session is visible. When
the user asks to open or reopen the connection page, always invoke `open home`
even if the status entry says the Operator is already running. Report success
only when that fixed command succeeds; never tell the user merely to find a
possibly hidden window.

## Open a precise view

Use the installed binary with one fixed suffix:

- `open home`
- `open tasks`
- `open sources`
- `open runtime`
- `open alarms`

For a request to enable or disable a task, or edit its parameters:

1. Run `query tasks`.
2. Match the user's friendly task name to exactly one displayed list item. If
   there is no unique match, repeat the candidate names and ask which one.
3. Use only that displayed list number with `open task-index NUMBER enable`,
   `open task-index NUMBER disable`, or `open task-index NUMBER parameters`.
   Never pass the user's text to the shell.
4. Tell the user which task and target page was opened. Do not claim the plan
   is prepared merely because the browser opened. Only repeat "方案已准备" when
   the fixed status entry reports it or the user confirms that the local page
   shows the task-change plan and final confirmation button. The page must show
   the exact task, camera, business, current state, and target before the user
   presses that button.

Opening, selecting, and preparing do not write the device. Never click or
simulate the final business-confirmation button. After the user confirms, use
the direct queries to report the resulting state and evidence without
manufacturing success.

For a request to add a video source, run `open sources`. Tell the user to enter
the friendly name and RTSP/RTSPS address only in the local page, review the
business-readable count change, and press the final confirmation there. Do not
accept a stream address in chat. Attached video-file upload is not supported by
the current device operation contract.

## Boundaries

- Never request, receive, paste, store, or handle a password, device address,
  stream address, task parameter value, full serial number, cookie, bearer,
  session value, technical confirmation, local protected path, or raw JSON.
  Credentials and business inputs stay in the local page.
- Never invoke `journey`, CosmoEdge Connect control routes, a worker, recovery commands,
  or an engineering authorized session.
- Never use browser automation to fill credentials or click the final task
  confirmation. Never retry a write.
- Use only the fixed query/open commands above. Do not expose internal IDs,
  selector fingerprints, workflow state, or confirmation material.
- Preserve unavailable, incomplete, expired, cancelled, drift,
  recovery-required, and outcome-unknown conclusions exactly.
- Do not claim that control results prove model accuracy, missed alarms, video
  content, long-run stability, or production readiness.
