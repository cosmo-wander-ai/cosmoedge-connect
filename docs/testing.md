# Testing and release acceptance

Code checks establish implementation behavior. An installed candidate also needs
native lifecycle, real-client delivery and device checks before its platform can
be listed as accepted.

## Automated checks

```sh
make check
make race
```

For focused diagnostics:

```sh
go test -p 1 -buildvcs=false -count=1 ./...
go vet ./...
python3 -m unittest discover -s integrations/workbuddy/tests -v
python3 -m unittest discover -s integrations/workbuddy/deploy/macos/tests -v
python3 -m unittest discover -s integrations/workbuddy/deploy/windows/tests -v
python3 -m unittest discover -s scripts/tests -v
python3 scripts/check-docs.py
```

Run race checks on a supported native platform. CI runs Go/client checks on
Linux, macOS and Windows, with Linux race checks. POSIX-only macOS installer,
macOS builder and report-hook tests skip on Windows; Windows DACL and native
PowerShell tests skip on non-Windows hosts. Record those outcomes as skips. Installer unit tests that replace OS boundaries do not prove real
launchd/PowerShell behavior. Cross-compilation is build evidence only.

Preserve exact schema/example paths used by contract tests under
[inspection](inspection/README.md). Frozen fixtures are synthetic regression
material, not device connectivity or model-accuracy evidence.

## Candidate checks

Freeze the source revision, package manifest and actual binaries. Verify a clean
install, retained connection after cold restart, upgrade, rejected mismatched
payload, and rollback of managed files. Confirm one service owns the listener
and state root; unrelated processes must remain untouched. Verify device state
separately from installation-file restoration.

For MCP, initialize a real stdio client, discover tools and use the returned
schemas without a Skill. Verify that two contexts cannot read one another's
operations or artifacts. Exercise two stdio processes sharing one journal and
the same request key; they must not duplicate submission or overwrite a newer
receipt with a stale result.
Disconnect after submission and recover the same request after restart without
repeating acquisition or device changes. A changed payload with the same request
key must fail.

## Native Windows lifecycle smoke

On a dedicated Windows runner with PowerShell 7, first build a Windows package
with `--with-mcp`, then run the real isolated lifecycle harness:

```powershell
$bundle = 'C:/path/to/new-cosmoedge-connect-package'
$manifestHash = (Get-FileHash "$bundle/manifest.json" -Algorithm SHA256).Hash
./scripts/test-windows-lifecycle.ps1 -Bundle $bundle -ExpectedManifestSHA256 $manifestHash -Python python -Go go
```

It tests first installation with `-NoStartup`, paired status, idempotent start,
MCP configuration, stop and a fresh restart. It builds the repository's normal
MCP example and connects through real stdio without `--mock`; that example only
lists tools and queries capabilities. No device is configured and no WorkBuddy
GUI is opened.

The harness supplies temporary private `LOCALAPPDATA` and `USERPROFILE` only to
child processes. It does not modify the parent's environment or register a login
shortcut. It refuses an existing listener on port 37789 and cleans up only its
exact installed executable paths and private directory. Cleanup failure fails
the check and retains the affected private directory for diagnosis.

This is native package/protocol evidence, not real-device, user-confirmation or
WorkBuddy attachment acceptance.

## Real workflow cases

| Case | Required evidence |
| --- | --- |
| Connection page | One client action creates or reuses the intended context; first-use, saved and unavailable-device cases render the form without a device query; invalid explicit references fail without replacement |
| Directory | Actual source and algorithm names from the selected device; ambiguity handled explicitly |
| Alarm summary | Exact window, timezone, filters, coverage and counts reconciled with original retained records |
| Partial/zero data | Correct boundaries; no fabricated uptime, incident cause or full-window estimate |
| Image and follow-up | Correct original bytes, model actually reads the image, user receives it, follow-up reuses it |
| Artifact resend | Same original digest; no new summary query or capture merely to resend |
| Enable/disable | Exact target and preserved parameters; local confirmation; one intended dispatch; original verification and fresh readback |
| Cancel/change of mind | Unconfirmed proposal invalidated, no old proposal accidentally executed |
| Interrupted call | Original request identity recovered; unknown result not replayed |
| Restore/restart | Original device configuration and enable state restored; current processing checked when expected |

Run the three main workflows in each claimed AI client. Record client/model
versions. Visual correctness needs the actual image and independent review;
model self-assessment is not enough. Long-running and disconnect recovery claims
need their own measured windows and restored-state evidence.

For connection latency, record prompt submission, first client call, command
completion and the first observation of the usable connection form separately.
`pageState: dispatched` only records the browser launch request; an HTTP receipt
or the host's final answer does not measure page rendering. Compare the same
prompt, host and model with the previous candidate, preserving sample counts
and cold/warm service conditions. Opening the page must not submit a device login
or automatically replace a saved connection.

## Evidence and release

Record results as passed, partial, failed or unverified, attached to the exact
candidate. Preserve first failures when later runs improve. Keep raw media,
credentials, request files and device details in private evidence locations;
public release notes need only the reproduction, candidate identities, measured
outcome and limits.

The [compatibility matrix](compatibility.md) is the release-facing support record.
Update it after the corresponding checks, not merely after a successful build.
