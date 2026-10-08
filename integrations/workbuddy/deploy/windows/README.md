# Windows CosmoEdge Connect installation

This entry builds paired Windows amd64 development packages with a service,
Python client, WorkBuddy Skill and optional local MCP adapter. Windows-native
installation and host behavior have their own acceptance gates; see
[compatibility](../../../../docs/compatibility.md).

## Build

Use a new output directory outside the source checkout:

```powershell
python scripts/build-connect-windows.py --with-mcp --output C:/builds/cosmoedge-connect-dev-windows --version cosmoedge-connect-dev-windows
```

`--go` may select a specific Go executable; it defaults to `go`. The builder
records source revision/inventory, creates the Windows service, Skill ZIP and
paired manifest, and reports `manifestSHA256`. `--with-mcp` adds the matching
adapter and its candidate file.

## Install or upgrade

Use the reported checksum and an existing Python 3.9+ executable:

```powershell
$bundle = 'C:/builds/cosmoedge-connect-dev-windows'
$python = 'C:/path/to/python.exe'
$manifestHash = '<manifestSHA256 from this build>'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$bundle/install-windows.ps1" -Bundle $bundle -ExpectedManifestSHA256 $manifestHash -Python $python
```

First installation creates a current-user-protected random transport token only
for a new or empty installation root. Existing valid tokens are preserved. A
nonempty installation whose token is missing is rejected; replacing the token
could invalidate saved encrypted credentials.

The installer validates package hashes and Python, backs up managed files and
Skill, retains runtime state, rejects an occupied port, then starts the paired
service on loopback and checks protocol/build identity. It adds a current-user
login shortcut. It does not change device tasks.

The installation is under `%LOCALAPPDATA%/CosmoEdgeConnect`; the Skill is under
`%USERPROFILE%/.workbuddy/skills/cosmoedge-operations`. Backups remain private
under `%LOCALAPPDATA%/CosmoEdgeConnectBackups`.

MCP-only use does not require the WorkBuddy application or native Skill import.
For WorkBuddy use, import the matching
`cosmoedge-operations.zip` through WorkBuddy. Start a new conversation and select
the refreshed Skill, then connect through the local page and query the catalog.
File installation alone does not establish that WorkBuddy loaded the new Skill.

## Lifecycle and MCP

```powershell
$control = "$env:LOCALAPPDATA/CosmoEdgeConnect/cosmoedge-connect-control.ps1"
& $control -Action Status
& $control -Action Stop
& $control -Action Start
& $control -Action McpConfig -ClientId codex
```

Start verifies paired files and is idempotent. Stop targets only this installed
executable. Stop the owned instance before installing a newer package.
`McpConfig` prints configuration for a package built with `--with-mcp`, without
token contents. Client IDs organize journal roots; multiple stdio processes may
share one configured root while keeping explicit business contexts. Regenerate
configuration after an upgrade or rollback. See [MCP](../../../../docs/mcp.md).

Failed installation stops its candidate and restores prior managed lifecycle
and Skill files. Current database state is preserved: restoring an older database
could replay a dispatched operation. Backups retain prior state for controlled
diagnosis; file recovery is not device restoration.

## Validation boundary

Portable tests cover package structure, token provisioning rules and client
behavior. Native PowerShell permission/lifecycle tests require Windows. Real
WorkBuddy image/report presentation and real-device enable/disable restoration
need separate checks on the exact Windows candidate. Skipped native tests and
cross-compilation do not establish those outcomes.
