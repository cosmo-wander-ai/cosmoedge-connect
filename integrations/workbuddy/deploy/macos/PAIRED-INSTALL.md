# macOS paired installation

The package installs one matched CosmoEdge Connect service, Python client and WorkBuddy
Skill. `--with-mcp` additionally includes the local stdio adapter. The managed
service uses the current user's `com.cosmoedge.connect` LaunchAgent and binds
to `127.0.0.1:37789`.

## Build

Run from a clean source checkout, using a new output directory outside it:

```sh
python3 scripts/build-connect-macos.py --development-app --with-mcp --version cosmoedge-connect-dev-local --output /absolute/path/to/cosmoedge-connect-dev-local
```

The builder requires Go, Python 3.9+ and macOS signing tools. Runtime installation
requires Python 3.9+ but does not need Go, Node or pip packages. `--arch arm64` or
`--arch amd64` selects the target. `--allow-dirty` is only for explicit development
candidates; the manifest retains the modified-source fact.

The output contains `install.command`, `manifest.json`, source inventory, service,
Skill/client and `cosmoedge-operations.zip`. With MCP enabled it also includes
the matched adapter and candidate identity. Keep the separately printed
`manifestSHA256` with the package. Hashes establish pairing and integrity, not
publisher identity; obtain packages from a trusted source.

`--development-app` is an ad hoc development app. `--signing-identity` selects
an available signing identity by fingerprint. The builder does not obtain a
certificate or perform notarization. Public distribution signing, MCP executable
signing and actual system permission behavior require their own release checks.
Do not treat a development signature as evidence of public distribution readiness.

## Install

Run as the logged-in desktop user, not root:

```sh
/path/to/bundle/install.command install --bundle /path/to/bundle --expected-manifest-sha256 <this package manifest SHA256>
```

The installer finds and validates Python 3.9+ and saves its absolute path. An
existing runtime may be selected with `COSMOEDGE_CONNECT_PYTHON=/absolute/path/to/python3`.
No runtime is silently installed. WorkBuddy calls the recorded interpreter,
independent of its shell PATH.

Managed files live under `~/Library/Application Support/CosmoEdgeConnect`:

- The release directory preserves the complete matched package.
- `CosmoEdge Connect.app` carries the service's own app identity.
- `runtime-state` preserves connection and operation databases.
- `access.token` is created on first installation and otherwise preserved.
- Installation metadata and Python path remain current-user private.

The paired Skill lives under `~/.workbuddy/skills/cosmoedge-operations`. An
explicit alternate Skill path can be selected with the installer's `--skill-dir`
option before the subcommand. The existing service token and runtime state must
not be removed to update a Skill.

The installer stops only its managed jobs, waits for the old listener to exit,
replaces paired files and verifies the candidate through its authenticated
version endpoint. An unrelated listener causes a conflict. Startup failure
attempts file/launch-state recovery and retains diagnostic metadata.

macOS may require local-network permission for CosmoEdge Connect. The user grants that
through the system prompt or Settings. `status` does not establish that permission
or actual device connectivity. The app is a managed background-service carrier;
use the installer lifecycle entry instead of launching another instance manually.

## WorkBuddy import

Skip native import when using only MCP; the WorkBuddy application is not required
for the MCP service path. The WorkBuddy Skill files remain part of the paired
package integrity checks.

Import the package's `cosmoedge-operations.zip` through WorkBuddy's native Skill
interface. If the same-name entry must be replaced, replace only that entry and
preserve the package and installer backup. Native scanning and disk files alone
do not prove import success; check the installed entry.

After native import:

```sh
/path/to/bundle/install.command finalize-skill-import
/path/to/bundle/install.command status
```

`finalize-skill-import` verifies candidate contents, ownership and paths before
normalizing only the known Skill files' permissions. It preserves allowed host
metadata and rejects tampering, missing/extra candidate files and links. It does
not replace contents, call the device, restart the service or import the Skill.

Start a new WorkBuddy conversation after an upgrade and select the current Skill.
If an assistant retains the old loaded instructions, use its native new-conversation
flow. Daily queries do not require repeatedly clearing context.

## MCP configuration

For a package built with `--with-mcp`:

```sh
/path/to/bundle/install.command mcp-config --client-id codex
/path/to/bundle/install.command mcp-config --client-id claude
```

Copy the emitted command and arguments into that client's stdio MCP settings.
The output has paths, never token contents. Each chosen client ID gets a private
journal; multiple processes from that same configuration may share it safely.
Business contexts remain explicit and are not inferred from processes or chats.
Regenerate configuration after upgrade or rollback because it refers
to the current release. The adapter expects the service to be running.

## Lifecycle and recovery

```sh
/path/to/bundle/install.command status
/path/to/bundle/install.command stop
/path/to/bundle/install.command start
/path/to/bundle/install.command restart
/path/to/bundle/install.command rollback
/path/to/bundle/install.command rollback --backup <backup ID returned by this installation>
```

A process lock serializes changes. Status verifies the paired files, app identity,
managed process/listener and permissions. It does not prove host attachment
presentation, visual correctness or device health. Start is idempotent; restart
waits for the old process to exit.

Rollback uses the recorded recovery point, restores managed files and verifies
the original service startup. An interrupted install must be reconciled before
another install. Recovery failure remains visible; it is not reported as success.

Runtime databases are preserved rather than rolled back. File recovery does not
undo device actions or prove database downgrade compatibility. Reconcile uncertain
operations and owned temporary resources before downgrading.

## Report hook development

The default report workflow does not require `summary-report-guard`.
`--with-summary-report-guard` is a development-only hook test option. Native
activation and actual interception require separate checks; file hashes alone
cannot prove the hook ran. The plugin is not included by default.

## Checks

```sh
python3 -m unittest discover -s integrations/workbuddy/deploy/macos/tests -v
```

These tests isolate filesystem and OS boundaries. They do not run real launchd,
connect to a device or prove native WorkBuddy import. The final candidate still
needs native installation, cold restart, actual content delivery and device
restoration checks described in the repository's testing guide.
