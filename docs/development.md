# Development

Build from the active mainline in a separate worktree for substantial changes.
Keep output directories outside the tracked source tree or under ignored
`output/`. Do not install development candidates over an active user installation
without a separate candidate and recovery plan.

## Toolchain

Use Go 1.25+, Python 3.9+ and Git. The `make` shortcuts require GNU Make;
on Windows use the individual Go/Python commands in [testing](testing.md) and
the direct Windows builder described in [installation](installation.md). Go's pure-Go SQLite driver does not require CGO for
normal builds. Native race tests require a supported C toolchain. Some Web UI
behavior tests invoke Node.js; install it in the developer environment before
running the full test set. Windows installer execution requires Windows
PowerShell; a skipped native test is not a pass.

```sh
make build
make check-plan
make check
```

Without Make, build the two public commands directly:

```sh
go build -o output/bin/ ./cmd/cosmoedge-connect ./cmd/cosmoedge-mcp
```

Run the synthetic MCP workflow without a device or credentials:

```sh
go run ./examples/mcp-client --server ./output/bin/cosmoedge-mcp --mock
```

On Windows the server path is `./output/bin/cosmoedge-mcp.exe`. The example
starts its own loopback fixture and exercises the actual stdio adapter.

`make build` builds the CosmoEdge Connect service and local MCP adapter.
`make check-plan` shows which checks the current changes need; `make check` runs
that selection. Project documentation and documentation images run only the
local link check. Code, build/CI configuration, runtime Skills, integration
files, schemas and unrecognized paths run the full local check set.

The default comparison starts at the branch's common ancestor with `origin/main`,
or `main` when no remote main is available, and includes staged, unstaged and
untracked non-ignored files. Use `make check CHECK_BASE=origin/main` to compare
against that exact baseline instead.
When the comparison cannot be established, the selection falls back to full
checks. To use the same selection without Make:

```sh
python3 scripts/check-changes.py --json
python3 scripts/check-changes.py --run
```

`make check-all` explicitly runs Go tests with serialized package execution,
Python client/installer tests, `go vet` and local documentation links, regardless
of the diff. The direct equivalent is
`python3 scripts/check-changes.py --all --run`.
`make race` separately covers active service, operations, shared operator and MCP packages.
See [testing](testing.md) for release validation beyond code checks. POSIX-only
macOS installer/builder and report-hook modules skip on Windows; the Windows
client, DACL and installer suites run natively there.

Use [troubleshooting](troubleshooting.md) for known connection, media, recovery
and clean-checkout failure modes. Before changing write or continuation behavior,
review the [operation recovery decision](decisions/0002-operation-recovery.md)
and its regression-test map.

## Packages

The current distribution notice inventory and native Windows packaging job use
Go 1.26.5. The three-platform source checks also exercise the minimum Go version
from `go.mod`. If packaging with another toolchain, refresh its runtime and
component notices as described in [the license inventory](../third_party/licenses/README.md).

From a clean checkout, choose a new output directory:

```sh
make package-macos VERSION=cosmoedge-connect-dev-local PACKAGE_DIR=../cosmoedge-connect-dev-local
make package-windows VERSION=cosmoedge-connect-dev-windows PACKAGE_DIR=../cosmoedge-connect-dev-windows
```

Each command is a platform-specific build path; running both is not a promise
of native acceptance on both platforms. macOS uses an explicit development app
and includes MCP. Builders record source revision, modified state, source
inventory and package hashes. Changing files during a build invalidates it.

A package's service, MCP adapter, Python client and Skill must retain their
paired identity. Use the installer-generated MCP configuration and regenerate
it after upgrade or rollback. Details are in [installation](installation.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `cmd/cosmoedge-connect` | Official local service |
| `cmd/cosmoedge-mcp` | Official stdio MCP adapter |
| `internal/operations` | Summary, capture and algorithm-change domains |
| `internal/mcpbridge` | MCP mapping, request journal and artifacts |
| `internal/operator` | Shared connection, session, confirmation and execution code |
| `internal/inspection` | Retained runtime/media/contracts and regression dependencies |
| `integrations/workbuddy` | Paired client, Skill and platform installation |
| `scripts` | Build, package and check entrypoints |
| `tools` | Development-only utilities and retained regression entrypoints |
| `docs` | Current documentation and live schema references |

Other commands under `cmd/` and their demo/fixtures support development and
regression tests. The two commands above are the product installation entrypoints.

The Go module is `github.com/cosmo-wander-ai/cosmoedge-connect`, without a `/v2`
suffix. Public client integrations use MCP; internal Go packages are implementation details.
Use issues and pull requests for plans and reviews; tracked phase diaries and
`.scratch/` ticket copies are retired.

## Device testing

Use a dedicated test device and explicit task-scoped authority. Capture only the
baseline needed to prove the change and restore it afterwards. Store credentials,
raw responses and evidence privately; public reports contain versions, sanitized
commands, results and remaining limits. Development-only test authority does not
become a product confirmation bypass.

The Windows Device Lab and development-authority helpers, where retained, are
non-release utilities. Their grants expire and constrain operations; a read lease
cannot dispatch writes. These helpers are not a prerequisite for using CosmoEdge Connect.
