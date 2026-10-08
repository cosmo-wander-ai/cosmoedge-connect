# Build and development scripts

The product package builders are `build-connect-macos.py` and
`build-connect-windows.py`. They produce a matched CosmoEdge Connect service,
MCP adapter when `--with-mcp` is selected, Python client and
`cosmoedge-operations` Skill. Use [installation](../docs/installation.md) for
current build and install commands.

`check-changes.py` selects documentation-only or full checks from the Git diff.
Use `--json` to inspect the selection, `--run` to execute it, `--base REF` for an
explicit baseline, or `--all --run` for full checks. Local selection includes
staged, unstaged and untracked non-ignored files. GitHub Actions supplies exact
base/head revisions and uses the same classification rules.

`check-docs.py` checks local documentation links. The Python suites under
`tests/` cover package builders and test helpers. Native Windows validation uses
`test-windows-python.ps1` and `test-windows-lifecycle.ps1`; see
[testing](../docs/testing.md) for their scope and required environment.

Other scripts support internal Operator/Inspection regression work and device
lab development. They are not alternate product installation entrypoints.
Development authority is bounded and separate from local business confirmation.
The Windows device-lab helper exposes typed reads rather than device writes.

Build and lifecycle scripts do not choose business targets, confirm proposals
or dispatch device changes. Those remain behind the service's Action Kernel.
Keep temporary outputs and private evidence outside the tracked tree.
