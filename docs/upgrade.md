# Upgrade and recovery

Upgrade CosmoEdge Connect using one matched package from the same release. Keep
the service, MCP adapter, WorkBuddy client, Skill and candidate files together.
Use the repository's `main` branch when building from source, following
[installation](installation.md).

## Before replacing a package

1. Preserve the current package, its manifest and the installer's protected
   backup. Keep credentials and runtime state private.
2. Finish or reconcile pending operations through their original client and
   request identity. An unknown device result must not be submitted again.
3. Obtain or build a complete package and record its manifest checksum.
4. Use the platform installer to stop its managed service and replace files.
   An unrelated listener must remain untouched.

The connection token is part of credential derivation and is preserved. Do not
delete it to repair a version or connection mismatch. First-install token
provisioning applies only to a new or empty installation root.

## After an upgrade

Check paired status and the saved device connection. Regenerate each client's
MCP configuration because its executable and candidate paths refer to a specific
release. Import the matching `cosmoedge-operations` Skill into WorkBuddy when
using that integration, then start a fresh conversation with the updated Skill.

Check the catalog, an image or report, and any pending-operation recovery using
the exact installed candidate. Keep the private MCP journal across ordinary
restarts. The WorkBuddy client and MCP adapter have separate request state;
continue each unresolved request through its original client and context.

## Recovering managed files

Use the recorded recovery point exposed by the platform installer. On macOS,
`install.command rollback` restores the managed package files and verifies the
restored service. Windows installation failure restores its prior managed files
and lifecycle; see the [Windows installer](../integrations/workbuddy/deploy/windows/README.md).

Runtime databases are preserved. File rollback does not undo device actions or
prove that a database can be read by an earlier binary. Reconcile uncertain
operations and owned temporary resources before changing versions. Restore any
device configuration through a separately confirmed operation and verify it on
the device.

## Verification

A new package requires its own relevant installation, client and device checks.
A matching source tree or successful file recovery does not inherit another
candidate's acceptance. Record the current outcome in
[compatibility](compatibility.md), using the cases in [testing](testing.md).
