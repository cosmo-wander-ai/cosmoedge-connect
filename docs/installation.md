# Installation

**English** | [简体中文](installation.zh-CN.md)

[Home](../README.md) · [Getting started](getting-started.md) · [MCP integration](mcp.md)

The service and official clients are built together from the same source
candidate. This guide covers source builds and development package installation;
when using a released package, check that version's manifest checksum and
compatibility notes.

## Requirements

| Purpose | Requirements |
| --- | --- |
| Build the service or MCP adapter from source | Go 1.25+ |
| Build a WorkBuddy package | Go, Python 3.9+; macOS packages also require `codesign` |
| Run the paired WorkBuddy package | Python 3.9+ and WorkBuddy |
| Connect a device | A CosmoEdge device reachable from this computer, with sources and algorithms already configured |

Development checks have additional dependencies, including Node.js; see
[Development](development.md). A successful build does not establish that the
platform's desktop client or real-device workflows have passed validation.

## Local service on macOS

Build from a clean source checkout and place the output outside the worktree:

```sh
python3 scripts/build-connect-macos.py --development-app --with-mcp --version cosmoedge-connect-dev-local --output /absolute/path/to/cosmoedge-connect-dev-local
```

Record the `manifestSHA256` printed by the builder. Replace `<manifest-sha256>`
below with that value, and install using the same package:

```sh
/absolute/path/to/cosmoedge-connect-dev-local/install.command install --bundle /absolute/path/to/cosmoedge-connect-dev-local --expected-manifest-sha256 <manifest-sha256>
```

For MCP, generate the client configuration after installation. WorkBuddy and its
Skill are not required:

```sh
/absolute/path/to/cosmoedge-connect-dev-local/install.command mcp-config --client-id codex
```

For WorkBuddy, also import `cosmoedge-operations.zip` from the package, then run:

```sh
/absolute/path/to/cosmoedge-connect-dev-local/install.command finalize-skill-import
/absolute/path/to/cosmoedge-connect-dev-local/install.command status
```

After upgrading the WorkBuddy integration, start a new conversation and select
the Skill again. After an MCP upgrade, regenerate the client configuration.
Open the local connection page from your chosen client, connect the device and
query its catalog. For installation, startup and recovery details, see
[macOS paired installation](../integrations/workbuddy/deploy/macos/PAIRED-INSTALL.md).
`--development-app` uses a development signature; it does not establish public
distribution signing or notarization.

## Local service on Windows

See [Windows installation](../integrations/workbuddy/deploy/windows/README.md)
for build and lifecycle commands. Installation and attachment delivery must be
tested on Windows; macOS results do not cover them. Install from a normal
PowerShell window as the currently signed-in user to preserve user-level file
ownership. The installation directory is `%LOCALAPPDATA%/CosmoEdgeConnect`, and
administrator privileges are not required. Refer to that guide for the current
implementation of token initialization on first installation.

## MCP clients

The local MCP adapter connects to an already configured CosmoEdge Connect
service. See [MCP integration](mcp.md) for build commands, configuration fields
and tool usage. Validate image reading, report delivery and the confirmation
page workflow separately for each client.

## Linux

The Go service can be built from source. There is no validated Linux desktop
installation package yet. See [Linux status](../integrations/workbuddy/deploy/linux/README.md)
for platform limits.

## Upgrade and recovery

Keep the previous paired package and the recovery point created by the
installer. Check current operations before upgrading files. Restoring installed
files does not roll back device tasks or databases. Cross-version state
compatibility and the original device configuration must be verified
separately; see [Upgrade and recovery](upgrade.md).
