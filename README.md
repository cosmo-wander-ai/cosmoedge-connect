# CosmoEdge Connect

**English** | [简体中文](README.zh-CN.md)

Connect AI assistants to CosmoEdge to query alarms, view source images, and
enable or disable installed algorithms.

The local service manages the device connection and execution. AI clients use
MCP or the paired WorkBuddy integration to request operations and receive results.

| What you want to do | What CosmoEdge Connect provides |
| --- | --- |
| “How many alarms were recorded at the east and west gates yesterday?” | Query retained records by time, source and algorithm, returning statistics and the original report |
| “Check whether anyone is in this view, and give me the image.” | Acquire the original source image for the host model to analyze, and retain it for follow-up questions |
| “Pause this algorithm, then restore its original settings.” | Prepare a change, execute it after confirmation on the local page, and read back device state |

The current scope is one CosmoEdge device. The host model interprets images;
alarm summaries state the scope actually read. Enable/disable operations use
existing sources and installed algorithms, preserving their parameters, regions
and schedules.

## Getting started

1. Follow [installation](docs/installation.md) to install the local service or
   build it from source.
2. Connect a device through the CosmoEdge Connect local page.
3. Configure an [MCP client](docs/mcp.md), or use the paired WorkBuddy Skill.
4. Follow the [quickstart](docs/getting-started.md) for your first query, image
   request and operation.

This is an alpha source preview. See [compatibility](docs/compatibility.md) for
the platform checks and the scope of this release. Package, client and device
acceptance must match the specific build being used. WeChat,
remote/cloud MCP, multiple devices and scheduled inspections are outside the
current supported scope.

## Development and integration

Third-party clients should use the public [MCP tool interface](docs/mcp.md).
The optional [operations Skill (Chinese)](skills/cosmoedge-operations/SKILL.md) provides
guidance on dates, sources, follow-up questions and result interpretation;
clients can call the tools without a Skill. WorkBuddy's paired Python client
also uses a `cosmoedge-operations` Skill; install the version for your chosen
integration. The official adapter and service are built as a matched pair.
The internal HTTP API supports the adapter implementation and has no separate
long-term compatibility commitment.

```sh
make build
go run ./examples/mcp-client --server ./output/bin/cosmoedge-mcp --mock
```

These commands build both public executables and run the
[MCP example without a Skill](examples/mcp-client/main.go) against a synthetic
service. They exercise tool calls, original artifacts and request recovery
without a device or credentials. On Windows, use the direct build commands in
[development](docs/development.md) and append `.exe` to the server path.

Building requires Go 1.25+. The WorkBuddy package also requires Python 3.9+;
see [development](docs/development.md) for other test dependencies. Adapter
build commands and invocation flags are documented in [MCP integration](docs/mcp.md).

| Documentation | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Responsibilities of the service, adapter, Skill and runtime state |
| [Operations](docs/operations.md) | Counting rules, image sources, request recovery and change outcomes |
| [Testing](docs/testing.md) | Automated checks, real-client validation and device acceptance |
| [Troubleshooting](docs/troubleshooting.md) | Connection, image delivery and request-recovery diagnostics |
| [Upgrade and recovery](docs/upgrade.md) | Paired package updates, backups and state recovery |
| [Contributing](CONTRIBUTING.md) | Developing and submitting changes |
| [Security](SECURITY.md) | Local state, credentials and vulnerability reporting |

## License

CosmoEdge Connect is licensed under the [Apache License 2.0](LICENSE).
Third-party components retain their own licenses; see [NOTICE](NOTICE).
