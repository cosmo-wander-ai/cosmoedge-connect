# Linux status

The Go service can be built from source:

```sh
go build -buildvcs=false -o cosmoedge-connect ./cmd/cosmoedge-connect
```

There is no accepted Linux desktop installation package in this release.
Linux integration work must provide current-user token/state provisioning,
service ownership, a usable local connection/review page, lifecycle recovery
and actual client attachment tests before claiming support. A successful Linux
cross-build alone does not establish any of those outcomes.

See [installation](../../../../docs/installation.md),
[MCP](../../../../docs/mcp.md) and
[compatibility](../../../../docs/compatibility.md) for supported paths and limits.
