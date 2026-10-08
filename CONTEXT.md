# CosmoEdge Connect terminology

The current product has three operations: retained-alarm summaries, image
capture for host analysis, and changes to installed algorithms. The public
integration boundary is described in [MCP](docs/mcp.md); implementation
boundaries are in [architecture](docs/architecture.md).

| Term | Meaning |
| --- | --- |
| Source | A camera or configured video source, selected from the current device catalog |
| Algorithm | An algorithm already installed on the connected device |
| Binding | An existing source/algorithm configuration, including its parameters, region and schedule |
| Summary | Counts and groupings of retained records actually read within a fixed window |
| Capture | One acquired original image; the host model supplies its visual interpretation |
| Operation | One persisted request and its execution result; reading it does not create another request |
| Request identity | A client-persisted identifier used to recover uncertain submission without replay |
| Business context | A client-managed grouping of operations and artifacts; not proof of a trusted chat identity |
| Proposal | A possible device change awaiting the local confirmation page |
| Original result | The persisted outcome of that operation at its original verification time |
| Current readback | A separate fresh observation of the device; it may differ from the original result |
| Artifact | An original image or report with integrity metadata and bounded availability |
| Candidate | A specific source revision, binary, client/Skill and package manifest |

The retained `internal/inspection` packages use their own bounded Inspection
Run, media, dataset and evaluation contracts. Those are internal implementation
and regression surfaces, not additional public product capabilities. Their
schema references remain under [docs/inspection](docs/inspection/README.md).
