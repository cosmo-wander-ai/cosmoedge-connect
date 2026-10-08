# From handover to on-site collaboration

**English** | [简体中文](scenarios.zh-CN.md)

[Home](../README.md) · [Getting started](getting-started.md)

A site task often involves more than looking up a number: review what was
recorded, inspect an image from a selected source, and confirm any change to
detection. CosmoEdge Connect brings those steps into one conversation with an
AI assistant, organizing existing alarms, images and device operations around
the task at hand.

If you already operate CosmoEdge, start with its existing sources and installed
algorithms. Use a computer that can reach the device, then follow
[Getting started](getting-started.md) to configure the local service and an
image-capable AI client. The current alpha source preview is intended for a
developer or integrator to prepare the environment.

The following are **example prompts and descriptions of behavior, not recorded
AI responses**. “Area A” and “Area B” are illustrative names; select actual
sources from the device catalog. No alarm counts, image contents or operation
outcomes are assumed.

## 1. Start a handover with the records

> Summarize yesterday's retained alarms for Area A and Area B. Compare them by source and alarm type, and give me the original report.

The assistant queries the selected records and returns statistics with the
original report, stating the dates, timezone, filters and read completeness.
The person taking over can use that information to choose which sources to
inspect further, with less manual filtering and aggregation.

> Within that result, what share came from Area A? Which source had more records?

Follow-up questions already covered by the result can reuse it. A different
date range or filter needs a new explicit query. When a read is incomplete,
comparisons must describe only the records that were retrieved.

## 2. Choose a source and inspect one image

> Get an image from this Area A source. Help me check whether any objects are visible in the passage, and give me the original image too.

The assistant acquires the selected source's original image for your AI model
to inspect and explain. An occasional image question can be explored directly,
without deploying a dedicated detection algorithm for every new question.

> In that same image, which objects can you make out on the right? Tell me which parts are unclear too.

This follow-up uses the same original, so you and the assistant are discussing
the same evidence. A new capture requires an explicit request such as “Get another
image.” Existing edge detection supplies alarm records; the host model helps
inspect images on demand. Both can contribute to the same task.

## 3. Assist with detection changes after a maintenance decision

Suppose the on-site team then decides to perform maintenance and selects an
enabled algorithm from the device catalog:

> Pause this algorithm on this source during maintenance, keeping its original settings.

The assistant prepares the specific change. Review the source, algorithm and
pause action on the local page, then **confirm the pause** to execute it.
Device state is read back, with existing parameters, regions and schedules
retained.

After maintenance, you ask:

> Maintenance is complete. Re-enable this algorithm using the retained settings, and check whether processing has started.

This creates a new proposal. **Confirm the restoration separately** on the
local page, then check both enable state and processing progress. If the outcome
is still unconfirmed, continue reading that operation; a submitted request is
not proof of restored processing.

## Applying these examples

These workflows use one selected CosmoEdge device. Replace the source names
with those in an existing campus, warehouse, shop, production site or another
deployment. The current release does not provide multi-device aggregation,
scheduled inspection or autonomous pause/restoration. Historical alarms and a
new image are different evidence and do not establish an incident's cause.
Retrieval time is not a verified exposure time, and test video is not the
current state of a real site. Image interpretations still need on-site judgment.
See [Compatibility](compatibility.md) for client image access, attachment
display and device-operation acceptance.

## Try a synthetic demonstration without a device

From the source directory, build and run the existing example with Go 1.25+:

```sh
go build -o output/bin/ ./cmd/cosmoedge-connect ./cmd/cosmoedge-mcp
go run ./examples/mcp-client --server ./output/bin/cosmoedge-mcp --mock
```

On Windows, use `./output/bin/cosmoedge-mcp.exe` as the server path in the second
command. The [example source](../examples/mcp-client/main.go) uses a synthetic
local service to exercise capture, original reports, request recovery, context
isolation, and preparing, opening review for and cancelling a proposal. It does
not connect to a real device, invoke an AI model or execute the pause/restoration
workflow above. It therefore does not establish image interpretation quality or
real-device results.

When you are ready to connect a device, continue with
[Getting started](getting-started.md).
