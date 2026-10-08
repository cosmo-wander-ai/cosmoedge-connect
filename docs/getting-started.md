# Getting started

**English** | [简体中文](getting-started.zh-CN.md)

[Home](../README.md) · [Installation](installation.md) · [MCP integration](mcp.md)

CosmoEdge Connect connects an AI client to one CosmoEdge device. Prepare a
computer that can reach the device, with sources and algorithms already
configured, then follow [Installation](installation.md) to install the service
and client.

## Connection and catalog

Start by asking:

> Connect a CosmoEdge device and open the device login page.

The client opens the dedicated connection page in one business call. It creates
the necessary session internally; a catalog query is not required first. The
form displays without waiting for an existing device to respond. Enter and save
the device information on that page, then ask:

> Show me the available sources and installed algorithms.

First confirm that the returned names and states belong to the intended device.
If a name is ambiguous, select a specific item from the catalog. A successful
installation or running process does not mean the device is connected.

## Delegate a complete task

Once connected, describe the job, its scope and what you want back:

> Prepare a shift handover brief: summarize yesterday's alarms for the East Gate and West Gate, get one image from each, list anything that needs an on-site check, and include the original report and images.

The assistant can organize the queries and image requests, then return a brief
with originals and items for people to check. You do not need to name each tool
call; device changes still need confirmation on the local page. See the
[task examples](scenarios.md) for more ways to delegate work. You can also make
the individual requests below.

## Query alarms

> Summarize yesterday's alarms for the East Gate and West Gate, list each source separately, and give me the original report.

Check the dates, timezone, sources and read completeness. You can ask follow-up
questions about counts or shares for a day or source within the same result.
Zero records means only that no matching records were retrieved within the
query scope; it does not prove all-day uptime, an absence of events or continuous
algorithm operation.

## View an image

> Check whether anyone is visible at the East Gate now, and give me the original image.

The model should obtain the original image before answering. A follow-up such
as "In this image, what is on the right?" reuses that image; "Take another look"
requests a fresh one. The retrieval time is not a verified exposure time, and
test video must not be described as the current state of a real location.

## Manage existing algorithms

Choose a task you are authorized to test:

> Pause person detection at the East Gate, keeping its original settings.

Check the source, algorithm and change on the local page, confirm it and wait
for the result. To restore it, ask:

> Restore the original settings and check whether processing has actually resumed.

The response should distinguish enabled state from actual processing progress.
You can cancel a proposal before confirmation; an operation that has already
run requires a new restoration proposal. After testing, verify that the
original settings and enable state have been restored.

## Incomplete results

After a timeout, continue querying the original operation. If an attachment
cannot be opened, retrieve the same original again; do not rerun a summary to
resend a report or capture another image because a download failed. See the
[Operations contract](operations.md) for details.

Image reading, attachment display and opening the confirmation page must be
validated separately for each client; see [Compatibility](compatibility.md).
