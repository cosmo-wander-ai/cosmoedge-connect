# Delegate a site task to your AI assistant

**English** | [简体中文](scenarios.zh-CN.md)

[Home](../README.md) · [Getting started](getting-started.md)

Preparing a handover often means finding records, selecting sources, getting
images and collecting the items that need follow-up. Give the assistant that
whole task: describe the goal and requirements, let it use Connect to gather
material, then receive a preliminary result with originals. You can focus on
what needs judgment or an on-site check.

If you already operate CosmoEdge, use a computer that can reach the device and
follow [Getting started](getting-started.md) to configure the local service and
an image-capable AI client. This alpha source preview is intended for a developer
or integrator to prepare the environment. The following are example tasks and
workflows, not recorded AI responses; use actual source names from your device.

## A complete handover delegation

Suppose a store already has back-door and receiving-area sources with relevant
detection configured. The person preparing the handover can ask:

> Prepare my shift handover: query yesterday's retained alarms at the back door
> and receiving area, grouped by source and type. Get one image from each source
> and review the visible objects in the aisles. List items for human follow-up
> by source, including anything unclear, and include the original report and
> images. Describe yesterday's records separately from the newly acquired images.

### How the assistant carries out the work

The host resolves the dates, sources and query scope from the task, calls Connect
to retrieve records and the original report, then requests images from the chosen
sources for its image model to review. The assistant organizes the material into
the requested handover format, returning both available results and unfinished work.

Edge algorithms continue their existing detection. This image review serves the
handover task. Yesterday's alarms and newly acquired images have different uses;
the latter cannot explain why yesterday's alarms occurred.

### What you receive

The host can organize the brief for staff as follows:

- **Record review:** query dates, sources, alarm distribution and the scope of
  records actually retrieved.
- **Image review:** visible observations by source, identifying areas that are
  unclear or cannot be assessed.
- **Follow-up items:** preliminary findings based on the role's rules, with items
  that need an on-site check or more information.
- **Original material:** the corresponding report and images for verification
  and further discussion.

The contents depend on the available evidence and host capabilities. Follow-up
items form part of the brief handed back to a person. Partners can agree the
brief's format, review rules and completion criteria with the customer.

### How people handle exceptions

When records are incomplete, the assistant should identify the missing scope;
when a source cannot provide an image, it should return the unfinished item;
when an image is unclear, it should identify what needs human inspection. Staff
then decide whether to query further, visit the site or ask another question.

> In that same receiving-area image, which areas need someone on site to check?

This follow-up reuses the same original. Explicitly request another capture when
you need a new image, so the two pieces of evidence remain distinguishable.

## Let the host start the task on a schedule: an integration example

A host with scheduling capabilities can start the same handover task on a plan.
Partners can configure it with a task such as the following, then validate the
trigger, tool calls, brief and notification against the customer's requirements:

> At 08:30 each day, prepare a handover for the selected device's back door and
> receiving area. Query yesterday's retained alarms and get one image from each
> source. Use our agreed aisle-review rules to list preliminary findings and
> items needing review. Include the original report and images, and deliver them
> to the duty staff through the host's configured notification channel. Include
> unfinished items when records are incomplete, capture fails or a finding is
> uncertain.

Connect provides the device tools and results; the host manages timing, workflow
and notifications. This release has no built-in scheduler. This is a host
integration to configure and validate, not a complete scheduled-inspection
solution shipped with Connect. Define the authorized scope and exception-handling
rules in the host as well. Device pauses and resumes still follow the confirmation
flow below.

## Assist with pause and resume after a maintenance decision

If maintenance is separately planned, staff first select a specific enabled
detection task, then ask the assistant to prepare the operation:

> Pause this algorithm on the receiving-area source during maintenance, keeping
> its original settings.

The assistant prepares the specific change. Review the source, algorithm and
pause action on the local page, then **confirm the pause** to execute it and
check device state. Existing parameters, regions and schedules are retained.

After maintenance, ask:

> Re-enable this algorithm using the retained settings, and check whether
> processing has started.

This creates a new proposal. **Confirm the restoration separately** on the local
page, then check enable state and processing progress. If the outcome is unclear,
continue reading the original operation. Each operation needs its own confirmation;
a scheduled task cannot provide that confirmation for you.

## Apply the examples to your site

Use the actual sources and role-specific rules from a campus, warehouse,
production site or other deployment. The current scope is one local user and one
selected device. Statistics cover retained records actually retrieved. Image
retrieval time is not a verified exposure time, and model interpretations still
need on-site judgment. See [Compatibility](compatibility.md) for client image
access, attachment display and device-operation acceptance.

Partners can start by mapping source terminology and preparing task templates,
then add review rules, training and retesting. Establish a workflow that one role
wants to use and whose results staff can verify, then expand to more tasks.

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
