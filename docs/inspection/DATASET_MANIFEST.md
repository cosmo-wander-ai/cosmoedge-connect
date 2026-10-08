# Governed inspection dataset intake v2

This document describes the implemented device-independent intake boundary in
`internal/inspection/dataset`. It is a direct v2 contract. There is no v1
decoder, migration, field alias, dual write, or compatibility adapter.

The public JSON body is the exact wire shape of `dataset.IntakeRequest`:

- schema: [`schema/dataset-manifest.schema.json`](schema/dataset-manifest.schema.json)
- neutral shape example: [`examples/dataset-manifest.example.json`](examples/dataset-manifest.example.json)

The JSON Schema is a structural companion. `dataset.DecodeIntake` and
`dataset.Validator` are authoritative for exact field names, ordering,
authorization, media catalog facts, review digests, retention, and split
isolation. The example uses synthetic digest values and cannot be admitted
without matching canonical media descriptors, probe facts, and authority.

## Boundary

The request contains governance metadata, typed labels, and opaque references.
It cannot represent media bytes, base64 data, a path, a URL, an endpoint, a
stream address, a credential, or a device command. `mediaRef` must have the
form `media_` followed by 32 lowercase hexadecimal characters. `tenantId` and
`siteId` are internal opaque scope references, not customer names, addresses,
camera labels, or other human-readable identifiers.

The request carries a non-secret `authorityRef` and the SHA-256 of the calling
principal. It does not carry an authorization grant. The validator derives the
complete authorization demand after resolving the canonical source and media
sets; an `Authorizer` must approve that exact demand.

## Exact schemas

| Object | Required schema value |
| --- | --- |
| intake | `cosmoedge.inspection.dataset.v2` |
| policy | `cosmoedge.inspection.dataset.policy.v2` |
| item | `cosmoedge.inspection.dataset.item.v2` |
| review | `cosmoedge.inspection.dataset.review.v2` |
| trusted probe facts | `cosmoedge.inspection.dataset.probe.v2` |

Unknown fields, duplicate keys, case variants, trailing JSON values, a v1
schema name, and payloads larger than 16 MiB are rejected before media lookup
or authorization.

## Policy and item ordering

One request is one immutable dataset revision. It has 3 to 10,000 items, and
must contain at least one `train`, one `validation`, and one `test` item.
`quarantine` is not a v2 split.

The following caller-provided arrays are strictly ascending and duplicate-free:

- policy `allowedKinds`, `allowedPrivacyClasses`, and
  `requiredRetentionPolicyRefs`;
- `items` by `itemId`;
- each item's `reviews` by `reviewId`; and
- structured-label `fields` by `name`.

The JSON Schema enforces the closed element sets, bounds, and uniqueness where
representable. The Go validator enforces lexical order and duplicate reviewer
digests.

The policy fixes:

- allowed media kinds and privacy classes;
- accepted retention-policy references and a dataset retention deadline;
- at least 1 second and at most 365 days of required remaining retention;
- one review-policy reference and 1 to 16 required approvals; and
- a same-source cross-split isolation window from 0 to 7 days.

Each item binds its opaque media reference to the expected media kind, lowercase
MIME type, SHA-256, explicit group, split, one typed label, and completed review
decisions. A `frame_set` has an empty MIME value; all other kinds require one.

## Closed label union

A label contains exactly one member matching `kind`. There is no raw JSON or
open map escape hatch.

| Kind | Value contract |
| --- | --- |
| `classification` | `meets_rule`, `needs_attention`, `uncertain`, `not_observable`, or `unsupported` |
| `enum` | one opaque enum reference |
| `structured` | up to 64 sorted fields; each value is exactly one boolean, enum, number, or integer |
| `count` | integer from 0 through 1,000,000,000 |
| `metric` | finite number with absolute value no greater than 10^15 and one opaque unit |
| `detection` | up to 2,000 labeled objects with normalized regions inside the image |
| `event` | opaque event type plus an `occurred` boolean |

For a normalized detection region, `x`, `y`, `width`, and `height` are in
`[0,1]`; width and height are positive; and `x + width` and `y + height` may not
exceed 1. Empty structured-field and detection-object arrays are valid typed
values, not missing values.

## Review binding

Only `approved` reviews are admissible. Every review contains:

- a pseudonymous reviewer SHA-256, never a reviewer account or name;
- the SHA-256 of the complete canonical media descriptor;
- the SHA-256 of the complete closed label;
- the exact policy reference; and
- a review time after media creation and capture, before intake, and before
  media expiry.

The validator requires the policy's approval count, rejects repeated reviewer
digests, and rejects stale or incorrectly bound review decisions. The digest
values in the example are placeholders for structural validation; production
intake must compute them from the actual canonical descriptor and label.

## Implemented admission flow

Admission is all-or-nothing:

1. Strict JSON and request-shape validation complete.
2. The trusted `MediaCatalog` resolves every `mediaRef` to the canonical
   `cosmoedge.inspection.media.v2` descriptor.
3. Tenant/site scope, availability, deletion state, privacy class, expiry,
   retention, kind, MIME type, and SHA-256 are checked.
4. Trusted probe facts must exactly match kind, MIME type, SHA-256, byte size,
   dimensions, and duration.
5. Review descriptor/label digests and approval policy are verified.
6. Explicit groups, exact content digests, canonical parent/child lineage,
   frame-set siblings, and adjacent same-source observations are checked for
   cross-split leakage.
7. The validator constructs sorted canonical source/media sets and asks the
   authority service to approve the exact dataset revision, policy digest,
   principal digest, item count, source set, and media set.
8. Only then is a safe pseudonymous `Dataset` projection produced.

Repeated media references or content digests fail. A caller-supplied group
cannot override canonical lineage or same-source temporal isolation.

## Safe output and durable repository

The successful `Dataset` projection removes raw tenant, site, source, group,
reviewer, authority, principal, descriptor digest, label digest, and media
integrity values. Tenant, site, source, and group strata are stable keyed-HMAC
pseudonyms. The output retains only bounded evaluation metadata and opaque
media references.

`SQLiteRepository` is the implemented durable store for that safe projection:

- a new file is protected as local state and opened with restrictive file
  permissions;
- it accepts only the exact repository schema version 2 and application ID;
- unknown, empty pre-existing, v1, near-v2, or future database shapes fail
  closed; there is no migration path;
- foreign keys, full synchronous commits, delete journaling, trusted-schema
  disablement, secure deletion, and integrity checks are enabled;
- dataset and per-item media-reference rows are inserted in one transaction;
- update and delete triggers make both tables immutable;
- complete dataset and item digests are rechecked on every read and at open;
- protected raw fields, credential-like fields, URL schemes, oversized stored
  values, and inconsistent mirror rows are treated as corruption; and
- an indeterminate commit returns a receipt that `ResolveCreate` classifies as
  committed, not committed, conflicting, or still unknown.

`Get` and `List` operate only on pseudonymous tenant/site strata and return
validated copies. The memory repository remains a concurrent device-free test
fixture, not the durable product store.

## Evaluation projection

`internal/inspectioneval` consumes a separate v3 evaluation projection. It is
not an intake endpoint and cannot authorize or admit customer media. Production
assembly starts from a committed dataset receipt and binds the admitted label
to authoritative runtime, application, delivery, feedback, and, for temporary
observations, independently governed review evidence. The resulting projection
drops media identity, source identity, model identity, and authority material.
Direct JSONL input remains a synthetic contract-regression channel only.
The independently governed temporary-review service is not yet composed into
the Product, so temporary-observation production evaluation remains gated.

Synthetic examples and metrics prove contract behavior only. They do not prove
real-scene accuracy, production delivery, device connectivity, or model quality.
