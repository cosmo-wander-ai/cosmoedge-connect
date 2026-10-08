# Inspection dataset v2 implementation

`internal/inspection/dataset` is the device-independent governed-dataset
admission boundary. It is direct v2 only: no v1 parser, alias, migration,
dual-write path, or compatibility adapter exists.

## Input and trust boundary

`DecodeIntake` accepts the exact `IntakeRequest` JSON shape documented in
[`../DATASET_MANIFEST.md`](../DATASET_MANIFEST.md). It rejects unknown fields,
duplicate keys, case aliases, trailing values, excessive depth or size, and
old schema names.

The caller supplies opaque scope, dataset, policy, item, media, group, purpose,
and non-secret authority references. It cannot supply a path, URL, media bytes,
base64 content, endpoint, stream address, credential, or native device command.
The caller also cannot self-declare source scope: the validator derives source
references only from trusted canonical media descriptors.

## Validator

`Validator.Validate` implements all-or-nothing admission. It checks:

- the exact intake, policy, item, probe, and review v2 schema constants;
- strict item, policy-list, review, and structured-field ordering;
- the closed classification, enum, structured, count, metric, detection, and
  event label union;
- canonical media scope, availability, retention, privacy, kind, MIME type,
  integrity, and trusted probe facts;
- review count, reviewer uniqueness, time bounds, policy binding, descriptor
  digest, and label digest;
- mandatory train/validation/test coverage;
- duplicate media/content, explicit-group, canonical-lineage, frame-set, and
  same-source temporal split leakage; and
- exact authorization of the principal, dataset revision, policy digest,
  canonical source/media sets, and item count.

Successful output is a metadata-only `Dataset`. Raw tenant, site, source,
group, reviewer, authority, principal, label-digest, descriptor-digest, and
integrity values are not projected. Tenant, site, source, and group strata are
keyed-HMAC pseudonyms.

## Repositories

`SQLiteRepository` is the protected durable repository. It creates only the
exact database schema version 2, persists the safe projection and its ordered
media-reference mirror transactionally, and makes both tables immutable.
Open and read paths verify the SQLite object shape, integrity, content digest,
item digest, mirror rows, bounds, and absence of protected fields or URL
schemes. Unknown, empty pre-existing, v1, near-v2, and future schemas fail
closed. There is no upgrade or migration path.

`CreateWithReceipt` distinguishes definite failure from an indeterminate commit;
`ResolveCreate` reconciles a returned receipt without repeating the write.
`Get` and `List` require pseudonymous tenant/site strata and return validated
copies.

`MemoryDatasetStore`, `MemoryMediaCatalog`, and `MemoryAuthorizer` are
concurrent metadata-only fixtures for tests. They are not production storage,
system authority, or device adapters.

## Remaining composition dependencies

Production composition must provide the trusted media catalog and probe,
system authorization adapter, protected pseudonymization key, and lifecycle
wiring for the SQLite repository. No real media ingestion, camera connection,
inference, training, or accuracy claim is implemented by this package.
