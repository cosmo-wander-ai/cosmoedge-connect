# Retained internal Inspection contracts

These documents support the internal Inspection packages and their regression
tests. They do not add public capabilities to the current CosmoEdge Connect release.
The current product is described in [architecture](../architecture.md) and
[operations](../operations.md).

- [Analysis result contract](ANALYSIS_CONTRACT.md), with its
  [schema](schema/analysis-result.schema.json) and
  [example](examples/analysis-result.example.json).
- [Dataset intake contract](DATASET_MANIFEST.md), with its
  [schema](schema/dataset-manifest.schema.json),
  [example](examples/dataset-manifest.example.json) and
  [implementation notes](dataset/README.md).

Keep these paths stable while contract tests read them. Synthetic fixtures prove
contract behavior, not field accuracy, source rights, real media admission or
production scheduling/delivery.
