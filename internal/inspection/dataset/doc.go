// Package dataset admits governed CosmoEdge inspection media into immutable
// training, validation, and test datasets.
//
// The package is deliberately device independent. Its only media input is an
// opaque media reference resolved to the canonical media v3 Descriptor and
// bounded probe facts. It has no API for paths, URLs, encoded payloads, byte
// slices, streams, credentials, or device commands.
//
// SQLiteRepository is the sole production persistence contract. In-memory
// dataset storage exists only as a private test fixture.
package dataset
