# xqnet analytical contract v0.2

Contract identifier: `xqnet-analysis-v0.2`

Status: reference analytical projection contract for xqnet 0.1.3-rc5.

## Separation of concerns

The following surfaces are versioned independently:

```text
Crosscue Event Model wire   0.1
Network eventizer           network-reference-v1.4
Analytical projection       xqnet-analysis-v0.2
```

`canonical/events.jsonl` is the canonical semantic stream. Parquet files are analysis-oriented projections and are not additional Core Event types.

The `context_json` and `provenance_json` projections preserve numeric JSON values,
including large integers and nested values, without conversion through binary
floating point. MCP returns these fields as JSON strings. Clients that parse
them must also use a number-preserving decoder when exact values matter.
Rebuild older affected datasets to replace metadata rounded by earlier releases.

## Evidence hierarchy

xqnet sits above source-native Zeek/Suricata evidence. Analysts and automated systems must preserve the distinction between:

1. source-native evidence;
2. observation/normalized-observation Core Events;
3. derived Core Events;
4. analytical projections and aggregates;
5. analyst/LLM inference.

An IP address is not a device. A MAC identifies an interface by default. An endpoint is not a service. A source-engine session boundary is not asserted to be engine-independent.

## Standard layers

- `observations.parquet` — evidence-facing observation/normalized-observation events.
- `events.parquet` — flattened analytical projection of canonical JSONL.
- `entities.parquet` — typed entity index.
- `bindings.parquet` — temporal relational evidence, including address, DNS, TLS-server-name and endpoint/service bindings.
- `sessions.parquet` — source-engine session/flow projections linked to parent connection events.
- `relationships.parquet` — communication relationships derived from qualifying connection evidence.
- `services.parquet` — endpoint/service materialization supported by application evidence.
- `presence_intervals.parquet` — observed intervals inside an explicitly configured network scope; not ENTER/LEAVE claims.
- `networks.parquet` — explicit operator-supplied observation/network scope.

## Traceability

Projection rows retain parent event identifiers or bounded parent-event lists where applicable. Truncation is explicit. Core provenance remains authoritative for semantic events.

## Temporal purity

A Core Event at time T must not contain facts only supportable after T. Whole-window counts, bytes, later protocol evidence and aggregate directionality belong in projections when they were not known at first observation.

## Physical materialization

All timestamp columns use signed 64-bit nanoseconds, normalized to UTC. Parquet
logical annotations are `TIMESTAMP(NANOS, isAdjustedToUTC=false)` (the Go tag is
`timestamp(nanosecond:local)`). The UTC wall-clock convention is part of this
contract, not the operator's local timezone. Metadata records
`xq:timestamp_precision=nanosecond` and `xq:timestamp_timezone=UTC`.

This annotation allows DuckDB to read timestamps as `TIMESTAMP_NS`. Its
timezone-aware timestamp type has microsecond precision; using Parquet's UTC
adjustment annotation would lose nanoseconds in DuckDB. Query parameters are
explicitly bound as UTC `TIMESTAMP_NS`, and MCP serializes returned times as
RFC3339 with up to nine fractional digits and a `Z` suffix. SQL consumers should
retain `TIMESTAMP_NS`, avoiding precision-losing casts to `TIMESTAMPTZ`.

See [DuckDB timestamp types](https://duckdb.org/docs/current/sql/data_types/timestamp)
for its precision and timezone behavior.

Input timestamps outside the finite signed-nanosecond range (approximately
1677–2262), or containing more than nine fractional digits, are rejected instead
of overflowing or truncating. DuckDB's reserved infinity values are excluded.
Negative timestamps and the Unix epoch are supported.

`xqnet-analysis-v0.1` used milliseconds. Rebuild those datasets from source
telemetry; do not relabel old Parquet files as v0.2. MCP and entity inspection
reject older analytical contracts with rebuild guidance. Summary-only inspection
remains available. Canonical event timing and IDs are unchanged by this storage
upgrade, apart from tool release provenance; the eventizer remains v1.2.

Distinct instants remain ordered at nanosecond precision. Exact ties retain the
existing deterministic API tie-breakers; this contract does not add a canonical
parent-before-child ordering guarantee to analytical query results.

Parquet uses explicit compression and bounded row groups/dictionaries. The reference defaults are:

```text
compression             zstd
row group max rows      131072
dictionary max bytes    8 MiB per column per row group
application batch       1024 rows
```

These are physical storage parameters and do not alter network event semantics.
