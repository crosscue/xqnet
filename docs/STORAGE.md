# xqnet storage/materialization

Canonical JSONL remains uncompressed for observability. Analytical Parquet is ZSTD-compressed by default.

The v0.2 analytical contract stores timestamps at nanosecond precision, normalized
to UTC. See [ANALYTICAL-CONTRACT.md](ANALYTICAL-CONTRACT.md) for logical annotations,
DuckDB compatibility and the finite timestamp range. Old millisecond datasets
must be rebuilt from source telemetry before use with the current analyst API.

Reference physical defaults:

```text
row_group_max_rows       131072
dictionary_max_bytes     8388608
parquet_batch_rows       1024
```

The manifest reports per-file bytes, input-relative expansion where the input is a single file, and actual row-group counts. Directory-based Zeek input does not have one meaningful input-byte denominator and therefore may report zero input expansion ratios.

Physical Parquet settings are reproducibility/performance controls and do not change semantic eventization.
