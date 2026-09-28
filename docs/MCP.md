# xqnet MCP analyst interface v0.1

Contract identifier: `xqnet-mcp-v0.1`.

`xqnet mcp <output-dir>` starts a read-only Model Context Protocol server over stdio for an existing `xqnet-analysis-v0.2` dataset.

## Architecture

```text
MCP client / future UI / future API
                |
          xqnet analyst API
                |
             DuckDB
                |
      analysis/*.parquet
```

DuckDB creates a temporary on-disk catalog containing views over the existing
Parquet files, then reopens that catalog read-only with file access restricted
to the dataset's analytical files. The catalog is removed when the dataset is
closed normally. The source data is queried directly, not imported into the
catalog, and the source dataset is not modified.

## Transport

```bash
xqnet mcp /path/to/xqnet-output
xqnet mcp --duckdb-threads 8 /path/to/xqnet-output
```

stdin/stdout are reserved for MCP JSON-RPC. Server diagnostics go to stderr.

## Tools

Common xq-family surface:

- `dataset_summary`
- `search_entities`
- `get_entity`
- `get_entity_timeline`
- `get_events`
- `get_observations`
- `explain_event`

Network-specific surface:

- `get_bindings`
- `get_sessions`
- `get_relationships`
- `get_services`
- `get_presence`
- `get_networks`
- `describe_endpoint`
- `explain_relationship`

Collection tools default to 100 rows, cap at 1000 and use opaque cursors. `get_observations` requires an entity identifier.

Time bounds and responses retain up to nine fractional digits. Bounds accept
RFC3339 offsets, normalize to UTC, and compare at nanosecond precision, including
inclusive `from`/`to` equality. Timestamps outside the finite analytical range or
with more than nine fractional digits are rejected. Existing
`xqnet-analysis-v0.1` datasets must be rebuilt for v0.2; changing only the manifest
cannot restore lost precision. The MCP tool/input/output shapes remain v0.1.

There is no arbitrary SQL tool in MCP v0.1.

## Resources

- `xqnet://dataset/manifest`
- `xqnet://dataset/capabilities`
- `xqnet://guidance/analyst`
- `xqnet://contract/analytical`
- `xqnet://contract/eventizer`
- `xqnet://contract/interoperability`

## Build implication

The MCP-capable binary embeds DuckDB through `duckdb-go`, so `CGO_ENABLED=1` and a suitable C toolchain are required. `go.mod` selects the Go 1.26.8 toolchain. The language version remains Go 1.25, which the pinned MCP Go SDK requires.
