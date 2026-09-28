# xqnet / xqmob family alignment

xqnet follows the same product architecture as xqmob without copying mobility semantics.

| Family surface | xqmob | xqnet |
|---|---|---|
| Canonical stream | Crosscue Mobility events | Crosscue Network events |
| Eventizer contract | `mobility-reference-*` | `network-reference-v1.4` |
| Analytical contract | `xqmob-analysis-*` | `xqnet-analysis-v0.2` |
| Compact discovery layer | entities | entities |
| Domain projections | segments/presence/transitions | bindings/sessions/relationships/services/presence |
| Inspect | `xqmob inspect` | `xqnet inspect` |
| MCP | mobility analyst tools | network analyst tools |
| Query engine | DuckDB | DuckDB |
| MCP transport | stdio | stdio |
| Result discipline | bounded/paginated | bounded/paginated |
| Parquet defaults | ZSTD + bounded row groups/dicts | same physical defaults |

The family standardizes transport, CLI conventions, manifests, contracts, pagination and evidence-guidance patterns. Domain semantics remain local to each tool.
