# xqnet diagnostics

Default `eventize` output is a concise operational summary. Use `--verbose` for per-file Parquet/storage detail or inspect the completed dataset later:

```bash
xqnet inspect --diagnostics output/
```

`manifest.json` always records:

- adapter/input kind and source identifier;
- event, observation, entity, binding, session, relationship, service, presence and network counts;
- elapsed processing time;
- canonical/analytical storage sizes and per-file bytes;
- Parquet compression, row-group/dictionary limits and actual row-group counts.

The analytical projections expose network-specific evidence diagnostics including:

- originator-role support and role basis;
- unidirectional versus bidirectional relationship evidence;
- source observation counts on bindings/services;
- bounded/truncated parent-event provenance;
- Community ID counts and bounded lists;
- presence eligibility only under explicit network scope.

MCP/analyst queries are read-only views over these same projections. Query errors or empty results do not alter the dataset.
