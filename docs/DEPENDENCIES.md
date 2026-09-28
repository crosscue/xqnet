# Dependencies and licensing

xqnet intentionally keeps its direct Go dependency set small.

| Dependency | Version | Role | Licence |
|---|---:|---|---|
| parquet-go | v0.32.0 | analytical Parquet | Apache-2.0 |
| duckdb-go/v2 | v2.10505.0 | embedded DuckDB analyst API | MIT |
| modelcontextprotocol/go-sdk | v1.7.0 | MCP server/transport | upstream mixed MIT/Apache-2.0 |

See `THIRD_PARTY_NOTICES.md` for release-packaging notes.

The repository does not vendor dependency source. The exact transitive graph is
resolved by Go modules at build time. Before publishing binaries, generate a
fresh dependency/licence inventory from the release commit and preserve any
required notices.

## External engines

Zeek and Suricata are external programs that xqnet may invoke when packet
captures are supplied. They are not Go module dependencies and are not included
in this source archive. Review their exact licences, rules/plugins and notices
separately if your distribution bundles or installs them.
