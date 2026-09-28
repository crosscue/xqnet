# Third-party notices

This file records the direct non-standard-library dependencies used by xqnet.
It is intended as release-packaging guidance, not as a substitute for reviewing
the complete dependency graph when redistributing binaries.

| Dependency | Pinned version | Purpose | Upstream license |
|---|---:|---|---|
| `github.com/parquet-go/parquet-go` | `v0.32.0` | Parquet analytical read-write support | Apache-2.0 |
| `github.com/duckdb/duckdb-go/v2` | `v2.10505.0` | Embedded read-only DuckDB analyst queries for MCP | MIT |
| `github.com/modelcontextprotocol/go-sdk` | `v1.7.0` | MCP server and stdio transport | mixed MIT / Apache-2.0 upstream licensing |

The MCP Go SDK is undergoing an upstream licensing transition: new
contributions are Apache-2.0 while existing code whose relicensing has not been
completed remains under MIT-style terms. Consult the exact `LICENSE` file in
the pinned module version when preparing redistributed binaries.

## External engines

xqnet can invoke Zeek or Suricata when packet-capture input is supplied. These
programs are external tools and are not included in this source archive. Their
licences, notices, plugins/rules and redistribution requirements must be handled
separately by the person or organization distributing/installing them.

## Binary redistribution

The source release does not vendor Go dependencies. A compiled xqnet binary
statically incorporates Go dependency code and, through `duckdb-go`, supported
prebuilt DuckDB components. Before publishing binary artifacts:

1. resolve and review the complete transitive dependency graph for the exact
   release commit;
2. preserve all required copyright, license and NOTICE material;
3. generate a machine-readable/software-bill-of-materials if your release
   process requires one;
4. verify that the binary and source archive contain the applicable notices.

Useful starting points include `go list -m -json all`, a Go license scanner,
`govulncheck`, and your normal software-composition-analysis tooling.
