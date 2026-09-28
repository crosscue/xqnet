# xqnet 0.1.3-rc5 package manifest

This archive is a **source release candidate** prepared for public open-source review under Apache-2.0.

## Frozen contracts

- tool: `xqnet 0.1.3-rc5`
- eventizer: `network-reference-v1.4`
- analytical contract: `xqnet-analysis-v0.2`
- MCP contract: `xqnet-mcp-v0.1`
- Crosscue Event Model wire/profile: `0.1` / `xq.net:profile-0.1`
- adapter mappings: `zeek-reference-v1` / `suricata-reference-v1`

This candidate advances the eventizer to `network-reference-v1.4` for exact
Zeek duration/RTT arithmetic and valid unidentified-application relationships.
It also preserves numeric context/provenance during Parquet materialization.
The analytical v0.2 and MCP v0.1 schemas remain unchanged. See `RELEASE_NOTES.md`
for rebuild requirements, compatibility details and explicit overwrite behavior.

## Package contents

- Go source under `cmd/` and `internal/`;
- Zeek and Suricata reference adapters and redistributable fixtures under `testdata/`;
- Network Profile producer-side validation;
- versioned analytical Parquet materialization and `inspect`;
- DuckDB-backed analyst API and read-only stdio MCP server;
- CI workflow and GitHub contribution templates under `.github/`;
- eventizer, analytical, MCP, storage, engine/interoperability and architecture documentation under `docs/`;
- Apache-2.0 `LICENSE`, project `NOTICE`, third-party notices and public contribution/security/governance files;
- `go.sum`, pinning checksums for the direct and indirect Go module graph;
- `SOURCE_MANIFEST.sha256` containing checksums for source-package files.

## Not included

- compiled binaries;
- generated xqnet analytical outputs;
- private/proprietary packet captures or network logs;
- Zeek or Suricata binaries/rules/plugins;
- vendored Go dependencies.

The candidate should be built and tested with the Go 1.26.8 toolchain named in `go.mod`, with CGO enabled, before promotion to a stable public tag.
