# xqnet 0.1.3-rc5

## Final review corrections

- Both adapters emit an empty `application_stack` array for relationships with
  no identified application protocol; ordinary unidentified TCP traffic now
  passes the public validator.
- Zeek duration and DNS RTT use exact decimal-to-nanosecond conversion, including
  scientific notation. `0.000065` seconds adds 65,000 ns, not 64,999 ns.
- Negative, non-finite, malformed, overflowing and sub-nanosecond intervals fail
  with source line/field diagnostics. Resulting timestamps outside the analytical
  range also fail before replacing existing output. Missing/null DNS RTT retains
  its query-time fallback; connection duration remains required.
- Numeric context/provenance, including large integers and nested values, remain
  exact through Parquet materialization and MCP's JSON metadata strings.
- MCP and architecture documentation now describes the temporary on-disk DuckDB
  catalog, its read-only reopening, and cleanup on normal close.
- Producer/eventizer advance to `0.1.3-rc5` / `network-reference-v1.4`.
  Analytical v0.2 and MCP v0.1 schemas remain unchanged.
- Rebuild affected datasets from original telemetry. Corrected Zeek times may
  change event IDs and dependent evidence; old rounded Parquet metadata cannot
  be repaired from that Parquet alone.

# xqnet 0.1.3-rc4

## Source timestamp integrity

- Both adapters reject missing, null, malformed, out-of-range or over-precise
  timestamps on supported records with source line and field diagnostics.
- Fractions longer than nine digits fail instead of being silently truncated.
- Zeek decimal Unix timestamps are parsed exactly, including negative fractions:
  `-1.25` maps to `1969-12-31T23:59:58.750000000Z`.
- Suricata retains its supported timezone layouts. Absent flow interval fields
  retain the record-time fallback; present invalid fields fail.
- These failures occur before replacement, preserving an existing dataset even
  with `--overwrite` and even when valid records preceded the failing record.
- The eventizer advances to `network-reference-v1.3`; producer version advances
  to `0.1.3-rc4`. Analytical v0.2 and MCP v0.1 schemas remain unchanged.
- Rebuild affected datasets from original telemetry. Corrected negative Zeek
  times can change event IDs and dependent evidence; discarded records and
  truncated precision cannot be recovered from old output.

# xqnet 0.1.3-rc3

## Validation

- Enforces required source/time/polarity fields and nonempty typed observation
  viewpoints, alongside reference feature/class/action/entity/polarity rules.
- Checks interval ordering, optional timestamp syntax, confidence, mapping and
  evidence provenance, canonical application stacks, presence scope and forbidden
  future aggregate fields.
- Missing context keys no longer become the nonempty string `<nil>`.
- File/read failures retain their underlying diagnostics in CLI errors.
- The validator remains a reference producer guard, not the normative conformance
  suite for arbitrary Event Model implementations.

## Analytical precision

- Advances the analytical contract to `xqnet-analysis-v0.2`; every timestamp
  column preserves nanoseconds in UTC, including pre-epoch instants.
- DuckDB reads `TIMESTAMP_NS`, time parameters bind at that precision, and MCP
  returns RFC3339 values without losing sub-millisecond or sub-microsecond order.
- Rejects unsupported precision/range instead of silent truncation/overflow.
- Old analytical datasets require rebuilding from source telemetry. Entity
  inspection and MCP reject old contracts; summary inspection remains available.
- The eventizer stays `network-reference-v1.2` and MCP tool shapes stay
  `xqnet-mcp-v0.1`. Producer version advances to `0.1.3-rc3`.

# xqnet 0.1.3-rc2

## Explicit output replacement

- Existing xqnet artifacts cause `eventize` to fail unless `--overwrite` is set.
- With explicit overwrite, replacement starts only after the adapter succeeds.
- Unrelated files are retained. Output subdirectory symlinks are rejected.
- Replacement writes are not atomic; use a new output directory to preserve the
  previous dataset through storage or materialization failures.

## Zeek connection timing

- Advances the eventizer to `network-reference-v1.2`.
- Connection summaries use the reported end (`ts + duration`) instead of the
  first-packet timestamp. Source intervals are retained in event context and
  session projections.
- Dependent entity/service/presence/relationship evidence follows that corrected
  time. Earliest relationship evidence is selected by completion time.
- Missing, malformed, negative, non-finite and out-of-range duration cause a
  line-specific error. Explicit zero duration is accepted.
- Zeek connection IDs, dependent IDs/parent references and ordering can change.
  This is an intentional semantic compatibility change from v1.1.
- Suricata semantics and the analytical/MCP schemas are unchanged; release and
  eventizer provenance advance to `0.1.3-rc2` / `network-reference-v1.2`.

# xqnet 0.1.3-rc1

First public open-source release candidate.

## Open-source packaging

- Adds Apache-2.0 `LICENSE` and project `NOTICE`.
- Adds contribution, security, governance, support, code-of-conduct and trademark guidance.
- Adds direct dependency/licensing notes and public release/publication checklist.
- Adds GitHub issue/PR templates, architecture/dependency documentation, an MCP agent starting prompt, changelog and source package manifest.
- Clarifies that xqnet is a reference implementation while the Crosscue Event Model/Network Profile remains normative.

## Contracts

- Eventizer remains `network-reference-v1.1`.
- Analytical contract remains `xqnet-analysis-v0.1`.
- MCP contract remains `xqnet-mcp-v0.1`.
- Zeek and Suricata mappings remain `zeek-reference-v1` and `suricata-reference-v1`.
- Network event semantics and analytical schemas are unchanged; only tool/producer release provenance advances to `0.1.3-rc1`.

# xqnet 0.1.2

Capture-input detection and Suricata format-guidance fix.

## Input handling

- Recognizes classic PCAP (microsecond/nanosecond, both endian forms) and PCAPNG from file magic rather than relying only on filename extensions.
- Treats `.dmp` as a capture-style extension, covering common tcpdump/trace dump naming.
- A raw `.dmp`/PCAP supplied with `--adapter suricata` is now routed through xqnet's existing automatic Suricata decode path instead of being parsed as EVE JSON.
- Improves the fallback EVE parser error to explain that Suricata expects newline-delimited EVE JSON and that raw captures should be passed directly to `xqnet eventize`.
- Improves the missing-Suricata-executable guidance and removes the obsolete `-in` wording.

## Contracts

- Eventizer remains `network-reference-v1.1`; no network event semantics or deterministic event-ID rules change.
- Analytical contract remains `xqnet-analysis-v0.1`.
- MCP contract remains `xqnet-mcp-v0.1`.

# xqnet 0.1.1

Deterministic event-ID collision hardening.

## Eventizer

- Advances the reference algorithm identifier from `network-reference-v1` to `network-reference-v1.1`.
- Fixes a validation failure where two legitimate emitted events could receive the same deterministic ID seed and therefore the same Core event ID.
- The first occurrence of every seed retains the exact v1 event ID.
- Second and later occurrences use a deterministic `|occurrence:N` seed suffix and record `provenance.parameters.event_id_occurrence`.
- This specifically covers repeated identical evidence within one source record, including duplicate Zeek DNS answers, without deduplicating or discarding the evidence.
- Zeek and Suricata semantic mappings remain `zeek-reference-v1` and `suricata-reference-v1`; network semantics are otherwise unchanged.

## Contracts

- Analytical contract remains `xqnet-analysis-v0.1`.
- MCP contract remains `xqnet-mcp-v0.1`.
- Crosscue Event Model wire and Network Profile remain unchanged.

# xqnet 0.1.0

First aligned xq-family reference release.

## Semantic baseline

- Crosscue Event Model wire `0.1`.
- Network Profile `xq.net:profile-0.1`.
- Eventizer `network-reference-v1` unchanged from the development build.
- Adapter mappings remain `zeek-reference-v1` and `suricata-reference-v1`.
- Existing network identity, DNS temporal-purity, relationship, Community-ID, service and presence semantics are preserved.

## Family alignment

- Added versioned `xqnet-analysis-v0.1` analytical contract.
- Added `xqnet inspect` with compact, diagnostic, JSON and entity-index modes.
- Added concise default `eventize` output and `--verbose` detail.
- Added family-style `--version` output including eventizer, analysis and MCP contracts.
- Standardized CLI errors on the `xqnet:` prefix and clean subcommand help handling.

## Parquet materialization

- ZSTD remains the default compression.
- Added bounded row groups: 131,072 rows by default.
- Added bounded dictionaries: 8 MiB per column per row group by default.
- Added Parquet physical settings and actual row-group counts to `manifest.json`.
- Added `xq:analysis_contract` and physical-setting metadata to analytical files.

## MCP / analyst API

- Added read-only `xqnet-mcp-v0.1` stdio server.
- Added a DuckDB-backed network analyst API over existing analytical Parquet files.
- Added bounded/cursor-paginated tools for entities, timelines, bindings, sessions, relationships, services, presence, networks, events and observations.
- Added `describe_endpoint`, `explain_event` and `explain_relationship` domain tools.
- Added manifest, capability, analyst-guidance, analytical-contract, eventizer and interoperability MCP resources.
- No arbitrary SQL tool is exposed in MCP v0.1.

## Build

The single MCP-capable binary now requires Go 1.25+, CGO and a C toolchain because it embeds DuckDB and the current official MCP Go SDK.
