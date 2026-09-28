# Changelog

This changelog summarizes public/tool releases. The eventizer, analytical and MCP contracts are versioned independently; see the release notes and contract documents for semantic detail.

## 0.1.3-rc5

Advances the eventizer to `network-reference-v1.4`. Zeek duration and DNS RTT
calculations preserve exact nanoseconds; invalid/unrepresentable intervals fail
before output replacement. Both adapters emit empty application arrays for
unidentified relationships. Parquet/MCP retain exact numeric context/provenance.
Corrects documentation of the temporary read-only DuckDB catalog. Analytical
v0.2 and MCP v0.1 schemas remain unchanged; rebuild affected datasets.

## 0.1.3-rc4

Advances the eventizer to `network-reference-v1.3`. Invalid source timestamps
now fail with line-specific errors before output replacement. Both adapters
reject fractions longer than nine digits, and Zeek parses negative fractional
Unix seconds correctly. Present malformed Suricata flow interval timestamps
are rejected instead of falling back to record time. Analytical v0.2 and MCP
v0.1 remain unchanged.

## 0.1.3-rc3

Strengthens public event validation and error diagnostics. Introduces
`xqnet-analysis-v0.2` with nanosecond timestamps, exact time filtering and
precision-preserving MCP responses. Older analytical datasets require rebuilding.
Eventizer v1.2 and MCP v0.1 remain unchanged.

## 0.1.3-rc2

Requires `eventize --overwrite` to replace existing output; adapter failures
preserve the previous dataset even when overwrite is requested. Advances the
eventizer to `network-reference-v1.2`: Zeek connection summaries and dependent
evidence use the reported connection end, while sessions retain their original
intervals. Missing or invalid duration is rejected. Connection and dependent IDs
may change; analytical and MCP schemas are unchanged.

## 0.1.3-rc1

First public open-source release candidate. Adds Apache-2.0 licensing, contribution/security/governance material, dependency notices and public-release hardening. No semantic contract changes.

## 0.1.2

Improved packet-capture detection, including `.dmp` and PCAP/PCAPNG magic, and clearer Suricata EVE/capture guidance. Eventizer remained `network-reference-v1.1`.

## 0.1.1

Hardened deterministic event-ID allocation against legitimate repeated seeds and 96-bit ID collisions; introduced `network-reference-v1.1` while preserving first-occurrence IDs.

## 0.1.0

First aligned xq-family reference release with `network-reference-v1`, `xqnet-analysis-v0.1`, `xqnet-mcp-v0.1`, bounded Parquet materialization, `inspect`, DuckDB analyst API and read-only network MCP tools.
