# xqnet architecture

xqnet is a reference network implementation for the Crosscue Event Model. Its
architecture separates source-engine evidence ingestion, semantic eventization,
analytical materialization and LLM-facing analysis.

```text
Zeek logs / Suricata EVE / packet capture
                |
                v
source adapter / external decode engine
                |
                v
network-reference eventizer
                |
                +--> canonical/events.jsonl
                |
                +--> analytical projections (Parquet)
                         |
                         +--> CLI inspect
                         +--> DuckDB analyst API
                                  |
                                  +--> read-only MCP over stdio
```

## Normative boundaries

The Crosscue Event Model specification/profile defines the interoperable event
contract. xqnet is a reference implementation of one reproducible network
eventizer and analytical projection model.

The following are independently versioned:

- `network-reference-v1.4`: eventizer behavior;
- `xqnet-analysis-v0.2`: analytical projection contract;
- `xqnet-mcp-v0.1`: MCP analyst contract;
- Event Model wire/profile versions.

## Evidence and identity hierarchy

Source-native Zeek/Suricata telemetry is the supplied evidence. xqnet preserves
an explicit network entity ladder:

```text
interface -> address -> endpoint -> service
```

A MAC is an interface identifier by default, an IP address is not a device, an
endpoint is not a service, and a source-engine connection/session record does
not automatically establish higher-level identity or intent.

Events and analytical objects such as bindings, sessions, relationships,
services and presence intervals are derived interpretations of that evidence.

## Source-engine boundary

When packet captures are supplied, xqnet invokes the selected upstream engine
(Zeek or Suricata) for packet decoding, stream reassembly and protocol parsing.
xqnet does not implement a packet decoder and does not claim source-engine
outputs are interchangeable at every semantic layer.

## MCP boundary

MCP is read-only over an existing xqnet dataset. DuckDB creates a temporary
on-disk catalog of views over the analytical Parquet files, then reopens it
read-only with restricted file access. The catalog is removed on normal close;
the source dataset is queried directly and is not imported or modified.
MCP stdout is reserved for protocol traffic and results are bounded.
