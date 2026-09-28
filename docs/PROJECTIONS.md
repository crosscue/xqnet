# xqnet analytical projections

Contract: `xqnet-analysis-v0.2`.

The Parquet outputs are analytical projections, not additional Crosscue Core Event types.

Every timestamp column preserves nanoseconds in UTC using the encoding described
in [the analytical contract](ANALYTICAL-CONTRACT.md). Older millisecond datasets
require rebuilding before use with the current analyst API.

## observations.parquet

Flattened observation/normalized-observation events for evidence-facing filtering.

## events.parquet

Flattened representation of `canonical/events.jsonl`, including context and provenance JSON for SQL systems that should not need to parse nested Core Event JSON.

## entities.parquet

Typed entity index covering interfaces, addresses, endpoints, services, domains, hostnames, software and explicit networks.

## bindings.parquet

Temporal relational evidence including ARP/DHCP address bindings, DNS address bindings, DNS aliases, TLS server-name bindings and endpoint→service bindings. Repetition is summarized with first/last time and observation counts.

## sessions.parquet

Source-engine session/flow projection linked to the parent connection event. Includes Community ID when available. Session boundaries are not asserted to be engine-independent.

## relationships.parquet

Observed communication relationships aggregated across qualifying connection evidence. Contains first/last observation, evidence directionality, traffic counts and bounded Community ID correlation metadata.

## services.parquet

Endpoint/service materialization supported by application evidence.

## presence_intervals.parquet

Capture-scoped observed intervals inside an explicitly configured network scope. These are not ENTER/LEAVE claims.

## networks.parquet

Explicit observation/network scope configured by the operator.

## Traceability

Every canonical event contains Core provenance. Projection rows retain event IDs or bounded parent-event lists where appropriate. A capped parent list is explicitly marked as truncated and is never presented as exhaustive provenance.

All Parquet files carry `xq:eventizer`, `xq:analysis_contract`, compression and physical row-group/dictionary metadata.
