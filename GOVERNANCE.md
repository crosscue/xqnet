# Governance

xqnet is currently maintained as a Crosscue-led reference implementation.

## Decision model

The project is maintainer-led. Maintainers are responsible for release scope,
compatibility decisions, security response and interpretation of the reference
implementation contracts.

Substantial changes should be discussed publicly before merge when practical,
especially changes to:

- event semantics and identity boundaries;
- analytical contracts;
- deterministic identity/provenance;
- MCP contracts;
- adapter/source-engine behavior;
- dependency or toolchain requirements.

The Crosscue Event Model specification is a separate project and remains the
normative source for Event Model conformance. xqnet is a reference
implementation, not the specification itself.

## Versioned contracts

xqnet deliberately versions independent surfaces separately:

- tool version: `xqnet` release version;
- eventizer: `network-reference-*`;
- analytical projections: `xqnet-analysis-*`;
- MCP analyst interface: `xqnet-mcp-*`;
- Crosscue Event Model wire/profile versions.

A change to one surface does not imply that the others must change.
