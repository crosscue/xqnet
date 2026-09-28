# Contributing to xqnet

Thanks for considering a contribution to xqnet.

xqnet is a reference network-event implementation for the Crosscue Event Model.
The project values reproducibility, evidence preservation, explicit identity
boundaries and clear separation between source telemetry, eventizer semantics
and analytical projections.

## Before opening a pull request

For significant semantic changes, open an issue first. Changes to any of these
surfaces require explicit versioning and accompanying contract documentation:

- `network-reference-*` eventizer behavior;
- `xqnet-analysis-*` projection schemas/meaning;
- `xqnet-mcp-*` tool/resource contracts;
- canonical Crosscue Event Model output behavior.

Adapter implementation changes must not silently collapse interface, address,
endpoint or service identities; invent communication relationships; merge DNS
query/response knowledge across time; or change deterministic event IDs without
an explicit eventizer contract/version decision.

## Development requirements

- Go toolchain 1.26.8, as selected by `go.mod` (language version 1.25)
- `CGO_ENABLED=1` and a suitable C toolchain for the DuckDB-enabled binary

Run the normal checks before submitting:

```bash
go mod tidy
go test ./...
go vet ./...
go test -race ./...
```

For an end-to-end smoke test:

```bash
go run ./cmd/xqnet eventize ./testdata/zeek \
  --adapter zeek --source contributor-test \
  --network-id network:test --network-cidrs 192.168.1.0/24 \
  --out /tmp/xqnet-test

go run ./cmd/xqnet validate /tmp/xqnet-test/canonical/events.jsonl
go run ./cmd/xqnet inspect /tmp/xqnet-test
```

## Coding and compatibility expectations

- Prefer straightforward Go and small domain-focused packages.
- Keep source adapters/eventization independent from MCP and presentation concerns.
- Preserve the distinction between canonical events and analytical projections.
- Treat source-native Zeek/Suricata evidence as evidential input, not truth about higher-level identity.
- An IP address is not a device; a MAC is an interface identifier by default.
- Connection attempts are not automatically established communication relationships.
- Community ID is a tuple-correlation mechanism, not a session identity.
- Network presence must remain explicitly scope-bound.
- MCP stdout is protocol-only; application diagnostics belong on stderr.
- Collection-returning MCP tools must remain bounded and paginated.
- Add regression coverage for every bug fix and semantic/versioned change.

## Tests for semantic changes

A semantic change should normally include:

1. a minimal synthetic/source fixture;
2. expected canonical event behavior;
3. expected analytical projection behavior where relevant;
4. documentation in the corresponding versioned contract;
5. an explicit version bump for the affected contract.

## Licensing contributions

xqnet is licensed under Apache-2.0. By submitting a contribution, you represent
that you have the right to submit it under the project's Apache-2.0 terms.
There is currently no separate contributor licence agreement (CLA).

Do not contribute code, captures, logs or documentation that you do not have the
right to redistribute.
