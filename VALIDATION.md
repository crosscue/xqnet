# Validation notes

## 0.1.3-rc5 verification

Checked with Go 1.26.8 in Ubuntu 24.04/WSL using pinned dependencies, CGO and
read-only module metadata:

- fresh full-package race-enabled tests, `go vet ./...`, module verification,
  a clean `go mod tidy -diff`, and a CLI build;
- the configured `govulncheck` reported no vulnerabilities;
- unidentified TCP traffic from both adapters produces two valid events,
  including a relationship with an empty application array;
- exact duration/RTT arithmetic covers ordinary decimals, scientific notation,
  duration boundaries, sub-nanosecond rejection and invalid input;
- connection, DNS answer, relationship and session times preserve 65,000 ns for
  the 65-microsecond regression case;
- existing output is preserved after invalid intervals or computed timestamp
  overflow, including with `--overwrite`;
- Parquet round trips preserve large signed/unsigned integers, exact decimals,
  scientific notation, nested context/provenance and other JSON value types;
- both fixture CLI conversions and validation pass (17 events each);
- all three MCP integration tests pass with the race detector, including large
  integer metadata surviving source ingestion, Parquet, DuckDB and MCP transport;
- source formatting and embedded contract copies are consistent.

The analytical schema remains v0.2 and MCP remains v0.1. Affected existing
datasets need rebuilding as described in `RELEASE_NOTES.md`.

## 0.1.3-rc4 verification

Checked with Go 1.26.8 in Ubuntu 24.04/WSL using the pinned dependencies,
CGO and read-only module metadata:

- fresh full-package race-enabled tests, `go vet ./...` and CLI build;
- missing, null, malformed, over-precise and out-of-range source timestamps,
  covering every supported Zeek log and Suricata EVE type;
- exact signed Unix seconds, negative subsecond values, nine-digit fractions
  and analytical-range boundaries;
- supported Suricata timezone layouts, invalid flow interval timestamps and
  absent-field fallback;
- byte-for-byte preservation of all existing dataset artifacts after timestamp
  failures with `--overwrite`, including valid records before the invalid line;
- both fixture CLI conversions and validation (17 events each), with canonical
  semantics unchanged from rc3 after removing only producer/eventizer versions;
- both MCP integration tests with the race detector;
- original invalid/over-precise Suricata and negative fractional Zeek review
  reproductions verified through the rebuilt CLI.

The dependency metadata is present in this source package. Statements below
about outstanding module metadata describe earlier verification environments.

## 0.1.3-rc3 verification

Checked with Go 1.26.5 in Ubuntu 24.04/WSL using the real pinned dependencies
and an available C/C++ toolchain:

- full-package `go test ./...`, `go test -race ./...`, `go vet ./...` and CLI build;
- public-validator negative cases and valid composition checks, plus generated
  Zeek/Suricata fixtures passing the same public guard;
- exact Parquet round trips across all timestamp-bearing projection types,
  including nanoseconds, timezone offsets, pre-epoch instants and range rejection;
- real DuckDB queries over events one nanosecond apart, verifying ordering,
  pagination and exact inclusive bounds in events/observations/sessions/timelines;
- legacy analytical-contract rejection in MCP/analyst and entity inspection;
- both MCP integration tests with the race detector, including nanosecond
  filtering and response serialization through the SDK client/server transport;
- CLI eventization and validation for both fixtures (17 events each), version
  output, entity inspection and Go formatting.

Dependency metadata was resolved through a temporary `-modfile` outside the
source tree. Full real-dependency runtime checks now pass in this environment;
the separate publication task of committing `go.sum` and resolved module metadata
remains outstanding. The earlier rc2 limitations below are historical.

## 0.1.3-rc2 targeted verification

The overwrite and Zeek timing changes were checked on Windows with Go 1.26.5:

- pipeline regression tests using the real pinned Parquet dependency: refusal
  without `--overwrite` for each known artifact, explicit replacement, unrelated
  file preservation, and complete preservation after an adapter input failure;
- Zeek regression tests for end-anchored events and derived evidence, unchanged
  session intervals, earliest-completed relationship parents, explicit zero
  duration, and rejection of missing/invalid/negative/non-finite/overflow duration;
- all existing Zeek, Suricata and capture-detection tests;
- `go vet` for pipeline, adapters, capture detection and configuration;
- formatting checks for all Go source.

Dependency metadata and caches for these checks were kept outside the source
tree; the release's outstanding `go.sum`/full-build verification work is not
resolved by this change. Full CLI/MCP tests remain blocked by missing module
checksums. Race testing was not run on this host (CGO is disabled and no C
compiler is available on PATH).

## Previous packaging checks

The aligned release was checked during packaging with:

- `gofmt` over all Go source;
- Zeek adapter regression suite;
- Suricata adapter regression suite;
- analyst cursor/time-bound unit tests;
- full-package compile, test, vet and race checks against isolated API-compatible stubs for Parquet/DuckDB/MCP;
- Zeek and Suricata synthetic end-to-end eventization and producer-side validation;
- semantic regression against the supplied `0.1.0-dev` build: canonical events are identical after removing only the expected `producer_version` change from `0.1.0-dev` to `0.1.0`.

The packaging environment cannot link the real Go 1.25 DuckDB/MCP dependencies. GitHub Actions therefore performs the authoritative real-dependency build and integration checks, including DuckDB-backed MCP client/server calls over an eventized test dataset.

On a normal host:

```bash
go mod tidy
make check
```

## Event ID uniqueness

`network-reference-v1.1` allocates deterministic Core event IDs collision-safely. The first occurrence of a normalized semantic/source seed retains the v1 SHA-256-derived ID. Repeated seeds, or an otherwise colliding truncated hash, are deterministically re-hashed with an `occurrence:N` suffix until an unused ID is obtained. Later occurrences record `provenance.parameters.event_id_occurrence`. Producer-side validation still requires every emitted event ID to be non-empty and unique.

## Capture input classification

xqnet v0.1.2 recognizes classic PCAP and PCAPNG from their four-byte file magic and also treats `.dmp` as a capture-style extension. Regression tests cover `.dmp`, classic PCAP magic, PCAPNG magic, Suricata EVE JSON non-classification, and the explicit Suricata format-guidance error.
