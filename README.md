# xqnet

`xqnet` is the Crosscue network-event reference implementation. It converts structured Zeek or Suricata telemetry into canonical Crosscue Network Profile events plus an analysis-ready Parquet layer, and exposes that analytical layer to LLM/agent clients through a domain-specific MCP server.

This repository is an **Apache-2.0 licensed reference implementation**. The Crosscue Event Model specification and Network Profile are the normative interoperability contracts; xqnet demonstrates one reproducible implementation and analytical/MCP pattern.

The design is aligned with the xq family reference architecture established by `xqmob`, while preserving network-specific semantics rather than forcing mobility abstractions onto network data.

## Version surfaces

```text
xqnet                  0.1.3-rc5
network eventizer      network-reference-v1.4
analytical contract    xqnet-analysis-v0.2
MCP contract           xqnet-mcp-v0.1
Event Model wire       0.1
Network Profile        xq.net:profile-0.1
```

Reference adapter mappings remain `zeek-reference-v1` and `suricata-reference-v1`.

The Event Model repository is: <https://github.com/crosscue/event-model>

## Reference implementation and status

`0.1.3-rc5` is a public open-source release candidate under Apache-2.0. It corrects Zeek duration/RTT rounding, produces valid application arrays for unidentified traffic, and preserves numeric context/provenance through Parquet and MCP. It retains strict source timestamp validation and explicit output replacement.

xqnet is a **reference implementation**, not the normative Crosscue Event Model specification. The specification/profile defines interoperability requirements; xqnet demonstrates one reproducible network producer, analytical projection model and domain-specific MCP analyst interface. Alternative conformant implementations are expected and welcome.

The independently versioned contracts remain frozen for this release candidate:

- eventizer: `network-reference-v1.4`;
- analytical projections: `xqnet-analysis-v0.2`;
- MCP analyst interface: `xqnet-mcp-v0.1`;
- Event Model wire/profile: `0.1` / `xq.net:profile-0.1`;
- adapter mappings: `zeek-reference-v1` / `suricata-reference-v1`.

See `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `CONTRIBUTING.md`, `SECURITY.md` and `docs/PUBLICATION_CHECKLIST.md` before publishing or redistributing release artifacts.

## Build

The MCP-capable binary embeds DuckDB and therefore requires CGO, a C toolchain, and the Go 1.26.8 toolchain selected by `go.mod`. The language version remains Go 1.25.

```bash
go mod tidy
CGO_ENABLED=1 go build -o xqnet ./cmd/xqnet
```

Pinned direct dependencies:

- `github.com/parquet-go/parquet-go v0.32.0`
- `github.com/duckdb/duckdb-go/v2 v2.10505.0`
- `github.com/modelcontextprotocol/go-sdk v1.7.0`

## Eventize

### Zeek JSON logs

```bash
./xqnet eventize ./zeek-logs \
  --adapter zeek \
  --source sensor-01 \
  --out output
```

### Suricata EVE JSON

```bash
./xqnet eventize ./eve.json \
  --adapter suricata \
  --source sensor-01 \
  --out output
```

### PCAP / PCAPNG / capture dumps

Packet captures are user-facing inputs, but packet decoding, stream reassembly and application-protocol decoding remain the responsibility of the selected upstream engine. xqnet recognizes classic PCAP and PCAPNG by file magic, so capture files with non-standard extensions such as `.dmp` are accepted as well.

```bash
./xqnet eventize capture.pcapng --adapter zeek --source sensor-01 --out output

# A tcpdump-style .dmp capture is also detected automatically:
./xqnet eventize capture.dmp --adapter zeek --source sensor-01 --out output
```

or:

```bash
./xqnet eventize capture.pcapng \
  --adapter suricata \
  --suricata-config ~/suricata-test/suricata.yaml \
  --source sensor-01 \
  --out output
```

## Standard output

Existing xqnet output files are protected by default. To replace a dataset, pass
`--overwrite` explicitly:

```bash
./xqnet eventize ./zeek-logs --adapter zeek --source sensor-01 --out output --overwrite
```

Only known xqnet artifacts are replaced; unrelated files are retained. Replacement
starts after the adapter successfully processes and validates the input. Writing
the replacement is not atomic: a later storage/materialization failure can leave
partial output, so use a new output directory when the previous dataset must be
retained throughout the entire run.

```text
output/
├── manifest.json
├── canonical/
│   └── events.jsonl
└── analysis/
    ├── entities.parquet
    ├── observations.parquet
    ├── events.parquet
    ├── bindings.parquet
    ├── sessions.parquet
    ├── relationships.parquet
    ├── services.parquet
    ├── presence_intervals.parquet
    └── networks.parquet
```

`canonical/events.jsonl` is the semantic source of truth. The Parquet files implement `xqnet-analysis-v0.2` and are intended for SQL, graph construction, filtering, visualisation, LLM retrieval and downstream enrichment.

Analytical timestamps retain up to nine fractional digits, normalized to UTC.
Older `xqnet-analysis-v0.1` datasets must be rebuilt from source telemetry before
using MCP or entity inspection with this release; their lost precision cannot be
recovered by changing the manifest. See [the analytical contract](docs/ANALYTICAL-CONTRACT.md)
for timestamp encoding and supported range.

## Identity and evidence model

xqnet keeps the network entity ladder explicit:

```text
interface → address → endpoint → service
```

A MAC identifies an interface by default, not a device. An IP address is not a device. An endpoint is not a service. Source-native Zeek/Suricata telemetry remains evidentially authoritative beneath the semantic/analytical layer.

Other important rules:

- a connection attempt is not automatically a communication relationship;
- `first_observed` is not `established`;
- DNS query and response knowledge remain temporally separate;
- Community ID correlates transport tuples but does not define a session;
- source-engine session boundaries may differ between Zeek and Suricata;
- network presence is materialized only within an explicitly configured network scope;
- aggregate relationship directionality records evidence strength rather than inventing roles.

Zeek connection summaries are timestamped at `ts + duration`, with the source
start/end interval retained in context and session projections. A missing,
invalid, negative or out-of-range duration is rejected with a line-specific
error; an explicit zero duration is accepted. Zeek may omit duration in some
valid native records, so those inputs require an upstream source with sufficient
timing evidence before xqnet can eventize them. Do not substitute a guessed zero.

See [`docs/NETWORK-EVENTIZER-V1.4.md`](docs/NETWORK-EVENTIZER-V1.4.md).

Supported source records with missing, null, malformed or out-of-range timestamps,
or timestamps with more than nine fractional digits, fail with line-specific
errors. They are not silently discarded or truncated. Suricata flow interval
fields fall back to record time only when absent; present invalid values fail.
Timestamp failures preserve existing output even with `--overwrite`. Rebuild
datasets affected by earlier timestamp loss or negative-time parsing from the
original telemetry.

Zeek connection durations and DNS RTTs use exact decimal arithmetic, including
scientific notation: 65 microseconds adds exactly 65,000 nanoseconds. Unsupported
sub-nanosecond intervals, invalid RTTs and resulting times outside the analytical
range fail before output replacement. Absent/null DNS RTT retains its existing
query-time fallback. Rebuild older affected datasets to apply these corrections.

## Network scope and presence

```bash
./xqnet eventize ./zeek-logs \
  --adapter zeek \
  --source sensor-01 \
  --network-id network:lab-lan \
  --network-cidrs 192.168.1.0/24 \
  --out output
```

Without explicit scope, `presence_intervals.parquet` is empty. First/last observation within scope does not manufacture ENTER/LEAVE semantics.

## Inspect

```bash
./xqnet inspect output/
./xqnet inspect --diagnostics output/
./xqnet inspect --entity endpoint:ip:203.0.113.8:443/tcp output/
./xqnet inspect --json output/
```

Normal `eventize` output is intentionally compact. Complete reproducibility and physical materialization information remains in `manifest.json`.

## MCP / LLM analyst interface

```bash
./xqnet mcp output/
```

or:

```bash
./xqnet mcp --duckdb-threads 8 output/
```

The MCP server is read-only and uses DuckDB to query the existing Parquet files directly. stdout is reserved exclusively for MCP stdio protocol messages; diagnostics go to stderr.

Common xq-family tools include dataset/entity discovery, timelines, events, observations and explanations. xqnet then adds network-domain tools for bindings, sessions, communication relationships, services, explicit-scope presence, networks and endpoint explanation.

See [`docs/MCP.md`](docs/MCP.md).

## Parquet physical defaults

To keep memory bounded on large analytical outputs, the family defaults established by xqmob are used here too:

```text
compression             zstd
row group max rows      131072
dictionary max bytes    8 MiB / column / row group
application batch       1024 rows
```

Override for benchmarking if needed:

```bash
./xqnet eventize ... \
  --parquet-row-group-rows 131072 \
  --parquet-dictionary-max-mib 8
```

These settings affect physical materialization only, never Network Profile event semantics.

## Validate

```bash
./xqnet validate output/canonical/events.jsonl
```

This is a producer-side guard and does not replace the Event Model repository's authoritative layered conformance tooling.

The guard checks required fields, timestamp syntax and intervals, polarity,
reference feature/class/action/entity compositions, provenance and observation
viewpoints, presence scope and temporal-purity constraints. It rejects absent or
null polarity, missing/non-string observation points, and timestamps with more
than nine fractional digits rather than silently truncating precision.

## Version

```bash
./xqnet --version
```

## xq-family architecture

```text
xqnet
 ├── source adapters / network-reference-v1.4
 ├── canonical Crosscue events
 ├── xqnet-analysis-v0.2
 ├── network analyst API
 └── xqnet-mcp-v0.1
        ↓
      DuckDB
        ↓
 analysis/*.parquet
```

The MCP transport conventions are intentionally family-consistent with xqmob, but the analytical tools are network-specific. Future `xqrf`, `xqais`, `xqadsb`, etc. should follow the same pattern rather than depend on one generic lowest-common-denominator MCP server.
## Open-source project

xqnet is licensed under the [Apache License 2.0](LICENSE). See:

- [CONTRIBUTING.md](CONTRIBUTING.md) for contribution/testing expectations;
- [SECURITY.md](SECURITY.md) for private vulnerability reporting;
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for dependency/licensing notes;
- [TRADEMARKS.md](TRADEMARKS.md) for branding guidance;
- [docs/PUBLICATION_CHECKLIST.md](docs/PUBLICATION_CHECKLIST.md) for release-candidate promotion checks.

Do not publish packet captures or network logs unless you are entitled to redistribute them and have reviewed them for sensitive information.

## Reference status

The tool, eventizer, analytical and MCP contracts are independently versioned. A compatible implementation does not need to use xqnet internally; conformance is determined by the applicable Crosscue Event Model/Profile contract rather than by matching this codebase byte-for-byte.
