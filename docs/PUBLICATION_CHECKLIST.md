# Public release checklist

Use this checklist when promoting a release candidate to a public GitHub tag.

## Source and licensing

- [ ] Confirm `LICENSE` is Apache-2.0.
- [ ] Review `NOTICE` and `THIRD_PARTY_NOTICES.md` against the exact dependency graph.
- [x] Run `go mod tidy` with the supported Go toolchain and commit the resulting `go.sum`.
- [x] Run a dependency licence scan of the module graph linked by `./cmd/xqnet`. Direct dependencies remain Apache-2.0, MIT, and mixed MIT/Apache-2.0 as recorded in `THIRD_PARTY_NOTICES.md`. Transitive licences reported for that graph are Apache-2.0, MIT, BSD-2-Clause, and BSD-3-Clause.
- [ ] Generate an SBOM for any published binary.
- [ ] Confirm all Zeek/Suricata test fixtures and sample data may be redistributed.
- [ ] Confirm no secrets, customer telemetry, internal paths or proprietary captures/logs are present.
- [ ] Confirm branding/trademark statements are appropriate.

## Engineering checks

```bash
go test ./...
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go test -tags mcpintegration ./internal/mcpserver
```

`go test -tags mcpintegration` needs `XQNET_TEST_DATASET` pointing at an xqnet
output directory. CI builds that directory with the Zeek fixture before the
tagged test. `govulncheck` also runs in `.github/workflows/test.yml`.

Also run both Zeek and Suricata eventization/validation smoke tests documented in
`CONTRIBUTING.md` / CI.

Recommended additional checks before a public binary release:

- `govulncheck ./...` (also run on every CI push and pull request);
- secret scanning (for example GitHub secret scanning or gitleaks);
- SBOM generation for release binaries;
- malware/signing checks required by your release process.

## Compatibility

- [ ] Verify `xqnet --version` reports the intended tool and contract versions.
- [ ] Confirm canonical Zeek/Suricata fixture output changed only where explicitly intended.
- [ ] Confirm analytical-contract and MCP-contract version bumps match actual schema/API changes.
- [ ] Confirm MCP emits no application text on stdout.
- [ ] Confirm `xqnet validate` passes generated canonical events.
- [ ] Confirm packet-capture format detection routes PCAP/PCAPNG/`.dmp` inputs correctly.

## Documentation

- [ ] README status/version text matches the release.
- [ ] Release notes describe user-visible changes and compatibility.
- [ ] Eventizer/analytical/MCP contracts referenced by the release exist in `docs/`.
- [x] Private security and conduct contacts are named in `SECURITY.md` and `CODE_OF_CONDUCT.md` (`hello@crosscue.uk`, with GitHub private vulnerability reporting as the preferred route).
- [ ] When the GitHub repository is created, enable private vulnerability reporting under Settings → Code security.

## GitHub release

- [ ] Tag with the intended semantic version (for this candidate: `v0.1.3-rc5`).
- [ ] Attach source archive/checksum and any approved binaries.
- [ ] Include the checksum and dependency/SBOM artifacts where applicable.
- [ ] Mark pre-release/release-candidate appropriately.
