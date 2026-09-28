# Security policy

## Supported versions

Security fixes are normally applied to the latest published xqnet release and,
where practical, the immediately preceding compatible release line.

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected security vulnerability.
Report it privately through GitHub once this repository has private
vulnerability reporting enabled:

<https://github.com/crosscue/xqnet/security/advisories/new>

Enable that setting under Settings, Code security, Private vulnerability
reporting, before the repository is made public.

Until that page is available, email [hello@crosscue.uk](mailto:hello@crosscue.uk)
with `xqnet security` in the subject. That address is the contact published at
<https://crosscue.uk/contact>.

Include enough information to reproduce and assess the issue, such as affected
version, platform, invocation, relevant configuration and a minimal proof of
concept where safe to provide one.

Please avoid accessing networks, captures or systems you do not own or have
permission to test.

## Scope notes

xqnet processes potentially sensitive network telemetry. Security reports may
therefore include issues involving:

- unexpected data disclosure through CLI/MCP output;
- path traversal or unsafe file handling;
- malformed packet/log input causing denial of service;
- unsafe invocation of external Zeek/Suricata executables;
- MCP protocol boundary violations, especially stdout contamination;
- DuckDB query-layer escape from the intended read-only analytical interface;
- dependency or native-library vulnerabilities affecting the shipped binary.
