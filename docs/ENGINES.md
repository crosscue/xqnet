# Upstream engine notes

## Zeek

For PCAP input, xqnet invokes Zeek with JSON logging, a small ARP logger, and Community ID seed 0. Zeek is located in this order:

1. explicit `--zeek` path;
2. `zeek` in `PATH`;
3. `/opt/zeek/bin/zeek`.

For pre-generated input, supply the directory containing JSON logs and no engine installation is required.

Every supported log record requires `ts` as decimal Unix seconds, with at most
nine fractional digits. Missing, null, malformed or out-of-range timestamps fail
with file/line diagnostics. Negative fractional values retain their exact sign.

`conn.log` records must include a finite, non-negative `duration` within the
supported range. xqnet uses `ts + duration` for whole-connection semantic evidence
and preserves the interval start/end in context and session projections. Some
native Zeek records omit duration; xqnet rejects them with a line-specific error
rather than inventing an end time. Explicit zero duration is accepted.

Duration and DNS RTT are converted from decimal seconds (including scientific
notation) to exact integer nanoseconds. Sub-nanosecond values and overflow fail
with line/field diagnostics before output replacement. Missing/null DNS RTT
retains the query-time fallback; present malformed or negative RTT is rejected.

## Suricata

Supported EVE records require a valid string `timestamp` with at most nine
fractional digits and within the analytical nanosecond range. Existing timezone
formats remain supported. Present `flow.start` and `flow.end` fields must also
be valid; only absent fields fall back to the record timestamp. Errors identify
the source line and field and preserve existing output even with `--overwrite`.
Unmapped EVE types remain ignored.

For source-neutral parity, the recommended EVE logger enables Community ID, detailed-only DNS, flow, TLS, DHCP and ARP. A representative fragment is:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      community-id-seed: 0
      types:
        - flow
        - dns:
            version: 3
            formats: [detailed]
        - tls:
            extended: yes
        - dhcp:
            enabled: yes
            extended: no
        - arp:
            enabled: yes
```

`community-id` belongs under the active `eve-log` block; `arp` belongs in its `types` list. Avoid a second `types:` block. Suricata may append to an existing `eve.json`, so use a fresh output directory or remove the old file before repeated offline runs.

When running Suricata manually as a non-root user, use a writable `-l` log directory rather than `/var/log/suricata`.
