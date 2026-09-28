# Zeek / Suricata interoperability

`xqnet` intentionally implements the same Network Profile semantics from two different source engines.

The reference development capture produced the following useful baseline:

- all 14 ARP interface↔address bindings matched exactly;
- all 10 interface entities matched exactly;
- all 2,851 unique Suricata Community IDs were present in Zeek;
- Zeek had 13 additional Community IDs, all unknown-transport multicast traffic;
- for 2,494 shared IDs where Suricata had supported originator-role evidence, subject→endpoint orientation agreed in all 2,494 cases;
- supported application-stack interpretation agreed in approximately 99.9% of those cases;
- unordered host-pair+protocol communication-graph overlap was approximately 96.6%.

These values are development observations, not normative conformance thresholds.

The important reference principle is semantic convergence without forcing the engines to expose identical native records or identical sessionization.
