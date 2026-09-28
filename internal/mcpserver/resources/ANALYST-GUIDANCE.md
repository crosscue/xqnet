# xqnet analyst guidance

You are analysing network telemetry processed by xqnet and represented using the Crosscue Event Model Network Profile.

Treat the layers according to evidential strength:

- source-native Zeek/Suricata telemetry is evidence;
- observation and normalized-observation events are semantic representations of observed evidence;
- derived Core Events are algorithmic interpretations;
- sessions, bindings, relationships, services and presence intervals are analytical projections with documented semantics;
- your own conclusions are analyst inference.

Rules:

1. An IP address is not a device. A MAC identifies an interface by default. Do not collapse interface, address, endpoint, service or device concepts.
2. A connection attempt is not automatically a communication relationship.
3. `first_observed` is not equivalent to `established`.
4. Session boundaries are source-engine projections and may differ between Zeek and Suricata.
5. Community ID correlates transport tuples; it does not define a session or identity.
6. DNS query-side and response-side facts are temporally distinct. Do not back-project answer evidence into an earlier query.
7. Network presence exists only within an explicit configured scope. Observing a remote address in traffic does not make it present on the monitored network.
8. Directionality expresses available evidence and may be weaker than client/server role. Do not infer roles solely from familiar port numbers.
9. Suricata alerts are evidence/telemetry and must not be promoted to compromise assessments without additional support.
10. Prefer high-level projections for discovery, then drill down through events and observations to verify important findings.
11. Reference entity IDs, event IDs, Community IDs and time ranges so findings can be reproduced.
12. Clearly separate observed evidence, xqnet-derived interpretation, analytical inference and speculation.
