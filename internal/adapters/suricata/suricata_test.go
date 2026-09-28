// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testState() *AppState {
	return &AppState{
		Source:        "test-sensor",
		Entities:      map[string]*EntityStat{},
		Relationships: map[string]*Relationship{},
		Bindings:      map[string]*Binding{},
		Services:      map[string]*ServiceStat{},
		Network:       NetworkContext{ObservationPoint: "test-sensor"},
	}
}

func writeEVE(t *testing.T, lines ...string) string {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "eve.json")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func countFeature(events []CoreEvent, feature string) int {
	n := 0
	for _, e := range events {
		if e.Feature == feature {
			n++
		}
	}
	return n
}

func firstFeature(events []CoreEvent, feature string) *CoreEvent {
	for i := range events {
		if events[i].Feature == feature {
			return &events[i]
		}
	}
	return nil
}

func TestARPBindingCoalescesAndUsesInterface(t *testing.T) {
	p := writeEVE(t,
		`{"timestamp":"2026-09-06T10:00:00.000000+0000","event_type":"arp","arp":{"opcode":"request","src_mac":"aa:bb:cc:dd:ee:01","src_ip":"192.168.1.10","dest_mac":"00:00:00:00:00:00","dest_ip":"192.168.1.1"}}`,
		`{"timestamp":"2026-09-06T10:00:01.000000+0000","event_type":"arp","arp":{"opcode":"request","src_mac":"aa:bb:cc:dd:ee:01","src_ip":"192.168.1.10","dest_mac":"00:00:00:00:00:00","dest_ip":"192.168.1.1"}}`,
	)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	if got := countFeature(st.Events, namespace+":address_binding"); got != 1 {
		t.Fatalf("address binding events=%d want 1", got)
	}
	b := st.Bindings[bindingKey("interface:mac:aa:bb:cc:dd:ee:01", "address:ip:192.168.1.10", "arp_address_binding")]
	if b == nil || b.Count != 2 || b.ParentEventCount != 1 {
		t.Fatalf("binding=%+v", b)
	}
	if _, ok := st.Entities["device:mac:aa:bb:cc:dd:ee:01"]; ok {
		t.Fatal("ARP must not create device:mac entity")
	}
	if _, ok := st.Entities["interface:mac:aa:bb:cc:dd:ee:01"]; !ok {
		t.Fatal("missing interface entity")
	}
}

func TestDNSRequestsAndResponsesRemainSeparate(t *testing.T) {
	p := writeEVE(t,
		`{"timestamp":"2026-09-06T10:00:00.000000+0000","flow_id":1,"event_type":"dns","src_ip":"10.0.0.2","src_port":53000,"dest_ip":"10.0.0.1","dest_port":53,"proto":"UDP","dns":{"version":3,"type":"request","id":77,"queries":[{"rrname":"www.example.com","rrtype":"A"}]}}`,
		`{"timestamp":"2026-09-06T10:00:00.010000+0000","flow_id":1,"event_type":"dns","src_ip":"10.0.0.1","src_port":53,"dest_ip":"10.0.0.2","dest_port":53000,"proto":"UDP","dns":{"version":3,"type":"answer","id":77,"rcode":"NOERROR","queries":[{"rrname":"www.example.com","rrtype":"A"}],"answers":[{"rrname":"www.example.com","rrtype":"A","ttl":60,"rdata":"203.0.113.8"}]}}`,
		`{"timestamp":"2026-09-06T10:01:00.000000+0000","flow_id":2,"event_type":"dns","src_ip":"10.0.0.1","src_port":53,"dest_ip":"10.0.0.3","dest_port":53001,"proto":"UDP","dns":{"version":3,"type":"answer","id":88,"rcode":"NOERROR","queries":[{"rrname":"orphan.example","rrtype":"A"}],"answers":[{"rrname":"orphan.example","rrtype":"A","ttl":60,"rdata":"203.0.113.9"}]}}`,
	)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	if got := countFeature(st.Events, namespace+":dns_query"); got != 1 {
		t.Fatalf("dns_query=%d want 1", got)
	}
	if got := countFeature(st.Events, namespace+":name_resolution"); got != 2 {
		t.Fatalf("name_resolution=%d want 2", got)
	}
	q := firstFeature(st.Events, namespace+":dns_query")
	if _, ok := q.Context["response_code"]; ok {
		t.Fatal("query event contains response_code")
	}
	seenFalse := false
	for _, e := range st.Events {
		if e.Feature == namespace+":name_resolution" && e.Subject == "domain:orphan.example" {
			v, ok := e.Context["query_observed"].(bool)
			if !ok || v {
				t.Fatalf("orphan response query_observed=%v", e.Context["query_observed"])
			}
			seenFalse = true
		}
	}
	if !seenFalse {
		t.Fatal("missing response-only resolution")
	}
}

func TestFlowUsesFlowEndAndQualifiesRelationshipsByEvidence(t *testing.T) {
	p := writeEVE(t,
		`{"timestamp":"2026-09-06T10:00:10.000000+0000","flow_id":10,"event_type":"flow","src_ip":"10.0.0.2","src_port":50000,"dest_ip":"10.0.0.9","dest_port":22,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":60,"bytes_toclient":0,"start":"2026-09-06T10:00:00.000000+0000","end":"2026-09-06T10:00:09.000000+0000","state":"new","reason":"timeout"}}`,
		`{"timestamp":"2026-09-06T10:00:20.000000+0000","flow_id":11,"event_type":"flow","src_ip":"10.0.0.2","src_port":5353,"dest_ip":"224.0.0.251","dest_port":5353,"proto":"UDP","app_proto":"mdns","flow":{"pkts_toserver":2,"pkts_toclient":0,"bytes_toserver":150,"bytes_toclient":0,"start":"2026-09-06T10:00:15.000000+0000","end":"2026-09-06T10:00:19.000000+0000","state":"new","reason":"timeout"}}`,
	)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	sortEvents(st.Events)
	if len(st.Sessions) != 2 {
		t.Fatalf("sessions=%d", len(st.Sessions))
	}
	if len(st.Relationships) != 1 {
		t.Fatalf("relationships=%d want 1", len(st.Relationships))
	}
	conn := firstFeature(st.Events, namespace+":connection")
	if conn == nil || conn.EventTime != "2026-09-06T10:00:09.000000000Z" {
		t.Fatalf("connection time=%v", conn)
	}
	if got := contextString(conn.Context, "source_record_time"); got != "2026-09-06T10:00:10.000000000Z" {
		t.Fatalf("source record time=%q", got)
	}
	if supported, _ := conn.Context["originator_role_supported"].(bool); supported {
		t.Fatal("unhinted flow must not claim supported originator role")
	}
	if got := contextString(conn.Context, "source_interval_start"); got != "2026-09-06T10:00:00.000000000Z" {
		t.Fatalf("source interval start=%q", got)
	}
	r := firstFeature(st.Events, namespace+":communication_relationship")
	if r == nil || contextString(r.Context, "evidence_directionality") != "unidirectional_observed" {
		t.Fatalf("relationship=%+v", r)
	}
	if err := validateGeneratedProfileEvents(st.Events); err != nil {
		t.Fatal(err)
	}
}

func TestTLSTargetsEndpointAndCreatesServerNameBinding(t *testing.T) {
	p := writeEVE(t, `{"timestamp":"2026-09-06T10:00:00.000000+0000","flow_id":22,"event_type":"tls","src_ip":"10.0.0.2","src_port":50000,"dest_ip":"203.0.113.8","dest_port":443,"proto":"TCP","tls":{"sni":"WWW.Example.COM.","version":"TLS 1.3"}}`)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	e := firstFeature(st.Events, namespace+":tls_session")
	if e == nil || e.Object != "endpoint:ip:203.0.113.8:443/tcp" {
		t.Fatalf("tls event=%+v", e)
	}
	b := st.Bindings[bindingKey("endpoint:ip:203.0.113.8:443/tcp", "domain:www.example.com", "tls_server_name_binding")]
	if b == nil {
		t.Fatal("missing TLS SNI binding")
	}
	if _, ok := st.Services["service:net:tls:ip:203.0.113.8:443/tcp"]; !ok {
		t.Fatal("missing TLS service projection")
	}
}

func TestDHCPUsesInterfaceAndAssignedAction(t *testing.T) {
	p := writeEVE(t, `{"timestamp":"2026-09-06T10:00:00.000000+0000","event_type":"dhcp","dhcp":{"type":"reply","id":7,"client_mac":"aa:bb:cc:dd:ee:01","assigned_ip":"192.168.1.10","dhcp_type":"ack","hostname":"LAB-HOST"}}`)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	if len(st.Events) != 2 {
		t.Fatalf("events=%d want 2", len(st.Events))
	}
	for _, e := range st.Events {
		if e.Subject != "interface:mac:aa:bb:cc:dd:ee:01" {
			t.Fatalf("subject=%q", e.Subject)
		}
	}
	if err := validateGeneratedProfileEvents(st.Events); err != nil {
		t.Fatal(err)
	}
}

func TestBundledSampleConforms(t *testing.T) {
	p := filepath.Join("..", "..", "..", "testdata", "suricata", "eve.json")
	st := testState()
	_, n, _ := net.ParseCIDR("192.168.1.0/24")
	st.Network = NetworkContext{ID: "network:lab-lan", CIDRs: []string{"192.168.1.0/24"}, ObservationPoint: st.Source}
	st.NetworkNets = []*net.IPNet{n}
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	sortEvents(st.Events)
	if len(st.Events) != 17 {
		t.Fatalf("events=%d want 17", len(st.Events))
	}
	if len(st.Relationships) != 2 {
		t.Fatalf("relationships=%d want 2", len(st.Relationships))
	}
	if err := validateGeneratedProfileEvents(st.Events); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(st.Events); i++ {
		a, _ := parseEventTime(st.Events[i-1].EventTime)
		b, _ := parseEventTime(st.Events[i].EventTime)
		if b.Before(a) {
			t.Fatalf("chronology inversion at %d", i)
		}
	}
}

func TestPCAPPointersAreRetainedInSourceRecord(t *testing.T) {
	p := writeEVE(t, `{"timestamp":"2026-09-06T10:00:00.000000+0000","flow_id":123,"pcap_filename":"/captures/lab.pcap","pcap_cnt":53381,"event_type":"tls","src_ip":"10.0.0.2","src_port":50000,"dest_ip":"203.0.113.8","dest_port":443,"proto":"TCP","tls":{"sni":"example.com"}}`)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	if len(st.Events) != 1 {
		t.Fatalf("events=%d", len(st.Events))
	}
	got := st.Events[0].Provenance.SourceRecords[0]
	if !strings.Contains(got, ":pcap:lab.pcap:packet:53381") {
		t.Fatalf("source record=%q", got)
	}
}

func TestDNSDetailedAnswersWinOverGrouped(t *testing.T) {
	p := writeEVE(t,
		`{"timestamp":"2026-09-06T10:00:00.000000+0000","flow_id":55,"event_type":"dns","src_ip":"10.0.0.2","src_port":53000,"dest_ip":"10.0.0.1","dest_port":53,"proto":"UDP","dns":{"version":3,"type":"request","id":77,"queries":[{"rrname":"www.example.com","rrtype":"A"}]}}`,
		`{"timestamp":"2026-09-06T10:00:00.010000+0000","flow_id":55,"event_type":"dns","src_ip":"10.0.0.1","src_port":53,"dest_ip":"10.0.0.2","dest_port":53000,"proto":"UDP","dns":{"version":3,"type":"answer","id":77,"queries":[{"rrname":"www.example.com","rrtype":"A"}],"answers":[{"rrname":"www.example.com","rrtype":"CNAME","ttl":60,"rdata":"edge.example.net"},{"rrname":"edge.example.net","rrtype":"A","ttl":60,"rdata":"203.0.113.8"}],"grouped":{"CNAME":["edge.example.net"],"A":["203.0.113.8"]}}}`,
	)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	if got := countFeature(st.Events, namespace+":name_alias"); got != 1 {
		t.Fatalf("name_alias=%d want 1", got)
	}
	if got := countFeature(st.Events, namespace+":name_resolution"); got != 1 {
		t.Fatalf("name_resolution=%d want 1", got)
	}
	for _, e := range st.Events {
		if (e.Feature == namespace+":name_alias" || e.Feature == namespace+":name_resolution") && contextString(e.Context, "answer_representation") != "detailed" {
			t.Fatalf("answer representation=%q", contextString(e.Context, "answer_representation"))
		}
	}
	if st.Bindings[bindingKey("domain:www.example.com", "address:ip:203.0.113.8", "dns_address_binding")] != nil {
		t.Fatal("detailed+grouped response manufactured direct query-name address binding")
	}
	if st.Bindings[bindingKey("domain:edge.example.net", "address:ip:203.0.113.8", "dns_address_binding")] == nil {
		t.Fatal("missing detailed owner-specific address binding")
	}
}

func TestDNSGroupedFallbackIsConservative(t *testing.T) {
	p := writeEVE(t,
		`{"timestamp":"2026-09-06T10:00:00.000000+0000","flow_id":56,"event_type":"dns","src_ip":"10.0.0.1","src_port":53,"dest_ip":"10.0.0.2","dest_port":53000,"proto":"UDP","dns":{"version":3,"type":"answer","id":77,"queries":[{"rrname":"www.example.com","rrtype":"A"}],"grouped":{"CNAME":["edge.example.net"],"A":["203.0.113.8"]}}}`,
	)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	if got := countFeature(st.Events, namespace+":name_alias"); got != 1 {
		t.Fatalf("name_alias=%d want 1", got)
	}
	if got := countFeature(st.Events, namespace+":name_resolution"); got != 0 {
		t.Fatalf("name_resolution=%d want 0 for grouped CNAME+A ambiguity", got)
	}
}

func TestFlowRoleHintCanBeCollectedAfterFlowRecord(t *testing.T) {
	p := writeEVE(t,
		`{"timestamp":"2026-09-06T10:00:10.000000+0000","flow_id":90,"event_type":"flow","src_ip":"10.0.0.2","src_port":50000,"dest_ip":"203.0.113.8","dest_port":80,"proto":"TCP","app_proto":"http","flow":{"pkts_toserver":5,"pkts_toclient":4,"bytes_toserver":500,"bytes_toclient":400,"start":"2026-09-06T10:00:00.000000+0000","end":"2026-09-06T10:00:09.000000+0000","state":"closed","reason":"shutdown"}}`,
		`{"timestamp":"2026-09-06T10:00:05.000000+0000","flow_id":90,"event_type":"http","src_ip":"10.0.0.2","src_port":50000,"dest_ip":"203.0.113.8","dest_port":80,"proto":"TCP","app_proto":"http","http":{"hostname":"example.com","url":"/"}}`,
	)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	conn := firstFeature(st.Events, namespace+":connection")
	if conn == nil {
		t.Fatal("missing connection")
	}
	if supported, _ := conn.Context["originator_role_supported"].(bool); !supported {
		t.Fatal("HTTP role hint should support originator role")
	}
	if got := contextString(conn.Context, "endpoint_role_basis"); !strings.Contains(got, "http_protocol_event") {
		t.Fatalf("role basis=%q", got)
	}
}

func TestCommunityIDRetainedInFlowEventAndSession(t *testing.T) {
	p := writeEVE(t, `{"timestamp":"2026-09-06T10:00:10.000000+0000","flow_id":101,"community_id":"1:example","event_type":"flow","src_ip":"10.0.0.2","src_port":50000,"dest_ip":"203.0.113.8","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":2,"bytes_toserver":300,"bytes_toclient":200,"start":"2026-09-06T10:00:00.000000+0000","end":"2026-09-06T10:00:09.000000+0000","state":"closed","reason":"shutdown"}}`)
	st := testState()
	if err := processEVE(st, p); err != nil {
		t.Fatal(err)
	}
	conn := firstFeature(st.Events, namespace+":connection")
	if conn == nil || contextString(conn.Context, "community_id") != "1:example" {
		t.Fatalf("connection community_id=%v", conn)
	}
	if len(st.Sessions) != 1 || st.Sessions[0].CommunityID != "1:example" {
		t.Fatalf("session=%+v", st.Sessions)
	}
}

func TestDuplicateEventSeedGetsUniqueDeterministicID(t *testing.T) {
	st := testState()
	ts := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	first := newEvent(st, ts, "normalized_observation", "address:ip:192.0.2.10", "endpoint:203.0.113.8:443/tcp", namespace+":connection", coreObserved, "", 0, nil, "suricata:eve.json:line:1:record:1", "suricata-flow-normalize")
	second := newEvent(st, ts, "normalized_observation", "address:ip:192.0.2.10", "endpoint:203.0.113.8:443/tcp", namespace+":connection", coreObserved, "", 0, nil, "suricata:eve.json:line:1:record:1", "suricata-flow-normalize")
	if first.ID == second.ID {
		t.Fatalf("duplicate seed produced duplicate event id %q", first.ID)
	}
	if got := second.Provenance.Parameters["event_id_occurrence"]; got != 2 {
		t.Fatalf("second occurrence provenance = %#v, want 2", got)
	}
}

func TestReadJSONLinesPacketCaptureGuidance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.dmp")
	if err := os.WriteFile(path, []byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	err := readJSONLines(path, func(_ int, _ map[string]any) error { return nil })
	if err == nil {
		t.Fatal("expected packet-capture format guidance error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "appears to be a packet capture") || !strings.Contains(msg, "xqnet eventize") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadJSONLinesNonEVEGuidance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(path, []byte("not-json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := readJSONLines(path, func(_ int, _ map[string]any) error { return nil })
	if err == nil {
		t.Fatal("expected EVE JSON format guidance error")
	}
	if !strings.Contains(err.Error(), "not a Suricata EVE JSON record") {
		t.Fatalf("unexpected error: %v", err)
	}
}
