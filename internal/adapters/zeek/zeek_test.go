// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package zeek

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleState(t *testing.T, scoped bool) *AppState {
	t.Helper()
	st := &AppState{
		Source:        "test-zeek",
		InputDir:      filepath.Join("..", "..", "..", "testdata", "zeek"),
		Entities:      map[string]*EntityStat{},
		Relationships: map[string]*Relationship{},
		Bindings:      map[string]*Binding{},
		Services:      map[string]*ServiceStat{},
	}
	if scoped {
		nets, cidrs, err := parseNetworkCIDRs("192.168.1.0/24")
		if err != nil {
			t.Fatal(err)
		}
		st.Network = NetworkContext{ID: "network:lab-lan", CIDRs: cidrs, ObservationPoint: st.Source}
		st.NetworkNets = nets
	}
	return st
}

func TestSampleEventization(t *testing.T) {
	st := sampleState(t, true)
	if err := processLogs(st); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	sortEvents(st.Events)

	if len(st.Events) != 17 {
		t.Fatalf("events=%d want 17", len(st.Events))
	}
	if len(st.Relationships) != 3 {
		t.Fatalf("relationships=%d want 3", len(st.Relationships))
	}
	if len(st.Sessions) != 3 {
		t.Fatalf("sessions=%d want 3", len(st.Sessions))
	}
	if _, ok := st.Entities["domain:example.com"]; !ok {
		t.Fatal("domain entity not projected")
	}
	if _, ok := st.Entities["endpoint:ip:203.0.113.10:443/tcp"]; !ok {
		t.Fatal("transport endpoint entity not projected")
	}
	if _, ok := st.Entities["service:net:tls:ip:203.0.113.10:443/tcp"]; !ok {
		t.Fatal("TLS service entity not projected from application evidence")
	}

	foundDNS := false
	foundRelationship := false
	foundScopedPresence := false
	foundTLS := false
	position := map[string]int{}
	for i, e := range st.Events {
		position[e.ID] = i
		if e.XQVersion != "0.1" {
			t.Fatalf("bad xq version: %s", e.XQVersion)
		}
		if e.Modality != modality || e.Profile != profile {
			t.Fatalf("bad network profile claim: modality=%s profile=%s", e.Modality, e.Profile)
		}
		if !strings.Contains(e.Modality, ":") || !strings.Contains(e.Feature, ":") || !strings.Contains(e.Action, ":") {
			t.Fatalf("unqualified semantic identifier in %+v", e)
		}
		if e.Action == "xq:enter" || e.Action == "xq:leave" {
			t.Fatalf("prototype must not infer entry/leave from capture boundaries")
		}
		if e.Feature == namespace+":address_binding" && e.Action == namespace+":first_observed" && strings.HasPrefix(e.Subject, "interface:mac:") && e.Class != "derived" {
			t.Fatalf("ARP first_observed binding must be derived, got class=%s", e.Class)
		}
		if e.Feature == namespace+":dns_query" && e.Object == "domain:example.com" {
			foundDNS = true
		}
		if e.Feature == namespace+":communication_relationship" && e.Object == "endpoint:ip:203.0.113.10:443/tcp" {
			foundRelationship = true
			if e.Action != namespace+":first_observed" {
				t.Fatalf("relationship action=%s want first_observed", e.Action)
			}
		}
		if e.Feature == namespace+":tls_session" {
			foundTLS = true
			if e.Object != "endpoint:ip:203.0.113.10:443/tcp" {
				t.Fatalf("TLS must target transport endpoint, got %s", e.Object)
			}
		}
		if e.Feature == corePresence {
			foundScopedPresence = true
			if e.Object != "network:lab-lan" {
				t.Fatalf("presence scope object=%s", e.Object)
			}
		}
	}
	if !foundDNS {
		t.Fatal("missing DNS semantic event")
	}
	if !foundRelationship {
		t.Fatal("missing derived HTTPS relationship")
	}
	if !foundTLS {
		t.Fatal("missing TLS endpoint event")
	}
	if !foundScopedPresence {
		t.Fatal("missing scoped presence event")
	}
	if e := st.Entities["address:ip:192.168.1.10"]; e == nil || e.PresenceEligible {
		t.Fatal("DHCP-resolved IP address should not duplicate presence projected on interface entity")
	}
	if _, ok := st.Bindings["endpoint:ip:203.0.113.10:443/tcp\x00domain:example.com\x00tls_server_name_binding"]; !ok {
		t.Fatal("missing endpoint-to-SNI binding")
	}
	for i, e := range st.Events {
		if e.Provenance == nil {
			continue
		}
		for _, parent := range e.Provenance.Parents {
			if p, ok := position[parent]; ok && p > i {
				t.Fatalf("child %s emitted before same-stream parent %s", e.ID, parent)
			}
		}
	}
}

func TestNoImplicitPresenceWithoutNetworkScope(t *testing.T) {
	st := sampleState(t, false)
	if err := processLogs(st); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	for _, e := range st.Events {
		if e.Feature == corePresence {
			t.Fatalf("unexpected unscoped presence event: %+v", e)
		}
	}
}

func TestConnectionSummaryUsesEndTime(t *testing.T) {
	st := sampleState(t, true)
	path := filepath.Join(t.TempDir(), "conn.log")
	record := `{"ts":1788606000.125,"duration":2.5,"uid":"timing","id.orig_h":"192.168.1.10","id.orig_p":50000,"id.resp_h":"203.0.113.8","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","orig_pkts":5,"resp_pkts":6,"orig_bytes":500,"resp_bytes":600}`
	if err := os.WriteFile(path, []byte(record+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := processConn(st, path); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	start := time.Unix(1788606000, 125000000).UTC()
	end := start.Add(2500 * time.Millisecond)
	connection := st.Events[0]
	for _, event := range st.Events {
		if event.EventTime != formatTime(end) {
			t.Fatalf("%s backdates whole-connection evidence: %s, want %s", event.Feature, event.EventTime, formatTime(end))
		}
	}
	if connection.Context["source_interval_start"] != formatTime(start) || connection.Context["source_interval_end"] != formatTime(end) {
		t.Fatalf("source interval missing: %+v", connection.Context)
	}
	if len(st.Sessions) != 1 || !st.Sessions[0].Start.Equal(start) || !st.Sessions[0].End.Equal(end) || st.Sessions[0].EventID != connection.ID {
		t.Fatalf("session interval or provenance changed: %+v", st.Sessions)
	}
	for _, service := range st.Services {
		if !service.First.Equal(end) {
			t.Fatalf("service evidence backdated: %+v", service)
		}
	}
	for _, entity := range st.Entities {
		if !entity.First.Equal(end) {
			t.Fatalf("entity evidence backdated: %+v", entity)
		}
	}
}

func TestConnectionDurationValidation(t *testing.T) {
	for _, tc := range []struct {
		name, duration string
		valid          bool
	}{
		{"missing", "", false},
		{"null", `,"duration":null`, false},
		{"negative", `,"duration":-1`, false},
		{"invalid", `,"duration":"unknown"`, false},
		{"nan", `,"duration":"NaN"`, false},
		{"infinite", `,"duration":"Inf"`, false},
		{"overflow", `,"duration":1e20`, false},
		{"zero", `,"duration":0`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "conn.log")
			record := `{"ts":1788606000,"uid":"duration","id.orig_h":"192.168.1.10","id.resp_h":"203.0.113.8","id.resp_p":443,"proto":"tcp","conn_state":"S0"` + tc.duration + "}\n"
			if err := os.WriteFile(path, []byte(record), 0o644); err != nil {
				t.Fatal(err)
			}
			st := sampleState(t, false)
			err := processConn(st, path)
			if tc.valid {
				if err != nil || len(st.Events) != 1 || !st.Sessions[0].Start.Equal(st.Sessions[0].End) {
					t.Fatalf("zero-duration connection rejected or altered: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "line 1") || !strings.Contains(err.Error(), "duration") || len(st.Events) != 0 {
				t.Fatalf("expected clear rejection without events, got %v, %+v", err, st.Events)
			}
		})
	}
}

func TestRelationshipUsesEarliestCompletedConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn.log")
	var records []string
	for i, pair := range [][2]int{{0, 10}, {1, 1}} {
		records = append(records, fmt.Sprintf(`{"ts":%d,"duration":%d,"uid":"c%d","id.orig_h":"192.168.1.10","id.resp_h":"203.0.113.8","id.resp_p":443,"proto":"tcp","conn_state":"SF","orig_pkts":2,"resp_pkts":2}`, 1788606000+pair[0], pair[1], i))
	}
	if err := os.WriteFile(path, []byte(strings.Join(records, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	if err := processConn(st, path); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	relationship := st.Events[len(st.Events)-1]
	if relationship.EventTime != formatTime(time.Unix(1788606002, 0)) || relationship.Provenance.Parents[0] != st.Events[1].ID {
		t.Fatalf("relationship uses first-starting rather than first-completed evidence: %+v", relationship)
	}
}

func TestDNSAliasAndAddressBindings(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606002.01,"uid":"CDNS1","id.orig_h":"192.168.1.10","id.resp_h":"192.168.1.1","query":"www.example.test","qtype_name":"A","rcode_name":"NOERROR","answers":["edge.example.test","203.0.113.9"]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "dns.log"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := &AppState{
		Source:        "test-zeek",
		InputDir:      dir,
		Entities:      map[string]*EntityStat{},
		Relationships: map[string]*Relationship{},
		Bindings:      map[string]*Binding{},
		Services:      map[string]*ServiceStat{},
	}
	if err := processDNS(st, filepath.Join(dir, "dns.log")); err != nil {
		t.Fatal(err)
	}
	seenAlias, seenAddress := false, false
	for _, b := range st.Bindings {
		switch b.Kind {
		case "dns_alias":
			seenAlias = true
		case "dns_address_binding":
			seenAddress = true
		}
	}
	if !seenAlias || !seenAddress {
		t.Fatalf("bindings missing: alias=%v address=%v", seenAlias, seenAddress)
	}
	for _, e := range st.Events {
		if e.Object == "domain:edge.example.test" && (e.Feature != namespace+":name_alias" || e.Action != namespace+":alias_of") {
			t.Fatalf("bad alias semantics: %+v", e)
		}
	}
}

func TestConnectionEndpointDoesNotImplyService(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606002.01,"duration":0,"uid":"CS0","id.orig_h":"192.168.1.10","id.orig_p":50000,"id.resp_h":"192.168.1.106","id.resp_p":3283,"proto":"tcp","conn_state":"S0","orig_pkts":1,"resp_pkts":0}` + "\n"
	path := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processConn(st, path); err != nil {
		t.Fatal(err)
	}
	ep := "endpoint:ip:192.168.1.106:3283/tcp"
	if _, ok := st.Entities[ep]; !ok {
		t.Fatal("referenced endpoint must exist in entities projection")
	}
	if len(st.Services) != 0 {
		t.Fatalf("S0 connection without application evidence created %d services", len(st.Services))
	}
	if len(st.Relationships) != 0 {
		t.Fatalf("S0 connection should not establish observed communication relationship")
	}
	if len(st.Sessions) != 1 || st.Sessions[0].Object != ep {
		t.Fatalf("session endpoint wrong: %+v", st.Sessions)
	}
}

func TestICMPDoesNotCreatePseudoService(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606002.01,"duration":0,"uid":"CICMP","id.orig_h":"192.168.1.10","id.resp_h":"10.0.1.255","id.resp_p":0,"proto":"icmp","conn_state":"OTH","orig_pkts":1,"resp_pkts":0}` + "\n"
	path := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processConn(st, path); err != nil {
		t.Fatal(err)
	}
	ep := "endpoint:ip:10.0.1.255/icmp"
	if _, ok := st.Entities[ep]; !ok {
		t.Fatalf("ICMP target should be endpoint entity %s", ep)
	}
	if len(st.Services) != 0 {
		t.Fatalf("ICMP traffic created pseudo-service: %+v", st.Services)
	}
}

func TestTLSEndpointAndServerNameBinding(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606003.1,"uid":"CTLS","id.orig_h":"192.168.1.10","id.resp_h":"203.0.113.5","id.resp_p":443,"version":"TLSv13","server_name":"example.test","established":true}` + "\n"
	path := filepath.Join(dir, "ssl.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processSSL(st, path); err != nil {
		t.Fatal(err)
	}
	ep := "endpoint:ip:203.0.113.5:443/tcp"
	if len(st.Events) != 1 || st.Events[0].Object != ep {
		t.Fatalf("TLS event must target endpoint: %+v", st.Events)
	}
	if _, ok := st.Services["service:net:tls:ip:203.0.113.5:443/tcp"]; !ok {
		t.Fatal("TLS parsing should provide TLS service evidence")
	}
	key := ep + "\x00domain:example.test\x00tls_server_name_binding"
	if _, ok := st.Bindings[key]; !ok {
		t.Fatal("missing TLS endpoint/server-name binding")
	}
}

func TestSortEventsUsesChronologicalTime(t *testing.T) {
	events := []CoreEvent{
		{ID: "later", EventTime: "2008-07-22T04:36:09.005318Z", Class: "normalized_observation"},
		{ID: "earlier", EventTime: "2008-07-22T04:36:09.00531Z", Class: "normalized_observation"},
	}
	sortEvents(events)
	if events[0].ID != "earlier" || events[1].ID != "later" {
		t.Fatalf("chronological ordering failed: %+v", events)
	}
}

func TestFixedNanosecondFormatting(t *testing.T) {
	ts := time.Date(2008, 7, 22, 4, 36, 9, 5_310_000, time.UTC)
	if got := formatTime(ts); got != "2008-07-22T04:36:09.005310000Z" {
		t.Fatalf("fixed timestamp=%s", got)
	}
}

func TestZeekTimestampPrecision(t *testing.T) {
	rec := map[string]any{"ts": json.Number("1788606002.01")}
	ts, err := zeekTime(rec)
	if err != nil {
		t.Fatal(err)
	}
	if got := ts.Format("2006-01-02T15:04:05.999999999Z07:00"); got != "2026-09-05T11:00:02.01Z" {
		t.Fatalf("timestamp=%s", got)
	}
}

func TestRelationshipFirstObservedIsTemporallyPure(t *testing.T) {
	st := sampleState(t, false)
	if err := processLogs(st); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)

	for _, e := range st.Events {
		if e.Feature != namespace+":communication_relationship" || e.Object != "endpoint:ip:203.0.113.10:443/tcp" {
			continue
		}
		if e.Subject != "address:ip:192.168.1.10" {
			t.Fatalf("normalized traffic must remain address-scoped, got %s", e.Subject)
		}
		for _, forbidden := range []string{"connections_observed", "first_seen", "last_seen", "originator_bytes", "responder_bytes"} {
			if _, ok := e.Context[forbidden]; ok {
				t.Fatalf("first_observed event contains future/aggregate field %q: %+v", forbidden, e.Context)
			}
		}
		if got := e.Context["evidence_directionality"]; got != "bidirectional_observed" {
			t.Fatalf("first-observation directionality=%v", got)
		}
		return
	}
	t.Fatal("missing HTTPS relationship event")
}

func TestUnidirectionalUDPRelationshipEvidence(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606002.01,"duration":0,"uid":"CUDP","id.orig_h":"192.168.1.10","id.orig_p":50000,"id.resp_h":"239.255.255.250","id.resp_p":1900,"proto":"udp","conn_state":"OTH","orig_pkts":3,"resp_pkts":0,"orig_bytes":300,"resp_bytes":0}` + "\n"
	path := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processConn(st, path); err != nil {
		t.Fatal(err)
	}
	if len(st.Relationships) != 1 {
		t.Fatalf("relationships=%d want 1", len(st.Relationships))
	}
	for _, r := range st.Relationships {
		if got := relationshipDirectionality(r); got != "unidirectional_observed" {
			t.Fatalf("directionality=%s", got)
		}
		if r.FirstDirectionality != "unidirectional_observed" {
			t.Fatalf("first directionality=%s", r.FirstDirectionality)
		}
	}
	deriveEvents(st)
	for _, e := range st.Events {
		if e.Feature == namespace+":communication_relationship" {
			if got := e.Context["evidence_directionality"]; got != "unidirectional_observed" {
				t.Fatalf("derived directionality=%v", got)
			}
			return
		}
	}
	t.Fatal("missing derived relationship")
}

func TestARPProducesTimeScopedInterfaceAddressBindingsWithoutIdentityCollapse(t *testing.T) {
	dir := t.TempDir()
	lines := strings.Join([]string{
		`{"ts":1788606001.0,"opcode":"request","mac_src":"00:11:22:33:44:55","mac_dst":"ff:ff:ff:ff:ff:ff","sender_ip":"192.168.1.64","sender_mac":"00:11:22:33:44:55","target_ip":"192.168.1.1","target_mac":"00:00:00:00:00:00"}`,
		`{"ts":1788606010.0,"opcode":"request","mac_src":"00:aa:bb:cc:dd:ee","mac_dst":"ff:ff:ff:ff:ff:ff","sender_ip":"192.168.1.64","sender_mac":"00:aa:bb:cc:dd:ee","target_ip":"192.168.1.1","target_mac":"00:00:00:00:00:00"}`,
	}, "\n") + "\n"
	path := filepath.Join(dir, "arp.log")
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, true)
	st.InputDir = dir
	if err := processARP(st, path); err != nil {
		t.Fatal(err)
	}
	if len(st.Events) != 2 || len(st.Bindings) != 2 {
		t.Fatalf("events=%d bindings=%d want 2/2", len(st.Events), len(st.Bindings))
	}
	for _, dev := range []string{"interface:mac:00:11:22:33:44:55", "interface:mac:00:aa:bb:cc:dd:ee"} {
		e := st.Entities[dev]
		if e == nil || !e.PresenceEligible {
			t.Fatalf("ARP interface missing/scoped presence not recorded: %s %+v", dev, e)
		}
	}
	if got := entityForIP(st, "192.168.1.64"); got != "address:ip:192.168.1.64" {
		t.Fatalf("ARP must not collapse ambiguous address to interface, got %s", got)
	}
	if e := st.Entities["address:ip:192.168.1.64"]; e == nil || e.PresenceEligible {
		t.Fatalf("ARP presence should be projected on observed interface, not duplicated address: %+v", e)
	}
}

func TestApplicationServiceStackIsNotCompositeService(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606002.01,"duration":0,"uid":"CXMPP","id.orig_h":"192.168.1.10","id.orig_p":50000,"id.resp_h":"203.0.113.5","id.resp_p":5222,"proto":"tcp","service":"xmpp,ssl","conn_state":"SF","orig_pkts":5,"resp_pkts":6,"orig_bytes":500,"resp_bytes":600}` + "\n"
	path := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processConn(st, path); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"service:net:xmpp:ip:203.0.113.5:5222/tcp",
		"service:net:tls:ip:203.0.113.5:5222/tcp",
	} {
		if _, ok := st.Services[want]; !ok {
			t.Fatalf("missing stack component service %s", want)
		}
	}
	if _, bad := st.Services["service:net:xmpp_ssl:ip:203.0.113.5:5222/tcp"]; bad {
		t.Fatal("application stack was incorrectly materialized as one composite service")
	}
	for _, r := range st.Relationships {
		if r.AppStack != "xmpp,tls" {
			t.Fatalf("application stack=%q want xmpp,tls", r.AppStack)
		}
	}
}

func TestPresenceUsesFirstInScopeEvidenceNotEntityFirstSeen(t *testing.T) {
	dir := t.TempDir()
	lines := strings.Join([]string{
		`{"ts":1788606001.0,"opcode":"request","mac_src":"02:00:00:00:00:01","mac_dst":"ff:ff:ff:ff:ff:ff","sender_ip":"169.254.0.10","sender_mac":"02:00:00:00:00:01","target_ip":"169.254.0.1","target_mac":"00:00:00:00:00:00"}`,
		`{"ts":1788606010.0,"opcode":"request","mac_src":"02:00:00:00:00:01","mac_dst":"ff:ff:ff:ff:ff:ff","sender_ip":"192.168.1.64","sender_mac":"02:00:00:00:00:01","target_ip":"192.168.1.1","target_mac":"00:00:00:00:00:00"}`,
	}, "\n") + "\n"
	path := filepath.Join(dir, "arp.log")
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, true)
	st.InputDir = dir
	if err := processARP(st, path); err != nil {
		t.Fatal(err)
	}
	iface := st.Entities["interface:mac:02:00:00:00:00:01"]
	if iface == nil {
		t.Fatal("interface missing")
	}
	if !iface.First.Before(iface.PresenceFirst) {
		t.Fatalf("expected entity first %s before in-scope presence first %s", iface.First, iface.PresenceFirst)
	}
	wantPresence := time.Unix(1788606010, 0).UTC()
	if !iface.PresenceFirst.Equal(wantPresence) {
		t.Fatalf("presence first=%s want %s", iface.PresenceFirst, wantPresence)
	}
	deriveEvents(st)
	for _, e := range st.Events {
		if e.Feature == corePresence && e.Subject == iface.Entity {
			if e.EventTime != formatTime(wantPresence) {
				t.Fatalf("presence event time=%s want %s", e.EventTime, formatTime(wantPresence))
			}
			return
		}
	}
	t.Fatal("missing interface presence event")
}

func TestARPRepeatedEvidenceCoalescesSemanticEvent(t *testing.T) {
	dir := t.TempDir()
	lines := strings.Join([]string{
		`{"ts":1788606001.0,"opcode":"request","mac_src":"00:11:22:33:44:55","mac_dst":"ff:ff:ff:ff:ff:ff","sender_ip":"192.168.1.64","sender_mac":"00:11:22:33:44:55","target_ip":"192.168.1.1","target_mac":"00:00:00:00:00:00"}`,
		`{"ts":1788606002.0,"opcode":"request","mac_src":"00:11:22:33:44:55","mac_dst":"ff:ff:ff:ff:ff:ff","sender_ip":"192.168.1.64","sender_mac":"00:11:22:33:44:55","target_ip":"192.168.1.1","target_mac":"00:00:00:00:00:00"}`,
		`{"ts":1788606003.0,"opcode":"reply","mac_src":"00:11:22:33:44:55","mac_dst":"00:aa:bb:cc:dd:ee","sender_ip":"192.168.1.64","sender_mac":"00:11:22:33:44:55","target_ip":"192.168.1.1","target_mac":"00:aa:bb:cc:dd:ee"}`,
	}, "\n") + "\n"
	path := filepath.Join(dir, "arp.log")
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processARP(st, path); err != nil {
		t.Fatal(err)
	}

	key := bindingKey("interface:mac:00:11:22:33:44:55", "address:ip:192.168.1.64", "arp_address_binding")
	b := st.Bindings[key]
	if b == nil {
		t.Fatal("missing repeated ARP binding")
	}
	if b.Count != 3 {
		t.Fatalf("binding observations=%d want 3", b.Count)
	}
	if b.ParentEventCount != 1 || len(b.ParentIDs) != 1 {
		t.Fatalf("semantic parents=%d retained=%d want 1/1", b.ParentEventCount, len(b.ParentIDs))
	}

	count := 0
	for _, e := range st.Events {
		if e.Subject == b.Subject && e.Object == b.Object && e.Feature == namespace+":address_binding" {
			count++
			if e.Action != namespace+":first_observed" {
				t.Fatalf("ARP action=%s want first_observed", e.Action)
			}
		}
	}
	if count != 1 {
		t.Fatalf("semantic ARP events=%d want 1", count)
	}
}

func TestApplicationStackCanonicalizationAcrossObservations(t *testing.T) {
	if got := mergeCommaSet("tls", "xmpp,tls"); got != "xmpp,tls" {
		t.Fatalf("merge stack=%q want xmpp,tls", got)
	}
	if got := mergeCommaSet("xmpp,tls", "tls"); got != "xmpp,tls" {
		t.Fatalf("reverse merge stack=%q want xmpp,tls", got)
	}
}

func TestProjectionProvenanceTruncationIsExplicit(t *testing.T) {
	st := sampleState(t, false)
	ts := time.Unix(1788606001, 0).UTC()
	for i := 0; i < maxProjectionParentEvents+5; i++ {
		touchBinding(st, "domain:example.test", "address:ip:203.0.113.9", "dns_address_binding", ts.Add(time.Duration(i)*time.Second), fmt.Sprintf("evt:%03d", i))
		touchService(st, "endpoint:ip:203.0.113.9:443/tcp", "address:ip:203.0.113.9", "203.0.113.9", "443", "tcp", "tls", ts.Add(time.Duration(i)*time.Second), "test", fmt.Sprintf("svc:%03d", i))
	}

	out := t.TempDir()
	if err := writeBindings(filepath.Join(out, "bindings.csv"), st.Bindings); err != nil {
		t.Fatal(err)
	}
	if err := writeServices(filepath.Join(out, "services.csv"), st.Services); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"bindings.csv", "services.csv"} {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		if !strings.Contains(s, "parent_event_count") || !strings.Contains(s, "parent_events_truncated") {
			t.Fatalf("%s missing explicit provenance columns: %s", name, s)
		}
		if !strings.Contains(s, ",true,") {
			t.Fatalf("%s did not mark capped provenance as truncated: %s", name, s)
		}
	}
}

func TestPublishedNetworkProfileConformanceOnSample(t *testing.T) {
	st := sampleState(t, true)
	if err := processLogs(st); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	sortEvents(st.Events)
	if err := validateGeneratedProfileEvents(st.Events); err != nil {
		t.Fatalf("sample failed published profile self-validation: %v", err)
	}
	for _, e := range st.Events {
		if e.Profile != "xq.net:profile-0.1" || e.Modality != "xq:network" {
			t.Fatalf("wrong published profile claim: %+v", e)
		}
		if strings.HasPrefix(e.Subject, "device:mac:") || strings.HasPrefix(e.Object, "device:mac:") {
			t.Fatalf("MAC was promoted to device: %+v", e)
		}
		if e.Action == "xq.net:observed" {
			t.Fatalf("network-local observed must not be emitted: %+v", e)
		}
	}
	if _, ok := st.Entities["network:lab-lan"]; !ok {
		t.Fatal("explicit network scope should be materialized as a network entity once in-scope evidence exists")
	}
}

func TestDNSQueryExcludesResponseOnlyFacts(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606002.01,"rtt":0.125,"uid":"CDNS2","id.orig_h":"192.168.1.10","id.orig_p":53000,"id.resp_h":"192.168.1.1","id.resp_p":53,"proto":"udp","query":"example.test","qtype_name":"A","rcode_name":"NOERROR","rejected":false,"answers":["203.0.113.9"]}` + "\n"
	path := filepath.Join(dir, "dns.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processDNS(st, path); err != nil {
		t.Fatal(err)
	}
	var query, answer *CoreEvent
	for i := range st.Events {
		e := &st.Events[i]
		switch e.Feature {
		case namespace + ":dns_query":
			query = e
		case namespace + ":name_resolution":
			answer = e
		}
	}
	if query == nil || answer == nil {
		t.Fatalf("expected query and answer events: %+v", st.Events)
	}
	for _, forbidden := range []string{"response_code", "rejected", "answers", "answer_count"} {
		if _, ok := query.Context[forbidden]; ok {
			t.Fatalf("query leaked response-only field %s: %+v", forbidden, query.Context)
		}
	}
	if answer.Context["response_code"] != "NOERROR" {
		t.Fatalf("response fact should remain on answer evidence: %+v", answer.Context)
	}
	qt, _ := time.Parse(time.RFC3339Nano, query.EventTime)
	at, _ := time.Parse(time.RFC3339Nano, answer.EventTime)
	if !at.After(qt) || at.Sub(qt) != 125*time.Millisecond {
		t.Fatalf("answer event time=%s query=%s want +125ms", answer.EventTime, query.EventTime)
	}
}

func TestDNSResponseOnlyDoesNotInventQuery(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1216695929.885422,"uid":"CRESPONLY","id.orig_h":"192.168.15.2","id.orig_p":32035,"id.resp_h":"192.168.15.1","id.resp_p":53,"proto":"udp","query":"time.apple.com","rcode_name":"NOERROR","rejected":false,"answers":["192.168.15.1"]}` + "\n"
	path := filepath.Join(dir, "dns.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processDNS(st, path); err != nil {
		t.Fatal(err)
	}
	if len(st.Events) != 1 {
		t.Fatalf("events=%d want one response-derived answer event: %+v", len(st.Events), st.Events)
	}
	e := st.Events[0]
	if e.Feature == namespace+":dns_query" {
		t.Fatalf("response-only Zeek record invented query event: %+v", e)
	}
	if e.Feature != namespace+":name_resolution" || e.Subject != "domain:time.apple.com" || e.Object != "address:ip:192.168.15.1" {
		t.Fatalf("unexpected response-only mapping: %+v", e)
	}
	if e.EventTime != "2008-07-22T03:05:29.885422000Z" {
		t.Fatalf("response-only answer time=%s want source response time", e.EventTime)
	}
	if got, ok := e.Context["query_observed"].(bool); !ok || got {
		t.Fatalf("response-only answer should declare query_observed=false: %+v", e.Context)
	}
	if _, ok := st.Entities["domain:time.apple.com"]; !ok {
		t.Fatal("response-only answer must materialize its domain subject")
	}
	if _, ok := st.Entities["address:ip:192.168.15.2"]; !ok {
		t.Fatal("response-only evidence should retain observed client address entity")
	}
	if _, ok := st.Bindings["domain:time.apple.com\x00address:ip:192.168.15.1\x00dns_address_binding"]; !ok {
		t.Fatal("response-only answer must retain DNS binding projection")
	}
}

func TestDNSQueryOnlyStillEmitsQueryWithoutRTT(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":1788606002.01,"uid":"CQUERYONLY","id.orig_h":"192.168.1.10","id.orig_p":53000,"id.resp_h":"192.168.1.1","id.resp_p":53,"proto":"udp","query":"example.test","qtype_name":"A"}` + "\n"
	path := filepath.Join(dir, "dns.log")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	if err := processDNS(st, path); err != nil {
		t.Fatal(err)
	}
	if len(st.Events) != 1 || st.Events[0].Feature != namespace+":dns_query" {
		t.Fatalf("query-only record should remain a query observation: %+v", st.Events)
	}
}

func TestSelfValidatorRejectsPublishedNegativeFixtureClasses(t *testing.T) {
	base := CoreEvent{
		XQVersion: "0.1", ID: "evt:test", EventTime: "2026-09-06T08:00:00.000000000Z",
		Source: "sensor-01", Modality: modality, Profile: profile, Class: "normalized_observation",
		Subject: "address:ip:192.0.2.10", Object: "endpoint:ip:198.51.100.8:443/tcp",
		Feature: namespace + ":connection", Action: coreObserved, Polarity: 0,
		Provenance: &Provenance{Producer: "test", ProducerVersion: "1", Method: "algorithmic", SourceRecords: []string{"src:1"}, Parameters: map[string]any{"mapping": "test"}},
		Context:    map[string]any{"observation_point": "sensor-01", "protocol": "tcp"},
	}
	if err := validateGeneratedProfileEvents([]CoreEvent{base}); err != nil {
		t.Fatalf("valid base rejected: %v", err)
	}

	badObserved := base
	badObserved.ID = "evt:bad-observed"
	badObserved.Action = namespace + ":observed"
	if err := validateGeneratedProfileEvents([]CoreEvent{badObserved}); err == nil {
		t.Fatal("validator accepted network-local observed action")
	}

	badMAC := base
	badMAC.ID = "evt:bad-mac"
	badMAC.Subject = "device:mac:00:11:22:33:44:55"
	if err := validateGeneratedProfileEvents([]CoreEvent{badMAC}); err == nil {
		t.Fatal("validator accepted MAC promoted to device")
	}

	badDNS := base
	badDNS.ID = "evt:bad-dns"
	badDNS.Object = "domain:example.test"
	badDNS.Feature = namespace + ":dns_query"
	badDNS.Action = namespace + ":queried"
	badDNS.Context = map[string]any{"observation_point": "sensor-01", "query_type": "A", "response_code": "NOERROR"}
	if err := validateGeneratedProfileEvents([]CoreEvent{badDNS}); err == nil {
		t.Fatal("validator accepted response code on point DNS query")
	}
}

func TestCommunityIDPropagationAndRelationshipAggregation(t *testing.T) {
	dir := t.TempDir()
	lines := strings.Join([]string{
		`{"ts":1788606002.01,"duration":0,"uid":"CCID1","community_id":"1:firstCommunityId=","id.orig_h":"192.168.1.10","id.orig_p":50000,"id.resp_h":"203.0.113.5","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","orig_pkts":5,"resp_pkts":6,"orig_bytes":500,"resp_bytes":600}`,
		`{"ts":1788606003.01,"duration":0,"uid":"CCID2","community_id":"1:secondCommunityId=","id.orig_h":"192.168.1.10","id.orig_p":50001,"id.resp_h":"203.0.113.5","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","orig_pkts":7,"resp_pkts":8,"orig_bytes":700,"resp_bytes":800}`,
	}, "\n") + "\n"
	path := filepath.Join(dir, "conn.log")
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processConn(st, path); err != nil {
		t.Fatal(err)
	}
	if len(st.Sessions) != 2 {
		t.Fatalf("sessions=%d want 2", len(st.Sessions))
	}
	if st.Sessions[0].CommunityID != "1:firstCommunityId=" || st.Sessions[1].CommunityID != "1:secondCommunityId=" {
		t.Fatalf("session Community IDs not propagated: %+v", st.Sessions)
	}
	for _, e := range st.Events {
		if e.Feature == namespace+":connection" {
			if got := valueString(e.Context["community_id"]); got == "" {
				t.Fatalf("connection event missing Community ID: %+v", e)
			}
		}
	}
	if len(st.Relationships) != 1 {
		t.Fatalf("relationships=%d want 1", len(st.Relationships))
	}
	var r *Relationship
	for _, rel := range st.Relationships {
		r = rel
	}
	if r.FirstCommunityID != "1:firstCommunityId=" {
		t.Fatalf("first Community ID=%q", r.FirstCommunityID)
	}
	if r.CommunityIDCount != 2 || len(r.CommunityIDs) != 2 {
		t.Fatalf("relationship Community IDs count=%d retained=%d", r.CommunityIDCount, len(r.CommunityIDs))
	}
	deriveEvents(st)
	for _, e := range st.Events {
		if e.Feature == namespace+":communication_relationship" {
			if got := valueString(e.Context["community_id"]); got != "1:firstCommunityId=" {
				t.Fatalf("first-observed relationship Community ID=%q", got)
			}
			return
		}
	}
	t.Fatal("missing derived relationship event")
}

func TestCommunityIDPolicyUsesSeedZeroForSuricataParity(t *testing.T) {
	if !strings.Contains(crosscueCommunityIDScript, "policy/protocols/conn/community-id-logging") {
		t.Fatal("PCAP runner Community ID script does not load Zeek policy")
	}
	if !strings.Contains(crosscueCommunityIDScript, "CommunityID::seed = 0") {
		t.Fatal("Community ID seed must be explicitly zero for default Suricata parity")
	}
}

func TestDuplicateEventSeedGetsUniqueDeterministicID(t *testing.T) {
	st := sampleState(t, false)
	ts := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	args := func(s *AppState) (CoreEvent, CoreEvent) {
		first := newEvent(s, ts, "normalized_observation", "domain:example.test", "address:ip:203.0.113.8", namespace+":name_resolution", namespace+":resolved_to", "", 0, nil, "zeek:dns.log:line:1:uid:test", "zeek-dns-address-answer-normalize")
		second := newEvent(s, ts, "normalized_observation", "domain:example.test", "address:ip:203.0.113.8", namespace+":name_resolution", namespace+":resolved_to", "", 0, nil, "zeek:dns.log:line:1:uid:test", "zeek-dns-address-answer-normalize")
		return first, second
	}
	first, second := args(st)
	if first.ID == second.ID {
		t.Fatalf("duplicate seed produced duplicate event id %q", first.ID)
	}
	seed := strings.Join([]string{st.Source, formatTime(ts), "normalized_observation", "domain:example.test", "address:ip:203.0.113.8", namespace + ":name_resolution", namespace + ":resolved_to", "zeek:dns.log:line:1:uid:test"}, "|")
	if first.ID != eventID(seed) {
		t.Fatalf("first occurrence changed existing deterministic id: got %q want %q", first.ID, eventID(seed))
	}
	if got := second.Provenance.Parameters["event_id_occurrence"]; got != 2 {
		t.Fatalf("second occurrence provenance = %#v, want 2", got)
	}
	fresh := sampleState(t, false)
	first2, second2 := args(fresh)
	if first.ID != first2.ID || second.ID != second2.ID {
		t.Fatalf("collision allocation is not deterministic: (%q,%q) vs (%q,%q)", first.ID, second.ID, first2.ID, second2.ID)
	}
}

func TestDuplicateDNSAnswersDoNotCollide(t *testing.T) {
	d := t.TempDir()
	line := `{"ts":1789291200.0,"uid":"dns-dup","id.orig_h":"192.0.2.10","id.orig_p":53000,"id.resp_h":"192.0.2.53","id.resp_p":53,"proto":"udp","query":"example.test","qtype_name":"A","answers":["203.0.113.8","203.0.113.8"]}`
	if err := os.WriteFile(filepath.Join(d, "dns.log"), []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = d
	if err := processLogs(st); err != nil {
		t.Fatal(err)
	}
	deriveEvents(st)
	sortEvents(st.Events)
	if err := validateGeneratedProfileEvents(st.Events); err != nil {
		t.Fatalf("duplicate DNS answers should validate with unique event IDs: %v", err)
	}
	seen := map[string]bool{}
	resolutionCount := 0
	for _, e := range st.Events {
		if seen[e.ID] {
			t.Fatalf("duplicate event id remains: %s", e.ID)
		}
		seen[e.ID] = true
		if e.Feature == namespace+":name_resolution" {
			resolutionCount++
		}
	}
	if resolutionCount != 2 {
		t.Fatalf("name resolution events=%d, want 2", resolutionCount)
	}
}
