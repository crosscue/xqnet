// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crosscue/xqnet/internal/adapters/suricata"
	"github.com/crosscue/xqnet/internal/adapters/zeek"
	"github.com/crosscue/xqnet/internal/config"
)

func validEvent() Event {
	zero := 0
	return Event{XQVersion: config.WireVersion, ID: "event:1", EventTime: "2026-09-18T10:00:00.123456789Z", Source: "sensor", Modality: config.Modality, Profile: config.ProfileID, Class: "normalized_observation", Subject: "address:ip:192.0.2.1", Object: "endpoint:ip:192.0.2.2:443/tcp", Feature: "xq.net:connection", Action: "xq:observed", Polarity: &zero, Context: map[string]any{"observation_point": "sensor"}, Provenance: &Provenance{Producer: "xqnet", ProducerVersion: config.Version, Method: "algorithmic", SourceRecords: []string{"conn.log:1"}, Parameters: map[string]any{"mapping": "zeek-conn-normalize"}}}
}

func TestRejectIncompleteEvents(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Event)
	}{
		{"empty id", func(e *Event) { e.ID = " " }},
		{"empty source", func(e *Event) { e.Source = " " }},
		{"missing timestamp", func(e *Event) { e.EventTime = "" }},
		{"malformed timestamp", func(e *Event) { e.EventTime = "not-a-time" }},
		{"excess precision", func(e *Event) { e.EventTime = "2026-09-18T10:00:00.1234567891Z" }},
		{"bad end", func(e *Event) { e.EndTime = "invalid" }},
		{"reversed interval", func(e *Event) { e.EndTime = "2026-09-18T09:00:00Z" }},
		{"bad observed time", func(e *Event) { e.ObservedTime = "invalid" }},
		{"missing polarity", func(e *Event) { e.Polarity = nil }},
		{"missing subject", func(e *Event) { e.Subject = "" }},
		{"bare endpoint prefix", func(e *Event) { e.Object = "endpoint:" }},
		{"missing viewpoint key", func(e *Event) { e.Context = map[string]any{"protocol": "tcp"} }},
		{"null viewpoint", func(e *Event) { e.Context["observation_point"] = nil }},
		{"numeric viewpoint", func(e *Event) { e.Context["observation_point"] = 12 }},
		{"blank viewpoint", func(e *Event) { e.Context["observation_point"] = " " }},
		{"missing provenance", func(e *Event) { e.Provenance = nil }},
		{"blank producer", func(e *Event) { e.Provenance.Producer = " " }},
		{"missing mapping", func(e *Event) { e.Provenance.Parameters = nil }},
		{"blank source records", func(e *Event) { e.Provenance.SourceRecords = []string{" "} }},
		{"noncanonical stack", func(e *Event) { e.Context["application_stack"] = []any{"tls", "http"} }},
		{"nonstring stack", func(e *Event) { e.Context["application_stack"] = []any{1} }},
		{"bad confidence", func(e *Event) { v := 1.1; e.Confidence = &v }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			tc.edit(&e)
			if p := EventProblems(e, map[string]bool{}); len(p) == 0 {
				t.Fatal("invalid event accepted")
			}
		})
	}
}

func TestReferenceCompositions(t *testing.T) {
	for _, tc := range []struct {
		feature, class, action, subject, object string
		polarity                                int
	}{
		{"connection", "normalized_observation", "xq:observed", "address:ip:192.0.2.1", "endpoint:ip:192.0.2.2:443/tcp", 0},
		{"communication_relationship", "derived", "xq.net:first_observed", "address:ip:192.0.2.1", "endpoint:ip:192.0.2.2:443/tcp", 1},
		{"address_binding", "derived", "xq.net:first_observed", "interface:mac:aa:bb:cc:dd:ee:ff", "address:ip:192.0.2.1", 1},
		{"address_binding", "normalized_observation", "xq.net:assigned", "interface:mac:aa:bb:cc:dd:ee:ff", "address:ip:192.0.2.1", 1},
		{"hostname_binding", "normalized_observation", "xq.net:reported", "interface:mac:aa:bb:cc:dd:ee:ff", "name:host:lab", 0},
		{"dns_query", "normalized_observation", "xq.net:queried", "address:ip:192.0.2.1", "domain:example.test", 0},
		{"name_resolution", "normalized_observation", "xq.net:resolved_to", "domain:example.test", "address:ip:192.0.2.1", 0},
		{"name_alias", "normalized_observation", "xq.net:alias_of", "domain:www.example.test", "domain:example.test", 0},
		{"tls_session", "normalized_observation", "xq:observed", "address:ip:192.0.2.1", "endpoint:ip:192.0.2.2:443/tcp", 0},
		{"service", "normalized_observation", "xq:observed", "endpoint:ip:192.0.2.2:443/tcp", "service:net:tls:ip:192.0.2.2:443/tcp", 0},
		{"software", "normalized_observation", "xq:observed", "address:ip:192.0.2.1", "software:example", 0},
		{"presence", "derived", "xq.net:first_observed", "address:ip:192.0.2.1", "network:lab", 1},
	} {
		t.Run(tc.feature+"/"+tc.action, func(t *testing.T) {
			e := validEvent()
			e.Feature, e.Class, e.Action, e.Subject, e.Object, e.Polarity = "xq.net:"+tc.feature, tc.class, tc.action, tc.subject, tc.object, &tc.polarity
			e.Context["evidence_directionality"] = "bidirectional_observed"
			if tc.feature == "presence" {
				e.Feature, e.State = "xq:presence", "xq:present"
				e.Context["network_context"] = e.Object
			}
			if p := EventProblems(e, map[string]bool{}); len(p) != 0 {
				t.Fatalf("valid composition rejected: %v", p)
			}
			bad := e
			bad.Class = "invalid"
			if p := EventProblems(bad, map[string]bool{}); len(p) == 0 {
				t.Fatal("invalid class accepted")
			}
			bad = e
			wrong := 1 - tc.polarity
			bad.Polarity = &wrong
			if p := EventProblems(bad, map[string]bool{}); len(p) == 0 {
				t.Fatal("invalid polarity accepted")
			}
			bad = e
			bad.Action = "xq.net:invalid"
			if p := EventProblems(bad, map[string]bool{}); len(p) == 0 {
				t.Fatal("invalid action accepted")
			}
			if tc.class == "derived" {
				bad = e
				bad.Context = map[string]any{"observation_points": []any{"sensor", "sensor"}}
				if p := EventProblems(bad, map[string]bool{}); len(p) == 0 {
					t.Fatal("duplicate viewpoints accepted")
				}
				bad = e
				bad.Provenance = &Provenance{Producer: "x", ProducerVersion: "1", Method: "m", Parameters: map[string]any{"mapping": "m"}}
				if p := EventProblems(bad, map[string]bool{}); len(p) == 0 {
					t.Fatal("derived event without evidence accepted")
				}
			}
		})
	}
}

func TestEventsFileErrors(t *testing.T) {
	b, err := json.Marshal(validEvent())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, contents, want string }{
		{"duplicate", string(b) + "\n" + string(b) + "\n", "duplicate id"},
		{"malformed", "{\n", "invalid JSON"},
		{"missing polarity", strings.Replace(string(b), `"polarity":0,`, "", 1) + "\n", "missing polarity"},
		{"null polarity", strings.Replace(string(b), `"polarity":0`, `"polarity":null`, 1) + "\n", "missing polarity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.jsonl")
			if err := os.WriteFile(path, []byte(tc.contents), 0o644); err != nil {
				t.Fatal(err)
			}
			r, err := EventsFile(path)
			if err == nil || !strings.Contains(strings.Join(r.Errors, "\n"), tc.want) {
				t.Fatalf("wanted %s, got %+v, %v", tc.want, r, err)
			}
		})
	}
}

func TestGeneratedAdapterOutputsPassPublicValidator(t *testing.T) {
	for _, name := range []string{"zeek", "suricata"} {
		t.Run(name, func(t *testing.T) {
			out := t.TempDir()
			var err error
			if name == "zeek" {
				_, err = zeek.Run(zeek.Options{InputPath: filepath.Join("..", "..", "testdata", name), OutDir: out, Source: "test", NetworkID: "network:test", NetworkCIDRs: "192.168.1.0/24"})
			} else {
				_, err = suricata.Run(suricata.Options{InputPath: filepath.Join("..", "..", "testdata", name, "eve.json"), OutDir: out, Source: "test", NetworkID: "network:test", NetworkCIDRs: "192.168.1.0/24"})
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := EventsFile(filepath.Join(out, "events.ndjson"))
			if err != nil || r.Events == 0 {
				t.Fatalf("adapter output rejected: %+v, %v", r, err)
			}
		})
	}
}

func TestUnidentifiedApplicationRelationshipsPassPublicValidator(t *testing.T) {
	for _, name := range []string{"zeek", "suricata"} {
		t.Run(name, func(t *testing.T) {
			input, out := t.TempDir(), t.TempDir()
			var err error
			if name == "zeek" {
				line := `{"ts":1788606000,"duration":1,"uid":"plain","id.orig_h":"192.0.2.1","id.orig_p":50000,"id.resp_h":"203.0.113.8","id.resp_p":12345,"proto":"tcp","conn_state":"SF","orig_pkts":2,"resp_pkts":2}`
				if err := os.WriteFile(filepath.Join(input, "conn.log"), []byte(line+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				_, err = zeek.Run(zeek.Options{InputPath: input, OutDir: out, Source: "test"})
			} else {
				path := filepath.Join(input, "eve.json")
				line := `{"timestamp":"2026-09-06T10:00:01Z","event_type":"flow","flow_id":7,"src_ip":"192.0.2.1","src_port":50000,"dest_ip":"203.0.113.8","dest_port":12345,"proto":"TCP","flow":{"start":"2026-09-06T10:00:00Z","end":"2026-09-06T10:00:01Z","pkts_toserver":2,"pkts_toclient":2,"bytes_toserver":100,"bytes_toclient":100,"state":"closed"}}`
				if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				_, err = suricata.Run(suricata.Options{InputPath: path, OutDir: out, Source: "test"})
			}
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(out, "events.ndjson")
			r, err := EventsFile(path)
			if err != nil || r.Events != 2 {
				t.Fatalf("unidentified application rejected: %+v, %v", r, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var relationships int
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var e Event
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatal(err)
				}
				if e.Feature == "xq.net:communication_relationship" {
					relationships++
					stack, ok := e.Context["application_stack"].([]any)
					if !ok || len(stack) != 0 {
						t.Fatalf("expected empty application array, got %#v", e.Context["application_stack"])
					}
				}
			}
			if relationships != 1 {
				t.Fatalf("relationship was lost: %d", relationships)
			}
		})
	}
}
