// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package zeek

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDurationAndRTTPreserveExactNanoseconds(t *testing.T) {
	for _, seconds := range []string{"0.000065", "6.5e-5"} {
		t.Run(seconds, func(t *testing.T) {
			dir := t.TempDir()
			conn := fmt.Sprintf(`{"ts":1788606000,"duration":%s,"uid":"exact","id.orig_h":"192.0.2.1","id.resp_h":"203.0.113.8","id.resp_p":443,"proto":"tcp","conn_state":"SF"}`, seconds)
			dns := fmt.Sprintf(`{"ts":1788606000,"rtt":%s,"uid":"dns","id.orig_h":"192.0.2.1","query":"example.com","qtype_name":"A","answers":["203.0.113.8"]}`, seconds)
			for name, line := range map[string]string{"conn.log": conn, "dns.log": dns} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(line+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			st := sampleState(t, false)
			st.InputDir = dir
			if err := processLogs(st); err != nil {
				t.Fatal(err)
			}
			deriveEvents(st)
			found := map[string]bool{}
			for _, e := range st.Events {
				if e.Feature == "xq.net:connection" || e.Feature == "xq.net:name_resolution" || e.Feature == "xq.net:communication_relationship" {
					found[e.Feature] = true
					if e.EventTime != "2026-09-05T11:00:00.000065000Z" {
						t.Fatalf("%s rounded to %s", e.Feature, e.EventTime)
					}
				}
			}
			if len(found) != 3 || st.Sessions[0].End.Sub(st.Sessions[0].Start).Nanoseconds() != 65000 {
				t.Fatalf("missing evidence or rounded session: %+v, %+v", found, st.Sessions)
			}
		})
	}
}

func TestInvalidRTTIsRejectedBeforeEvidence(t *testing.T) {
	for _, rtt := range []string{`-1`, `"NaN"`, `"Inf"`, `"invalid"`, `1e20`, `1e-10`} {
		path := filepath.Join(t.TempDir(), "dns.log")
		line := fmt.Sprintf(`{"ts":1788606000,"rtt":%s,"id.orig_h":"192.0.2.1","query":"example.com","qtype_name":"A","answers":["203.0.113.8"]}`, rtt)
		if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		st := sampleState(t, false)
		err := processDNS(st, path)
		if err == nil || !strings.Contains(err.Error(), "line 1: rtt:") || len(st.Events) != 0 {
			t.Fatalf("rtt=%s: expected rejection before events, got %v, %+v", rtt, err, st.Events)
		}
	}
}
