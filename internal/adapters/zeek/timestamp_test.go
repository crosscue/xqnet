// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package zeek

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllZeekLogsRejectInvalidTimestamps(t *testing.T) {
	for _, log := range []string{"arp.log", "dhcp.log", "conn.log", "dns.log", "ssl.log", "known_services.log", "software.log"} {
		for _, field := range []string{"", `"ts":null`, `"ts":"invalid"`, `"ts":true`, `"ts":1788606000.1234567899`, `"ts":9999999999999999999`} {
			t.Run(log+"/"+field, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, log), []byte("# source header\n{"+field+"}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				st := sampleState(t, false)
				st.InputDir = dir
				err := processLogs(st)
				if err == nil || !strings.Contains(err.Error(), log) || !strings.Contains(err.Error(), "line 2: ts:") {
					t.Fatalf("expected file/line timestamp error, got %v", err)
				}
			})
		}
	}
}

func TestNegativeFractionalTimestampEventization(t *testing.T) {
	dir := t.TempDir()
	line := `{"ts":-1.25,"duration":0,"uid":"negative","id.orig_h":"192.0.2.1","id.resp_h":"203.0.113.8","id.resp_p":443,"proto":"tcp","conn_state":"SF"}`
	if err := os.WriteFile(filepath.Join(dir, "conn.log"), []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := sampleState(t, false)
	st.InputDir = dir
	if err := processLogs(st); err != nil {
		t.Fatal(err)
	}
	if len(st.Events) != 1 || st.Events[0].EventTime != "1969-12-31T23:59:58.750000000Z" {
		t.Fatalf("incorrect negative timestamp: %+v", st.Events)
	}
	if got := st.Sessions[0].Start.UnixNano(); got != -1250000000 {
		t.Fatalf("session start=%d", got)
	}
}
