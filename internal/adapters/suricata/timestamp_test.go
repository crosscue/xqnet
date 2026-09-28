// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSupportedEVERecordsRejectInvalidTimestamps(t *testing.T) {
	for _, kind := range []string{"flow", "dns", "tls", "arp", "dhcp", "http", "http2", "ssh", "smtp", "imap", "ftp", "pgsql", "smb", "quic"} {
		for _, field := range []string{"", `,"timestamp":null`, `,"timestamp":"invalid"`, `,"timestamp":123`, `,"timestamp":"2026-09-06T10:00:00.1234567899Z"`, `,"timestamp":"2300-01-01T00:00:00Z"`} {
			t.Run(kind+"/"+field, func(t *testing.T) {
				path := writeEVE(t, `{"event_type":"stats"}`, fmt.Sprintf(`{"event_type":%q%s}`, kind, field))
				err := processEVE(testState(), path)
				if err == nil || !strings.Contains(err.Error(), "line 2: timestamp:") {
					t.Fatalf("expected timestamp error, got %v", err)
				}
			})
		}
	}
}

func TestEVETimestampLayoutsPreserveNanoseconds(t *testing.T) {
	for _, s := range []string{"2026-09-06T10:00:00.123456789Z", "2026-09-06T11:00:00.123456789+01:00", "2026-09-06T11:00:00.123456789+0100", "2026-09-06T10:00:00.123456789", "2026-09-06 11:00:00.123456789+0100"} {
		got, err := parseSourceTime(s)
		if err != nil || got.Format(time.RFC3339Nano) != "2026-09-06T10:00:00.123456789Z" {
			t.Errorf("parseSourceTime(%q) = %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"2026-09-06T10:00:00.1234567899+0000", "2026-09-06T10:00:00.1234567899", "2026-09-06 10:00:00.1234567899+0000", "2026-02-30T10:00:00Z", "2026-09-06T10:00:00+24:00"} {
		if _, err := parseSourceTime(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestEVEFlowRejectsInvalidIntervalTimestamps(t *testing.T) {
	for _, field := range []string{"start", "end"} {
		for _, value := range []string{`null`, `""`, `"invalid"`, `123`, `"2026-09-06T10:00:00.1234567899Z"`} {
			line := fmt.Sprintf(`{"timestamp":"2026-09-06T10:00:00Z","event_type":"flow","src_ip":"192.0.2.1","dest_ip":"203.0.113.8","proto":"TCP","flow":{%q:%s}}`, field, value)
			err := processEVE(testState(), writeEVE(t, line))
			if err == nil || !strings.Contains(err.Error(), "line 1: flow."+field+":") {
				t.Errorf("%s=%s: expected interval timestamp error, got %v", field, value, err)
			}
		}
	}
}

func TestEVEFlowMissingIntervalsRetainRecordTimeFallback(t *testing.T) {
	st := testState()
	line := `{"timestamp":"1969-12-31T23:59:59.999999999Z","event_type":"flow","flow_id":1,"src_ip":"192.0.2.1","dest_ip":"203.0.113.8","dest_port":443,"proto":"TCP","flow":{}}`
	if err := processEVE(st, writeEVE(t, line)); err != nil {
		t.Fatal(err)
	}
	if len(st.Sessions) != 1 || st.Sessions[0].Start.UnixNano() != -1 || st.Sessions[0].End.UnixNano() != -1 {
		t.Fatalf("incorrect fallback interval: %+v", st.Sessions)
	}
}
