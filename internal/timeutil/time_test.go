// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package timeutil

import "testing"

func TestNanosecondParsing(t *testing.T) {
	for _, s := range []string{"2026-09-18T10:00:00.123456789Z", "2026-09-18T11:00:00.123456789+01:00", "1969-12-31T23:59:59.999999999Z", "1970-01-01T00:00:00Z"} {
		tm, err := ParseNano(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if s[:4] == "2026" && tm.Nanosecond() != 123456789 {
			t.Fatal("nanoseconds lost")
		}
	}
	for _, s := range []string{"", "2026-09-18T10:00:00.1234567891Z", "2026-09-18T10:00:00+24:00", "2026-09-18T10:00:00,1Z", "1600-01-01T00:00:00Z", "2300-01-01T00:00:00Z", "2262-04-11T23:47:16.854775807Z"} {
		if _, err := ParseNano(s); err == nil {
			t.Fatalf("accepted invalid/unsupported timestamp %q", s)
		}
	}
}
