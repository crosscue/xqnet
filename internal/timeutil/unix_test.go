// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package timeutil

import (
	"testing"
	"time"
)

func TestParseUnixExactInstants(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"0", "1970-01-01T00:00:00Z"},
		{"0.000000001", "1970-01-01T00:00:00.000000001Z"},
		{"-0.000000001", "1969-12-31T23:59:59.999999999Z"},
		{"-1.25", "1969-12-31T23:59:58.75Z"},
		{"-1", "1969-12-31T23:59:59Z"},
		{"1788606000.123456789", "2026-09-05T11:00:00.123456789Z"},
		{"9223372036.854775806", "2262-04-11T23:47:16.854775806Z"},
		{"-9223372036.854775806", "1677-09-21T00:12:43.145224194Z"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseUnix(tc.input)
			if err != nil || got.Format(time.RFC3339Nano) != tc.want {
				t.Fatalf("ParseUnix(%q) = %v, %v; want %s", tc.input, got, err, tc.want)
			}
		})
	}
}

func TestParseUnixRejectsInvalidAndUnsupportedTimes(t *testing.T) {
	for _, s := range []string{"", "NaN", "Inf", "1.1234567890", "-0.0000000001", "1.", "1.bad", "1.-2", "1e3", " 1", "9223372036.854775807", "-9223372036.854775807", "9223372037", "-9223372037", "9223372036854775807", "-9223372036854775808.1", "99999999999999999999"} {
		if _, err := ParseUnix(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
