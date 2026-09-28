// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package timeutil

import (
	"math"
	"testing"
	"time"
)

func TestDurationSecondsExact(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  time.Duration
	}{
		{"0", 0}, {"-0.0", 0}, {"0e99999999", 0},
		{"0.000065", 65000}, {"6.5e-5", 65000}, {"0.000129", 129000},
		{"0.000000015", 15}, {"1.5E-8", 15}, {"1E+1", 10 * time.Second},
		{"0.0000000010", 1}, {"10000000000e-10", time.Second},
		{"1.000000001", time.Second + 1},
		{"9223372036.854775807", time.Duration(math.MaxInt64)},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseDurationSeconds(tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("%q: got %d, %v; want %d ns", tc.input, got, err, tc.want)
			}
		})
	}
	for _, input := range []string{"", "NaN", "Inf", "-0.000001", "1/2", "1_000", "0x1", "1.", "0.0000000001", "1e-10", "1.0000000001", "9223372036.854775808", "1e999999999", "1e-999999999", "1e999999999999999999999"} {
		if _, err := ParseDurationSeconds(input); err == nil {
			t.Errorf("accepted unsupported duration %q", input)
		}
	}
}
