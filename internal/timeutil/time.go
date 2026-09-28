// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package timeutil

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Go's time parser silently truncates fractions longer than nine digits.
// Reject those inputs instead of claiming to preserve unsupported precision.
var rfc3339 = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$`)

var unixSeconds = regexp.MustCompile(`^-?\d+(\.\d{1,9})?$`)

var durationSeconds = regexp.MustCompile(`^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$`)

// ParseDurationSeconds converts non-negative decimal seconds to exact integer
// nanoseconds. Scientific notation is accepted; sub-nanosecond values and
// overflow are rejected rather than rounded. Exponents never drive allocation.
func ParseDurationSeconds(s string) (time.Duration, error) {
	parts := durationSeconds.FindStringSubmatch(s)
	if parts == nil {
		return 0, fmt.Errorf("duration must be finite decimal seconds: %q", s)
	}
	digits := strings.TrimLeft(parts[2]+parts[3], "0")
	if digits == "" {
		return 0, nil
	}
	if parts[1] == "-" {
		return 0, fmt.Errorf("duration must be non-negative: %q", s)
	}
	var exponent int64
	if parts[4] != "" {
		var err error
		exponent, err = strconv.ParseInt(parts[4], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("duration exponent is out of range: %q", s)
		}
	}
	scale := 9 + exponent - int64(len(parts[3]))
	if scale < 0 {
		remove := -scale
		if remove >= int64(len(digits)) || strings.Trim(digits[int64(len(digits))-remove:], "0") != "" {
			return 0, fmt.Errorf("duration must be an exact number of nanoseconds: %q", s)
		}
		digits = digits[:int64(len(digits))-remove]
	} else {
		if int64(len(digits))+scale > 19 {
			return 0, fmt.Errorf("duration exceeds the supported range: %q", s)
		}
		digits += strings.Repeat("0", int(scale))
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("duration exceeds the supported range: %q", s)
	}
	return time.Duration(n), nil
}

// ParseUnix parses decimal Unix seconds without floating-point rounding. The
// sign applies to both the whole seconds and the fractional part, including -0.
func ParseUnix(s string) (time.Time, error) {
	if !unixSeconds.MatchString(s) {
		return time.Time{}, fmt.Errorf("timestamp must be decimal Unix seconds with at most nine fractional digits: %q", s)
	}
	whole, fraction, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid Unix timestamp %q: %w", s, err)
	}
	var nsec int64
	if fraction != "" {
		nsec, _ = strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
		if strings.HasPrefix(s, "-") {
			nsec = -nsec
		}
	}
	// Reject extreme seconds before time.Unix can normalize across int64 bounds.
	if sec < math.MinInt64/int64(time.Second)-1 || sec > math.MaxInt64/int64(time.Second) {
		return time.Time{}, fmt.Errorf("timestamp is outside the supported finite nanosecond range: %q", s)
	}
	return ParseNano(time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano))
}

func Parse(s string) (time.Time, error) {
	if !rfc3339.MatchString(s) {
		return time.Time{}, fmt.Errorf("timestamp must be RFC3339 with at most nine fractional digits: %q", s)
	}
	return time.Parse(time.RFC3339Nano, s)
}

// ParseNano validates the finite signed-nanosecond range used by Parquet and
// DuckDB TIMESTAMP_NS. Exclude DuckDB's reserved infinity values as well.
func ParseNano(s string) (time.Time, error) {
	t, err := Parse(s)
	if err != nil {
		return time.Time{}, err
	}
	n := t.UnixNano()
	if !time.Unix(0, n).Equal(t) || n <= math.MinInt64+1 || n == math.MaxInt64 {
		return time.Time{}, fmt.Errorf("timestamp is outside the supported finite nanosecond range: %q", s)
	}
	return t.UTC(), nil
}
