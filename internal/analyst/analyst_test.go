// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package analyst

import "testing"

func TestCursorRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 100, 999999} {
		c := encodeCursor(n)
		got, err := decodeCursor(c)
		if err != nil || got != n {
			t.Fatalf("cursor %d -> %q -> %d, %v", n, c, got, err)
		}
	}
}
func TestCursorRejectsInvalid(t *testing.T) {
	if _, err := decodeCursor("not-base64!"); err == nil {
		t.Fatal("expected invalid cursor error")
	}
}
func TestLimitBounds(t *testing.T) {
	if got := normalizeLimit(0); got != DefaultLimit {
		t.Fatalf("default=%d", got)
	}
	if got := normalizeLimit(MaxLimit + 1); got != MaxLimit {
		t.Fatalf("max=%d", got)
	}
	if got := normalizeLimit(7); got != 7 {
		t.Fatalf("explicit=%d", got)
	}
}
func TestParseBounds(t *testing.T) {
	if _, _, err := parseBounds("2026-01-02T03:04:05Z", "2026-01-02T04:04:05Z"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseBounds("2026-01-02T05:04:05Z", "2026-01-02T04:04:05Z"); err == nil {
		t.Fatal("expected reversed bounds error")
	}
	if _, _, err := parseBounds("not-a-time", ""); err == nil {
		t.Fatal("expected timestamp error")
	}
}
