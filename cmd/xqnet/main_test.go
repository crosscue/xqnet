// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePreservesReadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.jsonl")
	if err := runValidate([]string{path}); err == nil || !strings.Contains(err.Error(), "missing.jsonl") {
		t.Fatalf("lost underlying read error: %v", err)
	}
}

func TestInspectTimePrecision(t *testing.T) {
	if got := nanosTime(-1); got != "1969-12-31T23:59:59.999999999Z" {
		t.Fatalf("lost nanoseconds: %s", got)
	}
	if got := nanosTime(0); got != "1970-01-01T00:00:00Z" {
		t.Fatalf("epoch treated as missing: %s", got)
	}
}
