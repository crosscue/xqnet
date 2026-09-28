// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crosscue/xqnet/internal/pipeline"
)

func TestRejectLegacyEntityTimestampUnits(t *testing.T) {
	out := t.TempDir()
	b, err := json.Marshal(pipeline.Manifest{Tool: "xqnet", AnalysisContract: "xqnet-analysis-v0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(out, "address:ip:192.0.2.1"); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("legacy timestamp units not rejected: %v", err)
	}
	if _, err := Load(out, ""); err != nil {
		t.Fatalf("summary inspection should remain available: %v", err)
	}
}
