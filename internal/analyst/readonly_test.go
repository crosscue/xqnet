// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package analyst

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/pipeline"
)

func TestAnalystDatabaseIsReadOnlyAndPathLimited(t *testing.T) {
	input := t.TempDir()
	line := `{"ts":1789725600.0,"duration":0,"uid":"ro","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","id.resp_p":443,"proto":"tcp","conn_state":"SF","orig_pkts":1,"resp_pkts":1}` + "\n"
	if err := os.WriteFile(filepath.Join(input, "conn.log"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cfg := config.Default()
	cfg.Adapter, cfg.Source = "zeek", "readonly"
	if _, err := pipeline.Run(input, out, cfg); err != nil {
		t.Fatal(err)
	}
	ds, err := Open(out, Options{Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()

	var mode string
	if err := ds.db.QueryRow("SELECT current_setting('access_mode')").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "read_only" {
		t.Fatalf("access_mode=%q want read_only", mode)
	}
	page, err := ds.GetEvents(context.Background(), EventInput{Limit: 1})
	if err != nil || page.Returned == 0 {
		t.Fatalf("read-only dataset query failed: %+v %v", page, err)
	}

	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideSQL := filepath.ToSlash(outside)
	if _, err := ds.db.Exec("SELECT * FROM read_csv('" + sqlQuote(outsideSQL) + "')"); err == nil || !strings.Contains(err.Error(), "disabled by configuration") {
		t.Fatalf("outside read_csv error=%v", err)
	}
	dest := filepath.Join(out, "analysis", "should-not-write.txt")
	if _, err := ds.db.Exec("COPY (SELECT 1) TO '" + sqlQuote(filepath.ToSlash(dest)) + "'"); err == nil || !strings.Contains(err.Error(), "disabled by configuration") {
		t.Fatalf("dataset COPY error=%v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("COPY created %s: %v", dest, err)
	}
	if _, err := ds.db.Exec("CREATE TABLE hijack(n INTEGER)"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("CREATE TABLE error=%v", err)
	}
	if _, err := ds.db.Exec("SET allowed_paths=['/']"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("configuration change error=%v", err)
	}
}
