// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crosscue/xqnet/internal/config"
)

func TestOverwriteRequiresExplicitOptIn(t *testing.T) {
	for _, artifact := range append([]string{"manifest.json", "canonical/events.jsonl"}, analysisPaths()...) {
		t.Run(artifact, func(t *testing.T) {
			out := t.TempDir()
			path := filepath.Join(out, filepath.FromSlash(artifact))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("previous dataset"), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			cfg.Source, cfg.Adapter = "test", "zeek"
			_, err := Run(filepath.Join("..", "..", "testdata", "zeek"), out, cfg)
			if err == nil || !strings.Contains(err.Error(), "--overwrite") {
				t.Fatalf("expected explicit overwrite error, got %v", err)
			}
			b, err := os.ReadFile(path)
			if err != nil || string(b) != "previous dataset" {
				t.Fatalf("existing artifact changed: %q, %v", b, err)
			}
		})
	}
}

func TestOverwriteReplacesDatasetAndPreservesUnrelatedFiles(t *testing.T) {
	out := t.TempDir()
	cfg := config.Default()
	cfg.Source, cfg.Adapter = "first", "zeek"
	input := filepath.Join("..", "..", "testdata", "zeek")
	if _, err := Run(input, out, cfg); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(out, "notes.txt")
	if err := os.WriteFile(note, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Source, cfg.Overwrite = "replacement", true
	if _, err := Run(input, out, cfg); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "canonical", "events.jsonl"))
	if err != nil || !strings.Contains(string(b), `"source":"replacement"`) || strings.Contains(string(b), `"source":"first"`) {
		t.Fatalf("replacement dataset missing or contains old events: %v", err)
	}
	b, err = os.ReadFile(note)
	if err != nil || string(b) != "keep me" {
		t.Fatalf("unrelated file changed: %q, %v", b, err)
	}
}

func TestFailedInputPreservesDatasetEvenWithOverwrite(t *testing.T) {
	out := t.TempDir()
	cfg := config.Default()
	cfg.Source, cfg.Adapter = "test", "zeek"
	if _, err := Run(filepath.Join("..", "..", "testdata", "zeek"), out, cfg); err != nil {
		t.Fatal(err)
	}
	paths := append([]string{"manifest.json", "canonical/events.jsonl"}, analysisPaths()...)
	before := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		before[p] = string(b)
	}
	input := t.TempDir()
	if err := os.WriteFile(filepath.Join(input, "conn.log"), []byte("invalid JSON\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Overwrite = true
	if _, err := Run(input, out, cfg); err == nil {
		t.Fatal("expected invalid input error")
	}
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(p)))
		if err != nil || string(b) != before[p] {
			t.Fatalf("failed input changed %s: %v", p, err)
		}
	}
}

func TestInvalidTimestampsPreserveDatasetWithOverwrite(t *testing.T) {
	for _, adapter := range []string{"zeek", "suricata"} {
		t.Run(adapter, func(t *testing.T) {
			cfg := config.Default()
			cfg.Source, cfg.Adapter = "timestamp-test", adapter
			fixture := filepath.Join("..", "..", "testdata", adapter)
			if adapter == "suricata" {
				fixture = filepath.Join(fixture, "eve.json")
			}
			out := t.TempDir()
			if _, err := Run(fixture, out, cfg); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{}
			for _, path := range append([]string{"manifest.json", "canonical/events.jsonl"}, analysisPaths()...) {
				b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(path)))
				if err != nil {
					t.Fatal(err)
				}
				before[path] = string(b)
			}
			good := `{"ts":1788606000,"duration":0,"uid":"good","id.orig_h":"192.0.2.1","id.resp_h":"203.0.113.8","id.resp_p":443,"proto":"tcp","conn_state":"SF"}`
			bad := []string{`{}`, `{"ts":null}`, `{"ts":"invalid"}`, `{"ts":1788606000.1234567899}`}
			if adapter == "suricata" {
				good = `{"timestamp":"2026-09-06T10:00:00Z","event_type":"tls","src_ip":"192.0.2.1","dest_ip":"203.0.113.8","dest_port":443,"proto":"TCP","tls":{"sni":"example.com"}}`
				bad = []string{`{"event_type":"tls"}`, `{"event_type":"tls","timestamp":null}`, `{"event_type":"tls","timestamp":"invalid"}`, `{"event_type":"tls","timestamp":"2026-09-06T10:00:00.1234567899Z"}`, `{"event_type":"flow","timestamp":"2026-09-06T10:00:00Z","src_ip":"192.0.2.1","dest_ip":"203.0.113.8","flow":{"end":"invalid"}}`}
			}
			cfg.Overwrite = true
			for _, line := range bad {
				input := t.TempDir()
				path := filepath.Join(input, "conn.log")
				if adapter == "suricata" {
					path = filepath.Join(input, "eve.json")
					input = path
				}
				if err := os.WriteFile(path, []byte(good+"\n"+line+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := Run(input, out, cfg); err == nil || !strings.Contains(err.Error(), "line 2:") {
					t.Fatalf("expected line-specific error for %s: %v", line, err)
				}
				for path, want := range before {
					b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(path)))
					if err != nil || string(b) != want {
						t.Fatalf("invalid timestamp replaced %s: %v", path, err)
					}
				}
			}
		})
	}
}

func TestInvalidZeekIntervalsPreserveDatasetWithOverwrite(t *testing.T) {
	out := t.TempDir()
	cfg := config.Default()
	cfg.Source, cfg.Adapter = "interval-test", "zeek"
	if _, err := Run(filepath.Join("..", "..", "testdata", "zeek"), out, cfg); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, path := range append([]string{"manifest.json", "canonical/events.jsonl"}, analysisPaths()...) {
		b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		before[path] = string(b)
	}
	cfg.Overwrite = true
	for _, tc := range []struct{ file, line, field string }{
		{"conn.log", `{"ts":1788606000,"duration":1e-10,"id.orig_h":"192.0.2.1","id.resp_h":"203.0.113.8"}`, "duration"},
		{"conn.log", `{"ts":9223372036.854775806,"duration":0.000000001,"id.orig_h":"192.0.2.1","id.resp_h":"203.0.113.8"}`, "duration"},
		{"dns.log", `{"ts":1788606000,"rtt":1e-10,"id.orig_h":"192.0.2.1","query":"example.com","qtype_name":"A"}`, "rtt"},
		{"dns.log", `{"ts":9223372036.854775806,"rtt":0.000000001,"id.orig_h":"192.0.2.1","query":"example.com","qtype_name":"A"}`, "rtt"},
	} {
		input := t.TempDir()
		if err := os.WriteFile(filepath.Join(input, tc.file), []byte(tc.line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Run(input, out, cfg); err == nil || !strings.Contains(err.Error(), "line 1: "+tc.field+":") {
			t.Fatalf("expected interval error, got %v", err)
		}
		for path, want := range before {
			b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(path)))
			if err != nil || string(b) != want {
				t.Fatalf("invalid interval replaced %s: %v", path, err)
			}
		}
	}
}
