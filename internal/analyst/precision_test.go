// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package analyst

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/pipeline"
)

func TestRejectLegacyTimestampContract(t *testing.T) {
	out := t.TempDir()
	b, err := json.Marshal(pipeline.Manifest{Tool: "xqnet", AnalysisContract: "xqnet-analysis-v0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(out, Options{}); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("legacy timestamp units not rejected: %v", err)
	}
}

func TestNanosecondQueries(t *testing.T) {
	input := t.TempDir()
	// Both records fall in the same microsecond, as well as the same millisecond.
	data := `{"ts":1789725600.123456102,"duration":0,"uid":"later","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","id.resp_p":443,"proto":"tcp","conn_state":"SF","orig_pkts":2,"resp_pkts":2}
{"ts":1789725600.123456101,"duration":0,"uid":"earlier","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","id.resp_p":443,"proto":"tcp","conn_state":"SF","orig_pkts":2,"resp_pkts":2}
`
	if err := os.WriteFile(filepath.Join(input, "conn.log"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cfg := config.Default()
	cfg.Adapter, cfg.Source = "zeek", "precision"
	if _, err := pipeline.Run(input, out, cfg); err != nil {
		t.Fatal(err)
	}
	ds, err := Open(out, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	ctx := context.Background()
	first := time.Unix(1789725600, 123456101).UTC()
	second := first.Add(time.Nanosecond)
	wantFirst, wantSecond := first.Format(time.RFC3339Nano), second.Format(time.RFC3339Nano)
	page, err := ds.GetEvents(ctx, EventInput{Class: "normalized_observation", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0]["event_time"] != wantFirst || !page.HasMore {
		t.Fatalf("first page lost time/order: %+v", page)
	}
	page, err = ds.GetEvents(ctx, EventInput{Class: "normalized_observation", Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(page.Rows) != 1 || page.Rows[0]["event_time"] != wantSecond || page.HasMore {
		t.Fatalf("second page lost time/order: %+v, %v", page, err)
	}
	// An equivalent offset-form lower bound must not introduce timezone coercion
	// or the Go driver's default microsecond precision.
	from := second.In(time.FixedZone("test", 3600)).Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name, column string
		query        func() (Page, error)
	}{
		{"events", "event_time", func() (Page, error) {
			return ds.GetEvents(ctx, EventInput{Class: "normalized_observation", From: from, To: wantSecond})
		}},
		{"observations", "event_time", func() (Page, error) {
			return ds.GetObservations(ctx, ObservationInput{Entity: "address:ip:192.0.2.1", From: from, To: wantSecond})
		}},
		{"sessions", "start", func() (Page, error) { return ds.GetSessions(ctx, SessionInput{From: from, To: wantSecond}) }},
		{"timeline", "time", func() (Page, error) {
			return ds.GetTimeline(ctx, TimePageInput{Entity: "address:ip:192.0.2.1", From: from, To: wantSecond})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.query()
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Rows) == 0 {
				t.Fatal("exact nanosecond filter dropped matching data")
			}
			for _, row := range p.Rows {
				if row[tc.column] != wantSecond {
					t.Fatalf("filter admitted wrong timestamp: %+v", row)
				}
			}
		})
	}
	var typ string
	if err := ds.db.QueryRowContext(ctx, `SELECT typeof(event_time) FROM events LIMIT 1`).Scan(&typ); err != nil || typ != "TIMESTAMP_NS" {
		t.Fatalf("wrong DuckDB type %s: %v", typ, err)
	}
}
