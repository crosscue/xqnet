//go:build mcpintegration

// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crosscue/xqnet/internal/analyst"
	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/pipeline"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPDatasetSummaryAndEntitySearch(t *testing.T) {
	root := os.Getenv("XQNET_TEST_DATASET")
	if root == "" {
		t.Skip("XQNET_TEST_DATASET not set")
	}
	ds, err := analyst.Open(root, analyst.Options{Threads: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	s := NewServer(ds)
	c := mcp.NewClient(&mcp.Implementation{Name: "xqnet-test-client", Version: "0.0.1"}, nil)
	t1, t2 := mcp.NewInMemoryTransports()
	ss, err := s.Connect(context.Background(), t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := c.Connect(context.Background(), t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "dataset_summary", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("dataset_summary tool error: %+v", res.Content)
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "search_entities", Arguments: map[string]any{"limit": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("search_entities tool error: %+v", res.Content)
	}

	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"get_sessions", map[string]any{"entity": "endpoint:ip:203.0.113.10:443/tcp", "limit": 5}},
		{"get_relationships", map[string]any{"entity": "endpoint:ip:203.0.113.10:443/tcp", "limit": 5}},
		{"describe_endpoint", map[string]any{"endpoint": "endpoint:ip:203.0.113.10:443/tcp"}},
	} {
		res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("%s returned tool error: %+v", tc.name, res.Content)
		}
	}
	rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "xqnet://guidance/analyst"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rr.Contents) != 1 || rr.Contents[0].Text == "" {
		t.Fatal("analyst guidance resource empty")
	}
}

func TestMCPTimestampPrecision(t *testing.T) {
	input, out := t.TempDir(), t.TempDir()
	data := `{"ts":1789725600.123456101,"duration":0,"uid":"early","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","id.resp_p":443,"proto":"tcp","conn_state":"SF"}
{"ts":1789725600.123456102,"duration":0,"uid":"late","id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","id.resp_p":443,"proto":"tcp","conn_state":"SF"}
`
	if err := os.WriteFile(filepath.Join(input, "conn.log"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Adapter, cfg.Source = "zeek", "mcp-precision"
	if _, err := pipeline.Run(input, out, cfg); err != nil {
		t.Fatal(err)
	}
	ds, err := analyst.Open(out, analyst.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := NewServer(ds)
	c := mcp.NewClient(&mcp.Implementation{Name: "precision-test", Version: "1"}, nil)
	t1, t2 := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := c.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	want := time.Unix(1789725600, 123456102).UTC().Format(time.RFC3339Nano)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_events", Arguments: map[string]any{"class": "normalized_observation", "from": want, "to": want}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	var page analyst.Page
	for _, content := range res.Content {
		if content, ok := content.(*mcp.TextContent); ok {
			if err := json.Unmarshal([]byte(content.Text), &page); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(page.Rows) != 1 || page.Rows[0]["event_time"] != want {
		t.Fatalf("MCP lost timestamp or filter precision: %+v", page)
	}
}
