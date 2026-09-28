//go:build mcpintegration

// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crosscue/xqnet/internal/analyst"
	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/pipeline"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPPreservesLargeIntegerMetadata(t *testing.T) {
	input := filepath.Join(t.TempDir(), "eve.json")
	line := `{"timestamp":"2026-09-06T10:00:00Z","event_type":"tls","flow_id":9007199254740993,"src_ip":"192.0.2.1","src_port":50000,"dest_ip":"203.0.113.8","dest_port":443,"proto":"TCP","tls":{"sni":"example.com"}}`
	if err := os.WriteFile(input, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cfg := config.Default()
	cfg.Adapter, cfg.Source = "suricata", "metadata-test"
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
	c := mcp.NewClient(&mcp.Implementation{Name: "metadata-test", Version: "1"}, nil)
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
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_events", Arguments: map[string]any{"feature": "xq.net:tls_session"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	var page analyst.Page
	for _, content := range res.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			if err := json.Unmarshal([]byte(text.Text), &page); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(page.Rows) != 1 {
		t.Fatalf("expected one TLS event: %+v", page)
	}
	metadata, ok := page.Rows[0]["context_json"].(string)
	if !ok || !strings.Contains(metadata, `"suricata_flow_id":9007199254740993`) {
		t.Fatalf("MCP changed integer metadata: %#v", page.Rows[0]["context_json"])
	}
}
