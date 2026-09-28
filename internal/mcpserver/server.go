// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/crosscue/xqnet/internal/analyst"
	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/mcpbase"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed resources/*.md
var resourceFS embed.FS

type Options struct{ DuckDBThreads int }

type datasetSummaryOutput struct {
	analyst.DatasetSummary
	MCPContract string `json:"mcp_contract"`
}

func RunStdio(ctx context.Context, datasetRoot string, opts Options) error {
	ds, err := analyst.Open(datasetRoot, analyst.Options{Threads: opts.DuckDBThreads})
	if err != nil {
		return err
	}
	defer ds.Close()
	return mcpbase.RunStdio(ctx, NewServer(ds))
}

func NewServer(ds *analyst.Dataset) *mcp.Server {
	guidance, _ := resourceFS.ReadFile("resources/ANALYST-GUIDANCE.md")
	server := mcpbase.NewReadOnlyServer("xqnet", config.Version, string(guidance))
	registerResources(server, ds)
	registerTools(server, ds)
	return server
}

func registerResources(server *mcp.Server, ds *analyst.Dataset) {
	add := func(uri, name, desc, mime, text string) {
		server.AddResource(&mcp.Resource{URI: uri, Name: name, Description: desc, MIMEType: mime}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: mime, Text: text}}}, nil
		})
	}
	manifest, _ := ds.ManifestJSON()
	add("xqnet://dataset/manifest", "Dataset manifest", "Complete xqnet manifest for the opened dataset.", "application/json", string(manifest))
	caps := fmt.Sprintf(`{"analysis_contract":%q,"adapter":%q,"network_scope_materialized":%t}`, ds.Manifest.AnalysisContract, ds.Manifest.Stats.Adapter, ds.Manifest.Stats.Networks > 0)
	add("xqnet://dataset/capabilities", "Dataset capabilities", "Network analyst capabilities for the opened dataset.", "application/json", caps)
	for _, r := range []struct{ uri, file, name, desc string }{
		{"xqnet://guidance/analyst", "ANALYST-GUIDANCE.md", "Network analyst guidance", "Evidence and inference rules for LLM analysis of xqnet data."},
		{"xqnet://contract/analytical", "ANALYTICAL-CONTRACT.md", "Analytical contract", "xqnet analytical projection contract."},
		{"xqnet://contract/eventizer", "NETWORK-EVENTIZER-V1.4.md", "Network eventizer contract", "Reference network eventizer algorithm contract."},
		{"xqnet://contract/interoperability", "INTEROPERABILITY.md", "Interoperability guidance", "Zeek/Suricata correlation and interoperability semantics."},
	} {
		b, err := resourceFS.ReadFile("resources/" + r.file)
		if err == nil {
			add(r.uri, r.name, r.desc, "text/markdown", string(b))
		}
	}
}

func registerTools(server *mcp.Server, ds *analyst.Dataset) {
	mcp.AddTool(server, &mcp.Tool{Name: "dataset_summary", Description: "Return the compact dataset-level xqnet summary. Use this first when beginning a network investigation."}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return nil, datasetSummaryOutput{DatasetSummary: ds.Summary(), MCPContract: config.MCPContractVersion}, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "search_entities", Description: "Find typed network entities using bounded analytical filters. Use this to discover interfaces, addresses, endpoints, services, domains, hostnames, software or networks."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.SearchEntitiesInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.SearchEntities(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_entity", Description: "Return one network entity summary. Entity types are deliberately distinct; an IP or MAC is not automatically a device."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.EntityInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetEntity(ctx, in.Entity)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_entity_timeline", Description: "Return a chronological union of semantic events, source-engine sessions, bindings and explicit-scope presence for one network entity."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.TimePageInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetTimeline(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_bindings", Description: "Query temporal relational evidence such as ARP/DHCP address bindings, DNS address/alias bindings, TLS server-name bindings and endpoint-to-service bindings."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.BindingInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetBindings(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_sessions", Description: "Query source-engine session/flow projections. Session boundaries are adapter dependent; Community ID is a tuple correlation identifier, not a session identifier."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.SessionInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetSessions(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_relationships", Description: "Query observed communication relationships derived from qualifying connection evidence. first_observed is not proof of establishment."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.RelationshipInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetRelationships(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_services", Description: "Query endpoint/service materializations supported by application evidence."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.ServiceInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetServices(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_presence", Description: "Query observed presence intervals within an explicitly configured network scope. Presence is not inferred merely because an address appears in traffic."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.PresenceInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetPresence(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_networks", Description: "Return explicit network/observation scopes supplied by the operator."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.PageInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetNetworks(ctx, in.Limit, in.Cursor)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_events", Description: "Query flattened semantic network events by entity, class, feature, action and time range."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.EventInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetEvents(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "get_observations", Description: "Query observation/normalized-observation evidence involving one entity. Requires an entity and is capped at 1000 rows per call."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.ObservationInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.GetObservations(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "describe_endpoint", Description: "Describe one endpoint entity through linked services, sessions, communication relationships and bindings without collapsing the endpoint into a device identity."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.EndpointInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.DescribeEndpoint(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "explain_event", Description: "Explain one semantic event by returning linked observation, session, relationship, binding and service projections where present."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.EventIDInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.ExplainEvent(ctx, in.EventID)
		return nil, out, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "explain_relationship", Description: "Explain a communication relationship using its first qualifying parent event and sample source-engine sessions. Aggregate directionality may include later evidence."}, func(ctx context.Context, _ *mcp.CallToolRequest, in analyst.RelationshipKeyInput) (*mcp.CallToolResult, any, error) {
		out, err := ds.ExplainRelationship(ctx, in)
		return nil, out, err
	})
}

func ServerDescription() string {
	return strings.TrimSpace(`xqnet MCP is a read-only local network analyst interface. DuckDB queries xqnet Parquet projections directly. Results are bounded and cursor-paginated, source-engine evidence remains distinguishable from derived relationships/services/presence, and stdout is reserved exclusively for MCP stdio protocol messages.`)
}
