// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package mcpbase

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewReadOnlyServer(name, version, instructions string) *mcp.Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, &mcp.ServerOptions{Instructions: instructions, Logger: logger, Capabilities: &mcp.ServerCapabilities{}})
}
func RunStdio(ctx context.Context, server *mcp.Server) error {
	return server.Run(ctx, &mcp.StdioTransport{})
}
