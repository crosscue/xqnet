// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/crosscue/xqnet/internal/config"
	inspectpkg "github.com/crosscue/xqnet/internal/inspect"
	"github.com/crosscue/xqnet/internal/mcpserver"
	"github.com/crosscue/xqnet/internal/output"
	"github.com/crosscue/xqnet/internal/pipeline"
	validatepkg "github.com/crosscue/xqnet/internal/validate"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "eventize":
		err = runEventize(os.Args[2:])
	case "validate":
		err = runValidate(os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "mcp":
		err = runMCP(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("xqnet %s\neventizer %s\nanalysis %s\nmcp %s\nCrosscue Event Model wire %s / %s\n", config.Version, config.EventizerVersion, config.AnalysisContractVersion, config.MCPContractVersion, config.WireVersion, config.ProfileID)
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "xqnet:", err)
		os.Exit(1)
	}
}

func runEventize(args []string) error {
	cfg := config.Default()
	fs := flag.NewFlagSet("eventize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: xqnet eventize [flags] <input>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Input is a Zeek JSON-log directory, Suricata EVE JSON, or PCAP/PCAPNG/capture dumps decoded by the selected upstream engine.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	out := fs.String("out", "xqnet-output", "output directory")
	fs.BoolVar(&cfg.Overwrite, "overwrite", false, "explicitly replace existing xqnet output files")
	verbose := fs.Bool("verbose", false, "print full adapter, Parquet and storage detail")
	dictMiB := cfg.ParquetDictionaryMaxBytes / (1 << 20)
	fs.StringVar(&cfg.Adapter, "adapter", "zeek", "source adapter: zeek or suricata")
	fs.StringVar(&cfg.Source, "source", "", "source / observation-point identifier (required)")
	fs.StringVar(&cfg.NetworkID, "network-id", "", "optional explicit network scope, e.g. network:lab-lan")
	fs.StringVar(&cfg.NetworkCIDRs, "network-cidrs", "", "comma-separated CIDRs belonging to --network-id")
	fs.StringVar(&cfg.ParquetCompression, "parquet-compression", cfg.ParquetCompression, "Parquet page compression: zstd, snappy, or none")
	fs.Int64Var(&cfg.ParquetRowGroupRows, "parquet-row-group-rows", cfg.ParquetRowGroupRows, "maximum rows per Parquet row group")
	fs.Int64Var(&dictMiB, "parquet-dictionary-max-mib", dictMiB, "maximum dictionary bytes per Parquet column per row group in MiB; 0 means unlimited")
	fs.StringVar(&cfg.ZeekPath, "zeek", "", "Zeek executable path for PCAP input; defaults to PATH")
	fs.StringVar(&cfg.SuricataPath, "suricata", "", "Suricata executable path for PCAP input; defaults to PATH")
	fs.StringVar(&cfg.SuricataConfig, "suricata-config", "", "Suricata YAML config for PCAP input")
	input, flagArgs := peelInput(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if input == "" && fs.NArg() == 1 {
		input = fs.Arg(0)
	}
	if input == "" || fs.NArg() > 1 {
		return fmt.Errorf("usage: xqnet eventize [flags] <input>")
	}
	if cfg.Source == "" {
		return fmt.Errorf("--source is required")
	}
	if dictMiB < 0 {
		return fmt.Errorf("--parquet-dictionary-max-mib must be >= 0")
	}
	cfg.ParquetDictionaryMaxBytes = dictMiB * (1 << 20)
	absOut, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	stats, err := pipeline.Run(input, absOut, cfg)
	if err != nil {
		return err
	}
	printSummary(absOut, stats)
	if *verbose {
		printVerbose(stats, cfg)
	} else {
		fmt.Printf("  details: xqnet inspect --diagnostics %s\n", absOut)
	}
	return nil
}

func printSummary(out string, st pipeline.Stats) {
	fmt.Printf("xqnet: wrote %s\n", out)
	fmt.Printf("  adapter=%s input=%s events=%d observations=%d entities=%d bindings=%d sessions=%d relationships=%d services=%d presence=%d\n", st.Adapter, st.InputKind, st.Events, st.Observations, st.Entities, st.Bindings, st.Sessions, st.Relationships, st.Services, st.PresenceIntervals)
	fmt.Printf("  elapsed=%.2fs analysis=%s canonical=%s total=%s\n", st.ElapsedSeconds, humanBytes(st.Storage.AnalysisBytes), humanBytes(st.Storage.CanonicalBytes), humanBytes(st.Storage.OutputArtifactBytes))
}
func printVerbose(st pipeline.Stats, cfg config.Config) {
	fmt.Printf("  parquet: compression=%s row_group_max_rows=%d dictionary_max=%s\n", cfg.ParquetCompression, cfg.ParquetRowGroupRows, humanBytes(cfg.ParquetDictionaryMaxBytes))
	printParquetStats(st.Parquet)
	fmt.Printf("  storage: canonical=%s analysis=%s total=%s", humanBytes(st.Storage.CanonicalBytes), humanBytes(st.Storage.AnalysisBytes), humanBytes(st.Storage.OutputArtifactBytes))
	if st.Storage.InputBytes > 0 {
		fmt.Printf(" analysis/input=%.2fx total/input=%.2fx", st.Storage.AnalysisExpansionRatio, st.Storage.TotalArtifactExpansionRatio)
	}
	fmt.Println()
	for _, f := range st.Storage.Files {
		fmt.Printf("    %-42s %s\n", f.Path, humanBytes(f.Bytes))
	}
}
func printParquetStats(p output.ParquetMaterializationStats) {
	paths := make([]string, 0, len(p.Files))
	for k := range p.Files {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	for _, path := range paths {
		st := p.Files[path]
		fmt.Printf("    %-42s rows=%d row_groups=%d\n", path, st.Rows, st.RowGroups)
	}
}

func peelInput(args []string) (string, []string) {
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		return args[0], args[1:]
	}
	return "", args
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: xqnet validate <events.jsonl>") }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: xqnet validate <events.jsonl>")
	}
	r, err := validatepkg.EventsFile(fs.Arg(0))
	if err != nil {
		for _, m := range r.Errors {
			fmt.Fprintln(os.Stderr, m)
		}
		return fmt.Errorf("%d event(s), %d validation error(s): %w", r.Events, len(r.Errors), err)
	}
	fmt.Printf("valid: %d Network Profile 0.1 event(s)\n", r.Events)
	return nil
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: xqnet inspect [--json] [--diagnostics] [--entity ENTITY] <output-dir|manifest.json>")
		fs.PrintDefaults()
	}
	jsonOut := fs.Bool("json", false, "print the inspection report as JSON")
	diagnostics := fs.Bool("diagnostics", false, "print Parquet and per-file storage detail")
	entity := fs.String("entity", "", "optional entity identifier to resolve from entities.parquet")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: xqnet inspect [flags] <output-dir|manifest.json>")
	}
	r, err := inspectpkg.Load(fs.Arg(0), *entity)
	if err != nil {
		return err
	}
	if *jsonOut {
		b, err := inspectpkg.JSON(r)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	m := r.Manifest
	s := m.Stats
	fmt.Printf("xqnet dataset: %s\n", r.Root)
	fmt.Printf("  tool=%s eventizer=%s analysis=%s adapter=%s input=%s source=%s\n", m.ToolVersion, m.Eventizer, m.AnalysisContract, s.Adapter, s.InputKind, m.Source)
	fmt.Printf("  events=%d observations=%d entities=%d bindings=%d sessions=%d relationships=%d services=%d presence=%d networks=%d\n", s.Events, s.Observations, s.Entities, s.Bindings, s.Sessions, s.Relationships, s.Services, s.PresenceIntervals, s.Networks)
	fmt.Printf("  elapsed=%.2fs analysis=%s canonical=%s total=%s\n", s.ElapsedSeconds, humanBytes(s.Storage.AnalysisBytes), humanBytes(s.Storage.CanonicalBytes), humanBytes(s.Storage.OutputArtifactBytes))
	if *diagnostics {
		printParquetStats(s.Parquet)
		for _, f := range s.Storage.Files {
			fmt.Printf("    %-42s %s\n", f.Path, humanBytes(f.Bytes))
		}
	}
	if r.Entity != nil {
		e := r.Entity
		fmt.Printf("  entity=%s type=%s first=%s last=%s observations=%d originator=%d responder=%d\n", e.Entity, e.EntityType, nanosTime(e.FirstObserved), nanosTime(e.LastObserved), e.Observations, e.AsOriginator, e.AsResponder)
		fmt.Printf("    presence_eligible=%t scope=%s\n", e.PresenceEligible, e.PresenceScope)
	}
	return nil
}

func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: xqnet mcp [--duckdb-threads N] <output-dir>")
		fmt.Fprintln(os.Stderr, "\nStarts the read-only xqnet analyst MCP server over stdio. stdout is reserved for MCP protocol messages.")
		fs.PrintDefaults()
	}
	threads := fs.Int("duckdb-threads", 4, "DuckDB worker threads for analytical queries")
	dataset, flagArgs := peelInput(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if dataset == "" && fs.NArg() == 1 {
		dataset = fs.Arg(0)
	}
	if dataset == "" || fs.NArg() > 1 {
		return fmt.Errorf("usage: xqnet mcp [flags] <output-dir>")
	}
	if *threads <= 0 {
		return fmt.Errorf("--duckdb-threads must be > 0")
	}
	return mcpserver.RunStdio(context.Background(), dataset, mcpserver.Options{DuckDBThreads: *threads})
}

func usage() {
	fmt.Fprintln(os.Stderr, `xqnet - Crosscue network eventizer reference implementation

Usage:
  xqnet eventize [flags] <input>
  xqnet validate <events.jsonl>
  xqnet inspect [flags] <output-dir|manifest.json>
  xqnet mcp [flags] <output-dir>
  xqnet --version

Adapters:
  --adapter zeek       Zeek JSON-log directory or PCAP/PCAPNG/capture dump
  --adapter suricata   Suricata EVE JSON or PCAP/PCAPNG/capture dump

PCAP decoding remains an upstream Zeek/Suricata responsibility.
Canonical output is canonical/events.jsonl; analytical Parquet projections are under analysis/.`)
}
func nanosTime(ns int64) string {
	return time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
}
func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	d, e := int64(u), 0
	for v := n / u; v >= u && e < 5; v /= u {
		d *= u
		e++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(d), "KMGTPE"[e])
}
