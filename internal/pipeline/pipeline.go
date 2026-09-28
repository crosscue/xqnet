// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/crosscue/xqnet/internal/adapters/suricata"
	"github.com/crosscue/xqnet/internal/adapters/zeek"
	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/inputkind"
	"github.com/crosscue/xqnet/internal/output"
)

type FileStorage struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Bytes    int64  `json:"bytes"`
}
type StorageStats struct {
	InputBytes                  int64         `json:"input_bytes"`
	CanonicalBytes              int64         `json:"canonical_bytes"`
	AnalysisBytes               int64         `json:"analysis_bytes"`
	OutputArtifactBytes         int64         `json:"output_artifact_bytes_excluding_manifest"`
	CanonicalExpansionRatio     float64       `json:"canonical_expansion_ratio"`
	AnalysisExpansionRatio      float64       `json:"analysis_expansion_ratio"`
	TotalArtifactExpansionRatio float64       `json:"total_artifact_expansion_ratio"`
	Files                       []FileStorage `json:"files"`
}
type Stats struct {
	Adapter           string                             `json:"adapter"`
	InputKind         string                             `json:"input_kind"`
	Events            int64                              `json:"events"`
	Observations      int64                              `json:"observations"`
	Entities          int64                              `json:"entities"`
	Bindings          int64                              `json:"bindings"`
	Sessions          int64                              `json:"sessions"`
	Relationships     int64                              `json:"relationships"`
	Services          int64                              `json:"services"`
	PresenceIntervals int64                              `json:"presence_intervals"`
	Networks          int64                              `json:"networks"`
	ElapsedSeconds    float64                            `json:"elapsed_seconds"`
	Parquet           output.ParquetMaterializationStats `json:"parquet"`
	Storage           StorageStats                       `json:"storage"`
}
type Manifest struct {
	Tool             string        `json:"tool"`
	ToolVersion      string        `json:"tool_version"`
	Eventizer        string        `json:"eventizer"`
	EventModelWire   string        `json:"event_model_wire_version"`
	NetworkProfile   string        `json:"network_profile"`
	AnalysisContract string        `json:"analysis_contract"`
	CreatedUTC       string        `json:"created_utc"`
	Input            string        `json:"input"`
	Source           string        `json:"source"`
	Config           config.Config `json:"config"`
	Stats            Stats         `json:"stats"`
	Canonical        []string      `json:"canonical"`
	Analysis         []string      `json:"analysis"`
	Notes            []string      `json:"notes"`
}

func Run(inputPath, outDir string, cfg config.Config) (Stats, error) {
	started := time.Now()
	var st Stats
	if strings.TrimSpace(cfg.Source) == "" {
		return st, errors.New("--source is required")
	}
	if cfg.Adapter != "zeek" && cfg.Adapter != "suricata" {
		return st, fmt.Errorf("--adapter must be zeek or suricata, got %q", cfg.Adapter)
	}
	if cfg.ParquetCompression != "zstd" && cfg.ParquetCompression != "snappy" && cfg.ParquetCompression != "none" {
		return st, fmt.Errorf("unsupported parquet compression %q", cfg.ParquetCompression)
	}
	if cfg.ParquetRowGroupRows <= 0 {
		return st, fmt.Errorf("--parquet-row-group-rows must be > 0")
	}
	if cfg.ParquetDictionaryMaxBytes < 0 {
		return st, fmt.Errorf("--parquet-dictionary-max-mib must be >= 0")
	}
	if _, err := os.Stat(inputPath); err != nil {
		return st, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return st, err
	}
	if err := checkOutput(outDir, cfg.Overwrite); err != nil {
		return st, err
	}
	tmp, err := os.MkdirTemp(outDir, ".xqnet-adapter-")
	if err != nil {
		return st, err
	}
	defer os.RemoveAll(tmp)
	pcap := isPCAP(inputPath, cfg.Adapter)
	st.Adapter = cfg.Adapter
	if pcap {
		st.InputKind = "pcap"
	} else if cfg.Adapter == "zeek" {
		st.InputKind = "zeek-json"
	} else {
		st.InputKind = "suricata-eve"
	}
	switch cfg.Adapter {
	case "zeek":
		_, err = zeek.Run(zeek.Options{InputPath: inputPath, OutDir: tmp, Source: cfg.Source, EnginePath: cfg.ZeekPath, PCAP: pcap, NetworkID: cfg.NetworkID, NetworkCIDRs: cfg.NetworkCIDRs})
	case "suricata":
		_, err = suricata.Run(suricata.Options{InputPath: inputPath, OutDir: tmp, Source: cfg.Source, EnginePath: cfg.SuricataPath, ConfigPath: cfg.SuricataConfig, PCAP: pcap, NetworkID: cfg.NetworkID, NetworkCIDRs: cfg.NetworkCIDRs})
	}
	if err != nil {
		return st, err
	}
	// Keep the previous dataset until the replacement input has been processed.
	if err := checkOutput(outDir, cfg.Overwrite); err != nil {
		return st, err
	}
	if cfg.Overwrite {
		if err := removeKnownArtifacts(outDir); err != nil {
			return st, err
		}
	}
	mat, err := output.Materialize(tmp, outDir, cfg)
	if err != nil {
		return st, err
	}
	counts := mat.Counts
	st.Events = counts.Events
	st.Observations = counts.Observations
	st.Entities = counts.Entities
	st.Bindings = counts.Bindings
	st.Sessions = counts.Sessions
	st.Relationships = counts.Relationships
	st.Services = counts.Services
	st.PresenceIntervals = counts.Presence
	st.Networks = counts.Networks
	st.Parquet = mat.Parquet
	storage, err := collectStorage(outDir, inputPath)
	if err != nil {
		return st, err
	}
	st.Storage = storage
	st.ElapsedSeconds = time.Since(started).Seconds()
	if err := writeManifest(outDir, inputPath, cfg, st); err != nil {
		return st, err
	}
	return st, nil
}

func isPCAP(path, adapter string) bool {
	if inputkind.IsPacketCapture(path) {
		return true
	}
	if adapter == "suricata" {
		return false
	}
	// Zeek accepts capture input when a non-directory input is supplied; its
	// native JSON input form is a directory of logs.
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return false
	}
	return adapter == "zeek"
}

func analysisPaths() []string {
	return []string{"analysis/bindings.parquet", "analysis/entities.parquet", "analysis/events.parquet", "analysis/networks.parquet", "analysis/observations.parquet", "analysis/presence_intervals.parquet", "analysis/relationships.parquet", "analysis/services.parquet", "analysis/sessions.parquet"}
}

func checkOutput(out string, overwrite bool) error {
	// Never follow an output subdirectory link when replacing dataset files.
	for _, dir := range []string{"canonical", "analysis"} {
		info, err := os.Lstat(filepath.Join(out, dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output %s must be a directory, not a file or symlink", dir)
		}
	}
	paths := append([]string{"manifest.json", "canonical/events.jsonl"}, analysisPaths()...)
	for _, p := range paths {
		info, err := os.Lstat(filepath.Join(out, filepath.FromSlash(p)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !overwrite {
			return fmt.Errorf("output already contains %s; choose another --out directory or pass --overwrite to replace existing xqnet output", p)
		}
		if info.IsDir() {
			return fmt.Errorf("output artifact %s is a directory", p)
		}
	}
	return nil
}

func removeKnownArtifacts(out string) error {
	paths := append([]string{"manifest.json", "canonical/events.jsonl"}, analysisPaths()...)
	for _, p := range paths {
		e := os.Remove(filepath.Join(out, filepath.FromSlash(p)))
		if e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}
func collectStorage(out, input string) (StorageStats, error) {
	var s StorageStats
	info, err := os.Stat(input)
	if err == nil && !info.IsDir() {
		s.InputBytes = info.Size()
	}
	files := append([]string{"canonical/events.jsonl"}, analysisPaths()...)
	for _, p := range files {
		info, err := os.Stat(filepath.Join(out, filepath.FromSlash(p)))
		if err != nil {
			return s, err
		}
		cat := "analysis"
		if strings.HasPrefix(p, "canonical/") {
			cat = "canonical"
		}
		f := FileStorage{p, cat, info.Size()}
		s.Files = append(s.Files, f)
		if cat == "canonical" {
			s.CanonicalBytes += f.Bytes
		} else {
			s.AnalysisBytes += f.Bytes
		}
	}
	s.OutputArtifactBytes = s.CanonicalBytes + s.AnalysisBytes
	if s.InputBytes > 0 {
		s.CanonicalExpansionRatio = float64(s.CanonicalBytes) / float64(s.InputBytes)
		s.AnalysisExpansionRatio = float64(s.AnalysisBytes) / float64(s.InputBytes)
		s.TotalArtifactExpansionRatio = float64(s.OutputArtifactBytes) / float64(s.InputBytes)
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Bytes > s.Files[j].Bytes })
	return s, nil
}
func writeManifest(out, input string, cfg config.Config, stats Stats) error {
	m := Manifest{Tool: "xqnet", ToolVersion: config.Version, Eventizer: config.EventizerVersion, EventModelWire: config.WireVersion, NetworkProfile: config.ProfileID, AnalysisContract: config.AnalysisContractVersion, CreatedUTC: time.Now().UTC().Format(time.RFC3339), Input: filepath.Base(input), Source: cfg.Source, Config: cfg, Stats: stats, Canonical: []string{"canonical/events.jsonl"}, Analysis: analysisPaths(), Notes: []string{"canonical/events.jsonl is the semantic source of truth; Parquet files are analytical projections.", "xqnet is a reference implementation above source-native Zeek/Suricata telemetry; source-native logs remain evidentially authoritative.", "Sessions are adapter/source-engine projections; Community ID is a transport-tuple correlation identifier, not a session identifier.", "The reference implementation does not infer device identity from MAC or IP evidence alone.", "Parquet projections implement the versioned xqnet analytical contract and are queryable independently of canonical JSONL."}}
	f, e := os.Create(filepath.Join(out, "manifest.json"))
	if e != nil {
		return e
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}
