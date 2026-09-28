// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/output"
	"github.com/crosscue/xqnet/internal/pipeline"
	parquet "github.com/parquet-go/parquet-go"
)

type Report struct {
	Root     string            `json:"root"`
	Manifest pipeline.Manifest `json:"manifest"`
	Entity   *output.EntityRow `json:"entity,omitempty"`
}

func Load(path, entity string) (Report, error) {
	root, manifestPath, err := resolveRoot(path)
	if err != nil {
		return Report{}, err
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return Report{}, fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	var m pipeline.Manifest
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return Report{}, fmt.Errorf("decode manifest: %w", err)
	}
	r := Report{Root: root, Manifest: m}
	if entity == "" {
		return r, nil
	}
	if m.AnalysisContract != config.AnalysisContractVersion {
		return Report{}, fmt.Errorf("entity inspection requires analysis contract %s; dataset has %s; rebuild the dataset from source telemetry", config.AnalysisContractVersion, m.AnalysisContract)
	}
	ef, err := os.Open(filepath.Join(root, "analysis", "entities.parquet"))
	if err != nil {
		return Report{}, fmt.Errorf("open entities.parquet: %w", err)
	}
	defer ef.Close()
	reader := parquet.NewGenericReader[output.EntityRow](ef)
	defer reader.Close()
	buf := make([]output.EntityRow, 1024)
	for {
		n, re := reader.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i].Entity == entity {
				row := buf[i]
				r.Entity = &row
				return r, nil
			}
		}
		if errors.Is(re, io.EOF) {
			break
		}
		if re != nil {
			return Report{}, fmt.Errorf("read entities.parquet: %w", re)
		}
	}
	return Report{}, fmt.Errorf("entity %q not found", entity)
}

func resolveRoot(path string) (string, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", err
	}
	if info.IsDir() {
		return abs, filepath.Join(abs, "manifest.json"), nil
	}
	if filepath.Base(abs) != "manifest.json" {
		return "", "", fmt.Errorf("inspect expects an xqnet output directory or manifest.json")
	}
	return filepath.Dir(abs), abs, nil
}
func JSON(r Report) ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
