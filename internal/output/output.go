// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/timeutil"
	parquet "github.com/parquet-go/parquet-go"
)

type Event struct {
	XQVersion    string         `json:"xq_version"`
	ID           string         `json:"id"`
	EventTime    string         `json:"event_time"`
	EndTime      string         `json:"end_time,omitempty"`
	ObservedTime string         `json:"observed_time,omitempty"`
	Source       string         `json:"source"`
	Modality     string         `json:"modality"`
	Class        string         `json:"class"`
	Profile      string         `json:"profile,omitempty"`
	Subject      string         `json:"subject,omitempty"`
	Object       string         `json:"object,omitempty"`
	Feature      string         `json:"feature"`
	Action       string         `json:"action"`
	State        string         `json:"state,omitempty"`
	Polarity     int64          `json:"polarity"`
	Magnitude    *float64       `json:"magnitude,omitempty"`
	Unit         string         `json:"unit,omitempty"`
	Confidence   *float64       `json:"confidence,omitempty"`
	Provenance   any            `json:"provenance,omitempty"`
	Context      map[string]any `json:"context,omitempty"`
}

type EventRow struct {
	EventID          string  `parquet:"event_id"`
	EventTime        int64   `parquet:"event_time,timestamp(nanosecond:local)"`
	HasEndTime       bool    `parquet:"has_end_time"`
	EndTime          int64   `parquet:"end_time,timestamp(nanosecond:local)"`
	Source           string  `parquet:"source,dict"`
	Modality         string  `parquet:"modality,dict"`
	Class            string  `parquet:"class,dict"`
	Profile          string  `parquet:"profile,dict"`
	Subject          string  `parquet:"subject,dict"`
	Object           string  `parquet:"object,dict"`
	Feature          string  `parquet:"feature,dict"`
	Action           string  `parquet:"action,dict"`
	State            string  `parquet:"state,dict"`
	Polarity         int64   `parquet:"polarity"`
	HasMagnitude     bool    `parquet:"has_magnitude"`
	Magnitude        float64 `parquet:"magnitude"`
	Unit             string  `parquet:"unit,dict"`
	HasConfidence    bool    `parquet:"has_confidence"`
	Confidence       float64 `parquet:"confidence"`
	ContextJSON      string  `parquet:"context_json"`
	ProvenanceJSON   string  `parquet:"provenance_json"`
	EventizerVersion string  `parquet:"eventizer_version,dict"`
}

type ObservationRow struct {
	EventID          string `parquet:"event_id"`
	EventTime        int64  `parquet:"event_time,timestamp(nanosecond:local)"`
	Class            string `parquet:"class,dict"`
	Subject          string `parquet:"subject,dict"`
	Object           string `parquet:"object,dict"`
	Feature          string `parquet:"feature,dict"`
	Action           string `parquet:"action,dict"`
	State            string `parquet:"state,dict"`
	Polarity         int64  `parquet:"polarity"`
	Source           string `parquet:"source,dict"`
	EventizerVersion string `parquet:"eventizer_version,dict"`
}

type EntityRow struct {
	Entity           string `parquet:"entity"`
	EntityType       string `parquet:"entity_type,dict"`
	FirstObserved    int64  `parquet:"first_observed,timestamp(nanosecond:local)"`
	LastObserved     int64  `parquet:"last_observed,timestamp(nanosecond:local)"`
	Observations     int64  `parquet:"observations"`
	AsOriginator     int64  `parquet:"as_originator"`
	AsResponder      int64  `parquet:"as_responder"`
	PresenceScope    string `parquet:"presence_scope,dict"`
	PresenceEligible bool   `parquet:"presence_eligible"`
	EventizerVersion string `parquet:"eventizer_version,dict"`
}

type BindingRow struct {
	Subject               string `parquet:"subject,dict"`
	Object                string `parquet:"object,dict"`
	Kind                  string `parquet:"kind,dict"`
	FirstObserved         int64  `parquet:"first_observed,timestamp(nanosecond:local)"`
	LastObserved          int64  `parquet:"last_observed,timestamp(nanosecond:local)"`
	Observations          int64  `parquet:"observations"`
	ParentEventCount      int64  `parquet:"parent_event_count"`
	ParentEventsTruncated bool   `parquet:"parent_events_truncated"`
	ParentEvents          string `parquet:"parent_events"`
	EventizerVersion      string `parquet:"eventizer_version,dict"`
}

type SessionRow struct {
	UID                     string `parquet:"uid"`
	Subject                 string `parquet:"subject,dict"`
	Object                  string `parquet:"object,dict"`
	Start                   int64  `parquet:"start,timestamp(nanosecond:local)"`
	End                     int64  `parquet:"end,timestamp(nanosecond:local)"`
	Protocol                string `parquet:"protocol,dict"`
	Service                 string `parquet:"service,dict"`
	ApplicationStack        string `parquet:"application_stack,dict"`
	ConnectionState         string `parquet:"connection_state,dict"`
	SubjectBytes            int64  `parquet:"subject_bytes"`
	ObjectBytes             int64  `parquet:"object_bytes"`
	EndpointRoleBasis       string `parquet:"endpoint_role_basis,dict"`
	OriginatorRoleSupported bool   `parquet:"originator_role_supported"`
	CommunityID             string `parquet:"community_id,dict"`
	EventID                 string `parquet:"event_id"`
	EventizerVersion        string `parquet:"eventizer_version,dict"`
}

type RelationshipRow struct {
	Subject                        string `parquet:"subject,dict"`
	Object                         string `parquet:"object,dict"`
	Protocol                       string `parquet:"protocol,dict"`
	ApplicationStack               string `parquet:"application_stack,dict"`
	Directionality                 string `parquet:"directionality,dict"`
	FirstObservationDirectionality string `parquet:"first_observation_directionality,dict"`
	FirstEndpointRoleBasis         string `parquet:"first_endpoint_role_basis,dict"`
	FirstOriginatorRoleSupported   bool   `parquet:"first_originator_role_supported"`
	FirstObserved                  int64  `parquet:"first_observed,timestamp(nanosecond:local)"`
	LastObserved                   int64  `parquet:"last_observed,timestamp(nanosecond:local)"`
	Connections                    int64  `parquet:"connections"`
	SubjectPackets                 int64  `parquet:"subject_packets"`
	ObjectPackets                  int64  `parquet:"object_packets"`
	SubjectBytes                   int64  `parquet:"subject_bytes"`
	ObjectBytes                    int64  `parquet:"object_bytes"`
	FirstParentEvent               string `parquet:"first_parent_event"`
	FirstCommunityID               string `parquet:"first_community_id,dict"`
	CommunityIDCount               int64  `parquet:"community_id_count"`
	CommunityIDsTruncated          bool   `parquet:"community_ids_truncated"`
	CommunityIDs                   string `parquet:"community_ids"`
	Semantics                      string `parquet:"semantics"`
	EventizerVersion               string `parquet:"eventizer_version,dict"`
}

type ServiceRow struct {
	ServiceEntity         string `parquet:"service_entity"`
	EndpointEntity        string `parquet:"endpoint_entity"`
	HostEntity            string `parquet:"host_entity"`
	IP                    string `parquet:"ip,dict"`
	Port                  string `parquet:"port,dict"`
	Protocol              string `parquet:"protocol,dict"`
	Service               string `parquet:"service,dict"`
	FirstObserved         int64  `parquet:"first_observed,timestamp(nanosecond:local)"`
	LastObserved          int64  `parquet:"last_observed,timestamp(nanosecond:local)"`
	Observations          int64  `parquet:"observations"`
	EvidenceSource        string `parquet:"evidence_source,dict"`
	ParentEventCount      int64  `parquet:"parent_event_count"`
	ParentEventsTruncated bool   `parquet:"parent_events_truncated"`
	ParentEvents          string `parquet:"parent_events"`
	EventizerVersion      string `parquet:"eventizer_version,dict"`
}

type PresenceRow struct {
	Entity           string  `parquet:"entity"`
	Scope            string  `parquet:"scope,dict"`
	FirstObserved    int64   `parquet:"first_observed,timestamp(nanosecond:local)"`
	LastObserved     int64   `parquet:"last_observed,timestamp(nanosecond:local)"`
	DurationS        float64 `parquet:"duration_s"`
	ObservationCount int64   `parquet:"observation_count"`
	Semantics        string  `parquet:"semantics"`
	EventizerVersion string  `parquet:"eventizer_version,dict"`
}

type NetworkRow struct {
	Network          string `parquet:"network"`
	CIDRs            string `parquet:"cidrs"`
	ObservationPoint string `parquet:"observation_point,dict"`
	Semantics        string `parquet:"semantics"`
	EventizerVersion string `parquet:"eventizer_version,dict"`
}

type Counts struct {
	Events, Observations, Entities, Bindings, Sessions, Relationships, Services, Presence, Networks int64
}

type ParquetFileStats struct {
	Rows      int64 `json:"rows"`
	RowGroups int64 `json:"row_groups"`
}

type ParquetMaterializationStats struct {
	RowGroupMaxRows    int64                       `json:"row_group_max_rows"`
	DictionaryMaxBytes int64                       `json:"dictionary_max_bytes"`
	Files              map[string]ParquetFileStats `json:"files"`
}

type Materialization struct {
	Counts  Counts
	Parquet ParquetMaterializationStats
}

type parquetSink[T any] struct {
	file             *os.File
	writer           *parquet.GenericWriter[T]
	buf              []T
	rowsWritten      int64
	rowGroupsWritten int64
}

const ParquetBatchRows = 1024

func newSink[T any](path string, cfg config.Config) (*parquetSink[T], error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	options := []parquet.WriterOption{
		parquet.MaxRowsPerRowGroup(cfg.ParquetRowGroupRows),
		parquet.DictionaryMaxBytes(cfg.ParquetDictionaryMaxBytes),
	}
	switch cfg.ParquetCompression {
	case "zstd":
		options = append(options, parquet.Compression(&parquet.Zstd))
	case "snappy":
		options = append(options, parquet.Compression(&parquet.Snappy))
	case "none":
		options = append(options, parquet.Compression(&parquet.Uncompressed))
	default:
		_ = f.Close()
		return nil, fmt.Errorf("unsupported parquet compression %q", cfg.ParquetCompression)
	}
	w := parquet.NewGenericWriter[T](f, options...)
	w.SetKeyValueMetadata("xq:eventizer", config.EventizerVersion)
	w.SetKeyValueMetadata("xq:analysis_contract", config.AnalysisContractVersion)
	w.SetKeyValueMetadata("xq:timestamp_precision", "nanosecond")
	w.SetKeyValueMetadata("xq:timestamp_timezone", "UTC")
	w.SetKeyValueMetadata("xq:profile", config.ProfileID)
	w.SetKeyValueMetadata("xq:compression", cfg.ParquetCompression)
	w.SetKeyValueMetadata("xq:parquet_row_group_max_rows", fmt.Sprintf("%d", cfg.ParquetRowGroupRows))
	w.SetKeyValueMetadata("xq:parquet_dictionary_max_bytes", fmt.Sprintf("%d", cfg.ParquetDictionaryMaxBytes))
	return &parquetSink[T]{file: f, writer: w, buf: make([]T, 0, ParquetBatchRows)}, nil
}
func (s *parquetSink[T]) Write(v T) error {
	s.buf = append(s.buf, v)
	if len(s.buf) >= cap(s.buf) {
		return s.Flush()
	}
	return nil
}
func (s *parquetSink[T]) Flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	n, err := s.writer.Write(s.buf)
	if err != nil {
		return err
	}
	s.rowsWritten += int64(n)
	s.buf = s.buf[:0]
	return nil
}
func (s *parquetSink[T]) Close() error {
	if s == nil || (s.writer == nil && s.file == nil) {
		return nil
	}
	var first error
	if s.writer != nil {
		if err := s.Flush(); err != nil && first == nil {
			first = err
		}
		if err := s.writer.Close(); err != nil && first == nil {
			first = err
		}
		if view := s.writer.File(); view != nil {
			s.rowGroupsWritten = int64(len(view.RowGroups()))
		}
	}
	if s.file != nil {
		if err := s.file.Close(); err != nil && first == nil {
			first = err
		}
	}
	s.writer = nil
	s.file = nil
	s.buf = nil
	return first
}

func sinkStats[T any](s *parquetSink[T]) ParquetFileStats {
	if s == nil {
		return ParquetFileStats{}
	}
	return ParquetFileStats{Rows: s.rowsWritten + int64(len(s.buf)), RowGroups: s.rowGroupsWritten}
}

func Materialize(adapterDir, outDir string, cfg config.Config) (Materialization, error) {
	var result Materialization
	result.Parquet = ParquetMaterializationStats{RowGroupMaxRows: cfg.ParquetRowGroupRows, DictionaryMaxBytes: cfg.ParquetDictionaryMaxBytes, Files: map[string]ParquetFileStats{}}
	canonical := filepath.Join(outDir, "canonical")
	analysis := filepath.Join(outDir, "analysis")
	if err := os.MkdirAll(canonical, 0o755); err != nil {
		return result, err
	}
	if err := os.MkdirAll(analysis, 0o755); err != nil {
		return result, err
	}
	if err := copyFile(filepath.Join(adapterDir, "events.ndjson"), filepath.Join(canonical, "events.jsonl")); err != nil {
		return result, err
	}
	var err error
	write := func(path string, fn func() (int64, ParquetFileStats, error), dst *int64) error {
		n, st, e := fn()
		if e != nil {
			return e
		}
		*dst = n
		result.Parquet.Files[path] = st
		return nil
	}
	if err = write("analysis/events.parquet", func() (int64, ParquetFileStats, error) {
		return materializeEvents(filepath.Join(adapterDir, "events.ndjson"), filepath.Join(analysis, "events.parquet"), cfg)
	}, &result.Counts.Events); err != nil {
		return result, err
	}
	if err = write("analysis/observations.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "observations.csv"), filepath.Join(analysis, "observations.parquet"), cfg, parseObservation)
	}, &result.Counts.Observations); err != nil {
		return result, err
	}
	if err = write("analysis/entities.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "entities.csv"), filepath.Join(analysis, "entities.parquet"), cfg, parseEntity)
	}, &result.Counts.Entities); err != nil {
		return result, err
	}
	if err = write("analysis/bindings.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "bindings.csv"), filepath.Join(analysis, "bindings.parquet"), cfg, parseBinding)
	}, &result.Counts.Bindings); err != nil {
		return result, err
	}
	if err = write("analysis/sessions.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "sessions.csv"), filepath.Join(analysis, "sessions.parquet"), cfg, parseSession)
	}, &result.Counts.Sessions); err != nil {
		return result, err
	}
	if err = write("analysis/relationships.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "relationships.csv"), filepath.Join(analysis, "relationships.parquet"), cfg, parseRelationship)
	}, &result.Counts.Relationships); err != nil {
		return result, err
	}
	if err = write("analysis/services.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "services.csv"), filepath.Join(analysis, "services.parquet"), cfg, parseService)
	}, &result.Counts.Services); err != nil {
		return result, err
	}
	if err = write("analysis/presence_intervals.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "presence_intervals.csv"), filepath.Join(analysis, "presence_intervals.parquet"), cfg, parsePresence)
	}, &result.Counts.Presence); err != nil {
		return result, err
	}
	if err = write("analysis/networks.parquet", func() (int64, ParquetFileStats, error) {
		return csvToParquet(filepath.Join(adapterDir, "networks.csv"), filepath.Join(analysis, "networks.parquet"), cfg, parseNetwork)
	}, &result.Counts.Networks); err != nil {
		return result, err
	}
	return result, nil
}

func materializeEvents(src, dst string, cfg config.Config) (int64, ParquetFileStats, error) {
	s, err := newSink[EventRow](dst, cfg)
	if err != nil {
		return 0, ParquetFileStats{}, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = s.Close()
		}
	}()
	f, err := os.Open(src)
	if err != nil {
		return 0, ParquetFileStats{}, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var n int64
	for scan.Scan() {
		var e Event
		decoder := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		decoder.UseNumber()
		if err := decoder.Decode(&e); err != nil {
			return n, ParquetFileStats{}, err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return n, ParquetFileStats{}, fmt.Errorf("event line %d must contain exactly one JSON value", n+1)
		}
		t, err := parseTime(e.EventTime)
		if err != nil {
			return n, ParquetFileStats{}, err
		}
		r := EventRow{EventID: e.ID, EventTime: nanos(t), Source: e.Source, Modality: e.Modality, Class: e.Class, Profile: e.Profile, Subject: e.Subject, Object: e.Object, Feature: e.Feature, Action: e.Action, State: e.State, Polarity: e.Polarity, Unit: e.Unit, EventizerVersion: config.EventizerVersion}
		if e.EndTime != "" {
			et, err := parseTime(e.EndTime)
			if err != nil {
				return n, ParquetFileStats{}, err
			}
			r.HasEndTime = true
			r.EndTime = nanos(et)
		}
		if e.Magnitude != nil {
			r.HasMagnitude = true
			r.Magnitude = *e.Magnitude
		}
		if e.Confidence != nil {
			r.HasConfidence = true
			r.Confidence = *e.Confidence
		}
		if b, err := json.Marshal(e.Context); err == nil {
			r.ContextJSON = string(b)
		}
		if b, err := json.Marshal(e.Provenance); err == nil {
			r.ProvenanceJSON = string(b)
		}
		if err := s.Write(r); err != nil {
			return n, ParquetFileStats{}, err
		}
		n++
	}
	if err := scan.Err(); err != nil {
		return n, ParquetFileStats{}, err
	}
	if err := s.Close(); err != nil {
		return n, ParquetFileStats{}, err
	}
	closed = true
	return n, ParquetFileStats{Rows: n, RowGroups: s.rowGroupsWritten}, nil
}

func csvToParquet[T any](src, dst string, cfg config.Config, parse func(map[string]string) (T, error)) (int64, ParquetFileStats, error) {
	f, err := os.Open(src)
	if err != nil {
		return 0, ParquetFileStats{}, err
	}
	defer f.Close()
	r := csv.NewReader(bufio.NewReaderSize(f, 1<<20))
	header, err := r.Read()
	if err != nil {
		if err == io.EOF {
			s, er := newSink[T](dst, cfg)
			if er != nil {
				return 0, ParquetFileStats{}, er
			}
			er = s.Close()
			return 0, ParquetFileStats{Rows: 0, RowGroups: s.rowGroupsWritten}, er
		}
		return 0, ParquetFileStats{}, err
	}
	s, err := newSink[T](dst, cfg)
	if err != nil {
		return 0, ParquetFileStats{}, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = s.Close()
		}
	}()
	var n int64
	for {
		rec, er := r.Read()
		if er == io.EOF {
			break
		}
		if er != nil {
			return n, ParquetFileStats{}, er
		}
		m := map[string]string{}
		for i, h := range header {
			if i < len(rec) {
				m[h] = rec[i]
			}
		}
		v, er := parse(m)
		if er != nil {
			return n, ParquetFileStats{}, er
		}
		if er = s.Write(v); er != nil {
			return n, ParquetFileStats{}, er
		}
		n++
	}
	if err = s.Close(); err != nil {
		return n, ParquetFileStats{}, err
	}
	closed = true
	return n, ParquetFileStats{Rows: n, RowGroups: s.rowGroupsWritten}, nil
}

func parseObservation(m map[string]string) (ObservationRow, error) {
	t, e := parseTime(m["event_time"])
	return ObservationRow{m["id"], nanos(t), m["class"], m["subject"], m["object"], m["feature"], m["action"], m["state"], i64(m["polarity"]), m["source"], config.EventizerVersion}, e
}
func parseEntity(m map[string]string) (EntityRow, error) {
	a, e := parseTime(m["first_observed"])
	if e != nil {
		return EntityRow{}, e
	}
	b, e := parseTime(m["last_observed"])
	return EntityRow{m["entity"], m["entity_type"], nanos(a), nanos(b), i64(m["observations"]), i64(m["as_originator"]), i64(m["as_responder"]), m["presence_scope"], bval(m["presence_eligible"]), config.EventizerVersion}, e
}
func parseBinding(m map[string]string) (BindingRow, error) {
	a, e := parseTime(m["first_observed"])
	if e != nil {
		return BindingRow{}, e
	}
	b, e := parseTime(m["last_observed"])
	return BindingRow{m["subject"], m["object"], m["kind"], nanos(a), nanos(b), i64(m["observations"]), i64(m["parent_event_count"]), bval(m["parent_events_truncated"]), m["parent_events"], config.EventizerVersion}, e
}
func parseSession(m map[string]string) (SessionRow, error) {
	a, e := parseTime(m["start"])
	if e != nil {
		return SessionRow{}, e
	}
	b, e := parseTime(m["end"])
	roleBasis := m["endpoint_role_basis"]
	roleSupported := bval(m["originator_role_supported"])
	if roleBasis == "" {
		roleBasis = "zeek_originator_responder"
		roleSupported = true
	}
	return SessionRow{m["uid"], m["subject"], m["object"], nanos(a), nanos(b), m["protocol"], m["service"], m["application_stack"], m["connection_state"], i64(first(m["subject_bytes"], m["originator_bytes"])), i64(first(m["object_bytes"], m["responder_bytes"])), roleBasis, roleSupported, m["community_id"], m["event_id"], config.EventizerVersion}, e
}
func parseRelationship(m map[string]string) (RelationshipRow, error) {
	a, e := parseTime(m["first_observed"])
	if e != nil {
		return RelationshipRow{}, e
	}
	b, e := parseTime(m["last_observed"])
	roleBasis := m["first_endpoint_role_basis"]
	roleSupported := bval(m["first_originator_role_supported"])
	if roleBasis == "" {
		roleBasis = "zeek_originator_responder"
		roleSupported = true
	}
	return RelationshipRow{m["subject"], m["object"], m["protocol"], m["application_stack"], m["directionality"], m["first_observation_directionality"], roleBasis, roleSupported, nanos(a), nanos(b), i64(m["connections"]), i64(first(m["subject_packets"], m["originator_packets"])), i64(first(m["object_packets"], m["responder_packets"])), i64(first(m["subject_bytes"], m["originator_bytes"])), i64(first(m["object_bytes"], m["responder_bytes"])), m["first_parent_event"], m["first_community_id"], i64(m["community_id_count"]), bval(m["community_ids_truncated"]), m["community_ids"], m["semantics"], config.EventizerVersion}, e
}
func parseService(m map[string]string) (ServiceRow, error) {
	a, e := parseTime(m["first_observed"])
	if e != nil {
		return ServiceRow{}, e
	}
	b, e := parseTime(m["last_observed"])
	return ServiceRow{m["service_entity"], m["endpoint_entity"], m["host_entity"], m["ip"], m["port"], m["protocol"], m["service"], nanos(a), nanos(b), i64(m["observations"]), m["evidence_source"], i64(m["parent_event_count"]), bval(m["parent_events_truncated"]), m["parent_events"], config.EventizerVersion}, e
}
func parsePresence(m map[string]string) (PresenceRow, error) {
	var a, b time.Time
	var e error
	if m["first_observed"] != "" {
		a, e = parseTime(m["first_observed"])
		if e != nil {
			return PresenceRow{}, e
		}
	}
	if m["last_observed"] != "" {
		b, e = parseTime(m["last_observed"])
		if e != nil {
			return PresenceRow{}, e
		}
	}
	return PresenceRow{m["entity"], m["scope"], nanos(a), nanos(b), f64(m["duration_s"]), i64(m["observation_count"]), m["semantics"], config.EventizerVersion}, nil
}
func parseNetwork(m map[string]string) (NetworkRow, error) {
	return NetworkRow{m["network"], m["cidrs"], m["observation_point"], m["semantics"], config.EventizerVersion}, nil
}

func copyFile(src, dst string) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.Create(dst)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	ce := out.Close()
	if e != nil {
		return e
	}
	return ce
}
func parseTime(s string) (time.Time, error) {
	return timeutil.ParseNano(s)
}
func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}
func i64(s string) int64   { v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return v }
func f64(s string) float64 { v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64); return v }
func bval(s string) bool   { v, _ := strconv.ParseBool(strings.TrimSpace(s)); return v }
func first(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
