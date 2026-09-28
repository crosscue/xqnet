// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package analyst

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/pipeline"
	"github.com/crosscue/xqnet/internal/timeutil"
	"github.com/duckdb/duckdb-go/v2"
)

const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

type Options struct{ Threads int }

type Dataset struct {
	Root     string
	Manifest pipeline.Manifest
	db       *sql.DB
	views    map[string]bool
	cleanup  func()
}

var analysisTables = []string{
	"entities",
	"observations",
	"events",
	"bindings",
	"sessions",
	"relationships",
	"services",
	"presence_intervals",
	"networks",
}

type Page struct {
	Rows       []map[string]any `json:"rows"`
	Returned   int              `json:"returned"`
	HasMore    bool             `json:"has_more"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type DatasetSummary struct {
	Tool             string  `json:"tool"`
	ToolVersion      string  `json:"tool_version"`
	Eventizer        string  `json:"eventizer"`
	AnalysisContract string  `json:"analysis_contract"`
	Adapter          string  `json:"adapter"`
	InputKind        string  `json:"input_kind"`
	Source           string  `json:"source"`
	Events           int64   `json:"events"`
	Observations     int64   `json:"observations"`
	Entities         int64   `json:"entities"`
	Bindings         int64   `json:"bindings"`
	Sessions         int64   `json:"sessions"`
	Relationships    int64   `json:"relationships"`
	Services         int64   `json:"services"`
	Presence         int64   `json:"presence_intervals"`
	Networks         int64   `json:"networks"`
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
	AnalysisBytes    int64   `json:"analysis_bytes"`
	CanonicalBytes   int64   `json:"canonical_bytes"`
}

type PageInput struct {
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type EntityInput struct {
	Entity string `json:"entity" jsonschema:"network entity identifier"`
}

type SearchEntitiesInput struct {
	EntityType       string `json:"entity_type,omitempty"`
	MinObservations  int64  `json:"min_observations,omitempty"`
	MinAsOriginator  int64  `json:"min_as_originator,omitempty"`
	MinAsResponder   int64  `json:"min_as_responder,omitempty"`
	PresenceEligible *bool  `json:"presence_eligible,omitempty"`
	PresenceScope    string `json:"presence_scope,omitempty"`
	SortBy           string `json:"sort_by,omitempty"`
	Ascending        bool   `json:"ascending,omitempty"`
	Limit            int    `json:"limit,omitempty"`
	Cursor           string `json:"cursor,omitempty"`
}

type TimePageInput struct {
	Entity string `json:"entity,omitempty"`
	From   string `json:"from,omitempty" jsonschema:"RFC3339 lower time bound"`
	To     string `json:"to,omitempty" jsonschema:"RFC3339 upper time bound"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type BindingInput struct {
	Subject string `json:"subject,omitempty"`
	Object  string `json:"object,omitempty"`
	Kind    string `json:"kind,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
}

type SessionInput struct {
	Entity      string `json:"entity,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Service     string `json:"service,omitempty"`
	CommunityID string `json:"community_id,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Cursor      string `json:"cursor,omitempty"`
}

type RelationshipInput struct {
	Entity         string `json:"entity,omitempty"`
	Subject        string `json:"subject,omitempty"`
	Object         string `json:"object,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Directionality string `json:"directionality,omitempty"`
	MinConnections int64  `json:"min_connections,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	Cursor         string `json:"cursor,omitempty"`
}

type ServiceInput struct {
	EndpointEntity string `json:"endpoint_entity,omitempty"`
	HostEntity     string `json:"host_entity,omitempty"`
	Service        string `json:"service,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Limit          int    `json:"limit,omitempty"`
	Cursor         string `json:"cursor,omitempty"`
}

type PresenceInput struct {
	Entity string `json:"entity,omitempty"`
	Scope  string `json:"scope,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type EventInput struct {
	Entity  string `json:"entity,omitempty"`
	Class   string `json:"class,omitempty"`
	Feature string `json:"feature,omitempty"`
	Action  string `json:"action,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
}

type ObservationInput struct {
	Entity string `json:"entity" jsonschema:"entity required to bound evidence retrieval"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type EndpointInput struct {
	Endpoint string `json:"endpoint" jsonschema:"endpoint entity, e.g. endpoint:ip:203.0.113.8:443/tcp"`
}
type EventIDInput struct {
	EventID string `json:"event_id"`
}
type RelationshipKeyInput struct {
	Subject  string `json:"subject"`
	Object   string `json:"object"`
	Protocol string `json:"protocol,omitempty"`
}

type EndpointDescription struct {
	Endpoint      string         `json:"endpoint"`
	Entity        map[string]any `json:"entity,omitempty"`
	Services      Page           `json:"services"`
	Sessions      Page           `json:"sessions"`
	Relationships Page           `json:"relationships"`
	Bindings      Page           `json:"bindings"`
	EvidenceNote  string         `json:"evidence_note"`
}

type EventExplanation struct {
	Event         map[string]any   `json:"event"`
	Observation   map[string]any   `json:"observation,omitempty"`
	Sessions      []map[string]any `json:"sessions,omitempty"`
	Relationships []map[string]any `json:"relationships,omitempty"`
	Bindings      []map[string]any `json:"bindings,omitempty"`
	Services      []map[string]any `json:"services,omitempty"`
	EvidenceNote  string           `json:"evidence_note"`
}

type RelationshipExplanation struct {
	Relationship   map[string]any   `json:"relationship"`
	FirstEvent     map[string]any   `json:"first_event,omitempty"`
	SampleSessions []map[string]any `json:"sample_sessions,omitempty"`
	EvidenceNote   string           `json:"evidence_note"`
}

func Open(root string, opts Options) (*Dataset, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("MCP dataset must be an xqnet output directory")
	}
	b, err := os.ReadFile(filepath.Join(abs, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m pipeline.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if m.Tool != "xqnet" {
		return nil, fmt.Errorf("manifest tool is %q, expected xqnet", m.Tool)
	}
	if m.AnalysisContract != config.AnalysisContractVersion {
		return nil, fmt.Errorf("analyst API requires analysis contract %s; dataset has %s; rebuild the dataset from source telemetry with this xqnet version", config.AnalysisContractVersion, m.AnalysisContract)
	}
	if strings.ContainsAny(abs, "\r\n") {
		return nil, fmt.Errorf("dataset path contains a newline")
	}
	threads := opts.Threads
	if threads <= 0 {
		threads = 4
	}
	parquetPaths, err := analysisParquetPaths(abs)
	if err != nil {
		return nil, err
	}
	catalogDir, err := os.MkdirTemp("", "xqnet-analyst-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(catalogDir) }
	catalogPath := filepath.Join(catalogDir, "catalog.duckdb")
	if err := writeAnalysisViews(catalogPath, parquetPaths, threads); err != nil {
		cleanup()
		return nil, err
	}
	db, err := openReadOnlyAnalysis(catalogPath, parquetPaths, threads)
	if err != nil {
		cleanup()
		return nil, err
	}
	views := make(map[string]bool, len(analysisTables))
	for _, name := range analysisTables {
		views[name] = true
	}
	return &Dataset{Root: abs, Manifest: m, db: db, views: views, cleanup: cleanup}, nil
}

func (d *Dataset) Close() error {
	if d == nil {
		return nil
	}
	var err error
	if d.db != nil {
		err = d.db.Close()
	}
	if d.cleanup != nil {
		d.cleanup()
	}
	return err
}

func analysisParquetPaths(root string) (map[string]string, error) {
	paths := make(map[string]string, len(analysisTables))
	for _, name := range analysisTables {
		p := filepath.Join(root, "analysis", name+".parquet")
		info, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("dataset missing analysis/%s.parquet", name)
			}
			return nil, err
		}
		if info.IsDir() {
			return nil, fmt.Errorf("analysis/%s.parquet is a directory", name)
		}
		slash := filepath.ToSlash(p)
		if strings.ContainsAny(slash, "\r\n") {
			return nil, fmt.Errorf("analysis path contains a newline")
		}
		paths[name] = slash
	}
	return paths, nil
}

func writeAnalysisViews(catalogPath string, parquetPaths map[string]string, threads int) error {
	db, err := sql.Open("duckdb", fmt.Sprintf("%s?access_mode=READ_WRITE&threads=%d", filepath.ToSlash(catalogPath), threads))
	if err != nil {
		return fmt.Errorf("create analyst catalog: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, name := range analysisTables {
		q := fmt.Sprintf("CREATE VIEW %s AS SELECT * FROM read_parquet('%s')", name, sqlQuote(parquetPaths[name]))
		if _, err := db.ExecContext(context.Background(), q); err != nil {
			return fmt.Errorf("create DuckDB view %s: %w", name, err)
		}
	}
	return nil
}

func openReadOnlyAnalysis(catalogPath string, parquetPaths map[string]string, threads int) (*sql.DB, error) {
	allowed := make([]string, 0, len(analysisTables))
	for _, name := range analysisTables {
		allowed = append(allowed, parquetPaths[name])
	}
	boot := []string{
		"SET allowed_paths=" + sqlStringList(allowed),
		"SET enable_external_access=false",
		"SET allow_community_extensions=false",
		"SET autoinstall_known_extensions=false",
		"SET autoload_known_extensions=false",
		"SET lock_configuration=true",
	}
	connector, err := duckdb.NewConnector(fmt.Sprintf("%s?access_mode=READ_ONLY&threads=%d", filepath.ToSlash(catalogPath), threads), func(execer driver.ExecerContext) error {
		for _, q := range boot {
			if _, err := execer.ExecContext(context.Background(), q, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("open read-only DuckDB: %w", err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open read-only DuckDB: %w", err)
	}
	return db, nil
}

func sqlStringList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = "'" + sqlQuote(v) + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func sqlQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

func (d *Dataset) Summary() DatasetSummary {
	s := d.Manifest.Stats
	return DatasetSummary{Tool: d.Manifest.Tool, ToolVersion: d.Manifest.ToolVersion, Eventizer: d.Manifest.Eventizer, AnalysisContract: d.Manifest.AnalysisContract, Adapter: s.Adapter, InputKind: s.InputKind, Source: d.Manifest.Source, Events: s.Events, Observations: s.Observations, Entities: s.Entities, Bindings: s.Bindings, Sessions: s.Sessions, Relationships: s.Relationships, Services: s.Services, Presence: s.PresenceIntervals, Networks: s.Networks, ElapsedSeconds: s.ElapsedSeconds, AnalysisBytes: s.Storage.AnalysisBytes, CanonicalBytes: s.Storage.CanonicalBytes}
}

func (d *Dataset) SearchEntities(ctx context.Context, in SearchEntitiesInput) (Page, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(c string, v any) { where = append(where, c); args = append(args, v) }
	if in.EntityType != "" {
		add("entity_type = ?", in.EntityType)
	}
	if in.MinObservations > 0 {
		add("observations >= ?", in.MinObservations)
	}
	if in.MinAsOriginator > 0 {
		add("as_originator >= ?", in.MinAsOriginator)
	}
	if in.MinAsResponder > 0 {
		add("as_responder >= ?", in.MinAsResponder)
	}
	if in.PresenceEligible != nil {
		add("presence_eligible = ?", *in.PresenceEligible)
	}
	if in.PresenceScope != "" {
		add("presence_scope = ?", in.PresenceScope)
	}
	sortBy := in.SortBy
	if sortBy == "" {
		sortBy = "observations"
	}
	allowed := map[string]bool{"observations": true, "as_originator": true, "as_responder": true, "first_observed": true, "last_observed": true}
	if !allowed[sortBy] {
		return Page{}, fmt.Errorf("unsupported sort_by %q", sortBy)
	}
	dir := "DESC"
	if in.Ascending {
		dir = "ASC"
	}
	q := `SELECT entity, entity_type, first_observed, last_observed, observations, as_originator, as_responder, presence_scope, presence_eligible FROM entities WHERE ` + strings.Join(where, " AND ") + ` ORDER BY ` + sortBy + ` ` + dir + `, entity ASC`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}

func (d *Dataset) GetEntity(ctx context.Context, entity string) (map[string]any, error) {
	if strings.TrimSpace(entity) == "" {
		return nil, fmt.Errorf("entity is required")
	}
	rows, err := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM entities WHERE entity = ? LIMIT 1`, []any{entity})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("entity %q not found", entity)
	}
	return rows[0], nil
}

func (d *Dataset) GetBindings(ctx context.Context, in BindingInput) (Page, error) {
	where := []string{"1=1"}
	args := []any{}
	if in.Subject != "" {
		where = append(where, "subject = ?")
		args = append(args, in.Subject)
	}
	if in.Object != "" {
		where = append(where, "object = ?")
		args = append(args, in.Object)
	}
	if in.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, in.Kind)
	}
	if err := addTimeBounds(&where, &args, "first_observed", in.From, in.To); err != nil {
		return Page{}, err
	}
	q := `SELECT subject, object, kind, first_observed, last_observed, observations, parent_event_count, parent_events_truncated, parent_events FROM bindings WHERE ` + strings.Join(where, " AND ") + ` ORDER BY first_observed, subject, object, kind`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}
func (d *Dataset) GetSessions(ctx context.Context, in SessionInput) (Page, error) {
	where := []string{"1=1"}
	args := []any{}
	if in.Entity != "" {
		where = append(where, "(subject = ? OR object = ?)")
		args = append(args, in.Entity, in.Entity)
	}
	if in.Protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, in.Protocol)
	}
	if in.Service != "" {
		where = append(where, "service = ?")
		args = append(args, in.Service)
	}
	if in.CommunityID != "" {
		where = append(where, "community_id = ?")
		args = append(args, in.CommunityID)
	}
	if err := addTimeBounds(&where, &args, "start", in.From, in.To); err != nil {
		return Page{}, err
	}
	q := `SELECT uid, subject, object, start, "end", protocol, service, application_stack, connection_state, subject_bytes, object_bytes, endpoint_role_basis, originator_role_supported, community_id, event_id FROM sessions WHERE ` + strings.Join(where, " AND ") + ` ORDER BY start, uid`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}
func (d *Dataset) GetRelationships(ctx context.Context, in RelationshipInput) (Page, error) {
	where := []string{"1=1"}
	args := []any{}
	if in.Entity != "" {
		where = append(where, "(subject = ? OR object = ?)")
		args = append(args, in.Entity, in.Entity)
	}
	if in.Subject != "" {
		where = append(where, "subject = ?")
		args = append(args, in.Subject)
	}
	if in.Object != "" {
		where = append(where, "object = ?")
		args = append(args, in.Object)
	}
	if in.Protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, in.Protocol)
	}
	if in.Directionality != "" {
		where = append(where, "directionality = ?")
		args = append(args, in.Directionality)
	}
	if in.MinConnections > 0 {
		where = append(where, "connections >= ?")
		args = append(args, in.MinConnections)
	}
	if err := addTimeBounds(&where, &args, "first_observed", in.From, in.To); err != nil {
		return Page{}, err
	}
	q := `SELECT subject, object, protocol, application_stack, directionality, first_observation_directionality, first_endpoint_role_basis, first_originator_role_supported, first_observed, last_observed, connections, subject_packets, object_packets, subject_bytes, object_bytes, first_parent_event, first_community_id, community_id_count, community_ids_truncated, community_ids, semantics FROM relationships WHERE ` + strings.Join(where, " AND ") + ` ORDER BY first_observed, subject, object, protocol`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}
func (d *Dataset) GetServices(ctx context.Context, in ServiceInput) (Page, error) {
	where := []string{"1=1"}
	args := []any{}
	if in.EndpointEntity != "" {
		where = append(where, "endpoint_entity = ?")
		args = append(args, in.EndpointEntity)
	}
	if in.HostEntity != "" {
		where = append(where, "host_entity = ?")
		args = append(args, in.HostEntity)
	}
	if in.Service != "" {
		where = append(where, "service = ?")
		args = append(args, in.Service)
	}
	if in.Protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, in.Protocol)
	}
	if err := addTimeBounds(&where, &args, "first_observed", in.From, in.To); err != nil {
		return Page{}, err
	}
	q := `SELECT service_entity, endpoint_entity, host_entity, ip, port, protocol, service, first_observed, last_observed, observations, evidence_source, parent_event_count, parent_events_truncated, parent_events FROM services WHERE ` + strings.Join(where, " AND ") + ` ORDER BY first_observed, service_entity`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}
func (d *Dataset) GetPresence(ctx context.Context, in PresenceInput) (Page, error) {
	where := []string{"1=1"}
	args := []any{}
	if in.Entity != "" {
		where = append(where, "entity = ?")
		args = append(args, in.Entity)
	}
	if in.Scope != "" {
		where = append(where, "scope = ?")
		args = append(args, in.Scope)
	}
	if err := addTimeBounds(&where, &args, "first_observed", in.From, in.To); err != nil {
		return Page{}, err
	}
	q := `SELECT entity, scope, first_observed, last_observed, duration_s, observation_count, semantics FROM presence_intervals WHERE ` + strings.Join(where, " AND ") + ` ORDER BY first_observed, entity`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}
func (d *Dataset) GetNetworks(ctx context.Context, limit int, cursor string) (Page, error) {
	return d.queryPage(ctx, `SELECT network, cidrs, observation_point, semantics FROM networks ORDER BY network`, nil, limit, cursor)
}
func (d *Dataset) GetEvents(ctx context.Context, in EventInput) (Page, error) {
	where := []string{"1=1"}
	args := []any{}
	if in.Entity != "" {
		where = append(where, "(subject = ? OR object = ?)")
		args = append(args, in.Entity, in.Entity)
	}
	if in.Class != "" {
		where = append(where, "class = ?")
		args = append(args, in.Class)
	}
	if in.Feature != "" {
		where = append(where, "feature = ?")
		args = append(args, in.Feature)
	}
	if in.Action != "" {
		where = append(where, "action = ?")
		args = append(args, in.Action)
	}
	if err := addTimeBounds(&where, &args, "event_time", in.From, in.To); err != nil {
		return Page{}, err
	}
	q := `SELECT event_id, event_time, has_end_time, end_time, source, modality, class, profile, subject, object, feature, action, state, polarity, has_magnitude, magnitude, unit, has_confidence, confidence, context_json, provenance_json FROM events WHERE ` + strings.Join(where, " AND ") + ` ORDER BY event_time, event_id`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}
func (d *Dataset) GetObservations(ctx context.Context, in ObservationInput) (Page, error) {
	if strings.TrimSpace(in.Entity) == "" {
		return Page{}, fmt.Errorf("entity is required for get_observations")
	}
	where := []string{"(subject = ? OR object = ?)"}
	args := []any{in.Entity, in.Entity}
	if err := addTimeBounds(&where, &args, "event_time", in.From, in.To); err != nil {
		return Page{}, err
	}
	q := `SELECT event_id, event_time, class, subject, object, feature, action, state, polarity, source FROM observations WHERE ` + strings.Join(where, " AND ") + ` ORDER BY event_time, event_id`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}

func (d *Dataset) GetTimeline(ctx context.Context, in TimePageInput) (Page, error) {
	if strings.TrimSpace(in.Entity) == "" {
		return Page{}, fmt.Errorf("entity is required")
	}
	from, to, err := parseBounds(in.From, in.To)
	if err != nil {
		return Page{}, err
	}
	args := []any{}
	clause := func(base, col string, entityArgs ...any) string {
		args = append(args, entityArgs...)
		parts := []string{base}
		if !from.IsZero() {
			parts = append(parts, col+" >= ?")
			args = append(args, duckdb.Typed(from.UTC(), duckdb.TYPE_TIMESTAMP_NS))
		}
		if !to.IsZero() {
			parts = append(parts, col+" <= ?")
			args = append(args, duckdb.Typed(to.UTC(), duckdb.TYPE_TIMESTAMP_NS))
		}
		return strings.Join(parts, " AND ")
	}
	eventsWhere := clause("(subject = ? OR object = ?)", "event_time", in.Entity, in.Entity)
	sessionsWhere := clause("(subject = ? OR object = ?)", "start", in.Entity, in.Entity)
	bindingsWhere := clause("(subject = ? OR object = ?)", "first_observed", in.Entity, in.Entity)
	presenceWhere := clause("entity = ?", "first_observed", in.Entity)
	q := `SELECT * FROM (` +
		`SELECT 'event' AS timeline_kind, event_time AS time, CASE WHEN has_end_time THEN end_time ELSE NULL END AS end_time, event_id AS item_id, subject, object, feature AS kind, action AS detail FROM events WHERE ` + eventsWhere + ` UNION ALL ` +
		`SELECT 'session', start, "end", uid, subject, object, protocol, COALESCE(NULLIF(application_stack,''), service) FROM sessions WHERE ` + sessionsWhere + ` UNION ALL ` +
		`SELECT 'binding', first_observed, last_observed, subject || '->' || object || ':' || kind, subject, object, kind, CAST(observations AS VARCHAR) FROM bindings WHERE ` + bindingsWhere + ` UNION ALL ` +
		`SELECT 'presence', first_observed, last_observed, entity || ':' || scope, entity, scope, 'presence', CAST(observation_count AS VARCHAR) FROM presence_intervals WHERE ` + presenceWhere +
		`) ORDER BY time, timeline_kind, item_id`
	return d.queryPage(ctx, q, args, in.Limit, in.Cursor)
}

func (d *Dataset) DescribeEndpoint(ctx context.Context, in EndpointInput) (EndpointDescription, error) {
	if !strings.HasPrefix(in.Endpoint, "endpoint:") {
		return EndpointDescription{}, fmt.Errorf("endpoint must be an endpoint: entity")
	}
	entity, _ := d.GetEntity(ctx, in.Endpoint)
	services, err := d.GetServices(ctx, ServiceInput{EndpointEntity: in.Endpoint, Limit: 100})
	if err != nil {
		return EndpointDescription{}, err
	}
	sessions, err := d.GetSessions(ctx, SessionInput{Entity: in.Endpoint, Limit: 100})
	if err != nil {
		return EndpointDescription{}, err
	}
	rels, err := d.GetRelationships(ctx, RelationshipInput{Entity: in.Endpoint, Limit: 100})
	if err != nil {
		return EndpointDescription{}, err
	}
	binds, err := d.GetBindings(ctx, BindingInput{Subject: in.Endpoint, Limit: 100})
	if err != nil {
		return EndpointDescription{}, err
	}
	return EndpointDescription{Endpoint: in.Endpoint, Entity: entity, Services: services, Sessions: sessions, Relationships: rels, Bindings: binds, EvidenceNote: "Endpoint, service, session, binding and relationship rows are derived analytical projections over source-native network evidence; endpoint identity is not device identity."}, nil
}

func (d *Dataset) ExplainEvent(ctx context.Context, eventID string) (EventExplanation, error) {
	if strings.TrimSpace(eventID) == "" {
		return EventExplanation{}, fmt.Errorf("event_id is required")
	}
	rows, err := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM events WHERE event_id = ? LIMIT 1`, []any{eventID})
	if err != nil {
		return EventExplanation{}, err
	}
	if len(rows) == 0 {
		return EventExplanation{}, fmt.Errorf("event %q not found", eventID)
	}
	obs, _ := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM observations WHERE event_id = ? LIMIT 1`, []any{eventID})
	sessions, _ := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM sessions WHERE event_id = ? ORDER BY start LIMIT 20`, []any{eventID})
	rels, _ := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM relationships WHERE first_parent_event = ? ORDER BY first_observed LIMIT 20`, []any{eventID})
	binds, _ := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM bindings WHERE (';' || parent_events || ';') LIKE ('%;' || ? || ';%') ORDER BY first_observed LIMIT 20`, []any{eventID})
	services, _ := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM services WHERE (';' || parent_events || ';') LIKE ('%;' || ? || ';%') ORDER BY first_observed LIMIT 20`, []any{eventID})
	var ob map[string]any
	if len(obs) > 0 {
		ob = obs[0]
	}
	return EventExplanation{Event: rows[0], Observation: ob, Sessions: sessions, Relationships: rels, Bindings: binds, Services: services, EvidenceNote: "Canonical events are semantic interpretations of source evidence. Linked analytical rows summarize or project that evidence and should not be treated as independently observed facts."}, nil
}

func (d *Dataset) ExplainRelationship(ctx context.Context, in RelationshipKeyInput) (RelationshipExplanation, error) {
	if in.Subject == "" || in.Object == "" {
		return RelationshipExplanation{}, fmt.Errorf("subject and object are required")
	}
	where := `subject = ? AND object = ?`
	args := []any{in.Subject, in.Object}
	if in.Protocol != "" {
		where += ` AND protocol = ?`
		args = append(args, in.Protocol)
	}
	rows, err := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM relationships WHERE `+where+` ORDER BY first_observed LIMIT 1`, args)
	if err != nil {
		return RelationshipExplanation{}, err
	}
	if len(rows) == 0 {
		return RelationshipExplanation{}, fmt.Errorf("relationship not found")
	}
	r := rows[0]
	first := fmt.Sprint(r["first_parent_event"])
	var ev map[string]any
	if first != "" && first != "<nil>" {
		es, _ := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM events WHERE event_id = ? LIMIT 1`, []any{first})
		if len(es) > 0 {
			ev = es[0]
		}
	}
	sessions, _ := d.queryRows(ctx, `SELECT * EXCLUDE (eventizer_version) FROM sessions WHERE subject = ? AND object = ?`+func() string {
		if in.Protocol != "" {
			return ` AND protocol = ?`
		}
		return ""
	}()+` ORDER BY start LIMIT 20`, args)
	return RelationshipExplanation{Relationship: r, FirstEvent: ev, SampleSessions: sessions, EvidenceNote: "A communication relationship is derived from qualifying connection evidence. first_observed is not proof of establishment, and aggregate directionality may include later evidence unavailable to the first parent event."}, nil
}

func addTimeBounds(where *[]string, args *[]any, col, fromS, toS string) error {
	from, to, err := parseBounds(fromS, toS)
	if err != nil {
		return err
	}
	if !from.IsZero() {
		*where = append(*where, col+" >= ?")
		*args = append(*args, duckdb.Typed(from.UTC(), duckdb.TYPE_TIMESTAMP_NS))
	}
	if !to.IsZero() {
		*where = append(*where, col+" <= ?")
		*args = append(*args, duckdb.Typed(to.UTC(), duckdb.TYPE_TIMESTAMP_NS))
	}
	return nil
}
func parseBounds(fromS, toS string) (time.Time, time.Time, error) {
	var from, to time.Time
	var err error
	if fromS != "" {
		from, err = timeutil.ParseNano(fromS)
		if err != nil {
			return from, to, fmt.Errorf("from must be RFC3339: %w", err)
		}
	}
	if toS != "" {
		to, err = timeutil.ParseNano(toS)
		if err != nil {
			return from, to, fmt.Errorf("to must be RFC3339: %w", err)
		}
	}
	if !from.IsZero() && !to.IsZero() && from.After(to) {
		return from, to, fmt.Errorf("from must not be after to")
	}
	return from, to, nil
}
func (d *Dataset) queryPage(ctx context.Context, q string, args []any, limit int, cursor string) (Page, error) {
	limit = normalizeLimit(limit)
	offset, err := decodeCursor(cursor)
	if err != nil {
		return Page{}, err
	}
	args = append(args, limit+1, offset)
	rows, err := d.queryRows(ctx, q+` LIMIT ? OFFSET ?`, args)
	if err != nil {
		return Page{}, err
	}
	p := Page{}
	if len(rows) > limit {
		p.HasMore = true
		rows = rows[:limit]
		p.NextCursor = encodeCursor(offset + limit)
	}
	p.Rows = rows
	p.Returned = len(rows)
	return p, nil
}
func normalizeLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	if n > MaxLimit {
		return MaxLimit
	}
	return n
}
func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}
func decodeCursor(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid cursor")
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid cursor")
	}
	return n, nil
}
func (d *Dataset) queryRows(ctx context.Context, q string, args []any) ([]map[string]any, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[c] = normalizeSQLValue(vals[i])
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
func normalizeSQLValue(v any) any {
	switch x := v.(type) {
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []byte:
		return string(x)
	default:
		return x
	}
}
func (d *Dataset) ManifestJSON() ([]byte, error) { return json.MarshalIndent(d.Manifest, "", "  ") }
func StableMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
