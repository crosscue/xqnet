// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crosscue/xqnet/internal/config"
	"github.com/parquet-go/parquet-go"
)

func roundTrip[T any](t *testing.T, row T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.parquet")
	sink, err := newSink[T](path, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(row); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := parquet.ReadFile[T](path)
	if err != nil || len(rows) != 1 || !reflect.DeepEqual(rows[0], row) {
		t.Fatalf("Parquet changed row: %+v, %v", rows, err)
	}
}

func TestProjectionTimestampPrecision(t *testing.T) {
	const ts = "2026-09-18T11:00:00.123456789+01:00"
	tm, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatal(err)
	}
	want := tm.UnixNano()
	m := map[string]string{"event_time": ts, "first_observed": ts, "last_observed": ts, "start": ts, "end": ts}
	ob, err := parseObservation(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, ob)
	en, err := parseEntity(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, en)
	bi, err := parseBinding(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, bi)
	se, err := parseSession(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, se)
	re, err := parseRelationship(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, re)
	sv, err := parseService(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, sv)
	pr, err := parsePresence(m)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, pr)
	for _, row := range []any{ob, en, bi, se, re, sv, pr} {
		v := reflect.ValueOf(row)
		for i := 0; i < v.NumField(); i++ {
			if strings.Contains(v.Type().Field(i).Tag.Get("parquet"), "timestamp(") && v.Field(i).Int() != want {
				t.Fatalf("%s.%s lost precision: %d", v.Type().Name(), v.Type().Field(i).Name, v.Field(i).Int())
			}
		}
	}
}

func TestCanonicalEventTimestampPrecision(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "events.jsonl"), filepath.Join(dir, "events.parquet")
	data := `{"id":"before-epoch","event_time":"1969-12-31T23:59:59.999999999Z","end_time":"1970-01-01T00:00:00.000000001Z"}` + "\n"
	if err := os.WriteFile(src, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := materializeEvents(src, dst, config.Default()); err != nil {
		t.Fatal(err)
	}
	rows, err := parquet.ReadFile[EventRow](dst)
	if err != nil || len(rows) != 1 || rows[0].EventTime != -1 || rows[0].EndTime != 1 || !rows[0].HasEndTime {
		t.Fatalf("event interval lost precision: %+v, %v", rows, err)
	}
	for _, ts := range []string{"", "1600-01-01T00:00:00Z", "2300-01-01T00:00:00Z", "2026-01-01T00:00:00.1234567891Z"} {
		if _, err := parseTime(ts); err == nil {
			t.Fatalf("silently accepted unrepresentable timestamp %q", ts)
		}
	}
}

func TestCanonicalMetadataNumbersSurviveParquet(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "events.jsonl"), filepath.Join(dir, "events.parquet")
	contextJSON := `{"large":9007199254740993,"max_unsigned":18446744073709551615,"min_signed":-9223372036854775808,"nested":[{"decimal":0.1234567890123456789,"exponent":1.234567890123456789e+20}],"label":"keep","flag":true,"absent":null}`
	provenanceJSON := `{"parameters":{"sequence":9007199254740993,"nested":[18446744073709551615]}}`
	line := `{"id":"exact","event_time":"2026-09-06T10:00:00Z","context":` + contextJSON + `,"provenance":` + provenanceJSON + `}`
	if err := os.WriteFile(src, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := materializeEvents(src, dst, config.Default()); err != nil {
		t.Fatal(err)
	}
	rows, err := parquet.ReadFile[EventRow](dst)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read Parquet: %v, %+v", err, rows)
	}
	decode := func(s string) any {
		t.Helper()
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !reflect.DeepEqual(decode(contextJSON), decode(rows[0].ContextJSON)) || !reflect.DeepEqual(decode(provenanceJSON), decode(rows[0].ProvenanceJSON)) {
		t.Fatalf("metadata changed: %s / %s", rows[0].ContextJSON, rows[0].ProvenanceJSON)
	}
	for _, trailing := range []string{` {}`, ` garbage`} {
		if err := os.WriteFile(src, []byte(line+trailing+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := materializeEvents(src, dst, config.Default()); err == nil {
			t.Fatal("accepted multiple values or trailing junk in JSONL")
		}
	}
}
