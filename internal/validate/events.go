// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/crosscue/xqnet/internal/config"
	"github.com/crosscue/xqnet/internal/timeutil"
)

type Provenance struct {
	Producer        string         `json:"producer"`
	ProducerVersion string         `json:"producer_version"`
	Method          string         `json:"method"`
	Parents         []string       `json:"parents"`
	SourceRecords   []string       `json:"source_records"`
	Parameters      map[string]any `json:"parameters"`
}
type Event struct {
	XQVersion    string         `json:"xq_version"`
	ID           string         `json:"id"`
	EventTime    string         `json:"event_time"`
	EndTime      string         `json:"end_time,omitempty"`
	ObservedTime string         `json:"observed_time,omitempty"`
	Source       string         `json:"source"`
	Modality     string         `json:"modality"`
	Class        string         `json:"class"`
	Profile      string         `json:"profile"`
	Subject      string         `json:"subject"`
	Object       string         `json:"object"`
	Feature      string         `json:"feature"`
	Action       string         `json:"action"`
	State        string         `json:"state"`
	Polarity     *int           `json:"polarity"`
	Magnitude    *float64       `json:"magnitude,omitempty"`
	Confidence   *float64       `json:"confidence,omitempty"`
	Provenance   *Provenance    `json:"provenance"`
	Context      map[string]any `json:"context"`
}
type Report struct {
	Events int
	Errors []string
}

func EventsFile(path string) (Report, error) {
	var r Report
	f, e := os.Open(path)
	if e != nil {
		return r, fmt.Errorf("open events: %w", e)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 64*1024), 16*1024*1024)
	seen := map[string]bool{}
	line := 0
	for scan.Scan() {
		line++
		r.Events++
		var ev Event
		if e := json.Unmarshal(scan.Bytes(), &ev); e != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("line %d: invalid JSON: %v", line, e))
			continue
		}
		for _, p := range EventProblems(ev, seen) {
			r.Errors = append(r.Errors, fmt.Sprintf("line %d event %s: %s", line, ev.ID, p))
		}
	}
	if e := scan.Err(); e != nil {
		return r, fmt.Errorf("read events after line %d: %w", line, e)
	}
	if len(r.Errors) > 0 {
		return r, fmt.Errorf("%d validation error(s)", len(r.Errors))
	}
	return r, nil
}

func EventProblems(e Event, seen map[string]bool) []string {
	var p []string
	if strings.TrimSpace(e.ID) == "" {
		p = append(p, "missing id")
	} else if seen[e.ID] {
		p = append(p, "duplicate id")
	} else {
		if seen != nil {
			seen[e.ID] = true
		}
	}
	if strings.TrimSpace(e.Source) == "" {
		p = append(p, "missing source")
	}
	if strings.TrimSpace(e.Subject) == "" || strings.TrimSpace(e.Object) == "" {
		p = append(p, "subject and object are required by reference compositions")
	}
	t, timeErr := timeutil.Parse(e.EventTime)
	if timeErr != nil {
		p = append(p, "invalid event_time: "+timeErr.Error())
	}
	if e.EndTime != "" {
		end, err := timeutil.Parse(e.EndTime)
		if err != nil {
			p = append(p, "invalid end_time: "+err.Error())
		} else if timeErr == nil && end.Before(t) {
			p = append(p, "end_time precedes event_time")
		}
	}
	if e.ObservedTime != "" {
		if _, err := timeutil.Parse(e.ObservedTime); err != nil {
			p = append(p, "invalid observed_time: "+err.Error())
		}
	}
	polarity := 0
	if e.Polarity == nil {
		p = append(p, "missing polarity")
	} else {
		polarity = *e.Polarity
		if polarity < -1 || polarity > 1 {
			p = append(p, "polarity must be -1, 0 or 1")
		}
	}
	if e.Confidence != nil && (math.IsNaN(*e.Confidence) || math.IsInf(*e.Confidence, 0) || *e.Confidence < 0 || *e.Confidence > 1) {
		p = append(p, "confidence must be finite and between 0 and 1")
	}
	if e.Magnitude != nil && (math.IsNaN(*e.Magnitude) || math.IsInf(*e.Magnitude, 0)) {
		p = append(p, "magnitude must be finite")
	}
	if e.XQVersion != config.WireVersion {
		p = append(p, "wrong xq_version")
	}
	if e.Modality != config.Modality || e.Profile != config.ProfileID {
		p = append(p, "wrong modality/profile")
	}
	if strings.HasPrefix(e.Subject, "device:mac:") || strings.HasPrefix(e.Object, "device:mac:") {
		p = append(p, "MAC evidence must be interface-scoped")
	}
	if e.Provenance == nil || strings.TrimSpace(e.Provenance.Producer) == "" || strings.TrimSpace(e.Provenance.ProducerVersion) == "" || strings.TrimSpace(e.Provenance.Method) == "" {
		p = append(p, "incomplete provenance")
	}
	if e.Provenance == nil || cstr(e.Provenance.Parameters, "mapping") == "" {
		p = append(p, "missing provenance.parameters.mapping")
	}
	obs := e.Class == "normalized_observation" || e.Class == "observation" || e.Class == "transition"
	if obs {
		if cstr(e.Context, "observation_point") == "" {
			p = append(p, "observation missing observation_point")
		}
		if e.Provenance == nil || !nonemptyStrings(e.Provenance.SourceRecords) {
			p = append(p, "observation missing source_records")
		}
	}
	if e.Class == "derived" || e.Class == "fusion" || e.Class == "assessment" {
		if cstr(e.Context, "observation_point") == "" && !uniqueObservationPoints(e.Context["observation_points"]) {
			p = append(p, "derived event missing observation viewpoint")
		}
		if e.Provenance == nil || (!nonemptyStrings(e.Provenance.Parents) && !nonemptyStrings(e.Provenance.SourceRecords)) {
			p = append(p, "derived event lacks parent or source provenance")
		}
	}
	if e.Action == "xq.net:first_observed" && e.Class != "derived" {
		p = append(p, "first_observed must be derived")
	}
	if stack, exists := e.Context["application_stack"]; exists && !canonicalStack(stack) {
		p = append(p, "application_stack must be a canonical string array")
	}
	if e.Action == "xq.net:observed" {
		p = append(p, "use xq:observed, not xq.net:observed")
	}
	switch e.Feature {
	case "xq.net:connection":
		if e.Class != "normalized_observation" || e.Action != "xq:observed" || polarity != 0 || !entity(e.Object, "endpoint:") {
			p = append(p, "invalid connection composition")
		}
	case "xq.net:communication_relationship":
		if e.Class != "derived" || e.Action != "xq.net:first_observed" || polarity != 1 || !entity(e.Object, "endpoint:") {
			p = append(p, "invalid relationship composition")
		}
		d := cstr(e.Context, "evidence_directionality")
		if d != "unidirectional_observed" && d != "bidirectional_observed" {
			p = append(p, "invalid relationship directionality")
		}
		for _, k := range []string{"last_observed", "last_seen", "connections_observed", "total_connections", "total_bytes", "aggregate_directionality"} {
			if _, exists := e.Context[k]; exists {
				p = append(p, "relationship first_observed contains future aggregate field "+k)
			}
		}
	case "xq.net:address_binding":
		if !((e.Action == "xq.net:first_observed" && e.Class == "derived") || (e.Action == "xq.net:assigned" && e.Class == "normalized_observation")) || polarity != 1 || !(entity(e.Subject, "interface:") || entity(e.Subject, "device:")) || !entity(e.Object, "address:") {
			p = append(p, "invalid address binding composition")
		}
	case "xq.net:hostname_binding":
		if e.Class != "normalized_observation" || polarity != 0 || e.Action != "xq.net:reported" || !(entity(e.Subject, "interface:") || entity(e.Subject, "device:")) || !entity(e.Object, "name:host:") {
			p = append(p, "invalid hostname binding")
		}
	case "xq.net:dns_query":
		if e.Class != "normalized_observation" || polarity != 0 || e.Action != "xq.net:queried" || !entity(e.Object, "domain:") {
			p = append(p, "invalid DNS query")
		}
		for _, k := range []string{"response_code", "rejected", "answers", "answer_count"} {
			if _, ok := e.Context[k]; ok {
				p = append(p, "DNS query contains response-only field "+k)
			}
		}
	case "xq.net:name_resolution":
		if e.Class != "normalized_observation" || polarity != 0 || e.Action != "xq.net:resolved_to" || !entity(e.Subject, "domain:") || !entity(e.Object, "address:") {
			p = append(p, "invalid name resolution")
		}
	case "xq.net:name_alias":
		if e.Class != "normalized_observation" || polarity != 0 || e.Action != "xq.net:alias_of" || !entity(e.Subject, "domain:") || !entity(e.Object, "domain:") {
			p = append(p, "invalid name alias")
		}
	case "xq.net:tls_session":
		if e.Class != "normalized_observation" || polarity != 0 || e.Action != "xq:observed" || !entity(e.Object, "endpoint:") {
			p = append(p, "invalid TLS session")
		}
	case "xq.net:service":
		if e.Class != "normalized_observation" || polarity != 0 || e.Action != "xq:observed" || !entity(e.Subject, "endpoint:") || !entity(e.Object, "service:") {
			p = append(p, "invalid service observation")
		}
	case "xq.net:software":
		if e.Class != "normalized_observation" || polarity != 0 || e.Action != "xq:observed" || !entity(e.Object, "software:") {
			p = append(p, "invalid software observation")
		}
	case "xq:presence":
		if e.Class != "derived" || e.Action != "xq.net:first_observed" || e.State != "xq:present" || polarity != 1 || !entity(e.Object, "network:") {
			p = append(p, "invalid scoped presence")
		}
		if cstr(e.Context, "network_context") != e.Object {
			p = append(p, "presence network_context must match object")
		}
	default:
		p = append(p, "unsupported reference feature "+e.Feature)
	}
	return p
}
func cstr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return strings.TrimSpace(s)
}

func entity(s, prefix string) bool {
	return strings.HasPrefix(s, prefix) && strings.TrimSpace(strings.TrimPrefix(s, prefix)) != ""
}

func nonemptyStrings(ss []string) bool {
	if len(ss) == 0 {
		return false
	}
	for _, s := range ss {
		if strings.TrimSpace(s) == "" {
			return false
		}
	}
	return true
}

func stringArray(v any) ([]string, bool) {
	if ss, ok := v.([]string); ok {
		return ss, true
	}
	vs, ok := v.([]any)
	if !ok {
		return nil, false
	}
	ss := make([]string, len(vs))
	for i, v := range vs {
		var ok bool
		ss[i], ok = v.(string)
		if !ok {
			return nil, false
		}
	}
	return ss, true
}

func uniqueObservationPoints(v any) bool {
	ss, ok := stringArray(v)
	if !ok || !nonemptyStrings(ss) {
		return false
	}
	seen := map[string]bool{}
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func canonicalStack(v any) bool {
	ss, ok := stringArray(v)
	if !ok {
		return false
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if s == "" || s != strings.ToLower(strings.TrimSpace(s)) || s == "ssl" || s == "-" || strings.Contains(s, ",") || seen[s] {
			return false
		}
		seen[s] = true
	}
	return sort.SliceIsSorted(ss, func(i, j int) bool {
		if (ss[i] == "tls") != (ss[j] == "tls") {
			return ss[j] == "tls"
		}
		return ss[i] < ss[j]
	})
}
