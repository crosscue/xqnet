// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package suricata

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/crosscue/xqnet/internal/inputkind"
	"github.com/crosscue/xqnet/internal/timeutil"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	version                   = "0.1.3-rc5"
	namespace                 = "xq.net"
	modality                  = "xq:network"
	profile                   = "xq.net:profile-0.1"
	coreObserved              = "xq:observed"
	corePresence              = "xq:presence"
	maxProjectionParentEvents = 32
)

type Provenance struct {
	Producer        string         `json:"producer,omitempty"`
	ProducerVersion string         `json:"producer_version,omitempty"`
	Method          string         `json:"method,omitempty"`
	Parents         []string       `json:"parents,omitempty"`
	SourceRecords   []string       `json:"source_records,omitempty"`
	Parameters      map[string]any `json:"parameters,omitempty"`
}

type CoreEvent struct {
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
	Polarity     int            `json:"polarity"`
	Magnitude    *float64       `json:"magnitude,omitempty"`
	Unit         string         `json:"unit,omitempty"`
	Confidence   *float64       `json:"confidence,omitempty"`
	Provenance   *Provenance    `json:"provenance,omitempty"`
	Context      map[string]any `json:"context,omitempty"`
}

type EntityStat struct {
	Entity               string
	EntityType           string
	First                time.Time
	Last                 time.Time
	Observations         int
	AsOriginator         int
	AsResponder          int
	FirstParent          string
	PresenceEligible     bool
	PresenceScope        string
	PresenceFirst        time.Time
	PresenceLast         time.Time
	PresenceObservations int
	PresenceFirstParent  string
}

type Relationship struct {
	Subject             string
	Object              string
	Proto               string
	AppStack            string
	FirstAppStack       string
	FirstDirectionality string
	FirstRoleBasis      string
	FirstRoleSupported  bool
	First               time.Time
	Last                time.Time
	Connections         int
	OrigBytes           int64
	RespBytes           int64
	OrigPkts            int64
	RespPkts            int64
	FirstParent         string
}

type Binding struct {
	Subject          string
	Object           string
	Kind             string
	First            time.Time
	Last             time.Time
	Count            int
	ParentEventCount int
	ParentIDs        []string
}

type NetworkContext struct {
	ID               string
	CIDRs            []string
	ObservationPoint string
}

type ServiceStat struct {
	Entity           string
	EndpointEntity   string
	HostEntity       string
	IP               string
	Port             string
	Proto            string
	Service          string
	First            time.Time
	Last             time.Time
	Observations     int
	Source           string
	ParentEventCount int
	ParentIDs        []string
}

type Session struct {
	UID                     string
	Subject                 string
	Object                  string
	Start                   time.Time
	End                     time.Time
	Proto                   string
	Service                 string
	AppStack                string
	State                   string
	OrigBytes               int64
	RespBytes               int64
	RoleBasis               string
	OriginatorRoleSupported bool
	CommunityID             string
	EventID                 string
}

type AppState struct {
	Source        string
	InputDir      string
	Events        []CoreEvent
	Entities      map[string]*EntityStat
	Relationships map[string]*Relationship
	Bindings      map[string]*Binding
	Services      map[string]*ServiceStat
	Sessions      []Session
	Network       NetworkContext
	NetworkNets   []*net.IPNet
	EventIDSeeds  map[string]int
	EventIDs      map[string]bool
}

type FlowRoleHint struct {
	ClientIP   string
	ClientPort string
	ServerIP   string
	ServerPort string
	Basis      string
	Conflict   bool
}

type EVEHints struct {
	DNSRequests map[string]bool
	FlowRoles   map[string]*FlowRoleHint
}

type Options struct {
	InputPath    string
	OutDir       string
	Source       string
	EnginePath   string
	ConfigPath   string
	PCAP         bool
	NetworkID    string
	NetworkCIDRs string
}

type Stats struct {
	Events, Entities, Bindings, Relationships, Services, Sessions int
}

func Run(opts Options) (Stats, error) {
	var zero Stats
	if strings.TrimSpace(opts.InputPath) == "" {
		return zero, errors.New("input path is required")
	}
	if strings.TrimSpace(opts.OutDir) == "" {
		return zero, errors.New("output directory is required")
	}
	if strings.TrimSpace(opts.Source) == "" {
		return zero, errors.New("source is required")
	}
	evePath := opts.InputPath
	cleanup := func() {}
	if opts.PCAP {
		var err error
		evePath, cleanup, err = runSuricata(opts.InputPath, opts.EnginePath, opts.ConfigPath)
		if err != nil {
			return zero, err
		}
		defer cleanup()
	}
	nets, cidrs, err := parseNetworkCIDRs(opts.NetworkCIDRs)
	if err != nil {
		return zero, fmt.Errorf("network CIDRs: %w", err)
	}
	if opts.NetworkCIDRs != "" && opts.NetworkID == "" {
		return zero, errors.New("network-cidrs requires network-id")
	}
	st := &AppState{Source: opts.Source, InputDir: filepath.Dir(evePath), Entities: map[string]*EntityStat{}, Relationships: map[string]*Relationship{}, Bindings: map[string]*Binding{}, Services: map[string]*ServiceStat{}, Network: NetworkContext{ID: opts.NetworkID, CIDRs: cidrs, ObservationPoint: opts.Source}, NetworkNets: nets, EventIDSeeds: map[string]int{}, EventIDs: map[string]bool{}}
	if err := processEVE(st, evePath); err != nil {
		return zero, err
	}
	deriveEvents(st)
	sortEvents(st.Events)
	if err := validateGeneratedProfileEvents(st.Events); err != nil {
		return zero, fmt.Errorf("generated Network Profile validation failed: %w", err)
	}
	if err := writeOutputs(st, opts.OutDir); err != nil {
		return zero, err
	}
	return Stats{len(st.Events), len(st.Entities), len(st.Bindings), len(st.Relationships), len(st.Services), len(st.Sessions)}, nil
}

func runSuricata(pcap, configuredPath, configPath string) (string, func(), error) {
	bin := strings.TrimSpace(configuredPath)
	if bin == "" {
		var err error
		bin, err = exec.LookPath("suricata")
		if err != nil {
			return "", func() {}, errors.New("suricata executable not found in PATH; install Suricata, use --suricata to specify the executable, or pass pre-generated EVE JSON as the input")
		}
	}
	absPCAP, err := filepath.Abs(pcap)
	if err != nil {
		return "", func() {}, err
	}
	work, err := os.MkdirTemp("", "crosscue-suricata-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.RemoveAll(work) }
	args := []string{"-r", absPCAP, "-l", work}
	if strings.TrimSpace(configPath) != "" {
		absCfg, err := filepath.Abs(configPath)
		if err != nil {
			cleanup()
			return "", func() {}, err
		}
		args = append([]string{"-c", absCfg}, args...)
	}
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	eve := filepath.Join(work, "eve.json")
	if _, err := os.Stat(eve); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("Suricata completed but %s was not produced (check eve-log configuration): %w", eve, err)
	}
	return eve, cleanup, nil
}

func processEVE(st *AppState, path string) error {
	hints, err := collectEVEHints(path)
	if err != nil {
		return err
	}
	return readJSONLines(path, func(line int, rec map[string]any) error {
		eventType := strings.ToLower(str(rec, "event_type"))
		switch eventType {
		case "flow", "dns", "tls", "arp", "dhcp", "http", "http2", "ssh", "smtp", "imap", "ftp", "pgsql", "smb", "quic":
		default:
			// Unmapped EVE types do not contribute evidence to this eventizer.
			return nil
		}
		ts, err := parseSourceTime(rec["timestamp"])
		if err != nil {
			return fmt.Errorf("line %d: timestamp: %w", line, err)
		}
		srcRec := eveSourceRecord(path, line, rec)
		switch eventType {
		case "flow":
			if err := processFlowRecord(st, rec, ts, srcRec, hints.FlowRoles[valueString(rec["flow_id"])]); err != nil {
				return fmt.Errorf("line %d: %w", line, err)
			}
		case "dns":
			processDNSRecord(st, rec, ts, srcRec, hints.DNSRequests)
		case "tls":
			processTLSRecord(st, rec, ts, srcRec)
		case "arp":
			processARPRecord(st, rec, ts, srcRec)
		case "dhcp":
			processDHCPRecord(st, rec, ts, srcRec)
		case "http", "http2", "ssh", "smtp", "imap", "ftp", "pgsql", "smb", "quic":
			// These records can provide application-service evidence even when the
			// profile does not yet define protocol-specific semantic events.
			processApplicationEvidence(st, rec, ts, srcRec, eventType)
		}
		return nil
	})
}

func collectEVEHints(path string) (*EVEHints, error) {
	h := &EVEHints{DNSRequests: map[string]bool{}, FlowRoles: map[string]*FlowRoleHint{}}
	err := readJSONLines(path, func(_ int, rec map[string]any) error {
		fid := valueString(rec["flow_id"])
		et := strings.ToLower(str(rec, "event_type"))
		if et == "dns" {
			dns := mapVal(rec["dns"])
			typ := strings.ToLower(firstNonEmpty(valueString(dns["type"]), valueString(dns["event_type"])))
			key := firstNonEmpty(fid, str(rec, "src_ip")+">"+str(rec, "dest_ip")) + ":" + valueString(dns["id"])
			if typ == "request" || typ == "query" {
				h.DNSRequests[key] = true
				addFlowRoleHint(h.FlowRoles, fid, str(rec, "src_ip"), valueString(rec["src_port"]), str(rec, "dest_ip"), valueString(rec["dest_port"]), "dns_request")
			} else if typ == "response" || typ == "answer" {
				addFlowRoleHint(h.FlowRoles, fid, str(rec, "dest_ip"), valueString(rec["dest_port"]), str(rec, "src_ip"), valueString(rec["src_port"]), "dns_response")
			}
		}
		if fid != "" && (et == "http" || et == "http2" || et == "tls") {
			addFlowRoleHint(h.FlowRoles, fid, str(rec, "src_ip"), valueString(rec["src_port"]), str(rec, "dest_ip"), valueString(rec["dest_port"]), et+"_protocol_event")
		}
		return nil
	})
	return h, err
}

func addFlowRoleHint(m map[string]*FlowRoleHint, fid, clientIP, clientPort, serverIP, serverPort, basis string) {
	if fid == "" || clientIP == "" || serverIP == "" {
		return
	}
	h := m[fid]
	if h == nil {
		m[fid] = &FlowRoleHint{ClientIP: clientIP, ClientPort: clientPort, ServerIP: serverIP, ServerPort: serverPort, Basis: basis}
		return
	}
	if h.ClientIP != clientIP || h.ServerIP != serverIP || (h.ClientPort != "" && clientPort != "" && h.ClientPort != clientPort) || (h.ServerPort != "" && serverPort != "" && h.ServerPort != serverPort) {
		h.Conflict = true
		return
	}
	if h.Basis != basis && !strings.Contains(h.Basis, basis) {
		h.Basis += "+" + basis
	}
}

func eveSourceRecord(path string, line int, rec map[string]any) string {
	s := sourceRecord(path, line, firstNonEmpty(valueString(rec["flow_id"]), valueString(rec["tx_id"])))
	if f := strings.TrimSpace(valueString(rec["pcap_filename"])); f != "" {
		s += ":pcap:" + filepath.Base(f)
	}
	if n := strings.TrimSpace(valueString(rec["pcap_cnt"])); n != "" {
		s += ":packet:" + n
	}
	return s
}

func processFlowRecord(st *AppState, rec map[string]any, sourceTS time.Time, srcRec string, hint *FlowRoleHint) error {
	srcIP, dstIP := str(rec, "src_ip"), str(rec, "dest_ip")
	if srcIP == "" || dstIP == "" {
		return nil
	}
	proto := strings.ToLower(str(rec, "proto"))
	if proto == "" {
		proto = "unknown"
	}
	flow := mapVal(rec["flow"])
	start, end := sourceTS, sourceTS
	for _, bound := range []struct {
		name string
		dst  *time.Time
	}{{"start", &start}, {"end", &end}} {
		if raw, exists := flow[bound.name]; exists {
			t, err := parseSourceTime(raw)
			if err != nil {
				return fmt.Errorf("flow.%s: %w", bound.name, err)
			}
			*bound.dst = t
		}
	}
	if end.Before(start) {
		return errors.New("flow.end precedes flow.start")
	}
	// An EVE flow record is a whole-flow summary. Anchor the semantic point
	// observation at flow.end so its aggregate counters are temporally supportable.
	eventTS := end

	subjectIP, objectIP := srcIP, dstIP
	subjectPort, objectPort := valueString(rec["src_port"]), valueString(rec["dest_port"])
	roleBasis := "suricata_flow_source_destination"
	roleSupported := false
	if hint != nil && !hint.Conflict && hint.ClientIP != "" && hint.ServerIP != "" {
		subjectIP, objectIP = hint.ClientIP, hint.ServerIP
		subjectPort, objectPort = hint.ClientPort, hint.ServerPort
		roleBasis = hint.Basis
		roleSupported = true
	} else if hint != nil && hint.Conflict {
		roleBasis = "conflicting_suricata_role_evidence"
	} else if applicationStack(rec) != nil && len(applicationStack(rec)) > 0 {
		roleBasis = "suricata_app_protocol_direction_unconfirmed"
	}

	subject := entityForIP(st, subjectIP)
	object := endpointEntity(objectIP, objectPort, proto)
	toServerPkts, toClientPkts := int64Any(flow["pkts_toserver"]), int64Any(flow["pkts_toclient"])
	toServerBytes, toClientBytes := int64Any(flow["bytes_toserver"]), int64Any(flow["bytes_toclient"])
	state := strings.ToLower(valueString(flow["state"]))
	appStack := applicationStack(rec)
	ctx := compactContext(map[string]any{
		"suricata_flow_id": valueOrNil(rec["flow_id"]), "community_id": valueOrNil(rec["community_id"]), "protocol": proto,
		"source_record_time": fmtTime(sourceTS), "source_interval_start": fmtTime(start), "source_interval_end": fmtTime(end),
		"source_port": valueOrNil(rec["src_port"]), "destination_port": valueOrNil(rec["dest_port"]),
		"subject_port": subjectPort, "object_port": objectPort,
		"flow_state": state, "flow_reason": valueString(flow["reason"]),
		"subject_packets": toServerPkts, "object_packets": toClientPkts,
		"subject_bytes": toServerBytes, "object_bytes": toClientBytes,
		"originator_role_supported": roleSupported, "endpoint_role_basis": roleBasis,
		"application_stack": appStack,
		"interpretation":    "whole-flow EVE summary anchored at flow.end; aggregate knowledge is not backdated to flow.start or the EVE pseudo-record timestamp; client/server role is asserted only when corroborating Suricata role evidence is available",
	})
	if roleSupported {
		ctx["originator_port"] = subjectPort
		ctx["responder_port"] = objectPort
		ctx["originator_packets"] = toServerPkts
		ctx["responder_packets"] = toClientPkts
		ctx["originator_bytes"] = toServerBytes
		ctx["responder_bytes"] = toClientBytes
	}
	ev := newEvent(st, eventTS, "normalized_observation", subject, object, namespace+":connection", coreObserved, "", 0, ctx, srcRec, "suricata-flow-normalize")
	st.Events = append(st.Events, ev)
	touchEntity(st, subject, eventTS, ev.ID, true, false)
	responder := entityForIP(st, objectIP)
	touchEntity(st, responder, eventTS, ev.ID, false, true)
	touchEntity(st, object, eventTS, ev.ID, false, false)
	observePresence(st, subject, subjectIP, eventTS, ev.ID)
	observePresence(st, responder, objectIP, eventTS, ev.ID)
	for _, svc := range appStack {
		touchService(st, object, responder, objectIP, objectPort, proto, svc, eventTS, "suricata-flow-app-proto", ev.ID)
	}
	uid := "flow:" + firstNonEmpty(valueString(rec["flow_id"]), safeID(formatTime(eventTS)+"-"+subjectIP+"-"+objectIP))
	st.Sessions = append(st.Sessions, Session{UID: uid, Subject: subject, Object: object, Start: start, End: end, Proto: proto, Service: strings.Join(appStack, ","), AppStack: strings.Join(appStack, ","), State: state, OrigBytes: toServerBytes, RespBytes: toClientBytes, RoleBasis: roleBasis, OriginatorRoleSupported: roleSupported, CommunityID: valueString(rec["community_id"]), EventID: ev.ID})
	if !suricataRelationshipQualified(proto, toServerPkts, toClientPkts, toServerBytes, toClientBytes) {
		return nil
	}
	key := subject + "\x00" + object + "\x00" + proto
	r := st.Relationships[key]
	dir := "unidirectional_observed"
	if toClientPkts > 0 || toClientBytes > 0 {
		dir = "bidirectional_observed"
	}
	if r == nil {
		r = &Relationship{Subject: subject, Object: object, Proto: proto, First: eventTS, Last: eventTS, FirstParent: ev.ID, FirstDirectionality: dir, FirstAppStack: strings.Join(appStack, ","), FirstRoleBasis: roleBasis, FirstRoleSupported: roleSupported}
		st.Relationships[key] = r
	}
	if eventTS.Before(r.First) {
		r.First, r.FirstParent, r.FirstDirectionality, r.FirstAppStack, r.FirstRoleBasis, r.FirstRoleSupported = eventTS, ev.ID, dir, strings.Join(appStack, ","), roleBasis, roleSupported
	}
	if eventTS.After(r.Last) {
		r.Last = eventTS
	}
	r.Connections++
	r.OrigPkts += toServerPkts
	r.RespPkts += toClientPkts
	r.OrigBytes += toServerBytes
	r.RespBytes += toClientBytes
	r.AppStack = mergeCommaSet(r.AppStack, strings.Join(appStack, ","))
	return nil
}

func processDNSRecord(st *AppState, rec map[string]any, ts time.Time, srcRec string, seen map[string]bool) {
	dns := mapVal(rec["dns"])
	if len(dns) == 0 {
		return
	}
	typ := strings.ToLower(firstNonEmpty(valueString(dns["type"]), valueString(dns["event_type"])))
	key := firstNonEmpty(valueString(rec["flow_id"]), str(rec, "src_ip")+">"+str(rec, "dest_ip")) + ":" + valueString(dns["id"])
	queries := dnsQueries(dns)
	if typ == "request" || typ == "query" {
		seen[key] = true
		for qi, q := range queries {
			name := normalizeDomain(q.Name)
			if name == "" {
				continue
			}
			subject := entityForIP(st, str(rec, "src_ip"))
			domain := "domain:" + name
			ctx := compactContext(map[string]any{"suricata_flow_id": valueOrNil(rec["flow_id"]), "community_id": valueOrNil(rec["community_id"]), "dns_id": valueOrNil(dns["id"]), "query_type": q.Type, "server_ip": str(rec, "dest_ip"), "server_port": valueOrNil(rec["dest_port"]), "protocol": strings.ToLower(str(rec, "proto"))})
			ev := newEvent(st, ts, "normalized_observation", subject, domain, namespace+":dns_query", namespace+":queried", "", 0, ctx, srcRec+fmt.Sprintf(":query:%d", qi), "suricata-dns-request-normalize")
			st.Events = append(st.Events, ev)
			touchEntity(st, subject, ts, ev.ID, true, false)
			touchEntity(st, domain, ts, ev.ID, false, false)
			observePresence(st, subject, str(rec, "src_ip"), ts, ev.ID)
		}
		return
	}
	if typ != "response" && typ != "answer" {
		return
	}
	queryObserved := seen[key]
	answers, answerRepresentation := dnsAnswers(dns, queries)
	for ai, a := range answers {
		subjName := normalizeDomain(a.Name)
		if subjName == "" && len(queries) > 0 {
			subjName = normalizeDomain(queries[0].Name)
		}
		if subjName == "" {
			continue
		}
		subject := "domain:" + subjName
		rrtype := strings.ToUpper(a.Type)
		rdata := strings.TrimSpace(a.Data)
		if rdata == "" {
			continue
		}
		ctx := compactContext(map[string]any{"suricata_flow_id": valueOrNil(rec["flow_id"]), "community_id": valueOrNil(rec["community_id"]), "dns_id": valueOrNil(dns["id"]), "rrtype": rrtype, "ttl": a.TTL, "response_code": firstNonEmpty(valueString(dns["rcode"]), valueString(dns["rcode_name"])), "query_observed": queryObserved, "answer_representation": answerRepresentation, "server_ip": str(rec, "src_ip"), "client_ip": str(rec, "dest_ip")})
		if rrtype == "A" || rrtype == "AAAA" {
			if net.ParseIP(rdata) == nil {
				continue
			}
			object := addressEntity(rdata)
			ev := newEvent(st, ts, "normalized_observation", subject, object, namespace+":name_resolution", namespace+":resolved_to", "", 0, ctx, srcRec+fmt.Sprintf(":answer:%d", ai), "suricata-dns-answer-address-normalize")
			st.Events = append(st.Events, ev)
			touchEntity(st, subject, ts, ev.ID, false, false)
			touchEntity(st, object, ts, ev.ID, false, false)
			touchBinding(st, subject, object, "dns_address_binding", ts, ev.ID)
		} else if rrtype == "CNAME" {
			target := normalizeDomain(rdata)
			if target == "" {
				continue
			}
			object := "domain:" + target
			ev := newEvent(st, ts, "normalized_observation", subject, object, namespace+":name_alias", namespace+":alias_of", "", 0, ctx, srcRec+fmt.Sprintf(":answer:%d", ai), "suricata-dns-answer-alias-normalize")
			st.Events = append(st.Events, ev)
			touchEntity(st, subject, ts, ev.ID, false, false)
			touchEntity(st, object, ts, ev.ID, false, false)
			touchBinding(st, subject, object, "dns_alias", ts, ev.ID)
		}
	}
}

type dnsItem struct {
	Name, Type, Data string
	TTL              any
}

func dnsQueries(dns map[string]any) []dnsItem {
	out := []dnsItem{}
	if arr, ok := dns["queries"].([]any); ok {
		for _, v := range arr {
			m := mapVal(v)
			out = append(out, dnsItem{Name: valueString(m["rrname"]), Type: valueString(m["rrtype"])})
		}
	}
	if len(out) == 0 && valueString(dns["rrname"]) != "" {
		out = append(out, dnsItem{Name: valueString(dns["rrname"]), Type: valueString(dns["rrtype"])})
	}
	return out
}
func dnsAnswers(dns map[string]any, queries []dnsItem) ([]dnsItem, string) {
	out := []dnsItem{}
	if arr, ok := dns["answers"].([]any); ok && len(arr) > 0 {
		for _, v := range arr {
			m := mapVal(v)
			out = append(out, dnsItem{Name: valueString(m["rrname"]), Type: valueString(m["rrtype"]), Data: firstNonEmpty(valueString(m["rdata"]), valueString(m["a"]), valueString(m["aaaa"]), valueString(m["cname"])), TTL: m["ttl"]})
		}
		return out, "detailed"
	}
	if valueString(dns["rdata"]) != "" {
		return []dnsItem{{Name: valueString(dns["rrname"]), Type: valueString(dns["rrtype"]), Data: valueString(dns["rdata"]), TTL: dns["ttl"]}}, "legacy_detailed"
	}
	g := mapVal(dns["grouped"])
	if len(g) == 0 || len(queries) != 1 {
		return nil, "none"
	}
	// Grouped DNS deliberately loses per-RR owner names. Use it only when the
	// semantic owner remains unambiguous; never combine grouped CNAME+A data into
	// a manufactured direct query-name→address binding.
	q := queries[0].Name
	cnames := groupedStrings(g, "CNAME")
	if len(cnames) > 0 {
		if len(cnames) == 1 {
			out = append(out, dnsItem{Name: q, Type: "CNAME", Data: cnames[0]})
		}
		return out, "grouped_conservative"
	}
	for _, typ := range []string{"A", "AAAA"} {
		for _, data := range groupedStrings(g, typ) {
			out = append(out, dnsItem{Name: q, Type: typ, Data: data})
		}
	}
	return out, "grouped_conservative"
}

func groupedStrings(g map[string]any, want string) []string {
	for k, v := range g {
		if strings.EqualFold(k, want) {
			return stringSlice(v)
		}
	}
	return nil
}

func processTLSRecord(st *AppState, rec map[string]any, ts time.Time, srcRec string) {
	srcIP, dstIP := str(rec, "src_ip"), str(rec, "dest_ip")
	if srcIP == "" || dstIP == "" {
		return
	}
	proto := strings.ToLower(str(rec, "proto"))
	if proto == "" {
		proto = "tcp"
	}
	port := valueString(rec["dest_port"])
	subject := entityForIP(st, srcIP)
	endpoint := endpointEntity(dstIP, port, proto)
	tls := mapVal(rec["tls"])
	sni := normalizeDomain(valueString(tls["sni"]))
	ctx := compactContext(map[string]any{"suricata_flow_id": valueOrNil(rec["flow_id"]), "community_id": valueOrNil(rec["community_id"]), "server_ip": dstIP, "server_port": valueOrNil(rec["dest_port"]), "server_name": sni, "version": valueString(tls["version"]), "subject": valueString(tls["subject"]), "issuer": valueString(tls["issuer"]), "serial": valueString(tls["serial"]), "fingerprint": valueString(tls["fingerprint"]), "session_resumed": valueOrNil(tls["session_resumed"])})
	ev := newEvent(st, ts, "normalized_observation", subject, endpoint, namespace+":tls_session", coreObserved, "", 0, ctx, srcRec, "suricata-tls-normalize")
	st.Events = append(st.Events, ev)
	touchEntity(st, subject, ts, ev.ID, true, false)
	responder := entityForIP(st, dstIP)
	touchEntity(st, responder, ts, ev.ID, false, true)
	touchEntity(st, endpoint, ts, ev.ID, false, false)
	observePresence(st, subject, srcIP, ts, ev.ID)
	observePresence(st, responder, dstIP, ts, ev.ID)
	touchService(st, endpoint, responder, dstIP, port, proto, "tls", ts, "suricata-tls", ev.ID)
	if sni != "" {
		domain := "domain:" + sni
		touchEntity(st, domain, ts, ev.ID, false, false)
		touchBinding(st, endpoint, domain, "tls_server_name_binding", ts, ev.ID)
	}
}

func processARPRecord(st *AppState, rec map[string]any, ts time.Time, srcRec string) {
	arp := mapVal(rec["arp"])
	if len(arp) == 0 {
		return
	}
	opcode := strings.ToLower(valueString(arp["opcode"]))
	emit := func(role, mac, ip string) {
		mac = normalizeMAC(mac)
		ip = strings.TrimSpace(ip)
		if !validUnicastishMAC(mac) || !validARPAddress(ip) {
			return
		}
		iface := interfaceForMAC(mac)
		address := addressEntity(ip)
		key := bindingKey(iface, address, "arp_address_binding")
		first := st.Bindings[key] == nil
		parent := ""
		if first {
			ctx := compactContext(map[string]any{"protocol": "arp", "opcode": opcode, "role": role, "mac": mac, "ip": ip, "interpretation": "first observation of Suricata ARP evidence supporting this interface/address binding; not proof of authoritative address assignment"})
			ev := newEvent(st, ts, "derived", iface, address, namespace+":address_binding", namespace+":first_observed", "", 1, ctx, srcRec, "suricata-arp-address-binding-first-observation")
			if ev.Provenance != nil {
				ev.Provenance.Parameters["coalescing"] = "first_observed_per_interface_address_binding"
				ev.Provenance.Parameters["coalescing_scope"] = st.Source
			}
			st.Events = append(st.Events, ev)
			parent = ev.ID
		}
		touchEntity(st, iface, ts, parent, role == "sender", role == "target")
		touchEntity(st, address, ts, parent, false, false)
		touchBinding(st, iface, address, "arp_address_binding", ts, parent)
		observePresence(st, iface, ip, ts, parent)
	}
	emit("sender", valueString(arp["src_mac"]), valueString(arp["src_ip"]))
	if opcode == "reply" || opcode == "response" {
		emit("target", valueString(arp["dest_mac"]), valueString(arp["dest_ip"]))
	}
}

func processDHCPRecord(st *AppState, rec map[string]any, ts time.Time, srcRec string) {
	d := mapVal(rec["dhcp"])
	if len(d) == 0 {
		return
	}
	mac := normalizeMAC(valueString(d["client_mac"]))
	if !validUnicastishMAC(mac) {
		return
	}
	iface := interfaceForMAC(mac)
	touchEntity(st, iface, ts, "", true, false)
	dhcpType := strings.ToLower(valueString(d["dhcp_type"]))
	assigned := strings.TrimSpace(valueString(d["assigned_ip"]))
	if assigned != "" && net.ParseIP(assigned) != nil && (dhcpType == "ack" || dhcpType == "offer") {
		addr := addressEntity(assigned)
		ctx := compactContext(map[string]any{"dhcp_type": dhcpType, "message_type": valueString(d["type"]), "transaction_id": valueOrNil(d["id"]), "lease_time": valueOrNil(d["lease_time"]), "relay_ip": valueString(d["relay_ip"]), "client_id": valueString(d["client_id"])})
		ev := newEvent(st, ts, "normalized_observation", iface, addr, namespace+":address_binding", namespace+":assigned", "", 1, ctx, srcRec, "suricata-dhcp-address-assignment")
		st.Events = append(st.Events, ev)
		touchEntity(st, iface, ts, ev.ID, true, false)
		touchEntity(st, addr, ts, ev.ID, false, false)
		touchBinding(st, iface, addr, "dhcp_address_binding", ts, ev.ID)
		observePresence(st, iface, assigned, ts, ev.ID)
	}
	if host := normalizeHost(valueString(d["hostname"])); host != "" {
		h := "name:host:" + host
		ev := newEvent(st, ts, "normalized_observation", iface, h, namespace+":hostname_binding", namespace+":reported", "", 0, compactContext(map[string]any{"dhcp_type": dhcpType, "transaction_id": valueOrNil(d["id"])}), srcRec, "suricata-dhcp-hostname-report")
		st.Events = append(st.Events, ev)
		touchEntity(st, iface, ts, ev.ID, true, false)
		touchEntity(st, h, ts, ev.ID, false, false)
		touchBinding(st, iface, h, "dhcp_hostname_binding", ts, ev.ID)
	}
}

func processApplicationEvidence(st *AppState, rec map[string]any, ts time.Time, srcRec, eventType string) {
	srcIP, dstIP := str(rec, "src_ip"), str(rec, "dest_ip")
	if dstIP == "" {
		return
	}
	proto := strings.ToLower(str(rec, "proto"))
	if proto == "" {
		proto = "tcp"
	}
	port := valueString(rec["dest_port"])
	endpoint := endpointEntity(dstIP, port, proto)
	responder := entityForIP(st, dstIP)
	stack := applicationStack(rec)
	if len(stack) == 0 {
		stack = canonicalizeServiceStack([]string{eventType})
	}
	for i, svc := range stack {
		service := serviceEntity(dstIP, port, proto, svc)
		first := st.Services[service] == nil
		parent := ""
		if first {
			ev := newEvent(st, ts, "normalized_observation", endpoint, service, namespace+":service", coreObserved, "", 0,
				compactContext(map[string]any{"suricata_flow_id": valueOrNil(rec["flow_id"]), "community_id": valueOrNil(rec["community_id"]), "ip": dstIP, "port": port, "protocol": proto, "service": svc, "application_stack": stack, "evidence_type": eventType, "host_entity": responder}),
				srcRec+fmt.Sprintf(":service:%d", i), "suricata-application-service-observation")
			if ev.Provenance != nil {
				ev.Provenance.Parameters["coalescing"] = "one_semantic_service_observation_per_service_entity"
			}
			st.Events = append(st.Events, ev)
			parent = ev.ID
		}
		touchEntity(st, endpoint, ts, parent, false, false)
		touchEntity(st, responder, ts, parent, false, true)
		touchService(st, endpoint, responder, dstIP, port, proto, svc, ts, "suricata-"+eventType, parent)
	}
	if srcIP != "" {
		touchEntity(st, entityForIP(st, srcIP), ts, "", true, false)
		observePresence(st, entityForIP(st, srcIP), srcIP, ts, "")
	}
}

func applicationStack(rec map[string]any) []string {
	parts := []string{}
	for _, k := range []string{"app_proto", "app_proto_ts", "app_proto_tc", "app_proto_orig", "app_proto_expected"} {
		v := valueString(rec[k])
		if v != "" && v != "failed" && v != "unknown" {
			parts = append(parts, v)
		}
	}
	return canonicalizeServiceStack(parts)
}

func suricataRelationshipQualified(proto string, origPkts, respPkts, origBytes, respBytes int64) bool {
	if origPkts <= 0 && origBytes <= 0 {
		return false
	}
	if strings.ToLower(proto) == "tcp" {
		return respPkts > 0 || respBytes > 0
	}
	return true
}

// Preserve the existing EVE layouts, but reject fractions that time.Parse would
// silently truncate. Zone-less source times retain their historical UTC meaning.
var sourceTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]([01]\d|2[0-3]):?[0-5]\d)?$`)

func parseSourceTime(raw any) (time.Time, error) {
	s, ok := raw.(string)
	if !ok {
		return time.Time{}, errors.New("timestamp must be a nonempty string")
	}
	s = strings.TrimSpace(s)
	if !sourceTimestamp.MatchString(s) {
		return time.Time{}, fmt.Errorf("invalid timestamp or more than nine fractional digits: %q", s)
	}
	layouts := []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700", "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999-0700"}
	for _, l := range layouts {
		if t, e := time.Parse(l, s); e == nil {
			return timeutil.ParseNano(t.UTC().Format(time.RFC3339Nano))
		}
	}
	return time.Time{}, fmt.Errorf("invalid source timestamp: %q", s)
}
func mapVal(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func int64Any(v any) int64 { f, _ := numberFloat(v); return int64(f) }
func deriveEvents(st *AppState) {
	for _, e := range st.Entities {
		if e.PresenceFirstParent == "" || !e.PresenceEligible || e.PresenceScope == "" || e.PresenceFirst.IsZero() {
			continue
		}
		ev := newDerivedEvent(st, e.PresenceFirst, "derived", e.Entity, e.PresenceScope,
			corePresence, namespace+":first_observed", "xq:present", 1,
			map[string]any{
				"scope":          e.PresenceScope,
				"interpretation": "first observation within an explicitly configured network scope; not equivalent to network entry",
			},
			[]string{e.PresenceFirstParent}, "scoped-presence-first-observation")
		st.Events = append(st.Events, ev)
	}
	for _, r := range st.Relationships {
		if r.FirstParent == "" {
			continue
		}
		ctx := map[string]any{
			"protocol":                  r.Proto,
			"application_stack":         canonicalizeServiceStack(splitCommaSet(r.FirstAppStack)),
			"evidence_directionality":   r.FirstDirectionality,
			"endpoint_role_basis":       r.FirstRoleBasis,
			"originator_role_supported": r.FirstRoleSupported,
			"interpretation":            "first observation of this relationship within the available telemetry; context contains only evidence available from the first parent connection",
		}
		ev := newDerivedEvent(st, r.First, "derived", r.Subject, r.Object,
			namespace+":communication_relationship", namespace+":first_observed", "", 1,
			ctx, []string{r.FirstParent}, "relationship-first-observation")
		st.Events = append(st.Events, ev)
	}
}

func newEvent(st *AppState, ts time.Time, class, subject, object, feature, action, state string, polarity int, ctx map[string]any, srcRec, method string) CoreEvent {
	seed := strings.Join([]string{st.Source, formatTime(ts), class, subject, object, feature, action, srcRec}, "|")
	id, occurrence := allocateEventID(st, seed)
	parameters := map[string]any{"mapping": method, "adapter": "suricata-reference-v1", "eventizer_algorithm": "network-reference-v1.4"}
	if occurrence > 1 {
		parameters["event_id_occurrence"] = occurrence
	}
	return CoreEvent{
		XQVersion: "0.1", ID: id, EventTime: formatTime(ts),
		Source: st.Source, Modality: modality, Class: class, Profile: profile, Subject: subject, Object: object,
		Feature: feature, Action: action, State: state, Polarity: polarity,
		Provenance: &Provenance{Producer: "xqnet", ProducerVersion: version, Method: "algorithmic", SourceRecords: nonEmptySlice(srcRec), Parameters: parameters},
		Context:    eventContext(st, ctx),
	}
}

func newDerivedEvent(st *AppState, ts time.Time, class, subject, object, feature, action, state string, polarity int, ctx map[string]any, parents []string, method string) CoreEvent {
	seed := strings.Join([]string{st.Source, formatTime(ts), class, subject, object, feature, action, strings.Join(parents, ",")}, "|")
	id, occurrence := allocateEventID(st, seed)
	parameters := map[string]any{"mapping": method, "adapter": "suricata-reference-v1", "eventizer_algorithm": "network-reference-v1.4"}
	if occurrence > 1 {
		parameters["event_id_occurrence"] = occurrence
	}
	return CoreEvent{
		XQVersion: "0.1", ID: id, EventTime: formatTime(ts),
		Source: st.Source, Modality: modality, Class: class, Profile: profile, Subject: subject, Object: object,
		Feature: feature, Action: action, State: state, Polarity: polarity,
		Provenance: &Provenance{Producer: "xqnet", ProducerVersion: version, Method: "algorithmic", Parents: parents, Parameters: parameters},
		Context:    eventContext(st, ctx),
	}
}

func touchEntity(st *AppState, entity string, ts time.Time, parent string, orig, resp bool) {
	if entity == "" {
		return
	}
	d := st.Entities[entity]
	if d == nil {
		d = &EntityStat{Entity: entity, EntityType: entityType(entity), First: ts, Last: ts, FirstParent: parent}
		st.Entities[entity] = d
	}
	if ts.Before(d.First) {
		d.First, d.FirstParent = ts, parent
	}
	if ts.After(d.Last) {
		d.Last = ts
	}
	if d.FirstParent == "" && parent != "" {
		d.FirstParent = parent
	}
	d.Observations++
	if orig {
		d.AsOriginator++
	}
	if resp {
		d.AsResponder++
	}
}

func touchBinding(st *AppState, subject, object, kind string, ts time.Time, parent string) {
	key := bindingKey(subject, object, kind)
	x := st.Bindings[key]
	if x == nil {
		x = &Binding{Subject: subject, Object: object, Kind: kind, First: ts, Last: ts}
		st.Bindings[key] = x
	}
	if ts.Before(x.First) {
		x.First = ts
	}
	if ts.After(x.Last) {
		x.Last = ts
	}
	x.Count++
	if parent != "" {
		x.ParentEventCount++
		if len(x.ParentIDs) < maxProjectionParentEvents {
			x.ParentIDs = appendUnique(x.ParentIDs, parent)
		}
	}
}

func touchService(st *AppState, endpoint, hostEntity, ip, port, proto, service string, ts time.Time, source, parent string) {
	service = normalizeService(service)
	if endpoint == "" || service == "" {
		return
	}
	entity := serviceEntity(ip, port, proto, service)
	touchEntity(st, endpoint, ts, parent, false, false)
	touchEntity(st, entity, ts, parent, false, false)
	x := st.Services[entity]
	if x == nil {
		x = &ServiceStat{Entity: entity, EndpointEntity: endpoint, HostEntity: hostEntity, IP: ip, Port: port, Proto: proto, Service: service, First: ts, Last: ts, Source: source}
		st.Services[entity] = x
	}
	if x.EndpointEntity == "" {
		x.EndpointEntity = endpoint
	}
	if x.HostEntity == "" {
		x.HostEntity = hostEntity
	}
	if ts.Before(x.First) {
		x.First = ts
		x.Source = source
	}
	if ts.After(x.Last) {
		x.Last = ts
	}
	x.Observations++
	if parent != "" {
		x.ParentEventCount++
		if len(x.ParentIDs) < maxProjectionParentEvents {
			x.ParentIDs = appendUnique(x.ParentIDs, parent)
		}
	}
	touchBinding(st, endpoint, entity, "endpoint_service_binding", ts, parent)
}

func validateGeneratedProfileEvents(events []CoreEvent) error {
	seen := map[string]bool{}
	for _, e := range events {
		if e.ID == "" || seen[e.ID] {
			return fmt.Errorf("missing or duplicate event id %q", e.ID)
		}
		seen[e.ID] = true
		if e.XQVersion != "0.1" {
			return fmt.Errorf("%s: xq_version=%q, want 0.1", e.ID, e.XQVersion)
		}
		if e.Modality != modality || e.Profile != profile {
			return fmt.Errorf("%s: invalid profile claim modality=%q profile=%q", e.ID, e.Modality, e.Profile)
		}
		if strings.HasPrefix(e.Subject, "device:mac:") || strings.HasPrefix(e.Object, "device:mac:") {
			return fmt.Errorf("%s: MAC evidence must be interface-scoped, not device-scoped", e.ID)
		}
		if e.Provenance == nil || e.Provenance.Producer == "" || e.Provenance.ProducerVersion == "" || e.Provenance.Method == "" {
			return fmt.Errorf("%s: incomplete provenance producer metadata", e.ID)
		}
		if e.Provenance.Parameters == nil || strings.TrimSpace(valueString(e.Provenance.Parameters["mapping"])) == "" {
			return fmt.Errorf("%s: provenance.parameters.mapping is required by reference eventizer", e.ID)
		}
		if e.Class == "normalized_observation" || e.Class == "observation" || e.Class == "transition" {
			if contextString(e.Context, "observation_point") == "" {
				return fmt.Errorf("%s: observation event missing context.observation_point", e.ID)
			}
			if len(e.Provenance.SourceRecords) == 0 {
				return fmt.Errorf("%s: normalized observation missing source_records", e.ID)
			}
		}
		if e.Class == "derived" || e.Class == "fusion" || e.Class == "assessment" {
			if contextString(e.Context, "observation_point") == "" && !hasUniqueObservationPoints(e.Context) {
				return fmt.Errorf("%s: derived/fusion/assessment event missing observation viewpoint", e.ID)
			}
			if len(e.Provenance.Parents) == 0 && len(e.Provenance.SourceRecords) == 0 {
				return fmt.Errorf("%s: derived event lacks parent or source provenance", e.ID)
			}
		}
		if e.Action == namespace+":first_observed" && e.Class != "derived" {
			return fmt.Errorf("%s: first_observed must be a derived fact", e.ID)
		}
		if e.Action == namespace+":observed" {
			return fmt.Errorf("%s: network-local observed is invalid; use xq:observed", e.ID)
		}

		switch e.Feature {
		case namespace + ":connection":
			if e.Class != "normalized_observation" || e.Action != coreObserved || e.Polarity != 0 || !strings.HasPrefix(e.Object, "endpoint:") {
				return fmt.Errorf("%s: invalid connection composition/endpoint target", e.ID)
			}
		case namespace + ":communication_relationship":
			if e.Class != "derived" || e.Action != namespace+":first_observed" || e.Polarity != 1 || !strings.HasPrefix(e.Object, "endpoint:") {
				return fmt.Errorf("%s: invalid communication_relationship first_observed event", e.ID)
			}
			dir := contextString(e.Context, "evidence_directionality")
			if dir != "unidirectional_observed" && dir != "bidirectional_observed" {
				return fmt.Errorf("%s: relationship missing/invalid evidence_directionality", e.ID)
			}
			for _, forbidden := range []string{"last_observed", "last_seen", "connections_observed", "total_connections", "total_bytes", "aggregate_directionality"} {
				if _, ok := e.Context[forbidden]; ok {
					return fmt.Errorf("%s: relationship first_observed contains future aggregate field %s", e.ID, forbidden)
				}
			}
		case namespace + ":address_binding":
			switch e.Action {
			case namespace + ":first_observed":
				if e.Class != "derived" || e.Polarity != 1 || !(strings.HasPrefix(e.Subject, "interface:") || strings.HasPrefix(e.Subject, "device:")) || !strings.HasPrefix(e.Object, "address:") {
					return fmt.Errorf("%s: invalid first_observed address binding", e.ID)
				}
			case namespace + ":assigned":
				if e.Class != "normalized_observation" || e.Polarity != 1 || !(strings.HasPrefix(e.Subject, "interface:") || strings.HasPrefix(e.Subject, "device:")) || !strings.HasPrefix(e.Object, "address:") {
					return fmt.Errorf("%s: invalid assigned address binding", e.ID)
				}
			default:
				return fmt.Errorf("%s: unsupported address_binding action %q", e.ID, e.Action)
			}
		case namespace + ":hostname_binding":
			if e.Class != "normalized_observation" || e.Action != namespace+":reported" || e.Polarity != 0 || !(strings.HasPrefix(e.Subject, "interface:") || strings.HasPrefix(e.Subject, "device:")) || !strings.HasPrefix(e.Object, "name:host:") {
				return fmt.Errorf("%s: invalid hostname_binding event", e.ID)
			}
		case namespace + ":dns_query":
			if e.Class != "normalized_observation" || e.Action != namespace+":queried" || e.Polarity != 0 || !strings.HasPrefix(e.Object, "domain:") {
				return fmt.Errorf("%s: invalid dns_query event", e.ID)
			}
			for _, forbidden := range []string{"response_code", "rejected", "answers", "answer_count"} {
				if _, ok := e.Context[forbidden]; ok {
					return fmt.Errorf("%s: point DNS query contains response-only field %s", e.ID, forbidden)
				}
			}
		case namespace + ":name_resolution":
			if e.Class != "normalized_observation" || e.Action != namespace+":resolved_to" || e.Polarity != 0 || !strings.HasPrefix(e.Subject, "domain:") || !strings.HasPrefix(e.Object, "address:") {
				return fmt.Errorf("%s: invalid DNS address resolution", e.ID)
			}
		case namespace + ":name_alias":
			if e.Class != "normalized_observation" || e.Action != namespace+":alias_of" || e.Polarity != 0 || !strings.HasPrefix(e.Subject, "domain:") || !strings.HasPrefix(e.Object, "domain:") {
				return fmt.Errorf("%s: invalid DNS alias event", e.ID)
			}
		case namespace + ":tls_session":
			if e.Class != "normalized_observation" || e.Action != coreObserved || e.Polarity != 0 || !strings.HasPrefix(e.Object, "endpoint:") {
				return fmt.Errorf("%s: invalid TLS session endpoint target", e.ID)
			}
		case namespace + ":service":
			if e.Class != "normalized_observation" || e.Action != coreObserved || e.Polarity != 0 || !strings.HasPrefix(e.Subject, "endpoint:") || !strings.HasPrefix(e.Object, "service:") {
				return fmt.Errorf("%s: invalid endpoint-to-service observation", e.ID)
			}
		case namespace + ":software":
			if e.Class != "normalized_observation" || e.Action != coreObserved || e.Polarity != 0 || !strings.HasPrefix(e.Object, "software:") {
				return fmt.Errorf("%s: invalid software observation", e.ID)
			}
		case corePresence:
			if e.Class != "derived" || e.Action != namespace+":first_observed" || e.State != "xq:present" || e.Polarity != 1 || !strings.HasPrefix(e.Object, "network:") {
				return fmt.Errorf("%s: invalid scoped presence event", e.ID)
			}
			if contextString(e.Context, "network_context") == "" || contextString(e.Context, "network_context") != e.Object {
				return fmt.Errorf("%s: scoped presence network_context must match object", e.ID)
			}
		default:
			return fmt.Errorf("%s: feature %q is not emitted by Network Profile 0.1 reference eventizer", e.ID, e.Feature)
		}

		if stack, ok := contextStringSlice(e.Context, "application_stack"); ok {
			canon := canonicalizeServiceStack(stack)
			if strings.Join(stack, "\x00") != strings.Join(canon, "\x00") {
				return fmt.Errorf("%s: application_stack is not canonical: %v", e.ID, stack)
			}
		}
	}
	return nil
}

func contextString(ctx map[string]any, key string) string {
	if ctx == nil {
		return ""
	}
	return strings.TrimSpace(valueString(ctx[key]))
}

func contextStringSlice(ctx map[string]any, key string) ([]string, bool) {
	if ctx == nil {
		return nil, false
	}
	v, ok := ctx[key]
	if !ok || v == nil {
		return nil, false
	}
	vals := stringSlice(v)
	return vals, true
}

func hasUniqueObservationPoints(ctx map[string]any) bool {
	vals, ok := contextStringSlice(ctx, "observation_points")
	if !ok || len(vals) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func writeOutputs(st *AppState, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := writeEvents(filepath.Join(outDir, "events.ndjson"), st.Events); err != nil {
		return err
	}
	if err := writeObservations(filepath.Join(outDir, "observations.csv"), st.Events); err != nil {
		return err
	}
	if err := writeEntities(filepath.Join(outDir, "entities.csv"), st.Entities); err != nil {
		return err
	}
	if err := writePresence(filepath.Join(outDir, "presence_intervals.csv"), st.Entities); err != nil {
		return err
	}
	if err := writeRelationships(filepath.Join(outDir, "relationships.csv"), st.Relationships); err != nil {
		return err
	}
	if err := writeBindings(filepath.Join(outDir, "bindings.csv"), st.Bindings); err != nil {
		return err
	}
	if err := writeServices(filepath.Join(outDir, "services.csv"), st.Services); err != nil {
		return err
	}
	if err := writeSessions(filepath.Join(outDir, "sessions.csv"), st.Sessions); err != nil {
		return err
	}
	if err := writeNetworks(filepath.Join(outDir, "networks.csv"), st.Network); err != nil {
		return err
	}
	return nil
}

func writeEvents(path string, events []CoreEvent) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	return nil
}

func writeObservations(path string, events []CoreEvent) error {
	rows := [][]string{{"id", "event_time", "class", "subject", "object", "feature", "action", "state", "polarity", "source"}}
	for _, e := range events {
		if e.Class != "observation" && e.Class != "normalized_observation" {
			continue
		}
		rows = append(rows, []string{e.ID, e.EventTime, e.Class, e.Subject, e.Object, e.Feature, e.Action, e.State, strconv.Itoa(e.Polarity), e.Source})
	}
	return writeCSV(path, rows)
}

func writeEntities(path string, m map[string]*EntityStat) error {
	keys := sortedKeys(m)
	rows := [][]string{{"entity", "entity_type", "first_observed", "last_observed", "observations", "as_originator", "as_responder", "presence_scope", "presence_eligible"}}
	for _, k := range keys {
		e := m[k]
		rows = append(rows, []string{e.Entity, e.EntityType, fmtTime(e.First), fmtTime(e.Last), strconv.Itoa(e.Observations), strconv.Itoa(e.AsOriginator), strconv.Itoa(e.AsResponder), e.PresenceScope, strconv.FormatBool(e.PresenceEligible)})
	}
	return writeCSV(path, rows)
}

func writePresence(path string, m map[string]*EntityStat) error {
	keys := sortedKeys(m)
	rows := [][]string{{"entity", "scope", "first_observed", "last_observed", "duration_s", "observation_count", "semantics"}}
	for _, k := range keys {
		e := m[k]
		if !e.PresenceEligible || e.PresenceScope == "" {
			continue
		}
		dur := e.PresenceLast.Sub(e.PresenceFirst).Seconds()
		rows = append(rows, []string{e.Entity, e.PresenceScope, fmtTime(e.PresenceFirst), fmtTime(e.PresenceLast), strconv.FormatFloat(dur, 'f', 6, 64), strconv.Itoa(e.PresenceObservations), "observed interval within explicit network scope; not asserted enter/leave"})
	}
	return writeCSV(path, rows)
}

func writeRelationships(path string, m map[string]*Relationship) error {
	keys := sortedKeys(m)
	rows := [][]string{{"subject", "object", "protocol", "application_stack", "directionality", "first_observation_directionality", "first_endpoint_role_basis", "first_originator_role_supported", "first_observed", "last_observed", "connections", "subject_packets", "object_packets", "subject_bytes", "object_bytes", "first_parent_event", "semantics"}}
	for _, k := range keys {
		r := m[k]
		rows = append(rows, []string{r.Subject, r.Object, r.Proto, r.AppStack, relationshipDirectionality(r), r.FirstDirectionality, r.FirstRoleBasis, strconv.FormatBool(r.FirstRoleSupported), fmtTime(r.First), fmtTime(r.Last), strconv.Itoa(r.Connections), strconv.FormatInt(r.OrigPkts, 10), strconv.FormatInt(r.RespPkts, 10), strconv.FormatInt(r.OrigBytes, 10), strconv.FormatInt(r.RespBytes, 10), r.FirstParent, "observed relationship summary; subject/object preserve the first qualifying connection orientation; role support is explicit; directionality is aggregate evidence over the projection interval; first_observed is not proof of establishment"})
	}
	return writeCSV(path, rows)
}

func writeBindings(path string, m map[string]*Binding) error {
	keys := sortedKeys(m)
	rows := [][]string{{"subject", "object", "kind", "first_observed", "last_observed", "observations", "parent_event_count", "parent_events_truncated", "parent_events"}}
	for _, k := range keys {
		x := m[k]
		rows = append(rows, []string{x.Subject, x.Object, x.Kind, fmtTime(x.First), fmtTime(x.Last), strconv.Itoa(x.Count), strconv.Itoa(x.ParentEventCount), strconv.FormatBool(x.ParentEventCount > len(x.ParentIDs)), strings.Join(x.ParentIDs, ";")})
	}
	return writeCSV(path, rows)
}

func writeServices(path string, m map[string]*ServiceStat) error {
	keys := sortedKeys(m)
	rows := [][]string{{"service_entity", "endpoint_entity", "host_entity", "ip", "port", "protocol", "service", "first_observed", "last_observed", "observations", "evidence_source", "parent_event_count", "parent_events_truncated", "parent_events"}}
	for _, k := range keys {
		x := m[k]
		rows = append(rows, []string{x.Entity, x.EndpointEntity, x.HostEntity, x.IP, x.Port, x.Proto, x.Service, fmtTime(x.First), fmtTime(x.Last), strconv.Itoa(x.Observations), x.Source, strconv.Itoa(x.ParentEventCount), strconv.FormatBool(x.ParentEventCount > len(x.ParentIDs)), strings.Join(x.ParentIDs, ";")})
	}
	return writeCSV(path, rows)
}

func writeSessions(path string, sessions []Session) error {
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].Start.Equal(sessions[j].Start) {
			return sessions[i].UID < sessions[j].UID
		}
		return sessions[i].Start.Before(sessions[j].Start)
	})
	rows := [][]string{{"uid", "subject", "object", "start", "end", "protocol", "service", "application_stack", "connection_state", "subject_bytes", "object_bytes", "endpoint_role_basis", "originator_role_supported", "community_id", "event_id"}}
	for _, s := range sessions {
		rows = append(rows, []string{s.UID, s.Subject, s.Object, fmtTime(s.Start), fmtTime(s.End), s.Proto, s.Service, s.AppStack, s.State, strconv.FormatInt(s.OrigBytes, 10), strconv.FormatInt(s.RespBytes, 10), s.RoleBasis, strconv.FormatBool(s.OriginatorRoleSupported), s.CommunityID, s.EventID})
	}
	return writeCSV(path, rows)
}

func writeNetworks(path string, n NetworkContext) error {
	rows := [][]string{{"network", "cidrs", "observation_point", "semantics"}}
	if n.ID != "" {
		rows = append(rows, []string{n.ID, strings.Join(n.CIDRs, ";"), n.ObservationPoint, "explicit observation context supplied by operator; not inferred from packet endpoints"})
	}
	return writeCSV(path, rows)
}

func writeCSV(path string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.WriteAll(rows); err != nil {
		return err
	}
	return w.Error()
}

func readJSONLines(path string, fn func(int, map[string]any) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1024*1024)
	lineNo := 0
	for {
		b, err := r.ReadBytes('\n')
		if len(b) > 0 {
			lineNo++
			if lineNo == 1 && inputkind.HasPacketCaptureMagicBytes(b) {
				return fmt.Errorf("input %q appears to be a packet capture, but Suricata EVE JSON was expected at this stage; pass the capture directly to `xqnet eventize <capture> --adapter suricata --source <source> --out <dir>` and xqnet will run Suricata automatically", path)
			}
			s := strings.TrimSpace(string(b))
			if s != "" && !strings.HasPrefix(s, "#") {
				if !strings.HasPrefix(s, "{") {
					return fmt.Errorf("line %d is not a Suricata EVE JSON record; expected newline-delimited JSON objects (for raw PCAP/PCAPNG/.dmp captures, pass the capture directly to xqnet so Suricata can decode it)", lineNo)
				}
				dec := json.NewDecoder(strings.NewReader(s))
				dec.UseNumber()
				var rec map[string]any
				if e := dec.Decode(&rec); e != nil {
					return fmt.Errorf("line %d: %w", lineNo, e)
				}
				if e := fn(lineNo, rec); e != nil {
					return e
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	return nil
}

func str(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}

func valueString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	default:
		return fmt.Sprint(x)
	}
}

func valueOrNil(v any) any {
	if v == nil {
		return nil
	}
	return v
}

func floatVal(m map[string]any, key string) float64 { f, _ := numberFloat(m[key]); return f }
func int64Val(m map[string]any, key string) int64   { f, _ := numberFloat(m[key]); return int64(f) }
func numberFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, e := x.Float64()
		return f, e == nil
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, e := strconv.ParseFloat(x, 64)
		return f, e == nil
	default:
		return 0, false
	}
}

func stringSlice(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, v := range x {
			s := valueString(v)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	default:
		return nil
	}
}

func parseNetworkCIDRs(raw string) ([]*net.IPNet, []string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil, nil
	}
	parts := strings.Split(raw, ",")
	nets := make([]*net.IPNet, 0, len(parts))
	canonical := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, nil, fmt.Errorf("%q: %w", part, err)
		}
		nets = append(nets, n)
		canonical = append(canonical, n.String())
	}
	return nets, canonical, nil
}

func entityType(entity string) string {
	switch {
	case strings.HasPrefix(entity, "device:"):
		return "device"
	case strings.HasPrefix(entity, "interface:"):
		return "interface"
	case strings.HasPrefix(entity, "address:"):
		return "address"
	case strings.HasPrefix(entity, "domain:"):
		return "domain"
	case strings.HasPrefix(entity, "endpoint:"):
		return "endpoint"
	case strings.HasPrefix(entity, "service:"):
		return "service"
	case strings.HasPrefix(entity, "name:host:"):
		return "hostname"
	case strings.HasPrefix(entity, "software:"):
		return "software"
	case strings.HasPrefix(entity, "network:"):
		return "network"
	default:
		return "entity"
	}
}

func ipInNetworkScope(st *AppState, ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || len(st.NetworkNets) == 0 {
		return false
	}
	for _, n := range st.NetworkNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func observePresence(st *AppState, entity, ip string, ts time.Time, parent string) {
	if st.Network.ID == "" || entity == "" || !ipInNetworkScope(st, ip) {
		return
	}
	// If a unique interface/device-to-address binding has already been observed by this
	// instant, project presence on the stronger supported referent rather than duplicating it on the address.
	if entityType(entity) == "address" {
		if referent := boundPresenceReferentForAddressAt(st, addressEntity(ip), ts); referent != "" {
			entity = referent
		}
	}
	d := st.Entities[entity]
	if d == nil {
		return
	}
	// Materialize the explicitly configured network scope as a projection entity
	// once evidence is observed within that scope.
	touchEntity(st, st.Network.ID, ts, parent, false, false)
	d.PresenceEligible = true
	d.PresenceScope = st.Network.ID
	if d.PresenceFirst.IsZero() || ts.Before(d.PresenceFirst) {
		d.PresenceFirst = ts
		d.PresenceFirstParent = parent
	}
	if d.PresenceLast.IsZero() || ts.After(d.PresenceLast) {
		d.PresenceLast = ts
	}
	d.PresenceObservations++
}

func boundPresenceReferentForAddressAt(st *AppState, address string, ts time.Time) string {
	referent := ""
	for _, b := range st.Bindings {
		if (b.Kind != "dhcp_address_binding" && b.Kind != "arp_address_binding") || b.Object != address || b.First.After(ts) {
			continue
		}
		if referent != "" && referent != b.Subject {
			return "" // ambiguous; preserve weaker address-scoped presence
		}
		referent = b.Subject
	}
	return referent
}

func validARPAddress(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	v4 := p.To4()
	if v4 == nil {
		return false
	}
	return !(v4[0] == 0 && v4[1] == 0 && v4[2] == 0 && v4[3] == 0)
}

func validUnicastishMAC(mac string) bool {
	mac = normalizeMAC(mac)
	if mac == "" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return false
	}
	_, err := net.ParseMAC(mac)
	return err == nil
}

func eventContext(st *AppState, ctx map[string]any) map[string]any {
	out := map[string]any{"observation_point": st.Source}
	if st.Network.ID != "" {
		out["network_context"] = st.Network.ID
	}
	for k, v := range ctx {
		out[k] = v
	}
	return compactContext(out)
}

func entityForIP(st *AppState, ip string) string {
	// Keep normalized network observations address-scoped. DHCP and ARP
	// bindings are separate evidence and may be ambiguous or change over time;
	// they must not retroactively rewrite historical traffic into interface/device facts.
	return addressEntity(ip)
}
func addressEntity(ip string) string    { return "address:ip:" + strings.ToLower(strings.TrimSpace(ip)) }
func interfaceForMAC(mac string) string { return "interface:mac:" + normalizeMAC(mac) }
func endpointEntity(ip, port, proto string) string {
	ip = strings.ToLower(strings.TrimSpace(ip))
	proto = strings.ToLower(strings.TrimSpace(proto))
	port = strings.TrimSpace(port)
	if proto == "" {
		proto = "unknown"
	}
	if usesPorts(proto) && port != "" {
		return "endpoint:ip:" + ip + ":" + port + "/" + proto
	}
	return "endpoint:ip:" + ip + "/" + proto
}

func serviceEntity(ip, port, proto, service string) string {
	service = normalizeService(service)
	if service == "" {
		return ""
	}
	ep := strings.TrimPrefix(endpointEntity(ip, port, proto), "endpoint:")
	return "service:net:" + safeID(service) + ":" + ep
}

func normalizeService(service string) string {
	s := strings.ToLower(strings.TrimSpace(service))
	if s == "-" {
		return ""
	}
	// Normalize legacy/source-native SSL labels to the profile-level TLS semantic.
	if s == "ssl" {
		return "tls"
	}
	return s
}

func normalizeServiceStack(raw string) []string {
	parts := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(raw)), func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = normalizeService(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return canonicalizeServiceStack(out)
}

func serviceStackFromValue(v any) []string {
	stack := ""
	for _, raw := range stringSlice(v) {
		stack = mergeCommaSet(stack, strings.Join(normalizeServiceStack(raw), ","))
	}
	return splitCommaSet(stack)
}

func mergeCommaSet(a, b string) string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range []string{a, b} {
		for _, v := range strings.Split(raw, ",") {
			v = strings.TrimSpace(v)
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return strings.Join(canonicalizeServiceStack(out), ",")
}

// canonicalizeServiceStack gives deterministic semantic ordering to Zeek's
// application labels. Security wrappers such as TLS sit after the application
// protocol they protect, so xmpp,ssl consistently becomes xmpp,tls rather than
// oscillating between xmpp,tls and tls,xmpp as observations are aggregated.
func canonicalizeServiceStack(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := normalizeService(raw)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := serviceStackRank(out[i]), serviceStackRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}

func serviceStackRank(service string) int {
	switch normalizeService(service) {
	case "tls":
		return 100
	default:
		return 10
	}
}

func splitCommaSet(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func relationshipDirectionality(r *Relationship) string {
	if r == nil {
		return ""
	}
	if r.RespPkts > 0 || r.RespBytes > 0 {
		return "bidirectional_observed"
	}
	return "unidirectional_observed"
}

func bindingKey(subject, object, kind string) string {
	return subject + "\x00" + object + "\x00" + kind
}

func usesPorts(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "udp", "sctp", "dccp":
		return true
	default:
		return false
	}
}
func normalizeMAC(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ":"))
}
func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
func normalizeHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
func looksLikeDomain(s string) bool {
	s = normalizeDomain(s)
	return strings.Contains(s, ".") && !strings.ContainsAny(s, " \t/")
}
func safeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" && s != "-" {
			return s
		}
	}
	return ""
}
func allocateEventID(st *AppState, seed string) (string, int) {
	if st.EventIDSeeds == nil {
		st.EventIDSeeds = map[string]int{}
	}
	if st.EventIDs == nil {
		st.EventIDs = map[string]bool{}
	}
	occurrence := st.EventIDSeeds[seed] + 1
	for {
		candidateSeed := seed
		if occurrence > 1 {
			candidateSeed += "|occurrence:" + strconv.Itoa(occurrence)
		}
		id := eventID(candidateSeed)
		if !st.EventIDs[id] {
			st.EventIDSeeds[seed] = occurrence
			st.EventIDs[id] = true
			return id, occurrence
		}
		occurrence++
	}
}

func eventID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return "evt:" + hex.EncodeToString(h[:12])
}
func sourceRecord(path string, line int, uid string) string {
	s := "suricata:" + filepath.Base(path) + ":line:" + strconv.Itoa(line)
	if uid != "" {
		s += ":record:" + uid
	}
	return s
}
func nonEmptySlice(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return formatTime(t)
}
func compactContext(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for k, v := range m {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && (s == "" || s == "-") {
			continue
		}
		if a, ok := v.([]any); ok && len(a) == 0 {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
func sortEvents(events []CoreEvent) {
	// Compare actual instants rather than RFC3339 strings. RFC3339Nano permits
	// variable fractional precision, so lexical ordering can be chronologically
	// wrong (for example .005318 sorts before .00531).
	sort.SliceStable(events, func(i, j int) bool {
		ti, iok := parseEventTime(events[i].EventTime)
		tj, jok := parseEventTime(events[j].EventTime)
		if iok && jok && !ti.Equal(tj) {
			return ti.Before(tj)
		}
		if iok != jok {
			return iok
		}
		if !iok && events[i].EventTime != events[j].EventTime {
			return events[i].EventTime < events[j].EventTime
		}
		return eventOrderLess(events[i], events[j])
	})

	for start := 0; start < len(events); {
		end := start + 1
		for end < len(events) && sameEventInstant(events[end].EventTime, events[start].EventTime) {
			end++
		}
		topologicalTimestampGroup(events[start:end])
		start = end
	}
}

func parseEventTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func sameEventInstant(a, b string) bool {
	ta, oka := parseEventTime(a)
	tb, okb := parseEventTime(b)
	if oka && okb {
		return ta.Equal(tb)
	}
	return a == b
}

func eventOrderLess(a, b CoreEvent) bool {
	if a.Class != b.Class {
		// Source observations before derived events is a useful deterministic default.
		if a.Class == "normalized_observation" || a.Class == "observation" {
			return true
		}
		if b.Class == "normalized_observation" || b.Class == "observation" {
			return false
		}
	}
	if a.Subject != b.Subject {
		return a.Subject < b.Subject
	}
	if a.Object != b.Object {
		return a.Object < b.Object
	}
	if a.Feature != b.Feature {
		return a.Feature < b.Feature
	}
	if a.Action != b.Action {
		return a.Action < b.Action
	}
	return a.ID < b.ID
}

func topologicalTimestampGroup(group []CoreEvent) {
	if len(group) < 2 {
		return
	}
	byID := make(map[string]int, len(group))
	for i := range group {
		byID[group[i].ID] = i
	}
	indegree := make([]int, len(group))
	children := make([][]int, len(group))
	for child := range group {
		if group[child].Provenance == nil {
			continue
		}
		for _, parentID := range group[child].Provenance.Parents {
			parent, ok := byID[parentID]
			if !ok {
				continue
			}
			indegree[child]++
			children[parent] = append(children[parent], child)
		}
	}
	ready := make([]int, 0, len(group))
	for i := range group {
		if indegree[i] == 0 {
			ready = append(ready, i)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return eventOrderLess(group[ready[i]], group[ready[j]]) })
	ordered := make([]CoreEvent, 0, len(group))
	for len(ready) > 0 {
		i := ready[0]
		ready = ready[1:]
		ordered = append(ordered, group[i])
		for _, child := range children[i] {
			indegree[child]--
			if indegree[child] == 0 {
				ready = append(ready, child)
				sort.Slice(ready, func(a, b int) bool { return eventOrderLess(group[ready[a]], group[ready[b]]) })
			}
		}
	}
	if len(ordered) != len(group) {
		// Cycles should be impossible; preserve the deterministic pre-sort if malformed provenance appears.
		return
	}
	copy(group, ordered)
}

func sortedKeys[T any](m map[string]*T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
