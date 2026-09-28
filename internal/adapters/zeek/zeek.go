// Copyright 2026 Crosscue
// SPDX-License-Identifier: Apache-2.0

package zeek

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crosscue/xqnet/internal/timeutil"
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

const crosscueARPScript = `
@load base/frameworks/logging

module CrosscueARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        opcode: string &log;
        mac_src: string &log;
        mac_dst: string &log;
        sender_ip: addr &log;
        sender_mac: string &log;
        target_ip: addr &log;
        target_mac: string &log;
    };
}


event zeek_init() &priority=5
    {
    Log::create_stream(CrosscueARP::LOG, [$columns=CrosscueARP::Info, $path="arp"]);
    }

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    Log::write(CrosscueARP::LOG, [$ts=network_time(), $opcode="request",
                                  $mac_src=mac_src, $mac_dst=mac_dst,
                                  $sender_ip=SPA, $sender_mac=SHA,
                                  $target_ip=TPA, $target_mac=THA]);
    }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    Log::write(CrosscueARP::LOG, [$ts=network_time(), $opcode="reply",
                                  $mac_src=mac_src, $mac_dst=mac_dst,
                                  $sender_ip=SPA, $sender_mac=SHA,
                                  $target_ip=TPA, $target_mac=THA]);
    }
`

const crosscueCommunityIDScript = `
@load policy/protocols/conn/community-id-logging
redef CommunityID::seed = 0;
`

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
	First               time.Time
	Last                time.Time
	Connections         int
	OrigBytes           int64
	RespBytes           int64
	OrigPkts            int64
	RespPkts            int64
	FirstParent         string
	FirstCommunityID    string
	CommunityIDCount    int
	CommunityIDs        []string
	communityIDSeen     map[string]bool
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
	UID         string
	Subject     string
	Object      string
	Start       time.Time
	End         time.Time
	Proto       string
	Service     string
	AppStack    string
	State       string
	OrigBytes   int64
	RespBytes   int64
	EventID     string
	CommunityID string
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

type Options struct {
	InputPath    string
	OutDir       string
	Source       string
	EnginePath   string
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
	workingDir := opts.InputPath
	if opts.PCAP {
		dir, err := runZeek(opts.InputPath, opts.EnginePath)
		if err != nil {
			return zero, err
		}
		workingDir = dir
		defer os.RemoveAll(dir)
	}
	nets, cidrs, err := parseNetworkCIDRs(opts.NetworkCIDRs)
	if err != nil {
		return zero, fmt.Errorf("network CIDRs: %w", err)
	}
	if opts.NetworkCIDRs != "" && opts.NetworkID == "" {
		return zero, errors.New("network-cidrs requires network-id")
	}
	st := &AppState{Source: opts.Source, InputDir: workingDir, Entities: map[string]*EntityStat{}, Relationships: map[string]*Relationship{}, Bindings: map[string]*Binding{}, Services: map[string]*ServiceStat{}, Network: NetworkContext{ID: opts.NetworkID, CIDRs: cidrs, ObservationPoint: opts.Source}, NetworkNets: nets, EventIDSeeds: map[string]int{}, EventIDs: map[string]bool{}}
	if err := processLogs(st); err != nil {
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

func runZeek(pcap, configuredPath string) (string, error) {
	if _, err := os.Stat(pcap); err != nil {
		return "", err
	}
	zeek := strings.TrimSpace(configuredPath)
	if zeek == "" {
		var err error
		zeek, err = exec.LookPath("zeek")
		if err != nil {
			if _, statErr := os.Stat("/opt/zeek/bin/zeek"); statErr == nil {
				zeek = "/opt/zeek/bin/zeek"
			} else {
				return "", errors.New("zeek executable not found in PATH or /opt/zeek/bin/zeek; use --zeek or supply pre-generated Zeek JSON logs")
			}
		}
	} else if _, err := os.Stat(zeek); err != nil {
		return "", fmt.Errorf("configured Zeek executable %q: %w", zeek, err)
	}
	dir, err := os.MkdirTemp("", "crosscue-zeek-")
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(pcap)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	arpScript := filepath.Join(dir, "crosscue-arp.zeek")
	if err := os.WriteFile(arpScript, []byte(crosscueARPScript), 0o644); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("write bundled ARP Zeek script: %w", err)
	}
	communityIDScript := filepath.Join(dir, "crosscue-community-id.zeek")
	if err := os.WriteFile(communityIDScript, []byte(crosscueCommunityIDScript), 0o644); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("write bundled Community ID Zeek script: %w", err)
	}
	cmd := exec.Command(zeek, "-r", abs, "LogAscii::use_json=T", arpScript, communityIDScript)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return dir, nil
}

func processLogs(st *AppState) error {
	handlers := []struct {
		name string
		fn   func(*AppState, string) error
	}{
		{"arp.log", processARP},
		{"dhcp.log", processDHCP},
		{"conn.log", processConn},
		{"dns.log", processDNS},
		{"ssl.log", processSSL},
		{"known_services.log", processKnownServices},
		{"software.log", processSoftware},
	}
	found := 0
	for _, h := range handlers {
		path := filepath.Join(st.InputDir, h.name)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		found++
		if err := h.fn(st, path); err != nil {
			return fmt.Errorf("%s: %w", h.name, err)
		}
	}
	if found == 0 {
		return errors.New("no supported Zeek logs found; expected JSON arp.log, conn.log, dns.log, dhcp.log, ssl.log, known_services.log, or software.log")
	}
	return nil
}

func processARP(st *AppState, path string) error {
	return readJSONLines(path, func(line int, rec map[string]any) error {
		ts, err := zeekTime(rec)
		if err != nil {
			return fmt.Errorf("line %d: ts: %w", line, err)
		}
		opcode := strings.ToLower(str(rec, "opcode"))
		srcRec := sourceRecord(path, line, "")

		// ARP supplies direct L2 evidence that a hardware address asserted an
		// IPv4 address at this observation point. Keep that as a time-scoped
		// binding: do not globally replace address entities with interface or device entities.
		emit := func(role, mac, ip string) {
			mac = normalizeMAC(mac)
			ip = strings.TrimSpace(ip)
			if !validUnicastishMAC(mac) || !validARPAddress(ip) {
				return
			}
			iface := interfaceForMAC(mac)
			address := addressEntity(ip)

			// ARP can be extremely repetitive. Preserve the raw evidence count in
			// bindings.csv, but emit only the first semantic event for a unique
			// interface/address binding. Subsequent ARP packets remain available in
			// Zeek's arp.log rather than bloating the Core event stream.
			key := bindingKey(iface, address, "arp_address_binding")
			first := st.Bindings[key] == nil
			parent := ""
			if first {
				ctx := compactContext(map[string]any{
					"protocol":              "arp",
					"opcode":                opcode,
					"role":                  role,
					"mac":                   mac,
					"ip":                    ip,
					"frame_source_mac":      normalizeMAC(str(rec, "mac_src")),
					"frame_destination_mac": normalizeMAC(str(rec, "mac_dst")),
					"interpretation":        "first observation of ARP evidence supporting this interface/address binding within the available telemetry; not proof of authoritative address assignment",
				})
				ev := newEvent(st, ts, "derived", iface, address,
					namespace+":address_binding", namespace+":first_observed", "", 1,
					ctx, srcRec, "zeek-arp-address-binding-first-observation")
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

		emit("sender", firstNonEmpty(str(rec, "sender_mac"), str(rec, "mac_src")), str(rec, "sender_ip"))
		// On replies the target hardware address is normally meaningful and
		// provides a second observed binding. Requests commonly carry a zero
		// target MAC, which validUnicastishMAC rejects.
		if opcode == "reply" {
			emit("target", firstNonEmpty(str(rec, "target_mac"), str(rec, "mac_dst")), str(rec, "target_ip"))
		}
		return nil
	})
}

func processConn(st *AppState, path string) error {
	return readJSONLines(path, func(line int, rec map[string]any) error {
		ts, err := zeekTime(rec)
		if err != nil {
			return fmt.Errorf("line %d: ts: %w", line, err)
		}
		origIP, respIP := str(rec, "id.orig_h"), str(rec, "id.resp_h")
		if origIP == "" || respIP == "" {
			return nil
		}
		// conn.log ts is the first packet, but the record summarizes the
		// whole connection. Final counters and state are only supportable at
		// the end of its reported interval.
		duration, err := timeutil.ParseDurationSeconds(valueString(rec["duration"]))
		if err != nil {
			return fmt.Errorf("line %d: duration: %w", line, err)
		}
		start := ts
		ts, err = addSourceDuration(start, duration)
		if err != nil {
			return fmt.Errorf("line %d: duration: %w", line, err)
		}
		respP := valueString(rec["id.resp_p"])
		proto := strings.ToLower(str(rec, "proto"))
		rawService := strings.ToLower(str(rec, "service"))
		appStack := normalizeServiceStack(rawService)
		appStackText := strings.Join(appStack, ",")
		firstDirectionality := connectionDirectionality(rec)
		uid := str(rec, "uid")
		communityID := str(rec, "community_id")
		subject := entityForIP(st, origIP)
		object := endpointEntity(respIP, respP, proto)
		srcRec := sourceRecord(path, line, uid)

		ctx := compactContext(map[string]any{
			"source_interval_start": formatTime(start),
			"source_interval_end":   formatTime(ts),
			"zeek_uid":              uid,
			"community_id":          communityID,
			"originator_ip":         origIP,
			"originator_port":       valueOrNil(rec["id.orig_p"]),
			"responder_ip":          respIP,
			"responder_port":        valueOrNil(rec["id.resp_p"]),
			"responder_entity":      entityForIP(st, respIP),
			"protocol":              proto,
			"service":               rawService,
			"application_stack":     appStack,
			"connection_state":      str(rec, "conn_state"),
			"duration_s":            valueOrNil(rec["duration"]),
			"originator_bytes":      valueOrNil(rec["orig_bytes"]),
			"responder_bytes":       valueOrNil(rec["resp_bytes"]),
			"originator_packets":    valueOrNil(rec["orig_pkts"]),
			"responder_packets":     valueOrNil(rec["resp_pkts"]),
		})
		ev := newEvent(st, ts, "normalized_observation", subject, object,
			namespace+":connection", coreObserved, "", 0, ctx, srcRec, "zeek-conn-normalize")
		st.Events = append(st.Events, ev)
		touchEntity(st, subject, ts, ev.ID, true, false)
		responderEntity := entityForIP(st, respIP)
		touchEntity(st, responderEntity, ts, ev.ID, false, true)
		touchEntity(st, object, ts, ev.ID, false, false)
		observePresence(st, subject, origIP, ts, ev.ID)
		observePresence(st, responderEntity, respIP, ts, ev.ID)

		session := Session{
			UID: uid, Subject: subject, Object: object, Start: start, End: ts,
			Proto: proto, Service: rawService, AppStack: appStackText, State: str(rec, "conn_state"),
			OrigBytes: int64Val(rec, "orig_bytes"), RespBytes: int64Val(rec, "resp_bytes"), EventID: ev.ID, CommunityID: communityID,
		}
		st.Sessions = append(st.Sessions, session)

		if qualifiesForRelationship(proto, str(rec, "conn_state")) {
			key := subject + "\x00" + object
			r := st.Relationships[key]
			if r == nil {
				r = &Relationship{Subject: subject, Object: object, Proto: proto, AppStack: appStackText, FirstAppStack: appStackText, FirstDirectionality: firstDirectionality, First: ts, Last: ts, FirstParent: ev.ID, FirstCommunityID: communityID, communityIDSeen: map[string]bool{}}
				st.Relationships[key] = r
			} else {
				r.AppStack = mergeCommaSet(r.AppStack, appStackText)
			}
			if ts.Before(r.First) {
				r.First, r.FirstParent = ts, ev.ID
				r.FirstAppStack = appStackText
				r.FirstDirectionality = firstDirectionality
				r.FirstCommunityID = communityID
			}
			if ts.After(r.Last) {
				r.Last = ts
			}
			addRelationshipCommunityID(r, communityID)
			r.Connections++
			r.OrigBytes += int64Val(rec, "orig_bytes")
			r.RespBytes += int64Val(rec, "resp_bytes")
			r.OrigPkts += int64Val(rec, "orig_pkts")
			r.RespPkts += int64Val(rec, "resp_pkts")
		}

		// conn.log proves that the transport endpoint was referenced. It only
		// contributes a service projection when Zeek actually identified an
		// application protocol; successful transport alone is not service evidence.
		if qualifiesForRelationship(proto, str(rec, "conn_state")) {
			for _, svc := range appStack {
				touchService(st, object, responderEntity, respIP, respP, proto, svc, ts, "conn", ev.ID)
			}
		}
		return nil
	})
}

func processDNS(st *AppState, path string) error {
	return readJSONLines(path, func(line int, rec map[string]any) error {
		ts, err := zeekTime(rec)
		if err != nil {
			return fmt.Errorf("line %d: ts: %w", line, err)
		}
		clientIP := str(rec, "id.orig_h")
		query := normalizeDomain(str(rec, "query"))
		if clientIP == "" || query == "" {
			return nil
		}
		uid := str(rec, "uid")
		srcRec := sourceRecord(path, line, uid)
		subject := entityForIP(st, clientIP)
		domain := "domain:" + query
		answerTS, err := dnsResponseTime(ts, rec)
		if err != nil {
			return fmt.Errorf("line %d: rtt: %w", line, err)
		}
		queryObserved := dnsQueryObserved(rec)
		if queryObserved {
			ctx := compactContext(map[string]any{
				"zeek_uid":    uid,
				"query":       query,
				"query_type":  str(rec, "qtype_name"),
				"client_port": valueOrNil(rec["id.orig_p"]),
				"server_ip":   str(rec, "id.resp_h"),
				"server_port": valueOrNil(rec["id.resp_p"]),
				"protocol":    strings.ToLower(str(rec, "proto")),
			})
			qev := newEvent(st, ts, "normalized_observation", subject, domain,
				namespace+":dns_query", namespace+":queried", "", 0, ctx, srcRec, "zeek-dns-normalize")
			st.Events = append(st.Events, qev)
			touchEntity(st, subject, ts, qev.ID, true, false)
			touchEntity(st, domain, ts, qev.ID, false, false)
			observePresence(st, subject, clientIP, ts, qev.ID)
		}

		responsePresenceObserved := false
		for _, ans := range stringSlice(rec["answers"]) {
			ans = strings.TrimSpace(ans)
			if ans == "" {
				continue
			}
			var object, answerKind, bindingKind, feature, action, mapping string
			if net.ParseIP(ans) != nil {
				object = addressEntity(ans)
				answerKind = "address"
				bindingKind = "dns_address_binding"
				feature = namespace + ":name_resolution"
				action = namespace + ":resolved_to"
				mapping = "zeek-dns-address-answer-normalize"
			} else if looksLikeDomain(ans) {
				object = "domain:" + normalizeDomain(ans)
				answerKind = "domain"
				bindingKind = "dns_alias"
				feature = namespace + ":name_alias"
				action = namespace + ":alias_of"
				mapping = "zeek-dns-alias-answer-normalize"
			} else {
				continue
			}
			answerCtx := compactContext(map[string]any{
				"answer_kind":    answerKind,
				"query_type":     str(rec, "qtype_name"),
				"zeek_uid":       uid,
				"client_ip":      clientIP,
				"client_port":    valueOrNil(rec["id.orig_p"]),
				"server_ip":      str(rec, "id.resp_h"),
				"server_port":    valueOrNil(rec["id.resp_p"]),
				"protocol":       strings.ToLower(str(rec, "proto")),
				"response_code":  str(rec, "rcode_name"),
				"rejected":       valueOrNil(rec["rejected"]),
				"response_rtt_s": valueOrNil(rec["rtt"]),
			})
			if !queryObserved {
				answerCtx["query_observed"] = false
			}
			aev := newEvent(st, answerTS, "normalized_observation", domain, object,
				feature, action, "", 0, answerCtx, srcRec, mapping)
			st.Events = append(st.Events, aev)
			touchEntity(st, domain, answerTS, aev.ID, false, false)
			touchEntity(st, object, answerTS, aev.ID, false, false)
			touchBinding(st, domain, object, bindingKind, answerTS, aev.ID)
			if !queryObserved && !responsePresenceObserved {
				touchEntity(st, subject, answerTS, aev.ID, true, false)
				observePresence(st, subject, clientIP, answerTS, aev.ID)
				responsePresenceObserved = true
			}
		}
		return nil
	})
}

func processDHCP(st *AppState, path string) error {
	return readJSONLines(path, func(line int, rec map[string]any) error {
		ts, err := zeekTime(rec)
		if err != nil {
			return fmt.Errorf("line %d: ts: %w", line, err)
		}
		mac := normalizeMAC(str(rec, "mac"))
		ip := firstNonEmpty(str(rec, "assigned_addr"), str(rec, "client_addr"))
		host := normalizeHost(firstNonEmpty(str(rec, "host_name"), str(rec, "client_fqdn")))
		if mac == "" {
			return nil
		}
		subject := interfaceForMAC(mac)
		srcRec := sourceRecord(path, line, strings.Join(stringSlice(rec["uids"]), ","))
		if ip != "" && net.ParseIP(ip) != nil {
			object := addressEntity(ip)
			ctx := compactContext(map[string]any{
				"mac":               mac,
				"assigned_address":  ip,
				"lease_time_s":      valueOrNil(rec["lease_time"]),
				"requested_address": str(rec, "requested_addr"),
				"server_address":    str(rec, "server_addr"),
				"message_types":     rec["msg_types"],
				"client_software":   str(rec, "client_software"),
			})
			ev := newEvent(st, ts, "normalized_observation", subject, object,
				namespace+":address_binding", namespace+":assigned", "", 1, ctx, srcRec, "zeek-dhcp-normalize")
			st.Events = append(st.Events, ev)
			touchEntity(st, subject, ts, ev.ID, true, false)
			touchEntity(st, object, ts, ev.ID, false, false)
			touchBinding(st, subject, object, "dhcp_address_binding", ts, ev.ID)
			observePresence(st, subject, ip, ts, ev.ID)
		}
		if host != "" {
			object := "name:host:" + host
			ev := newEvent(st, ts, "normalized_observation", subject, object,
				namespace+":hostname_binding", namespace+":reported", "", 0,
				map[string]any{"hostname": host, "mac": mac}, srcRec, "zeek-dhcp-hostname-normalize")
			st.Events = append(st.Events, ev)
			touchEntity(st, subject, ts, ev.ID, true, false)
			touchEntity(st, object, ts, ev.ID, false, false)
			touchBinding(st, subject, object, "dhcp_hostname_binding", ts, ev.ID)
		}
		return nil
	})
}

func processSSL(st *AppState, path string) error {
	return readJSONLines(path, func(line int, rec map[string]any) error {
		ts, err := zeekTime(rec)
		if err != nil {
			return fmt.Errorf("line %d: ts: %w", line, err)
		}
		clientIP := str(rec, "id.orig_h")
		serverIP := str(rec, "id.resp_h")
		if clientIP == "" || serverIP == "" {
			return nil
		}
		proto := "tcp"
		port := valueString(rec["id.resp_p"])
		sni := normalizeDomain(str(rec, "server_name"))
		subject := entityForIP(st, clientIP)
		object := endpointEntity(serverIP, port, proto)
		uid := str(rec, "uid")
		srcRec := sourceRecord(path, line, uid)
		ctx := compactContext(map[string]any{
			"zeek_uid":      uid,
			"server_ip":     serverIP,
			"server_port":   valueOrNil(rec["id.resp_p"]),
			"server_name":   sni,
			"version":       str(rec, "version"),
			"cipher":        str(rec, "cipher"),
			"curve":         str(rec, "curve"),
			"established":   valueOrNil(rec["established"]),
			"resumed":       valueOrNil(rec["resumed"]),
			"next_protocol": str(rec, "next_protocol"),
		})
		ev := newEvent(st, ts, "normalized_observation", subject, object,
			namespace+":tls_session", coreObserved, "", 0, ctx, srcRec, "zeek-tls-normalize")
		st.Events = append(st.Events, ev)
		touchEntity(st, subject, ts, ev.ID, true, false)
		responderEntity := entityForIP(st, serverIP)
		touchEntity(st, responderEntity, ts, ev.ID, false, true)
		touchEntity(st, object, ts, ev.ID, false, false)
		observePresence(st, subject, clientIP, ts, ev.ID)
		observePresence(st, responderEntity, serverIP, ts, ev.ID)
		// A parsed TLS handshake is direct application-service evidence.
		touchService(st, object, responderEntity, serverIP, port, proto, "tls", ts, "ssl", ev.ID)
		if sni != "" {
			domain := "domain:" + sni
			touchEntity(st, domain, ts, ev.ID, false, false)
			touchBinding(st, object, domain, "tls_server_name_binding", ts, ev.ID)
		}
		return nil
	})
}

func processKnownServices(st *AppState, path string) error {
	return readJSONLines(path, func(line int, rec map[string]any) error {
		ts, err := zeekTime(rec)
		if err != nil {
			return fmt.Errorf("line %d: ts: %w", line, err)
		}
		ip := firstNonEmpty(str(rec, "host"), str(rec, "id.resp_h"))
		if ip == "" {
			return nil
		}
		port := firstNonEmpty(valueString(rec["port_num"]), valueString(rec["id.resp_p"]))
		proto := strings.ToLower(firstNonEmpty(str(rec, "port_proto"), str(rec, "proto")))
		if proto == "" {
			proto = "unknown"
		}
		stack := serviceStackFromValue(rec["service"])
		if len(stack) == 0 {
			return nil
		}
		endpoint := endpointEntity(ip, port, proto)
		hostEntity := entityForIP(st, ip)
		srcRec := sourceRecord(path, line, "")
		for _, svc := range stack {
			service := serviceEntity(ip, port, proto, svc)
			ev := newEvent(st, ts, "normalized_observation", endpoint, service,
				namespace+":service", coreObserved, "", 0,
				compactContext(map[string]any{"ip": ip, "port": port, "protocol": proto, "service": svc, "application_stack": stack, "host_entity": hostEntity}),
				srcRec, "zeek-known-services-normalize")
			st.Events = append(st.Events, ev)
			touchEntity(st, hostEntity, ts, ev.ID, false, true)
			touchEntity(st, endpoint, ts, ev.ID, false, false)
			touchService(st, endpoint, hostEntity, ip, port, proto, svc, ts, "known_services", ev.ID)
			observePresence(st, hostEntity, ip, ts, ev.ID)
		}
		return nil
	})
}

func processSoftware(st *AppState, path string) error {
	return readJSONLines(path, func(line int, rec map[string]any) error {
		ts, err := zeekTime(rec)
		if err != nil {
			return fmt.Errorf("line %d: ts: %w", line, err)
		}
		host := firstNonEmpty(str(rec, "host"), str(rec, "id.resp_h"), str(rec, "id.orig_h"))
		if host == "" {
			return nil
		}
		name := firstNonEmpty(str(rec, "name"), str(rec, "software"))
		if name == "" {
			return nil
		}
		subject := entityForIP(st, host)
		object := "software:" + safeID(name)
		srcRec := sourceRecord(path, line, "")
		ctx := compactContext(map[string]any{
			"software_type":  str(rec, "software_type"),
			"name":           name,
			"version_major":  valueOrNil(rec["version.major"]),
			"version_minor":  valueOrNil(rec["version.minor"]),
			"version_minor2": valueOrNil(rec["version.minor2"]),
			"version_minor3": valueOrNil(rec["version.minor3"]),
			"version_addl":   str(rec, "version.addl"),
		})
		ev := newEvent(st, ts, "normalized_observation", subject, object,
			namespace+":software", coreObserved, "", 0, ctx, srcRec, "zeek-software-normalize")
		st.Events = append(st.Events, ev)
		touchEntity(st, subject, ts, ev.ID, false, true)
		touchEntity(st, object, ts, ev.ID, false, false)
		observePresence(st, subject, host, ts, ev.ID)
		return nil
	})
}

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
			"protocol":                r.Proto,
			"application_stack":       canonicalizeServiceStack(splitCommaSet(r.FirstAppStack)),
			"evidence_directionality": r.FirstDirectionality,
			"community_id":            r.FirstCommunityID,
			"interpretation":          "first observation of this relationship within the available telemetry; context contains only evidence available from the first parent connection",
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
	parameters := map[string]any{"mapping": method, "adapter": "zeek-reference-v1", "eventizer_algorithm": "network-reference-v1.4"}
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
	parameters := map[string]any{"mapping": method, "adapter": "zeek-reference-v1", "eventizer_algorithm": "network-reference-v1.4"}
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

func addRelationshipCommunityID(r *Relationship, communityID string) {
	communityID = strings.TrimSpace(communityID)
	if r == nil || communityID == "" {
		return
	}
	if r.communityIDSeen == nil {
		r.communityIDSeen = map[string]bool{}
	}
	if r.communityIDSeen[communityID] {
		return
	}
	r.communityIDSeen[communityID] = true
	r.CommunityIDCount++
	if len(r.CommunityIDs) < maxProjectionParentEvents {
		r.CommunityIDs = append(r.CommunityIDs, communityID)
	}
}

func qualifiesForRelationship(proto, state string) bool {
	if strings.ToLower(proto) != "tcp" {
		return true
	}
	switch strings.ToUpper(state) {
	case "S0", "REJ", "RSTOS0":
		return false
	default:
		return true
	}
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
	rows := [][]string{{"subject", "object", "protocol", "application_stack", "directionality", "first_observation_directionality", "first_observed", "last_observed", "connections", "originator_packets", "responder_packets", "originator_bytes", "responder_bytes", "first_parent_event", "first_community_id", "community_id_count", "community_ids_truncated", "community_ids", "semantics"}}
	for _, k := range keys {
		r := m[k]
		rows = append(rows, []string{r.Subject, r.Object, r.Proto, r.AppStack, relationshipDirectionality(r), r.FirstDirectionality, fmtTime(r.First), fmtTime(r.Last), strconv.Itoa(r.Connections), strconv.FormatInt(r.OrigPkts, 10), strconv.FormatInt(r.RespPkts, 10), strconv.FormatInt(r.OrigBytes, 10), strconv.FormatInt(r.RespBytes, 10), r.FirstParent, r.FirstCommunityID, strconv.Itoa(r.CommunityIDCount), strconv.FormatBool(r.CommunityIDCount > len(r.CommunityIDs)), strings.Join(r.CommunityIDs, ";"), "observed relationship summary; directionality is aggregate evidence over the projection interval; first_observed is not proof of establishment; Community IDs identify contributing flow tuples when available"})
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
	rows := [][]string{{"uid", "subject", "object", "start", "end", "protocol", "service", "application_stack", "connection_state", "originator_bytes", "responder_bytes", "community_id", "event_id"}}
	for _, s := range sessions {
		rows = append(rows, []string{s.UID, s.Subject, s.Object, fmtTime(s.Start), fmtTime(s.End), s.Proto, s.Service, s.AppStack, s.State, strconv.FormatInt(s.OrigBytes, 10), strconv.FormatInt(s.RespBytes, 10), s.CommunityID, s.EventID})
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
			s := strings.TrimSpace(string(b))
			if s != "" && !strings.HasPrefix(s, "#") {
				if !strings.HasPrefix(s, "{") {
					return fmt.Errorf("line %d is not JSON; generate Zeek logs with LogAscii::use_json=T", lineNo)
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

func dnsQueryObserved(rec map[string]any) bool {
	// Zeek may emit a dns.log record when only the response side of a
	// transaction is visible. The record still contains the DNS question name,
	// but that does not prove this observation point saw the query packet.
	// A positive RTT proves Zeek correlated request and response; otherwise the
	// query type is used as the reference-adapter signal that query-side evidence
	// was actually available.
	if rtt, ok := numberFloat(rec["rtt"]); ok && rtt > 0 {
		return true
	}
	if strings.TrimSpace(str(rec, "qtype_name")) != "" {
		return true
	}
	if v, ok := rec["qtype"]; ok && v != nil && strings.TrimSpace(valueString(v)) != "" {
		return true
	}
	return false
}

func dnsResponseTime(queryTime time.Time, rec map[string]any) (time.Time, error) {
	// Zeek dns.log may include RTT for a completed query/response transaction.
	// When available, place answer facts at the response side of the interval
	// rather than back-projecting them onto the point query event.
	if rec["rtt"] == nil {
		return queryTime, nil
	}
	rtt, err := timeutil.ParseDurationSeconds(valueString(rec["rtt"]))
	if err != nil {
		return time.Time{}, err
	}
	return addSourceDuration(queryTime, rtt)
}

func addSourceDuration(start time.Time, duration time.Duration) (time.Time, error) {
	return timeutil.ParseNano(start.Add(duration).UTC().Format(time.RFC3339Nano))
}

func zeekTime(rec map[string]any) (time.Time, error) {
	v, ok := rec["ts"]
	if !ok || v == nil {
		return time.Time{}, errors.New("timestamp is required")
	}
	var s string
	switch x := v.(type) {
	case json.Number:
		s = x.String()
	case string:
		s = x
	default:
		return time.Time{}, errors.New("timestamp must be decimal Unix seconds")
	}
	return timeutil.ParseUnix(s)
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
	// Zeek historically reports TLS as ssl in conn.log. Normalize the
	// application semantic while preserving source-native values in context.
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

func connectionDirectionality(rec map[string]any) string {
	if int64Val(rec, "resp_pkts") > 0 || int64Val(rec, "resp_bytes") > 0 {
		return "bidirectional_observed"
	}
	return "unidirectional_observed"
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
	s := "zeek:" + filepath.Base(path) + ":line:" + strconv.Itoa(line)
	if uid != "" {
		s += ":uid:" + uid
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
