package agent

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

func hitTestAssignment() HitMonitorAssignment {
	start := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	return HitMonitorAssignment{ID: "monitor-one", ServerID: "endpoint-one", StartsAt: start, ExpiresAt: start.Add(120 * time.Second),
		Ports: []Port{{Port: 22, Protocol: "tcp"}, {Port: 2022, Protocol: "tcp"}, {Port: 8080, Protocol: "tcp"}, {Port: 53, Protocol: "udp"}}}
}

func hitTestLine(id, source, destination, protocol string, port int) string {
	return fmt.Sprintf("kernel: %sIN=eth0 OUT= MAC=00:11:22:33 SRC=%s DST=%s LEN=60 PROTO=%s SPT=49152 DPT=%d", HitRulePrefix(id), source, destination, protocol, port)
}

func TestHitKernelLogObservesExactIPv4IPv6AndSSHPorts(t *testing.T) {
	item := hitTestAssignment()
	at := item.StartsAt.Add(time.Second)
	tests := []struct {
		name, source, destination, protocol, expectedSource string
		port                                                int
	}{
		{"ipv4-service", "192.0.2.19", "10.0.0.1", "TCP", "192.0.2.19", 8080},
		{"ipv6-service", "2001:db8:0:0::19", "2001:db8::1", "TCP", "2001:db8::19", 8080},
		{"ipv4-udp", "198.51.100.5", "10.0.0.1", "UDP", "198.51.100.5", 53},
		{"ipv6-udp", "2001:db8::20", "2001:db8::1", "UDP", "2001:db8::20", 53},
		{"ssh-default", "192.0.2.19", "10.0.0.1", "TCP", "192.0.2.19", 22},
		{"ssh-custom", "192.0.2.19", "10.0.0.1", "TCP", "192.0.2.19", 2022},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := hitTestLine(item.ID, test.source, test.destination, test.protocol, test.port)
			event, ok := ParseHitKernelLog(message, at, item, "journal-cursor-one")
			if !ok {
				t.Fatal("approved ingress observation rejected")
			}
			if event.SourceIP != test.expectedSource || event.Port != test.port || event.Protocol != strings.ToLower(test.protocol) ||
				event.Count != 1 || event.Verdict != "observed" || !event.FirstSeen.Equal(at) || !event.LastSeen.Equal(at) {
				t.Fatalf("packet was reclassified or broadened: %+v", event)
			}
			if decoded, err := hex.DecodeString(event.EventID); err != nil || len(decoded) != 32 {
				t.Fatalf("invalid stable event identity %q", event.EventID)
			}
		})
	}
	// A claimed count/action in unrelated log text cannot become connection or verdict evidence.
	event, ok := ParseHitKernelLog(hitTestLine(item.ID, "192.0.2.1", "10.0.0.1", "TCP", 22)+" COUNT=999 ACCEPT", at, item, "cursor-count")
	if !ok || event.Count != 1 || event.Verdict != "observed" {
		t.Fatalf("untrusted metadata changed evidence: %+v", event)
	}
}

func TestHitKernelLogRequiresOwnedPrefixExplicitIngressAndUnambiguousFields(t *testing.T) {
	item := hitTestAssignment()
	base := hitTestLine(item.ID, "192.0.2.19", "10.0.0.1", "TCP", 8080)
	tests := map[string]string{
		"no-prefix":             strings.Replace(base, HitRulePrefix(item.ID), "", 1),
		"learning-prefix":       strings.Replace(base, HitRulePrefix(item.ID), RulePrefix(item.ID), 1),
		"probe-prefix":          strings.Replace(base, HitRulePrefix(item.ID), "PRTP012345abcdef:", 1),
		"other-monitor":         hitTestLine("monitor-other", "192.0.2.19", "10.0.0.1", "TCP", 8080),
		"missing-in":            strings.Replace(base, "IN=eth0 ", "", 1),
		"empty-in-outgoing":     strings.Replace(base, "IN=eth0 OUT=", "IN= OUT=eth0", 1),
		"missing-out":           strings.Replace(base, "OUT= ", "", 1),
		"forwarded":             strings.Replace(base, "OUT= ", "OUT=eth1 ", 1),
		"duplicate-in":          base + " IN=eth1",
		"duplicate-out":         base + " OUT=",
		"duplicate-source":      base + " SRC=192.0.2.19",
		"duplicate-destination": base + " DST=10.0.0.1",
		"duplicate-protocol":    base + " PROTO=TCP",
		"duplicate-port":        base + " DPT=8080",
		"malformed-source":      strings.Replace(base, "SRC=192.0.2.19", "SRC=example.invalid", 1),
		"malformed-destination": strings.Replace(base, "DST=10.0.0.1", "DST=not-an-ip", 1),
		"missing-source":        strings.Replace(base, "SRC=192.0.2.19 ", "", 1),
		"missing-destination":   strings.Replace(base, "DST=10.0.0.1 ", "", 1),
		"mixed-ip-families":     strings.Replace(base, "SRC=192.0.2.19", "SRC=2001:db8::19", 1),
		"scoped-ipv6":           hitTestLine(item.ID, "fe80::1%eth0", "fe80::2%eth0", "TCP", 8080),
		"wrong-protocol":        strings.Replace(base, "PROTO=TCP", "PROTO=UDP", 1),
		"unsupported-protocol":  strings.Replace(base, "PROTO=TCP", "PROTO=ICMP", 1),
		"unapproved-port":       strings.Replace(base, "DPT=8080", "DPT=8081", 1),
		"malformed-port":        strings.Replace(base, "DPT=8080", "DPT=http", 1),
		"missing-port":          strings.Replace(base, " DPT=8080", "", 1),
		"zero-port":             strings.Replace(base, "DPT=8080", "DPT=0", 1),
		"port-overflow":         strings.Replace(base, "DPT=8080", "DPT=65536", 1),
	}
	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			if event, ok := ParseHitKernelLog(message, item.StartsAt.Add(time.Second), item, "cursor"); ok {
				t.Fatalf("unowned/ambiguous ingress accepted: %+v", event)
			}
		})
	}
	for _, cursor := range []string{"", strings.Repeat("x", 4097)} {
		if _, ok := ParseHitKernelLog(base, item.StartsAt, item, cursor); ok {
			t.Error("missing or oversized cursor accepted")
		}
	}
	// Prefix and IN may be adjacent in the kernel's real log format.
	if _, ok := ParseHitKernelLog(base, item.StartsAt, item, "cursor"); !ok {
		t.Fatal("prefix-adjacent IN was not parsed")
	}
}

func TestHitKernelLogUsesHalfOpenLeaseAndStableCursorIdentity(t *testing.T) {
	item := hitTestAssignment()
	message := hitTestLine(item.ID, "192.0.2.19", "10.0.0.1", "TCP", 8080)
	for _, test := range []struct {
		name     string
		at       time.Time
		accepted bool
	}{
		{"before-start", item.StartsAt.Add(-time.Nanosecond), false},
		{"at-start", item.StartsAt, true},
		{"before-expiry", item.ExpiresAt.Add(-time.Nanosecond), true},
		{"at-expiry", item.ExpiresAt, false},
		{"after-expiry", item.ExpiresAt.Add(time.Nanosecond), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, ok := ParseHitKernelLog(message, test.at, item, "cursor-boundary")
			if ok != test.accepted {
				t.Fatalf("accepted=%v, want %v", ok, test.accepted)
			}
		})
	}
	at := item.StartsAt.Add(90 * time.Second)
	first, ok := ParseHitKernelLog(message, at, item, "stable-cursor")
	if !ok {
		t.Fatal("initial observation rejected")
	}
	repeat, _ := ParseHitKernelLog(message, at, item, "stable-cursor")
	renewed := item
	renewed.StartsAt, renewed.ExpiresAt = item.StartsAt.Add(time.Minute), item.ExpiresAt.Add(time.Minute)
	again, ok := ParseHitKernelLog(message, at, renewed, "stable-cursor")
	if !ok || first.EventID != repeat.EventID || first.EventID != again.EventID {
		t.Fatal("replay or lease renewal changed an existing packet's identity")
	}
	differentCursor, _ := ParseHitKernelLog(message, at, item, "different-cursor")
	other := item
	other.ID = "another-monitor"
	differentMonitor, ok := ParseHitKernelLog(hitTestLine(other.ID, "192.0.2.19", "10.0.0.1", "TCP", 8080), at, other, "stable-cursor")
	if !ok || differentCursor.EventID == first.EventID || differentMonitor.EventID == first.EventID {
		t.Fatal("different journal records or monitor namespaces collided")
	}
}

func TestHitAssignmentRequiresBoundedExactEndpointLease(t *testing.T) {
	item := hitTestAssignment()
	at := item.StartsAt
	if err := validateHitAssignment(item, item.ServerID, at, true); err != nil {
		t.Fatal(err)
	}
	ports := make([]Port, maxHitPorts)
	for index := range ports {
		ports[index] = Port{Port: index + 1, Protocol: "tcp"}
	}
	maximum := item
	maximum.Ports = ports
	if err := validateHitAssignment(maximum, item.ServerID, at, true); err != nil {
		t.Fatalf("exact port cap rejected: %v", err)
	}
	sameNumberDifferentTransport := item
	sameNumberDifferentTransport.Ports = []Port{{Port: 53, Protocol: "tcp"}, {Port: 53, Protocol: "udp"}, {Port: 65535, Protocol: "tcp"}}
	if err := validateHitAssignment(sameNumberDifferentTransport, item.ServerID, at, true); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*HitMonitorAssignment){
		"wrong-server":         func(x *HitMonitorAssignment) { x.ServerID = "endpoint-other" },
		"missing-monitor-id":   func(x *HitMonitorAssignment) { x.ID = "" },
		"oversized-monitor-id": func(x *HitMonitorAssignment) { x.ID = strings.Repeat("a", 129) },
		"path-monitor-id":      func(x *HitMonitorAssignment) { x.ID = "../monitor" },
		"empty-ports":          func(x *HitMonitorAssignment) { x.Ports = nil },
		"too-many-ports": func(x *HitMonitorAssignment) {
			x.Ports = append(append([]Port{}, ports...), Port{Port: maxHitPorts + 1, Protocol: "tcp"})
		},
		"duplicate-port": func(x *HitMonitorAssignment) {
			x.Ports = []Port{{Port: 22, Protocol: "tcp"}, {Port: 22, Protocol: "tcp"}}
		},
		"zero-port":             func(x *HitMonitorAssignment) { x.Ports = []Port{{Port: 0, Protocol: "tcp"}} },
		"port-overflow":         func(x *HitMonitorAssignment) { x.Ports = []Port{{Port: 65536, Protocol: "tcp"}} },
		"unsupported-protocol":  func(x *HitMonitorAssignment) { x.Ports = []Port{{Port: 8080, Protocol: "sctp"}} },
		"noncanonical-protocol": func(x *HitMonitorAssignment) { x.Ports = []Port{{Port: 8080, Protocol: "TCP"}} },
		"empty-lease":           func(x *HitMonitorAssignment) { x.ExpiresAt = x.StartsAt },
		"reversed-lease":        func(x *HitMonitorAssignment) { x.ExpiresAt = x.StartsAt.Add(-time.Second) },
		"ttl-over-120":          func(x *HitMonitorAssignment) { x.ExpiresAt = x.StartsAt.Add(120*time.Second + time.Nanosecond) },
		"expired-lease":         func(x *HitMonitorAssignment) { x.StartsAt = at.Add(-120 * time.Second); x.ExpiresAt = at },
		"starts-too-far-ahead": func(x *HitMonitorAssignment) {
			x.StartsAt = at.Add(61 * time.Second)
			x.ExpiresAt = at.Add(120 * time.Second)
		},
		"expires-too-far-ahead": func(x *HitMonitorAssignment) {
			x.StartsAt = at.Add(time.Second)
			x.ExpiresAt = at.Add(121 * time.Second)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			altered := item
			change(&altered)
			if err := validateHitAssignment(altered, item.ServerID, at, true); err == nil {
				t.Fatalf("invalid lease accepted: %+v", altered)
			}
		})
	}
	// Expired leases remain structurally checkable for delivery/draining, never fresh authority.
	expired := item
	if err := validateHitAssignment(expired, item.ServerID, item.ExpiresAt, false); err != nil {
		t.Fatalf("stored lease cannot be validated for draining: %v", err)
	}
}

func TestHitAssignmentRejectsJSONBooleansForTypedLeaseFields(t *testing.T) {
	item := hitTestAssignment()
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "server_id", "starts_at", "expires_at", "ports"} {
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		value[field] = true
		malformed, _ := json.Marshal(value)
		var decoded HitMonitorAssignment
		if err := json.Unmarshal(malformed, &decoded); err == nil {
			t.Errorf("boolean %s accepted", field)
		}
	}
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	value["ports"] = []map[string]any{{"port": true, "protocol": "tcp"}}
	malformed, _ := json.Marshal(value)
	var decoded HitMonitorAssignment
	if err := json.Unmarshal(malformed, &decoded); err == nil {
		t.Error("boolean port became a numeric port")
	}
}

func TestHitObservationRuleIsDistinctFixedLogOnlyInstrumentation(t *testing.T) {
	item := hitTestAssignment()
	if !regexp.MustCompile("^PRTH[0-9a-f]{16}:$").MatchString(HitRulePrefix(item.ID)) || HitRulePrefix(item.ID) != HitRulePrefix(item.ID) ||
		HitRulePrefix(item.ID) == HitRulePrefix("other-monitor") || HitRulePrefix(item.ID) == RulePrefix(item.ID) || strings.HasPrefix(HitRulePrefix(item.ID), "PRTP") {
		t.Fatal("hit prefix is unstable or overlaps another observer namespace")
	}
	for _, port := range item.Ports {
		rule := HitObservationRule(item.ID, port)
		info, err := parseRich(rule)
		if err != nil || info.Action != "" || !info.HasLog || info.Port != fmt.Sprint(port.Port) || info.Transport != port.Protocol ||
			info.LogLimit != "20/s" || info.LogLevel != "info" || info.LogPrefix != HitRulePrefix(item.ID) ||
			info.Source != "" || info.Service != "" || info.Protocol != "" {
			t.Fatalf("rule can change access or broaden port scope: %q (%+v, %v)", rule, info, err)
		}
		if strings.Contains(rule, "--permanent") || strings.Contains(rule, "accept") || strings.Contains(rule, "drop") || strings.Contains(rule, "reject") {
			t.Fatalf("observation rule contains a mutation/action: %q", rule)
		}
		record := OwnedRule{SessionID: "hit:" + item.ID, Zone: "public", Rule: rule, ExpiresAt: item.ExpiresAt}
		if !ownedHitObservation(rule, record) {
			t.Fatal("exact owned observation not recognized")
		}
		normalized := strings.Replace(rule, "port port=\"", "port port='", 1)
		normalized = strings.Replace(normalized, fmt.Sprintf("%d\"", port.Port), fmt.Sprintf("%d'", port.Port), 1)
		if !ownedHitObservation(normalized, record) {
			t.Fatal("equivalent firewalld quote normalization lost ownership")
		}
		for _, candidate := range []string{rule + " accept", rule + " drop", strings.Replace(rule, "20/s", "21/s", 1), strings.Replace(rule, HitRulePrefix(item.ID), HitRulePrefix("other"), 1)} {
			if ownedHitObservation(candidate, record) {
				t.Fatalf("unowned/action-bearing rule hidden from inventory: %q", candidate)
			}
		}
		for _, namespace := range []string{item.ID, "probe", "hit:other-monitor"} {
			other := record
			other.SessionID = namespace
			if ownedHitObservation(rule, other) {
				t.Fatalf("ownership crossed observer namespace %q", namespace)
			}
		}
		noncanonicalRecord := record
		noncanonicalRecord.Rule = rule + " accept"
		if ownedHitObservation(noncanonicalRecord.Rule, noncanonicalRecord) {
			t.Fatal("persisted action-bearing rule granted hit ownership")
		}
	}
}
