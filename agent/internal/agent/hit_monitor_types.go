package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const HitMonitorCapability = "port_hit_monitor_v1"
const maxHitMonitors = 8
const maxHitPorts = 64
const hitLeaseLifetime = 120 * time.Second
const maxHitStateBytes = 2 * 1024 * 1024
const maxHitBatchBytes = 512 * 1024
const maxHitEvents = 1000

type HitMonitorAssignment struct {
	ObservationKinds []string  `json:"observation_kinds,omitempty"`
	ID               string    `json:"id"`
	ServerID         string    `json:"server_id"`
	StartsAt         time.Time `json:"starts_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	Ports            []Port    `json:"ports"`
}
type HitEvent struct {
	EventID string `json:"event_id"`
	Flow
}
type HitBatch struct {
	BatchID        string     `json:"batch_id"`
	MonitorID      string     `json:"monitor_id"`
	LeaseStartsAt  time.Time  `json:"lease_starts_at"`
	LeaseExpiresAt time.Time  `json:"lease_expires_at"`
	Events         []HitEvent `json:"events"`
}
type HitMonitorCoverage struct {
	Capture         *TrafficCaptureCoverage `json:"traffic_capture,omitempty"`
	Enabled         bool                    `json:"enabled"`
	Status          string                  `json:"status"`
	Error           string                  `json:"error"`
	ActiveMonitors  int                     `json:"active_monitors"`
	RateLimited     bool                    `json:"rate_limited"`
	DroppedEvents   int                     `json:"dropped_events"`
	PendingBatches  int                     `json:"pending_batches"`
	CoverageLimited bool                    `json:"coverage_limited"`
}
type HitMonitorStatus struct {
	TrafficCaptureCoverage
	ID             string     `json:"id"`
	Status         string     `json:"status"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	CheckedAt      time.Time  `json:"checked_at"`
	Error          string     `json:"error,omitempty"`
	DroppedEvents  int        `json:"dropped_events,omitempty"`
}

var hitID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var hitServerID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func HitRulePrefix(id string) string {
	hash := sha256.Sum256([]byte("prthak-port-hit-v1\x00" + id))
	return "PRTH" + hex.EncodeToString(hash[:8]) + ":"
}
func HitObservationRule(id string, port Port) string {
	return fmt.Sprintf(`rule priority="-32740" port port="%d" protocol="%s" log prefix="%s" level="info" limit value="20/s"`, port.Port, port.Protocol, HitRulePrefix(id))
}
func validateHitAssignment(item HitMonitorAssignment, server string, at time.Time, fresh bool) error {
	if err := validateObservationKinds(item.ObservationKinds); err != nil {
		return err
	}
	if !hitID.MatchString(item.ID) || !hitServerID.MatchString(server) || item.ServerID != server || len(item.Ports) < 1 || len(item.Ports) > maxHitPorts || !item.ExpiresAt.After(item.StartsAt) || item.ExpiresAt.Sub(item.StartsAt) > hitLeaseLifetime {
		return errors.New("invalid endpoint-bound hit-monitor lease")
	}
	if fresh && (!item.ExpiresAt.After(at) || item.ExpiresAt.After(at.Add(hitLeaseLifetime)) || item.StartsAt.After(at.Add(time.Minute))) {
		return errors.New("hit-monitor lease is expired or exceeds120seconds")
	}
	seen := map[Port]bool{}
	for _, port := range item.Ports {
		if port.Port < 1 || port.Port > 65535 || (port.Protocol != "tcp" && port.Protocol != "udp") || seen[port] {
			return errors.New("hit monitoring needs exact distinct TCP/UDP ports")
		}
		seen[port] = true
	}
	return nil
}
func hitPortsKey(ports []Port) string {
	values := []string{}
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d/%s", port.Port, port.Protocol))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}
func ParseHitKernelLog(message string, when time.Time, assignment HitMonitorAssignment, cursor string) (HitEvent, bool) {
	if assignment.ObservationKinds != nil {
		return HitEvent{}, false
	}
	if cursor == "" || len(cursor) > 4096 || when.Before(assignment.StartsAt) || !when.Before(assignment.ExpiresAt) {
		return HitEvent{}, false
	}
	prefix := HitRulePrefix(assignment.ID)
	position := strings.Index(message, prefix)
	if position < 0 {
		return HitEvent{}, false
	}
	fields := map[string]string{}
	for _, token := range strings.Fields(message[position+len(prefix):]) {
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		if key != "IN" && key != "OUT" && key != "SRC" && key != "DST" && key != "PROTO" && key != "DPT" {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return HitEvent{}, false
		}
		fields[key] = value
	}
	if fields["IN"] == "" || fields["OUT"] != "" {
		return HitEvent{}, false
	}
	if _, present := fields["OUT"]; !present {
		return HitEvent{}, false
	}
	source, err := netip.ParseAddr(fields["SRC"])
	if err != nil || source.Zone() != "" {
		return HitEvent{}, false
	}
	destination, err := netip.ParseAddr(fields["DST"])
	if err != nil || destination.Zone() != "" || source.Is4() != destination.Is4() {
		return HitEvent{}, false
	}
	if !directNumber.MatchString(fields["DPT"]) {
		return HitEvent{}, false
	}
	port, err := strconv.Atoi(fields["DPT"])
	if err != nil {
		return HitEvent{}, false
	}
	protocol := strings.ToLower(fields["PROTO"])
	for _, allowed := range assignment.Ports {
		if allowed.Port == port && allowed.Protocol == protocol {
			id := sha256.Sum256([]byte("prthak-hit-event-v1\x00" + assignment.ID + "\x00" + cursor))
			return HitEvent{EventID: hex.EncodeToString(id[:]), Flow: Flow{SourceIP: source.Unmap().String(), Port: port, Protocol: protocol, Verdict: "observed", Count: 1, FirstSeen: when, LastSeen: when}}, true
		}
	}
	return HitEvent{}, false
}
func ownedHitObservation(value string, record OwnedRule) bool {
	if !strings.HasPrefix(record.SessionID, "hit:") {
		return false
	}
	id := strings.TrimPrefix(record.SessionID, "hit:")
	if !hitID.MatchString(id) {
		return false
	}
	info, err := parseRich(record.Rule)
	if err != nil || info.Action != "" || info.Priority != -32740 || info.Port == "" || info.Source != "" || info.Service != "" || info.Family != "" || info.Protocol != "" || info.LogPrefix != HitRulePrefix(id) || info.LogLevel != "info" || info.LogLimit != "20/s" {
		return false
	}
	port, err := strconv.Atoi(info.Port)
	if err != nil || port < 1 || port > 65535 || (info.Transport != "tcp" && info.Transport != "udp") {
		return false
	}
	if record.Rule != HitObservationRule(id, Port{port, info.Transport}) {
		return false
	}
	actual, err := parseRich(value)
	return err == nil && actual == info
}
