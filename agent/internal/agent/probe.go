package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Security events are packet observations, never proof of a successful connection
// or malicious intent. Only events checked against a fresh socket read are sent.
type SecurityEvent struct {
	EventID                 string    `json:"event_id"`
	Kind                    string    `json:"kind"`
	SourceIP                string    `json:"source_ip"`
	DestinationIP           string    `json:"destination_ip"`
	Port                    int       `json:"port"`
	Protocol                string    `json:"protocol"`
	Count                   int       `json:"count"`
	FirstSeen               time.Time `json:"first_seen"`
	LastSeen                time.Time `json:"last_seen"`
	Listening               bool      `json:"listening"`
	InventoryCheckedAt      time.Time `json:"inventory_checked_at"`
	ObservedWhileMonitoring bool      `json:"observed_while_monitoring"`
}
type SecurityMonitorCoverage struct {
	Enabled       bool       `json:"enabled"`
	Status        string     `json:"status"`
	Error         string     `json:"error"`
	RateLimited   bool       `json:"rate_limited"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	DroppedEvents int        `json:"dropped_events"`
	Zones         []string   `json:"zones"`
}
type ProbeSettings struct {
	Enabled       bool
	RatePerSecond int
	Zone          string
}
type probeRule struct {
	Zone      string    `json:"zone"`
	Rule      string    `json:"rule"`
	ExpiresAt time.Time `json:"expires_at"`
}
type probeState struct {
	Prefix   string                  `json:"prefix"`
	Rules    []probeRule             `json:"rules"`
	Cursor   string                  `json:"cursor"`
	Coverage SecurityMonitorCoverage `json:"coverage"`
}
type securityEnvelope struct {
	CreatedAt time.Time       `json:"created_at"`
	Events    []SecurityEvent `json:"events"`
}
type ProbeMonitor struct {
	dir              string
	settings         ProbeSettings
	commands         CommandRunner
	simulate         bool
	state            probeState
	nextRead         time.Time
	nextRefresh      time.Time
	pendingPath      string
	pendingEvents    []SecurityEvent
	pendingCreatedAt time.Time
	deliveryError    string
	refreshError     error
	readError        error
	nextReport       time.Time
	lastReportedKey  string
}

var probePrefixPattern = regexp.MustCompile(`^PRTP[0-9a-f]{12}:$`)

const probeRuleLifetime = 120 * time.Second

func NewProbeMonitor(dir string, settings ProbeSettings, commands CommandRunner, simulate bool) (*ProbeMonitor, error) {
	if settings.RatePerSecond == 0 {
		settings.RatePerSecond = 5
	}
	if settings.RatePerSecond < 1 || settings.RatePerSecond > 100 {
		return nil, errors.New("probe_log_rate_per_second must be 1..100")
	}
	m := &ProbeMonitor{dir: dir, settings: settings, commands: commands, simulate: simulate}
	data, err := os.ReadFile(filepath.Join(dir, "probe-state.json"))
	if err == nil {
		if err = json.Unmarshal(data, &m.state); err != nil {
			return nil, errors.New("invalid persisted security monitor state")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if m.state.Prefix == "" {
		m.state.Prefix = "PRTP" + batchID()[:12] + ":"
	}
	if !probePrefixPattern.MatchString(m.state.Prefix) {
		return nil, errors.New("invalid security monitor ownership prefix")
	}
	m.state.Coverage.Enabled = settings.Enabled
	m.state.Coverage.RateLimited = true
	m.state.Coverage.Status = "off"
	m.state.Coverage.Zones = []string{}
	return m, nil
}
func (m *ProbeMonitor) Coverage() SecurityMonitorCoverage { return m.state.Coverage }
func (m *ProbeMonitor) OwnedRules() []OwnedRule {
	rules := []OwnedRule{}
	for _, rule := range m.state.Rules {
		rules = append(rules, OwnedRule{SessionID: "probe", Zone: rule.Zone, Rule: rule.Rule, ExpiresAt: rule.ExpiresAt})
	}
	return rules
}
func (m *ProbeMonitor) save() error {
	return atomicJSON(filepath.Join(m.dir, "probe-state.json"), m.state)
}
func probeRuleText(prefix, family, protocol string, rate int) string {
	return fmt.Sprintf(`rule priority="-32750" family="%s" protocol value="%s" log prefix="%s" level="info" limit value="%d/s"`, family, protocol, prefix, rate)
}
func (m *ProbeMonitor) remove(ctx context.Context, r probeRule) error {
	pattern := regexp.MustCompile(`^rule priority="-32750" family="(ipv4|ipv6)" protocol value="(tcp|udp)" log prefix="` + regexp.QuoteMeta(m.state.Prefix) + `" level="info" limit value="([0-9]{1,3})/s"$`)
	parts := pattern.FindStringSubmatch(r.Rule)
	rate := 0
	if len(parts) == 4 {
		rate, _ = strconv.Atoi(parts[3])
	}
	if len(parts) != 4 || rate < 1 || rate > 100 {
		return errors.New("refusing to remove unowned security instrumentation")
	}
	if m.simulate {
		return nil
	}
	out, err := m.commands.Run(ctx, "firewall-cmd", "--zone="+r.Zone, "--remove-rich-rule="+r.Rule)
	if strings.Contains(out, "NOT_ENABLED") {
		return nil
	}
	return err
}
func (m *ProbeMonitor) Close(ctx context.Context) error {
	var first error
	kept := []probeRule{}
	for _, r := range m.state.Rules {
		if err := m.remove(ctx, r); err != nil {
			kept = append(kept, r)
			if first == nil {
				first = err
			}
		}
	}
	m.state.Rules = kept
	m.state.Coverage.Status = "off"
	if first != nil {
		m.state.Coverage.Status = "error"
		m.state.Coverage.Error = first.Error()
	}
	if err := m.save(); first == nil {
		first = err
	}
	return first
}
func (m *ProbeMonitor) zones(ctx context.Context) ([]string, error) {
	if m.simulate {
		return []string{"simulated"}, nil
	}
	if out, err := m.commands.Run(ctx, "ufw", "status"); err == nil && strings.Contains(strings.ToLower(out), "status: active") {
		return nil, errors.New("UFW is active; security instrumentation not installed")
	}
	if out, err := m.commands.Run(ctx, "firewall-cmd", "--state"); err != nil || strings.TrimSpace(out) != "running" {
		return nil, errors.New("firewalld is not running; security observations unavailable")
	}
	out, err := m.commands.Run(ctx, "firewall-cmd", "--get-active-zones")
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			name := strings.Fields(line)[0]
			if m.settings.Zone == "" || m.settings.Zone == name {
				result = append(result, name)
			}
		}
	}
	if len(result) == 0 || len(result) > 32 {
		return nil, errors.New("security monitor requires 1..32 matching active zones")
	}
	sort.Strings(result)
	return result, nil
}
func (m *ProbeMonitor) refresh(ctx context.Context, at time.Time) error {
	zones, err := m.zones(ctx)
	if err != nil {
		return err
	}
	desired := map[string]probeRule{}
	for _, zone := range zones {
		for _, family := range []string{"ipv4", "ipv6"} {
			for _, protocol := range []string{"tcp", "udp"} {
				text := probeRuleText(m.state.Prefix, family, protocol, m.settings.RatePerSecond)
				desired[zone+"\x00"+text] = probeRule{zone, text, at.Add(probeRuleLifetime)}
			}
		}
	}
	kept := []probeRule{}
	for index, rule := range m.state.Rules {
		key := rule.Zone + "\x00" + rule.Rule
		_, wanted := desired[key]
		if !wanted || !at.Add(40*time.Second).Before(rule.ExpiresAt) {
			if err = m.remove(ctx, rule); err != nil {
				m.state.Rules = append(kept, m.state.Rules[index:]...)
				return err
			}
			continue
		}
		if !m.simulate {
			out, e := m.commands.Run(ctx, "firewall-cmd", "--zone="+rule.Zone, "--query-rich-rule="+rule.Rule)
			if e != nil && strings.TrimSpace(out) != "no" {
				return e
			}
			if strings.TrimSpace(out) != "yes" {
				continue
			}
		}
		kept = append(kept, rule)
		delete(desired, key)
	}
	m.state.Rules = kept
	keys := []string{}
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rule := desired[key]
		// Record ownership before the call: if a process dies during a successful
		// D-Bus write, restart can still clean that exact log-only rule.
		m.state.Rules = append(m.state.Rules, rule)
		if err = m.save(); err != nil {
			return err
		}
		if !m.simulate {
			if _, err = m.commands.Run(ctx, "firewall-cmd", "--zone="+rule.Zone, "--add-rich-rule="+rule.Rule, "--timeout=120s"); err != nil {
				return err
			}
		}
	}
	m.state.Coverage.Zones = zones
	if m.state.Coverage.StartedAt == nil {
		started := at
		m.state.Coverage.StartedAt = &started
	}
	return m.save()
}

func socketAccepts(listeners []Listener, destination netip.Addr, port int, protocol string) bool {
	for _, listener := range listeners {
		if listener.Port != port || listener.Protocol != protocol {
			continue
		}
		text := strings.Trim(listener.Address, "[]")
		if text == "0.0.0.0" {
			if destination.Unmap().Is4() {
				return true
			}
			continue
		}
		if text == "" || text == "*" || text == "::" {
			return true
		}
		if address, err := netip.ParseAddr(text); err == nil && address.WithZone("").Unmap() == destination.WithZone("").Unmap() {
			return true
		}
	}
	return false
}
func ParseProbeLog(message, prefix string, when, checkedAt time.Time, listeners []Listener) (SecurityEvent, bool) {
	if !probePrefixPattern.MatchString(prefix) || !strings.Contains(message, prefix) {
		return SecurityEvent{}, false
	}
	message = message[strings.Index(message, prefix)+len(prefix):]
	fields := map[string]string{}
	for _, part := range strings.Fields(message) {
		if pair := strings.SplitN(part, "=", 2); len(pair) == 2 {
			fields[pair[0]] = pair[1]
		}
	}
	// Host ingress only: forwarded traffic and local loopback probes are outside
	// this observer's scope.
	if fields["IN"] == "" || fields["OUT"] != "" {
		return SecurityEvent{}, false
	}
	source, err := netip.ParseAddr(fields["SRC"])
	if err != nil || source.IsLoopback() || source.IsMulticast() {
		return SecurityEvent{}, false
	}
	destination, err := netip.ParseAddr(fields["DST"])
	if err != nil || destination.IsMulticast() {
		return SecurityEvent{}, false
	}
	port, err := strconv.Atoi(fields["DPT"])
	if err != nil || port < 1 || port > 65535 {
		return SecurityEvent{}, false
	}
	protocol := strings.ToLower(fields["PROTO"])
	if protocol != "tcp" && protocol != "udp" {
		return SecurityEvent{}, false
	}
	if checkedAt.Before(when.Add(-time.Minute)) || checkedAt.Sub(when) > 2*time.Minute {
		return SecurityEvent{}, false
	}
	if socketAccepts(listeners, destination, port, protocol) {
		return SecurityEvent{}, false
	}
	return SecurityEvent{EventID: batchID(), Kind: "unexpected_port_hit", SourceIP: source.Unmap().String(), DestinationIP: destination.Unmap().String(), Port: port, Protocol: protocol, Count: 1, FirstSeen: when, LastSeen: when, Listening: false, InventoryCheckedAt: checkedAt, ObservedWhileMonitoring: true}, true
}
func (m *ProbeMonitor) spool(events []SecurityEvent, at time.Time) error {
	if len(events) == 0 {
		return nil
	}
	dir := filepath.Join(m.dir, "security-spool")
	files, err := spoolFiles(dir)
	if err != nil {
		return err
	}
	if len(files) >= 100 {
		for _, event := range events {
			m.state.Coverage.DroppedEvents += event.Count
		}
		return errors.New("security spool full; observed events dropped")
	}
	err = atomicJSON(filepath.Join(dir, fmt.Sprintf("%019d-%s.json", at.UnixNano(), batchID())), securityEnvelope{at, events})
	if err != nil {
		for _, event := range events {
			m.state.Coverage.DroppedEvents += event.Count
		}
	}
	return err
}
func (m *ProbeMonitor) read(ctx context.Context, at time.Time) error {
	if m.simulate {
		return nil
	} // Simulation never invents hits.
	args := []string{"-k", "--output=json", "--no-pager", "-n", "2000"}
	if m.state.Cursor != "" {
		args = append(args, "--after-cursor="+m.state.Cursor)
	} else {
		since := at
		if m.state.Coverage.StartedAt != nil {
			since = *m.state.Coverage.StartedAt
		}
		args = append(args, fmt.Sprintf("--since=@%d", since.Unix()))
	}
	text, err := m.commands.Run(ctx, "journalctl", args...)
	if err != nil {
		m.state.Cursor = ""
		m.state.Coverage.DroppedEvents++
		return errors.New("kernel journal unavailable or cursor lost; security coverage gap")
	}
	sockets, err := m.commands.Run(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return errors.New("cannot verify current listeners; unexpected-port classification suspended")
	}
	listeners := ParseSockets(sockets)
	aggregated := map[string]SecurityEvent{}
	cursor := m.state.Cursor
	lines := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		lines++
		var entry JournalEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue
		}
		if entry.Cursor != "" {
			cursor = entry.Cursor
		}
		micros, e := strconv.ParseInt(entry.Timestamp, 10, 64)
		if e != nil || micros <= 0 || micros > at.Add(time.Minute).UnixMicro() {
			continue
		}
		when := time.UnixMicro(micros).UTC()
		if m.state.Coverage.StartedAt != nil && when.Before(*m.state.Coverage.StartedAt) {
			continue
		}
		event, ok := ParseProbeLog(entry.Message, m.state.Prefix, when, at, listeners)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s|%d", event.SourceIP, event.DestinationIP, event.Protocol, event.Port)
		if previous, found := aggregated[key]; found {
			previous.Count++
			if when.Before(previous.FirstSeen) {
				previous.FirstSeen = when
			}
			if when.After(previous.LastSeen) {
				previous.LastSeen = when
			}
			aggregated[key] = previous
		} else {
			aggregated[key] = event
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	events := []SecurityEvent{}
	keys := []string{}
	for key := range aggregated {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var first error
	for _, key := range keys {
		events = append(events, aggregated[key])
		if len(events) == 100 {
			if err = m.spool(events, at); err != nil && first == nil {
				first = err
			}
			events = nil
		}
	}
	if err = m.spool(events, at); err != nil && first == nil {
		first = err
	}
	m.state.Cursor = cursor
	checked := at
	m.state.Coverage.LastCheckedAt = &checked
	if lines >= 2000 && first == nil {
		first = errors.New("kernel journal read bound reached; security coverage may be incomplete")
	}
	if err = m.save(); err != nil && first == nil {
		first = err
	}
	return first
}
func (m *ProbeMonitor) Tick(ctx context.Context, at time.Time) error {
	if !m.settings.Enabled {
		if len(m.state.Rules) > 0 {
			return m.Close(ctx)
		}
		m.state.Coverage.Status = "off"
		return nil
	}
	var first error
	if !at.Before(m.nextRefresh) {
		m.nextRefresh = at.Add(30 * time.Second)
		m.refreshError = m.refresh(ctx, at)
	}
	if m.refreshError == nil && len(m.state.Rules) > 0 && !at.Before(m.nextRead) {
		m.nextRead = at.Add(10 * time.Second)
		m.readError = m.read(ctx, at)
	}
	first = m.refreshError
	if first == nil {
		first = m.readError
	}
	if first != nil {
		m.state.Coverage.Status = "error"
		m.state.Coverage.Error = first.Error()
	} else if len(m.state.Rules) > 0 {
		m.state.Coverage.Status = "active"
		m.state.Coverage.Error = ""
	}
	if m.simulate && m.settings.Enabled {
		m.state.Coverage.Status = "degraded"
		m.state.Coverage.Error = "simulation; no real kernel observations"
	}
	if first == nil && m.deliveryError != "" {
		m.state.Coverage.Status = "degraded"
		m.state.Coverage.Error = m.deliveryError
	}
	if err := m.save(); first == nil {
		first = err
	}
	return first
}
func coverageReportKey(coverage SecurityMonitorCoverage) string {
	return fmt.Sprintf("%t|%s|%s|%d", coverage.Enabled, coverage.Status, coverage.Error, coverage.DroppedEvents)
}
func (m *ProbeMonitor) ShouldReport(at time.Time) bool {
	if at.Before(m.nextReport) {
		return false
	}
	events, _ := m.Pending(at)
	needed := len(events) > 0 || coverageReportKey(m.state.Coverage) != m.lastReportedKey
	if needed {
		m.nextReport = at.Add(15 * time.Second)
	}
	return needed
}
func (m *ProbeMonitor) Reported(at time.Time, coverage SecurityMonitorCoverage) {
	m.lastReportedKey = coverageReportKey(coverage)
	m.nextReport = at.Add(15 * time.Second)
}
func (m *ProbeMonitor) Pending(at time.Time) ([]SecurityEvent, error) {
	if m.pendingPath != "" {
		if !securityEnvelopeExpired(securityEnvelope{m.pendingCreatedAt, m.pendingEvents}, at) {
			return append([]SecurityEvent{}, m.pendingEvents...), nil
		}
		for _, event := range m.pendingEvents {
			m.state.Coverage.DroppedEvents += event.Count
		}
		if err := os.Remove(m.pendingPath); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		m.pendingPath = ""
		m.pendingEvents = nil
	}
	files, err := spoolFiles(filepath.Join(m.dir, "security-spool"))
	if err != nil {
		return nil, err
	}
	for _, path := range files {
		data, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		var envelope securityEnvelope
		if json.Unmarshal(data, &envelope) != nil || !validSecurityEnvelope(envelope) {
			_ = quarantineBatch(path)
			m.state.Coverage.DroppedEvents++
			continue
		}
		if securityEnvelopeExpired(envelope, at) {
			for _, event := range envelope.Events {
				m.state.Coverage.DroppedEvents += event.Count
			}
			if e = os.Remove(path); e != nil {
				return nil, e
			}
			continue
		}
		m.pendingPath = path
		m.pendingEvents = envelope.Events
		m.pendingCreatedAt = envelope.CreatedAt
		return append([]SecurityEvent{}, envelope.Events...), nil
	}
	return nil, nil
}
func validSecurityEnvelope(envelope securityEnvelope) bool {
	if envelope.CreatedAt.IsZero() || len(envelope.Events) < 1 || len(envelope.Events) > 100 {
		return false
	}
	for _, event := range envelope.Events {
		if len(event.EventID) != 32 || event.Kind != "unexpected_port_hit" || event.Port < 1 || event.Port > 65535 || (event.Protocol != "tcp" && event.Protocol != "udp") || event.Count < 1 || event.Count > 100000000 || event.FirstSeen.IsZero() || event.LastSeen.Before(event.FirstSeen) || event.InventoryCheckedAt.IsZero() || event.Listening {
			return false
		}
		if _, err := netip.ParseAddr(event.SourceIP); err != nil {
			return false
		}
		if _, err := netip.ParseAddr(event.DestinationIP); err != nil {
			return false
		}
	}
	return true
}
func securityEnvelopeExpired(envelope securityEnvelope, at time.Time) bool {
	if at.Sub(envelope.CreatedAt) > 24*time.Hour-time.Minute {
		return true
	}
	for _, event := range envelope.Events {
		if at.Sub(event.FirstSeen) > 24*time.Hour-time.Minute {
			return true
		}
	}
	return false
}
func (m *ProbeMonitor) Acknowledge(ids []string) error {
	if m.pendingPath == "" {
		return nil
	}
	ack := map[string]bool{}
	for _, id := range ids {
		ack[id] = true
	}
	kept := []SecurityEvent{}
	for _, event := range m.pendingEvents {
		if !ack[event.EventID] {
			kept = append(kept, event)
		}
	}
	if len(kept) == len(m.pendingEvents) {
		m.deliveryError = "controller did not acknowledge pending security observations"
		m.state.Coverage.Status = "degraded"
		m.state.Coverage.Error = m.deliveryError
		return m.save()
	}
	if len(kept) == 0 {
		if err := os.Remove(m.pendingPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		m.pendingPath = ""
		m.pendingEvents = nil
		m.deliveryError = ""
		return nil
	}
	if err := atomicJSON(m.pendingPath, securityEnvelope{m.pendingEvents[0].FirstSeen, kept}); err != nil {
		return err
	}
	m.pendingEvents = kept
	return nil
}
