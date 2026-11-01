package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeClassificationRequiresHostIngressAndCurrentClosedPort(t *testing.T) {
	at := time.Now().UTC()
	prefix := "PRTP123456abcdef:"
	log := prefix + " IN=eth0 OUT= SRC=10.20.0.7 DST=10.20.0.9 PROTO=TCP SPT=12345 DPT=9999 SYN"
	listeners := []Listener{{Port: 80, Protocol: "tcp", Address: "0.0.0.0"}, {Port: 9999, Protocol: "tcp", Address: "127.0.0.1"}}
	event, ok := ParseProbeLog(log, prefix, at, at, listeners)
	if !ok || event.Port != 9999 || event.Listening || event.Kind != "unexpected_port_hit" {
		t.Fatalf("closed-port observation missing: %+v %v", event, ok)
	}
	for _, message := range []string{strings.ReplaceAll(log, "DPT=9999", "DPT=80"), strings.ReplaceAll(log, "OUT= ", "OUT=eth1 "), strings.ReplaceAll(log, "SRC=10.20.0.7", "SRC=127.0.0.1"), strings.ReplaceAll(log, "IN=eth0", "IN="), strings.ReplaceAll(log, "PROTO=TCP", "PROTO=ICMP"), strings.ReplaceAll(log, prefix, "OTHER:"), strings.ReplaceAll(log, "DPT=9999", "DPT=70000")} {
		if _, ok := ParseProbeLog(message, prefix, at, at, listeners); ok {
			t.Fatalf("unrelated/listening traffic became a probe: %s", message)
		}
	}
	if _, ok = ParseProbeLog(log, prefix, at.Add(-3*time.Minute), at, listeners); ok {
		t.Fatal("stale journal observation asserted current closed port")
	}
	if _, ok = ParseProbeLog(log, prefix, at, at, []Listener{{Port: 9999, Protocol: "tcp", Address: "::"}}); ok {
		t.Fatal("possible dual-stack listener classified closed")
	}
}

type probeCommands struct {
	calls       []string
	journal     string
	failSockets bool
}

func (r *probeCommands) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	switch name {
	case "ufw":
		return "Status: inactive", nil
	case "firewall-cmd":
		if len(args) > 0 && args[0] == "--state" {
			return "running", nil
		}
		if len(args) > 0 && args[0] == "--get-active-zones" {
			return "public\n  interfaces: eth0", nil
		}
		if strings.Contains(call, "--query-rich-rule=") {
			return "yes", nil
		}
		return "success", nil
	case "ss":
		if r.failSockets {
			return "", errors.New("ss unavailable")
		}
		return `tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=12,fd=3))`, nil
	case "journalctl":
		return r.journal, nil
	}
	return "", fmt.Errorf("unexpected command %s", name)
}
func probeJournal(at time.Time, prefix string) string {
	lines := []string{}
	for n, port := range []int{9999, 9999, 80} {
		entry := JournalEntry{Message: fmt.Sprintf("%s IN=eth0 OUT= SRC=10.20.0.7 DST=10.20.0.9 PROTO=TCP SPT=123 DPT=%d SYN", prefix, port), Cursor: fmt.Sprintf("cursor-%d", n), Timestamp: fmt.Sprint(at.UnixMicro())}
		data, _ := json.Marshal(entry)
		lines = append(lines, string(data))
	}
	return strings.Join(lines, "\n")
}
func TestProbeMonitorUsesBoundedLogOnlyRulesAndDurableExplicitAcknowledgements(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	commands := &probeCommands{}
	m, err := NewProbeMonitor(t.TempDir(), ProbeSettings{Enabled: true, RatePerSecond: 5}, commands, false)
	if err != nil {
		t.Fatal(err)
	}
	commands.journal = probeJournal(at, m.state.Prefix)
	if err = m.Tick(context.Background(), at); err != nil {
		t.Fatal(err)
	}
	if len(m.OwnedRules()) != 4 || m.Coverage().Status != "active" || !m.Coverage().RateLimited {
		t.Fatalf("unexpected coverage %+v", m.Coverage())
	}
	for _, call := range commands.calls {
		if strings.Contains(call, "--add-rich-rule=") {
			if !strings.Contains(call, "--timeout=120s") || strings.Contains(call, " accept") || strings.Contains(call, " drop") || strings.Contains(call, " reject") || strings.Contains(call, "--permanent") {
				t.Fatalf("unsafe instrumentation %s", call)
			}
		}
		if strings.Contains(call, "--reload") || strings.Contains(call, "--set-log-denied") {
			t.Fatal("changed global firewall settings")
		}
	}
	events, err := m.Pending(at)
	if err != nil || len(events) != 1 || events[0].Count != 2 || events[0].Port != 9999 {
		t.Fatalf("unexpected observations %+v %v", events, err)
	}
	if err = m.Acknowledge(nil); err != nil {
		t.Fatal(err)
	}
	retry, _ := m.Pending(at)
	if len(retry) != 1 || retry[0].EventID != events[0].EventID {
		t.Fatal("unacknowledged security observations lost")
	}
	restarted, err := NewProbeMonitor(m.dir, m.settings, commands, false)
	if err != nil {
		t.Fatal(err)
	}
	replayed, _ := restarted.Pending(at)
	if len(replayed) != 1 || replayed[0].EventID != events[0].EventID {
		t.Fatal("security observations did not survive restart")
	}
	if err = restarted.Acknowledge([]string{events[0].EventID}); err != nil {
		t.Fatal(err)
	}
	remaining, _ := restarted.Pending(at)
	if len(remaining) != 0 {
		t.Fatal("acknowledged security events replayed")
	}
	if err = m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(m.dir, "probe-state.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("probe state is not private")
	}
}
func TestProbeNeverClassifiesWhenSocketReadFailsAndSimulationInventsNoTraffic(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	commands := &probeCommands{failSockets: true}
	m, _ := NewProbeMonitor(t.TempDir(), ProbeSettings{Enabled: true}, commands, false)
	commands.journal = probeJournal(at, m.state.Prefix)
	if err := m.Tick(context.Background(), at); err == nil {
		t.Fatal("failed verification did not mark unknown coverage")
	}
	events, _ := m.Pending(at)
	if len(events) != 0 || m.Coverage().Status != "error" {
		t.Fatal("failed socket read fabricated closed ports")
	}
	simulation, _ := NewProbeMonitor(t.TempDir(), ProbeSettings{Enabled: true}, commands, true)
	if err := simulation.Tick(context.Background(), at); err != nil {
		t.Fatal(err)
	}
	events, _ = simulation.Pending(at)
	if len(events) != 0 || simulation.Coverage().Status != "degraded" {
		t.Fatal("simulation generated actual security traffic")
	}
	disabledCommands := &probeCommands{}
	disabled, _ := NewProbeMonitor(t.TempDir(), ProbeSettings{}, disabledCommands, false)
	if err := disabled.Tick(context.Background(), at); err != nil || len(disabledCommands.calls) != 0 {
		t.Fatal("disabled monitor executed firewall commands")
	}
}
func TestProbeRefusesUnownedCleanupAndSpoolFullReportsLoss(t *testing.T) {
	at := time.Now().UTC()
	m, _ := NewProbeMonitor(t.TempDir(), ProbeSettings{Enabled: true}, &probeCommands{}, false)
	if err := m.remove(context.Background(), probeRule{Zone: "public", Rule: `rule port port="22" protocol="tcp" accept`}); err == nil {
		t.Fatal("unowned rule removal allowed")
	}
	dir := filepath.Join(m.dir, "security-spool")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 100; n++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%03d.json", n)), []byte(`{"events":[]}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.spool([]SecurityEvent{{Count: 7}}, at); err == nil || m.Coverage().DroppedEvents != 7 {
		t.Fatal("bounded spool did not expose dropped observations")
	}
}

type probeRoundTripper func(*http.Request) (*http.Response, error)

func (fn probeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
func TestSecurityAcknowledgementIDsAreExplicitAndResetOnFailure(t *testing.T) {
	status := 200
	client, err := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 2}, true)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = probeRoundTripper(func(request *http.Request) (*http.Response, error) {
		body := `{"ack_security_event_ids":["persisted-event"],"ack_firewall_change_ids":["plan-1"]}`
		if status != 200 {
			body = `{"error":"retry"}`
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
	})
	if err = client.Report(context.Background(), Report{}); err != nil || len(client.SecurityAcks) != 1 || len(client.FirewallAcks) != 1 {
		t.Fatal("durable receipt not decoded")
	}
	status = 503
	if err = client.Report(context.Background(), Report{}); err == nil || len(client.SecurityAcks) != 0 || len(client.FirewallAcks) != 0 {
		t.Fatal("failed report retained stale security acknowledgements")
	}
}
func TestAgentRetainsFirewallOutcomeButStopsUploadingAfterDurableReceipt(t *testing.T) {
	dir := t.TempDir()
	config := Config{ControllerURL: "http://127.0.0.1", StateDir: dir, IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1}
	client, err := NewClient(config, true)
	if err != nil {
		t.Fatal(err)
	}
	reports := []Report{}
	client.HTTP.Transport = probeRoundTripper(func(request *http.Request) (*http.Response, error) {
		var report Report
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			return nil, err
		}
		reports = append(reports, report)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ack_firewall_change_ids":["plan-1"]}`)), Header: make(http.Header), Request: request}, nil
	})
	a := &Agent{Config: config, Client: client, Commands: &probeCommands{}, Simulate: true, State: State{FirewallChangeResults: []FirewallChangeResult{{ID: "plan-1", PlanDigest: strings.Repeat("a", 64), Status: "applied", Message: "verified", CompletedAt: time.Now().UTC()}}}}
	if err = a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || len(reports[0].FirewallChangeResults) != 1 || len(reports[1].FirewallChangeResults) != 0 {
		t.Fatal("acknowledged terminal outcome reuploaded")
	}
	if len(a.State.FirewallChangeResults) != 1 || !a.State.FirewallChangeResults[0].Acknowledged {
		t.Fatal("idempotence history removed instead of acknowledging delivery")
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted State
	if err = json.Unmarshal(data, &persisted); err != nil || !persisted.FirewallChangeResults[0].Acknowledged {
		t.Fatal("delivery acknowledgement not durable")
	}
}
func TestPendingSecurityEventsExpireWithoutPoisoningHeartbeats(t *testing.T) {
	at := time.Now().UTC()
	m, _ := NewProbeMonitor(t.TempDir(), ProbeSettings{}, &probeCommands{}, false)
	event, ok := ParseProbeLog("PRTP123456abcdef: IN=eth0 OUT= SRC=10.20.0.7 DST=10.20.0.9 PROTO=TCP DPT=9999", "PRTP123456abcdef:", at, at, nil)
	if !ok {
		t.Fatal("fixture missing")
	}
	if err := m.spool([]SecurityEvent{event}, at); err != nil {
		t.Fatal(err)
	}
	pending, _ := m.Pending(at)
	if len(pending) != 1 {
		t.Fatal("missing pending observations")
	}
	expired, err := m.Pending(at.Add(24 * time.Hour))
	if err != nil || len(expired) != 0 || m.Coverage().DroppedEvents != 1 {
		t.Fatal("cached old observation blocks all future reports")
	}
	bad := filepath.Join(m.dir, "security-spool", "000-invalid.json")
	if err = os.WriteFile(bad, []byte(`{"created_at":"2026-01-01T00:00:00Z","events":[{}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	event.EventID = batchID()
	event.FirstSeen = at.Add(24 * time.Hour)
	event.LastSeen = event.FirstSeen
	event.InventoryCheckedAt = event.FirstSeen
	if err = m.spool([]SecurityEvent{event}, event.FirstSeen); err != nil {
		t.Fatal(err)
	}
	next, err := m.Pending(event.FirstSeen)
	if err != nil || len(next) != 1 || next[0].EventID != event.EventID {
		t.Fatal("malformed payload blocked later valid observations")
	}
}
func TestProbeKernelPrefixAdjacentToINField(t *testing.T) {
	now := time.Now()
	prefix := "PRTP123456abcdef:"
	message := prefix + "IN=eth0 OUT= SRC=10.20.0.7 DST=10.20.0.9 PROTO=TCP DPT=9999"
	if _, ok := ParseProbeLog(message, prefix, now, now, nil); !ok {
		t.Fatal("real nftables adjacent prefix/IN format rejected")
	}
}
