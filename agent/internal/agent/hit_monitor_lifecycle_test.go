package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type hitLifecycleCall struct {
	name string
	args []string
}

type hitLifecycleCommands struct {
	rules                 map[string]bool
	entries               []JournalEntry
	calls                 []hitLifecycleCall
	adds, removes         []string
	addTimeouts           []int
	onQuery               func(string)
	raceAdd               bool
	failAddAfterWrite     bool
	removeErr, journalErr error
}

func (f *hitLifecycleCommands) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, hitLifecycleCall{name, append([]string{}, args...)})
	switch name {
	case "journalctl":
		if f.journalErr != nil {
			return "", f.journalErr
		}
		after := ""
		for _, arg := range args {
			if strings.HasPrefix(arg, "--after-cursor=") {
				after = strings.TrimPrefix(arg, "--after-cursor=")
			}
		}
		start := 0
		for index, entry := range f.entries {
			if entry.Cursor == after && after != "" {
				start = index + 1
				break
			}
		}
		var out strings.Builder
		for _, entry := range f.entries[start:] {
			raw, err := json.Marshal(entry)
			if err != nil {
				return "", err
			}
			out.Write(raw)
			out.WriteByte('\n')
		}
		return out.String(), nil
	case "ufw":
		return "Status: inactive", nil
	case "firewall-cmd":
		for _, arg := range args {
			if arg == "--permanent" || arg == "--reload" {
				return "", errors.New("hit fake refuses permanent/reload mutations")
			}
			switch arg {
			case "--state":
				return "running", nil
			case "--get-active-zones":
				return "public\n  interfaces: eth0\n", nil
			case "--list-all-zones":
				values := []string{}
				for rule, present := range f.rules {
					if present {
						values = append(values, rule)
					}
				}
				sort.Strings(values)
				text := "public (active)\n  target: default\n  interfaces: eth0\n  rich rules:\n"
				for _, rule := range values {
					text += "    " + rule + "\n"
				}
				return text, nil
			}
			if strings.HasPrefix(arg, "--query-rich-rule=") {
				rule := strings.TrimPrefix(arg, "--query-rich-rule=")
				if f.onQuery != nil {
					f.onQuery(rule)
				}
				if f.rules[rule] {
					return "yes", nil
				}
				return "no", errors.New("not enabled")
			}
			if strings.HasPrefix(arg, "--add-rich-rule=") {
				rule := strings.TrimPrefix(arg, "--add-rich-rule=")
				f.adds = append(f.adds, rule)
				timeout := 0
				for _, value := range args {
					if strings.HasPrefix(value, "--timeout=") {
						timeout, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(value, "--timeout="), "s"))
					}
				}
				f.addTimeouts = append(f.addTimeouts, timeout)
				if f.raceAdd {
					f.raceAdd = false
					f.rules[rule] = true
					return "ALREADY_ENABLED", nil
				}
				if f.rules[rule] {
					return "ALREADY_ENABLED", nil
				}
				f.rules[rule] = true
				if f.failAddAfterWrite {
					return "", errors.New("ambiguous command result after possible installation")
				}
				return "success", nil
			}
			if strings.HasPrefix(arg, "--remove-rich-rule=") {
				rule := strings.TrimPrefix(arg, "--remove-rich-rule=")
				f.removes = append(f.removes, rule)
				if f.removeErr != nil {
					return "", f.removeErr
				}
				if !f.rules[rule] {
					return "NOT_ENABLED", nil
				}
				delete(f.rules, rule)
				return "success", nil
			}
		}
	}
	return "", fmt.Errorf("unexpected hit-monitor command %s %q", name, args)
}

type hitLifecycleHarness struct {
	dir              string
	base, wall, mono time.Time
	commands         *hitLifecycleCommands
	monitor          *HitMonitor
}

func newHitLifecycleHarness(t *testing.T, maxSpool int, base time.Time) *hitLifecycleHarness {
	t.Helper()
	h := &hitLifecycleHarness{dir: t.TempDir(), base: base, wall: base, mono: base,
		commands: &hitLifecycleCommands{rules: map[string]bool{}}}
	m, err := NewHitMonitor(h.dir, "public", maxSpool, h.commands, false)
	if err != nil {
		t.Fatal(err)
	}
	h.attach(m)
	return h
}

func (h *hitLifecycleHarness) attach(m *HitMonitor) {
	h.monitor = m
	m.clock = func() time.Time { return h.wall }
	m.monotonic = func() time.Time { return h.mono }
}

func (h *hitLifecycleHarness) assignment(id string, ports ...Port) HitMonitorAssignment {
	if len(ports) == 0 {
		ports = []Port{{Port: 8080, Protocol: "tcp"}}
	}
	return HitMonitorAssignment{ID: id, ServerID: "endpoint-one", StartsAt: h.base, ExpiresAt: h.base.Add(120 * time.Second), Ports: ports}
}

func (h *hitLifecycleHarness) advance(seconds int) {
	h.wall = h.base.Add(time.Duration(seconds) * time.Second)
	h.mono = h.base.Add(time.Duration(seconds) * time.Second)
}

func (h *hitLifecycleHarness) set(t *testing.T, items ...HitMonitorAssignment) {
	t.Helper()
	if err := h.monitor.SetAssignments("endpoint-one", items, h.wall); err != nil {
		t.Fatal(err)
	}
}

func hitLifecycleEntry(item HitMonitorAssignment, cursor, source string, at time.Time) JournalEntry {
	return JournalEntry{Cursor: cursor, Timestamp: strconv.FormatInt(at.UnixMicro(), 10),
		Message: hitTestLine(item.ID, source, "10.0.0.1", "TCP", item.Ports[0].Port)}
}

func hitLifecycleBatch(t *testing.T, item HitMonitorAssignment, cursor, source string, at time.Time) HitBatch {
	t.Helper()
	entry := hitLifecycleEntry(item, cursor, source, at)
	event, ok := ParseHitKernelLog(entry.Message, at, item, cursor)
	if !ok {
		t.Fatal("invalid test hit event")
	}
	batch := HitBatch{MonitorID: item.ID, LeaseStartsAt: item.StartsAt, LeaseExpiresAt: item.ExpiresAt, Events: []HitEvent{event}}
	batch.BatchID = hitBatchDigest(batch)
	return batch
}

func hitLifecycleBatches(t *testing.T, m *HitMonitor) []HitBatch {
	t.Helper()
	files, err := spoolFiles(filepath.Join(m.dir, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	result := []HitBatch{}
	for _, path := range files {
		raw, err := readPrivateSetupBound(path, maxHitBatchBytes)
		if err != nil {
			t.Fatal(err)
		}
		var batch HitBatch
		if err = json.Unmarshal(raw, &batch); err != nil {
			t.Fatal(err)
		}
		if err = validateHitBatch(batch); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("nonprivate hit spool %s: %v", path, err)
		}
		result = append(result, batch)
	}
	return result
}

func hitLifecycleClient(t *testing.T, server string, status *int, received *[]HitBatch) *Client {
	t.Helper()
	identity := &atomic.Pointer[tls.Certificate]{}
	identity.Store(&tls.Certificate{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: server}}})
	return &Client{identity: identity, config: Config{ControllerURL: "https://management.invalid", ControlURL: "https://control.invalid", DiscoveryURL: "https://discovery.invalid"},
		HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != "POST" || request.URL.Path != "/api/v1/agent/hits" || request.URL.Host != "discovery.invalid" {
				t.Fatalf("hit upload used another API/channel: %s %s", request.Method, request.URL)
			}
			var batch HitBatch
			if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
				t.Fatal(err)
			}
			if err := validateHitBatch(batch); err != nil {
				t.Fatal(err)
			}
			*received = append(*received, batch)
			return &http.Response{StatusCode: *status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})}}
}

func TestHitLifecycleExpiredDuringPreflightNeverAddsRule(t *testing.T) {
	h := newHitLifecycleHarness(t, 4, time.Now().UTC())
	item := h.assignment("expiry-during-query")
	h.set(t, item)
	queries := 0
	h.commands.onQuery = func(string) { queries++; h.wall = item.ExpiresAt.Add(time.Second) }
	_ = h.monitor.Tick(context.Background(), h.base)
	if queries == 0 {
		t.Fatal("preflight path was not exercised")
	}
	if len(h.commands.adds) != 0 || len(h.monitor.OwnedRules()) != 0 {
		t.Fatalf("expired lease installed instrumentation: adds=%v owned=%v", h.commands.adds, h.monitor.OwnedRules())
	}
}

func TestHitLifecycleMonotonicExpirySurvivesWallClockRollbackAndSameEpochReplay(t *testing.T) {
	h := newHitLifecycleHarness(t, 4, time.Now().UTC())
	item := h.assignment("monotonic-lease")
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.advance(90)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	// Wall time still makes the signed lease look valid; elapsed time has exceeded its cap.
	h.wall = h.base.Add(10 * time.Second)
	h.mono = h.base.Add(121 * time.Second)
	_ = h.monitor.Tick(context.Background(), h.wall)
	if len(h.commands.adds) != 1 || len(h.commands.removes) != 1 || len(h.commands.rules) != 0 {
		t.Fatalf("clock rollback prolonged instrumentation: adds=%d removes=%d rules=%d", len(h.commands.adds), len(h.commands.removes), len(h.commands.rules))
	}
	// Re-presenting the identical signed lease must not reset its monotonic deadline.
	if err := h.monitor.SetAssignments(item.ServerID, []HitMonitorAssignment{item}, h.wall); err == nil {
		_ = h.monitor.Tick(context.Background(), h.wall)
	}
	if len(h.commands.adds) != 1 || len(h.commands.rules) != 0 {
		t.Fatal("same lease epoch reset its elapsed-time deadline")
	}
}

func TestHitLifecycleRestartCleansConfirmedRulesWithoutRestoringCaptureAuthority(t *testing.T) {
	h := newHitLifecycleHarness(t, 4, time.Now().UTC().Add(-30*time.Second))
	item := h.assignment("restart-cleanup")
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.commands.entries = []JournalEntry{
		hitLifecycleEntry(item, "before-restart", "192.0.2.1", h.base.Add(5*time.Second)),
		hitLifecycleEntry(item, "after-restart", "192.0.2.2", h.base.Add(50*time.Second)),
	}
	restarted, err := NewHitMonitor(h.dir, "public", 4, h.commands, false)
	if err != nil {
		t.Fatal(err)
	}
	h.attach(restarted)
	h.advance(60)
	_ = restarted.Tick(context.Background(), h.wall)
	if len(h.commands.adds) != 1 || len(h.commands.removes) != 1 || len(h.commands.rules) != 0 || len(restarted.active) != 0 {
		t.Fatalf("restart reused cached lease: adds=%d removes=%d active=%d", len(h.commands.adds), len(h.commands.removes), len(restarted.active))
	}
	for _, batch := range hitLifecycleBatches(t, restarted) {
		for _, event := range batch.Events {
			if event.SourceIP == "192.0.2.2" {
				t.Fatal("restart captured a new packet without fresh authority")
			}
		}
	}
}

func TestHitLifecycleFreshSameEpochRestartRetainsOldTailAndResumesOnlyFreshInterval(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC().Add(-30*time.Second))
	item := h.assignment("restart-resume")
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.commands.entries = []JournalEntry{hitLifecycleEntry(item, "old-tail", "192.0.2.1", h.base.Add(5*time.Second))}
	restarted, err := NewHitMonitor(h.dir, "public", 8, h.commands, false)
	if err != nil {
		t.Fatal(err)
	}
	h.attach(restarted)
	h.advance(40)
	h.set(t, item)
	if err := restarted.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.commands.entries = append(h.commands.entries, hitLifecycleEntry(item, "new-tail", "2001:db8::2", h.base.Add(50*time.Second)))
	// Keep IP families coherent while proving IPv6 survives persisted spool delivery.
	h.commands.entries[len(h.commands.entries)-1].Message = hitTestLine(item.ID, "2001:db8::2", "2001:db8::1", "TCP", 8080)
	h.advance(51)
	if err := restarted.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	sources := map[string]int{}
	for _, batch := range hitLifecycleBatches(t, restarted) {
		if batch.MonitorID != item.ID || !batch.LeaseStartsAt.Equal(item.StartsAt) || !batch.LeaseExpiresAt.Equal(item.ExpiresAt) {
			t.Fatalf("old tail was assigned a different lease: %+v", batch)
		}
		for _, event := range batch.Events {
			sources[event.SourceIP] += event.Count
		}
	}
	if !reflect.DeepEqual(sources, map[string]int{"192.0.2.1": 1, "2001:db8::2": 1}) {
		t.Fatalf("restart lost old tail or fresh resumed records: %v", sources)
	}
}

func TestHitLifecyclePreexistingOrAmbiguousRulesAreNeverAdoptedOrRemoved(t *testing.T) {
	for _, mode := range []string{"preexisting", "already-enabled-race", "uncertain-command"} {
		t.Run(mode, func(t *testing.T) {
			h := newHitLifecycleHarness(t, 4, time.Now().UTC())
			item := h.assignment(mode)
			rule := HitObservationRule(item.ID, item.Ports[0])
			h.set(t, item)
			switch mode {
			case "preexisting":
				h.commands.rules[rule] = true
			case "already-enabled-race":
				h.commands.raceAdd = true
			case "uncertain-command":
				h.commands.failAddAfterWrite = true
			}
			if err := h.monitor.Tick(context.Background(), h.wall); err == nil {
				t.Fatal("unconfirmed ownership was reported healthy")
			}
			if len(h.monitor.OwnedRules()) != 0 {
				t.Fatal("ambiguous/preexisting rule became owned inventory")
			}
			h.advance(1)
			h.set(t)
			_ = h.monitor.Tick(context.Background(), h.wall)
			if len(h.commands.removes) != 0 || !h.commands.rules[rule] {
				t.Fatalf("monitor removed instrumentation it could not prove it owned: removes=%v", h.commands.removes)
			}
			if mode == "preexisting" && len(h.commands.adds) != 0 {
				t.Fatal("preexisting rule was needlessly mutated")
			}
		})
	}
}

func TestHitLifecycleFailedCleanupCannotPersistMoreThanRuleCapacity(t *testing.T) {
	h := newHitLifecycleHarness(t, 4, time.Now().UTC())
	oldPorts, newPorts := make([]Port, maxHitPorts), make([]Port, maxHitPorts)
	for index := range oldPorts {
		oldPorts[index] = Port{Port: 1000 + index, Protocol: "tcp"}
		newPorts[index] = Port{Port: 2000 + index, Protocol: "tcp"}
	}
	first := h.assignment("capacity-old", oldPorts...)
	h.set(t, first)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if len(h.monitor.state.Rules) != maxHitPorts {
		t.Fatal("fixture did not fill rule capacity")
	}
	h.commands.removeErr = errors.New("firewalld removal unavailable")
	h.advance(1)
	replacement := h.assignment("capacity-new", newPorts...)
	h.set(t, replacement)
	if err := h.monitor.Tick(context.Background(), h.wall); err == nil {
		t.Fatal("failed cleanup was not reported")
	}
	if len(h.monitor.state.Rules) != maxHitPorts || len(h.commands.adds) != maxHitPorts {
		t.Fatalf("cleanup records/new installs exceeded capacity: records=%d adds=%d", len(h.monitor.state.Rules), len(h.commands.adds))
	}
	if _, err := NewHitMonitor(h.dir, "public", 4, h.commands, false); err != nil {
		t.Fatalf("manager persisted state its own loader rejects: %v", err)
	}
}

func TestHitLifecycleSpoolFullRetainsCursorAndStoppedTailUntilDeliveryResumes(t *testing.T) {
	h := newHitLifecycleHarness(t, 1, time.Now().UTC())
	item := h.assignment("spool-pressure")
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	existing := hitLifecycleBatch(t, item, "existing-record", "192.0.2.1", h.base.Add(time.Second))
	if err := h.monitor.spool(existing); err != nil {
		t.Fatal(err)
	}
	h.commands.entries = []JournalEntry{hitLifecycleEntry(item, "waiting-record", "192.0.2.2", h.base.Add(2*time.Second))}
	h.advance(3)
	if err := h.monitor.Tick(context.Background(), h.wall); err == nil {
		t.Fatal("spool-full collection did not fail")
	}
	if h.monitor.state.Cursor != "" {
		t.Fatal("cursor advanced past an unspooled packet")
	}
	h.advance(4)
	h.set(t)
	h.advance(40)
	if err := h.monitor.Tick(context.Background(), h.wall); err == nil {
		t.Fatal("undrained tail was silently discarded")
	}
	if h.monitor.state.Cursor != "" || len(h.monitor.state.Grants) == 0 {
		t.Fatal("stopped lease history needed to replay the retained cursor was lost")
	}
	status := 200
	received := []HitBatch{}
	client := hitLifecycleClient(t, item.ServerID, &status, &received)
	if sent, err := h.monitor.Flush(context.Background(), client, h.wall); err != nil || sent != 1 {
		t.Fatalf("cannot relieve spool pressure: sent=%d err=%v", sent, err)
	}
	h.advance(41)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	batches := hitLifecycleBatches(t, h.monitor)
	if len(batches) != 1 || len(batches[0].Events) != 1 || batches[0].Events[0].SourceIP != "192.0.2.2" || h.monitor.state.Cursor != "waiting-record" {
		t.Fatalf("durable retry lost the stopped tail: batches=%+v cursor=%q", batches, h.monitor.state.Cursor)
	}
}

func TestHitLifecycleLeaseTaggedRenewalAndRepeatedJournalPageAreIdempotent(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	old := h.assignment("lease-tagged")
	h.set(t, old)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.commands.entries = []JournalEntry{hitLifecycleEntry(old, "old-cursor", "192.0.2.1", h.base.Add(5*time.Second))}
	h.advance(6)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	renewed := old
	renewed.StartsAt = h.base.Add(60 * time.Second)
	renewed.ExpiresAt = h.base.Add(180 * time.Second)
	h.advance(60)
	h.set(t, renewed)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.commands.entries = append(h.commands.entries, hitLifecycleEntry(renewed, "new-cursor", "192.0.2.2", h.base.Add(70*time.Second)))
	h.advance(71)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	before := hitLifecycleBatches(t, h.monitor)
	if len(before) != 2 {
		t.Fatalf("renewal lost distinct lease tags: %+v", before)
	}
	leases := map[string]string{}
	eventIDs := map[string]bool{}
	for _, batch := range before {
		if len(batch.Events) != 1 {
			t.Fatal("unexpected batch events")
		}
		leases[batch.Events[0].SourceIP] = batch.LeaseStartsAt.Format(time.RFC3339Nano)
		eventIDs[batch.Events[0].EventID] = true
	}
	if leases["192.0.2.1"] != old.StartsAt.Format(time.RFC3339Nano) || leases["192.0.2.2"] != renewed.StartsAt.Format(time.RFC3339Nano) || len(eventIDs) != 2 {
		t.Fatalf("renewal relabeled event history: %v", leases)
	}
	h.monitor.state.Cursor = ""
	if err := h.monitor.save(); err != nil {
		t.Fatal(err)
	}
	h.advance(72)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	after := hitLifecycleBatches(t, h.monitor)
	if len(after) != len(before) {
		t.Fatal("journal replay created duplicate spool payloads")
	}
	beforeIDs, afterIDs := []string{}, []string{}
	for _, batch := range before {
		beforeIDs = append(beforeIDs, batch.BatchID)
	}
	for _, batch := range after {
		afterIDs = append(afterIDs, batch.BatchID)
	}
	sort.Strings(beforeIDs)
	sort.Strings(afterIDs)
	if !reflect.DeepEqual(beforeIDs, afterIDs) {
		t.Fatal("journal retry changed stable batch identity")
	}
}

func TestHitLifecycleHTTPRetryQuarantineAndAcknowledgmentStayPrivateAndExact(t *testing.T) {
	for _, test := range []struct {
		name                  string
		status                int
		retained, quarantined bool
	}{
		{"request-timeout", 408, true, false}, {"server-error", 500, true, false}, {"permanent-rejection", 400, false, true}, {"acknowledged", 200, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHitLifecycleHarness(t, 4, time.Now().UTC())
			item := h.assignment("http-" + test.name)
			h.set(t, item)
			batch := hitLifecycleBatch(t, item, "http-cursor", "192.0.2.1", h.base.Add(time.Second))
			if err := h.monitor.spool(batch); err != nil {
				t.Fatal(err)
			}
			status := test.status
			received := []HitBatch{}
			client := hitLifecycleClient(t, item.ServerID, &status, &received)
			sent, err := h.monitor.Flush(context.Background(), client, h.base.Add(2*time.Second))
			if (test.status != 200) != (err != nil) {
				t.Fatalf("HTTP%d err=%v", test.status, err)
			}
			if test.status == 200 && sent != 1 {
				t.Fatalf("successful receipt count=%d", sent)
			}
			remaining := hitLifecycleBatches(t, h.monitor)
			if (len(remaining) == 1) != test.retained {
				t.Fatalf("HTTP%d retained=%d", test.status, len(remaining))
			}
			quarantine, _ := os.ReadDir(filepath.Join(h.monitor.dir, "spool", "quarantine"))
			if (len(quarantine) == 1) != test.quarantined {
				t.Fatalf("HTTP%d quarantine=%d", test.status, len(quarantine))
			}
			if len(received) != 1 || !reflect.DeepEqual(received[0], batch) {
				t.Fatal("uploader changed the private batch")
			}
			if test.retained {
				status = 200
				if sent, err = h.monitor.Flush(context.Background(), client, h.base.Add(3*time.Second)); err != nil || sent != 1 {
					t.Fatalf("retry did not acknowledge exact batch: sent=%d err=%v", sent, err)
				}
				if len(received) != 2 || !reflect.DeepEqual(received[0], received[1]) || len(hitLifecycleBatches(t, h.monitor)) != 0 {
					t.Fatal("retry changed IDs/payload or failed to remove acknowledged batch")
				}
			}
		})
	}
}

func TestHitLifecycleChangedBatchBoundariesPreservePacketIdentity(t *testing.T) {
	h := newHitLifecycleHarness(t, 4, time.Now().UTC())
	item := h.assignment("batch-boundaries")
	h.set(t, item)
	first := hitLifecycleBatch(t, item, "packet-a", "192.0.2.1", h.base.Add(time.Second))
	second := hitLifecycleBatch(t, item, "packet-b", "192.0.2.2", h.base.Add(2*time.Second))
	combined := first
	combined.Events = append(append([]HitEvent{}, first.Events...), second.Events...)
	combined.BatchID = hitBatchDigest(combined)
	if err := h.monitor.spool(combined); err != nil {
		t.Fatal(err)
	}
	if err := h.monitor.spool(first); err != nil {
		t.Fatal(err)
	}
	if err := h.monitor.spool(combined); err != nil {
		t.Fatal(err)
	}
	batches := hitLifecycleBatches(t, h.monitor)
	if len(batches) != 2 {
		t.Fatalf("exact batch retry duplicated payloads: %d", len(batches))
	}
	occurrences := map[string]int{}
	for _, batch := range batches {
		for _, event := range batch.Events {
			occurrences[event.EventID]++
		}
	}
	if len(occurrences) != 2 || occurrences[first.Events[0].EventID] != 2 || occurrences[second.Events[0].EventID] != 1 {
		t.Fatal("packet identity changed with batch boundaries; backend event dedup cannot be reliable")
	}
}
