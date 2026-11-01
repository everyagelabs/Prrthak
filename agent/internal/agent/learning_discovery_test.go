package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func automaticSession(now time.Time) Session {
	return Session{ID: "automatic-learning-123", ServerIDs: []string{"host-a"}, SelectionMode: "discovered", DiscoveryPending: true, Ports: []Port{}, StartsAt: now, ExpiresAt: now.Add(time.Hour), Status: "active"}
}

func TestAutomaticLearningForcesFreshDiscoveryAndExcludesPendingCollection(t *testing.T) {
	count := 0
	start := time.Now().UTC()
	a := &Agent{Config: Config{StateDir: t.TempDir(), IntervalSeconds: 300, DiscoveryIntervalSeconds: 900}, Commands: inventoryCommands(&count, nil), confirmed: true, State: State{Coverage: map[string]*Coverage{}}}
	cached := a.inventoryReport(context.Background(), start)
	a.ackInventoryReport(cached)
	s := automaticSession(start.Add(time.Minute))
	a.State.Policy = &Policy{Version: 42, Digest: "unchanged", Mode: "monitor", LearningSessions: []Session{s}}
	if len(ActiveSessions(a.State.Policy, s.StartsAt)) != 0 {
		t.Fatal("pending automatic request was treated as collecting")
	}
	if err := a.LearningTick(context.Background(), s.StartsAt); err != nil || len(a.State.Coverage) != 0 || len(a.State.Rules) != 0 {
		t.Fatalf("pending request installed instrumentation or claimed coverage: %+v %v", a.State, err)
	}
	fresh := a.inventoryReport(context.Background(), s.StartsAt)
	if count != 2 || !fresh.DiscoveryPerformed || fresh.DiscoveredAt.Before(s.StartsAt) || len(fresh.LearningDiscoverySessionIDs) != 1 || fresh.LearningDiscoverySessionIDs[0] != s.ID {
		t.Fatalf("automatic request reused cached discovery: %+v scans=%d", fresh, count)
	}
	if fresh.AgentVersion != Version || len(fresh.Capabilities) < 6 || fresh.Capabilities[0] != LearningDiscoveryCapability {
		t.Fatal("endpoint failed to advertise learning discovery support")
	}
	a.ackInventoryReport(fresh)
	report := a.inventoryReport(context.Background(), s.StartsAt.Add(time.Second))
	if count != 2 || report.DiscoveryPerformed || len(report.LearningDiscoverySessionIDs) != 0 {
		t.Fatal("acknowledged cached report claimed fresh learning discovery")
	}
	// An endpoint can be configured for a slower heartbeat, but a still-pending
	// automatic request retries within one minute if the controller did not freeze it.
	retry := a.inventoryReport(context.Background(), s.StartsAt.Add(time.Minute))
	if count != 3 || !retry.DiscoveryPerformed || len(retry.LearningDiscoverySessionIDs) != 1 {
		t.Fatal("pending learning discovery did not retry within60seconds")
	}
	if a.State.Policy.Version != 42 || a.State.Policy.Digest != "unchanged" {
		t.Fatal("automatic learning changed access policy identity")
	}
}

func TestAutomaticDiscoveryDeliveryRetryRetainsFreshScanBinding(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	a.Commands = inventoryCommands(&count, nil)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	reports := []Report{}
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var report Report
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
		status := 200
		if len(reports) == 2 {
			status = 503
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})
	if err = a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	s := automaticSession(clock)
	a.State.Policy = &Policy{Version: 1, Digest: "fixed", Mode: "monitor", LearningSessions: []Session{s}}
	if err = a.report(context.Background()); err == nil {
		t.Fatal("failed learning discovery report was not surfaced")
	}
	clock = clock.Add(time.Second)
	if err = a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count != 2 || len(reports[1].LearningDiscoverySessionIDs) != 1 || len(reports[2].LearningDiscoverySessionIDs) != 1 || !reports[1].DiscoveredAt.Equal(*reports[2].DiscoveredAt) || reports[1].LearningDiscoverySessionIDs[0] != s.ID {
		t.Fatal("HTTP retry lost its fresh scan/session binding or repeated discovery")
	}
	clock = clock.Add(time.Second)
	if err = a.report(context.Background()); err != nil || len(reports[3].LearningDiscoverySessionIDs) != 0 || reports[3].DiscoveryPerformed {
		t.Fatal("cached heartbeat replayed acknowledged learning discovery")
	}
}

func TestAutomaticLearningDiscoveryErrorRetriesAndExpiryStopsRequests(t *testing.T) {
	count := 0
	fail := false
	start := time.Now().UTC()
	a := &Agent{Config: Config{IntervalSeconds: 300, DiscoveryIntervalSeconds: 900}, Commands: inventoryCommands(&count, &fail)}
	initial := a.inventoryReport(context.Background(), start)
	a.ackInventoryReport(initial)
	s := automaticSession(start.Add(time.Minute))
	s.ExpiresAt = s.StartsAt.Add(2 * time.Minute)
	a.State.Policy = &Policy{LearningSessions: []Session{s}}
	fail = true
	report := a.inventoryReport(context.Background(), s.StartsAt)
	if report.DiscoveryError == "" || len(report.LearningDiscoverySessionIDs) != 1 || len(report.Listeners) != 1 || !report.DiscoveredAt.Equal(*initial.DiscoveredAt) {
		t.Fatal("failed fresh discovery was hidden or previous inventory was discarded")
	}
	a.ackInventoryReport(report)
	fail = false
	retry := a.inventoryReport(context.Background(), s.StartsAt.Add(time.Minute))
	if count != 3 || retry.DiscoveryError != "" || !retry.DiscoveryPerformed || len(retry.LearningDiscoverySessionIDs) != 1 || retry.DiscoveredAt.Before(s.StartsAt) {
		t.Fatal("failed learning discovery did not retry successfully within60seconds")
	}
	a.ackInventoryReport(retry)
	expired := a.inventoryReport(context.Background(), s.ExpiresAt)
	if count != 3 || len(expired.LearningDiscoverySessionIDs) != 0 || len(ActiveSessions(a.State.Policy, s.ExpiresAt)) != 0 {
		t.Fatal("expired pending learning request retried or started collection")
	}
}

func TestSyncFetchesFrozenHostPortsAfterFreshDiscoverySameCycle(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 300, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	commands := inventoryCommands(&count, nil)
	base := commands.fn
	commands.fn = func(name string, args []string) (string, error) {
		if name == "firewall-cmd" && len(args) > 0 && args[0] == "--get-active-zones" {
			return "public\n  interfaces: eth0", nil
		}
		return base(name, args)
	}
	a.Commands = commands
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	cached := a.inventoryReport(context.Background(), clock.Add(-time.Minute))
	a.ackInventoryReport(cached)
	s := automaticSession(clock)
	fixtureAuthenticatedClient(a, "host-a")
	policyRequests := 0
	discoveryAcknowledged := false
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := "{}"
		if strings.HasSuffix(request.URL.Path, "/policy") {
			policyRequests++
			assigned := s
			if discoveryAcknowledged {
				assigned.DiscoveryPending = false
				assigned.Ports = []Port{{2022, "tcp"}, {8080, "tcp"}}
			}
			encoded, err := json.Marshal(Policy{ServerID: "host-a", Version: 7, Digest: "access-fixed", Mode: "monitor", Services: []Service{}, LearningSessions: []Session{assigned}})
			if err != nil {
				t.Fatal(err)
			}
			body = string(encoded)
		} else {
			var report Report
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
				t.Fatal(err)
			}
			if len(report.LearningDiscoverySessionIDs) != 0 {
				if count != 2 || !report.DiscoveryPerformed || report.DiscoveredAt.Before(s.StartsAt) {
					t.Fatal("learning discovery acknowledgement was not an actual fresh scan")
				}
				discoveryAcknowledged = true
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	if err = a.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if policyRequests != 2 || !discoveryAcknowledged || len(ActiveSessions(a.State.Policy, clock)) != 1 {
		t.Fatal("fresh per-host assignment was not fetched in the same control cycle")
	}
	if err = a.LearningTick(context.Background(), clock); err != nil {
		t.Fatal(err)
	}
	if len(a.State.Rules) != 2 || a.State.Policy.Version != 7 || a.State.Policy.Digest != "access-fixed" {
		t.Fatalf("frozen port collection changed access identity or selected wrong ports: %+v", a.State)
	}
	for _, rule := range a.State.Rules {
		if !strings.Contains(rule.Rule, `port="2022"`) && !strings.Contains(rule.Rule, `port="8080"`) || strings.Contains(rule.Rule, " accept") || strings.Contains(rule.Rule, " drop") || strings.Contains(rule.Rule, " reject") {
			t.Fatalf("collector changed access or instrumented an unassigned port: %s", rule.Rule)
		}
	}
}

func TestValidateAutomaticDiscoveryAssignmentAndNoListeners(t *testing.T) {
	start := time.Now().UTC()
	s := automaticSession(start)
	p := &Policy{Version: 1, Digest: "valid", Mode: "monitor", LearningSessions: []Session{s}}
	if err := ValidatePolicy(p); err != nil {
		t.Fatal(err)
	}
	p.LearningSessions[0].DiscoveryPending = false
	if err := ValidatePolicy(p); err != nil || len(ActiveSessions(p, start)) != 0 {
		t.Fatal("no-listener discovery became wildcard collection")
	}
	p.LearningSessions[0].DiscoveryPending = true
	p.LearningSessions[0].Ports = []Port{{8080, "tcp"}}
	if ValidatePolicy(p) == nil {
		t.Fatal("pending discovery was allowed to carry instrumentation ports")
	}
	p.LearningSessions[0] = s
	p.LearningSessions[0].SelectionMode = "manual"
	if ValidatePolicy(p) == nil {
		t.Fatal("manual empty scope was accepted as discovery")
	}
}

func TestSavedAutomaticRequestResumesDiscoveryAfterRestart(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	start := time.Now().UTC()
	s := automaticSession(start)
	saved := State{Policy: &Policy{ServerID: "host-a", Version: 9, Digest: "access-fixed", Mode: "monitor", LearningSessions: []Session{s}}}
	if err := atomicJSON(filepath.Join(c.StateDir, "state.json"), saved); err != nil {
		t.Fatal(err)
	}
	a, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	a.Commands = inventoryCommands(&count, nil)
	report := a.inventoryReport(context.Background(), start.Add(time.Second))
	if count != 1 || !report.DiscoveryPerformed || len(report.LearningDiscoverySessionIDs) != 1 || report.LearningDiscoverySessionIDs[0] != s.ID || a.State.Policy.Version != 9 {
		t.Fatal("restart lost the pending request or collected without a new scan")
	}
	for _, name := range []string{"enrollment-pending.key", "enrollment-pending.csr"} {
		if _, err := os.Stat(filepath.Join(c.StateDir, name)); !os.IsNotExist(err) {
			t.Fatal("learning discovery created a new endpoint enrollment identity")
		}
	}
}
