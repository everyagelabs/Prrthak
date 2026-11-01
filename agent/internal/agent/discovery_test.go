package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func inventoryCommands(counter *int, fail *bool) *fakeRunner {
	return &fakeRunner{fn: func(name string, args []string) (string, error) {
		switch name {
		case "ss":
			*counter++
			if fail != nil && *fail {
				return "", errors.New("socket inventory temporarily unavailable")
			}
			return `tcp LISTEN 0 128 0.0.0.0:2022 0.0.0.0:* users:(("sshd",pid=9999999,fd=3))`, nil
		case "ufw":
			return "Status: inactive", nil
		case "firewall-cmd":
			if len(args) > 0 && args[0] == "--state" {
				return "running", nil
			}
			return "1.3.0", nil
		case "systemctl":
			return "", nil
		}
		return "", nil
	}}
}
func TestOwnerProcessIdentifiesSSHOnCustomPort(t *testing.T) {
	listeners := ParseSockets(`tcp LISTEN 0 128 0.0.0.0:2022 0.0.0.0:* users:(("sshd",pid=314,fd=3))
tcp LISTEN 0 128 [::]:9443 [::]:* users:(("nginx",pid=315,fd=4))
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("mystery",pid=316,fd=5))`)
	if len(listeners) != 3 {
		t.Fatalf("listeners=%+v", listeners)
	}
	found := map[int]Listener{}
	for _, item := range listeners {
		found[item.Port] = item
	}
	if found[2022].Service != "SSH" || found[2022].PID != 314 {
		t.Fatalf("custom SSH identity missing %+v", found[2022])
	}
	if found[9443].Service != "Nginx" {
		t.Fatal("service was inferred from conventional port instead of owning process")
	}
	if found[22].Service != "Unknown service" {
		t.Fatal("unknown process on22 was falsely labeled SSH")
	}
}
func TestProcessCgroupIdentifiesOwningApplicationUnit(t *testing.T) {
	rows := []Listener{{Port: 8443, Protocol: "tcp", Address: "::", Process: "nginx", PID: 41}, {Port: 8080, Protocol: "tcp", Address: "0.0.0.0", Process: "billing-api", PID: 42}}
	result := EnrichListeners(rows, func(pid int) (string, error) {
		if pid == 41 {
			return `0::/system.slice/billing\x2dweb.service`, nil
		}
		return "9:cpu:/system.slice/billing-api.service", nil
	}, nil)
	if result[0].SystemdUnit != "billing-web.service" || result[0].Application != "billing-web.service" || result[0].Service != "Nginx" {
		t.Fatalf("unit correlation incorrect %+v", result[0])
	}
	if result[1].Service != "Unknown service" || result[1].Application != "billing-api.service" {
		t.Fatalf("custom application identity incorrect %+v", result[1])
	}
}
func TestSocketActivatedSSHUsesObservedUnitAndAddress(t *testing.T) {
	bindings := ParseSystemdSockets(`[::]:2022 ssh.socket ssh.service
/run/user/a socket with spaces.socket ssh.service
/run/socket:2022 not-network.socket ssh.service
127.0.0.1:9000 extra columns extra.socket extra.service
LISTEN UNIT ACTIVATES`)
	if len(bindings) != 1 {
		t.Fatalf("ambiguous/non-network list-sockets rows accepted %+v", bindings)
	}
	rows := []Listener{{Port: 2022, Protocol: "tcp", Address: "::", Process: "systemd", PID: 1}}
	got := EnrichListeners(rows, func(int) (string, error) { return "0::/init.scope", nil }, bindings)[0]
	if got.Service != "SSH" || got.SystemdUnit != "ssh.service" || got.Application != "ssh.service" {
		t.Fatalf("socket-activated SSH not recognized %+v", got)
	}
}
func TestSocketFallbackRejectsAmbiguousAndPortOnlyMatches(t *testing.T) {
	bindings := ParseSystemdSockets(`10.0.0.1:2022 ssh.socket ssh.service
[::]:8080 first.socket nginx.service
[::]:8080 second.socket apache2.service`)
	rows := []Listener{{Port: 2022, Protocol: "tcp", Address: "10.0.0.2", Process: "systemd", PID: 1}, {Port: 8080, Protocol: "tcp", Address: "::", Process: "systemd", PID: 1}}
	got := EnrichListeners(rows, func(int) (string, error) { return "0::/init.scope", nil }, bindings)
	for _, row := range got {
		if row.Service != "Unknown service" || row.SystemdUnit != "" {
			t.Fatalf("ambiguous/unit-port-only inference %+v", row)
		}
	}
}
func TestDiscoveryCadenceCachesOriginalTimestampForFifteenMinutes(t *testing.T) {
	count := 0
	a := &Agent{Config: Config{IntervalSeconds: 60, DiscoveryIntervalSeconds: 900}, Commands: inventoryCommands(&count, nil)}
	clock := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	a.clock = func() time.Time { return clock }
	first := a.inventoryReport(context.Background(), a.currentTime())
	if count != 1 || !first.DiscoveryPerformed || first.DiscoveredAt == nil {
		t.Fatal("startup did not discover immediately")
	}
	scanned := *first.DiscoveredAt
	a.ackInventoryReport(first)
	for _, offset := range []time.Duration{time.Second, 60 * time.Second, 899 * time.Second} {
		clock = scanned.Add(offset)
		report := a.inventoryReport(context.Background(), a.currentTime())
		if count != 1 || report.DiscoveryPerformed || !report.DiscoveredAt.Equal(scanned) || report.DiscoveryIntervalSeconds != 900 {
			t.Fatalf("heartbeat repeated scan or reset timestamp %+v count=%d", report, count)
		}
	}
	clock = scanned.Add(900 * time.Second)
	next := a.inventoryReport(context.Background(), a.currentTime())
	if count != 2 || !next.DiscoveryPerformed || !next.DiscoveredAt.Equal(clock) {
		t.Fatal("15minute scan did not execute")
	}
}
func TestDiscoveryFailureRetainsInventoryAndRetriesNextControlInterval(t *testing.T) {
	count := 0
	fail := false
	a := &Agent{Config: Config{IntervalSeconds: 60, DiscoveryIntervalSeconds: 900}, Commands: inventoryCommands(&count, &fail)}
	start := time.Now().UTC()
	first := a.inventoryReport(context.Background(), start)
	a.ackInventoryReport(first)
	fail = true
	failed := a.inventoryReport(context.Background(), start.Add(900*time.Second))
	if !failed.DiscoveryPerformed || failed.DiscoveryError == "" || !failed.DiscoveredAt.Equal(*first.DiscoveredAt) || len(failed.Listeners) != 1 {
		t.Fatal("failed scan discarded previous authoritative inventory")
	}
	a.ackInventoryReport(failed)
	_ = a.inventoryReport(context.Background(), start.Add(901*time.Second))
	if count != 2 {
		t.Fatal("failed scan retried too rapidly")
	}
	fail = false
	recovered := a.inventoryReport(context.Background(), start.Add(960*time.Second))
	if count != 3 || !recovered.DiscoveryPerformed || recovered.DiscoveryError != "" {
		t.Fatal("failed scan did not retry on next control interval")
	}
}
func TestSyncSecondReportDoesNotRepeatSocketDiscovery(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, e := New(c, false, "")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	fixtureAuthenticatedClient(a, "discovery-test")
	a.Commands = inventoryCommands(&count, nil)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	reports := []Report{}
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("User-Agent") != "Prthak-agent/"+Version {
			t.Errorf("wire User-Agent must remain ASCII: %q", request.Header.Get("User-Agent"))
		}
		body := "{}"
		if strings.HasSuffix(request.URL.Path, "/policy") {
			body = `{"server_id":"discovery-test","version":1,"digest":"cached-policy","mode":"monitor","services":[],"learning_sessions":[]}`
		} else {
			var r Report
			if e := json.NewDecoder(request.Body).Decode(&r); e != nil {
				t.Fatal(e)
			}
			reports = append(reports, r)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	if e = a.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	clock = clock.Add(time.Minute)
	if e = a.Sync(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count != 1 || len(reports) != 3 {
		t.Fatalf("ss scans=%d reports=%d", count, len(reports))
	}
	for i, r := range reports {
		if r.DiscoveryPerformed != (i == 0) {
			t.Fatalf("wrong discovery metadata report%d: %+v", i, r)
		}
		if r.Listeners[0].Service != "SSH" || r.Listeners[0].Port != 2022 {
			t.Fatal("reported service identity lost")
		}
	}
}
func TestSimulationSSHAndManualDiscoveryRequest(t *testing.T) {
	commands := &fakeRunner{fn: func(string, []string) (string, error) { t.Fatal("simulation invoked an OS command"); return "", nil }}
	c := Config{StateDir: t.TempDir(), DiscoveryIntervalSeconds: 900, IntervalSeconds: 60}
	a := &Agent{Config: c, Commands: commands, Simulate: true}
	start := time.Now().UTC()
	first := a.inventoryReport(context.Background(), start)
	ssh := false
	for _, item := range first.Listeners {
		if item.Port == 2022 && item.Service == "SSH" {
			ssh = true
		}
	}
	if !ssh {
		t.Fatal("simulated custom-port SSH identity missing")
	}
	if e := RequestDiscovery(c); e != nil {
		t.Fatal(e)
	}
	requested, e := a.consumeDiscoveryRequest()
	if e != nil || !requested {
		t.Fatalf("manual request not consumed: %v", e)
	}
	report := a.inventoryReport(context.Background(), start.Add(time.Minute))
	if !report.DiscoveryPerformed {
		t.Fatal("explicit manual request did not bypass15min cadence")
	}
	requested, e = a.consumeDiscoveryRequest()
	if e != nil || requested {
		t.Fatal("manual request replayed")
	}
}

func TestDiscoverySnapshotRetriesUntilControllerAcknowledges(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, e := New(c, false, "")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	a.Commands = inventoryCommands(&count, nil)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	reports := []Report{}
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var report Report
		if e := json.NewDecoder(request.Body).Decode(&report); e != nil {
			t.Fatal(e)
		}
		reports = append(reports, report)
		status := 200
		body := "{}"
		if len(reports) == 1 {
			status = 503
			body = `{"error":"controller temporarily unavailable"}`
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	if e = a.report(context.Background()); e == nil {
		t.Fatal("first failed HTTP report was not surfaced")
	}
	original := *reports[0].DiscoveredAt
	clock = clock.Add(time.Minute)
	if e = a.report(context.Background()); e != nil {
		t.Fatal(e)
	}
	clock = clock.Add(time.Minute)
	if e = a.report(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count != 1 || len(reports) != 3 {
		t.Fatalf("pending HTTP delivery caused rescan: ss=%d reports=%d", count, len(reports))
	}
	if !reports[0].DiscoveryPerformed || !reports[1].DiscoveryPerformed || reports[2].DiscoveryPerformed {
		t.Fatal("fresh discovery was lost before acknowledgement or replayed afterward")
	}
	for _, report := range reports {
		if report.DiscoveredAt == nil || !report.DiscoveredAt.Equal(original) || len(report.Listeners) != 1 || report.Listeners[0].Service != "SSH" {
			t.Fatal("retry changed or lost pending listener snapshot/timestamp")
		}
	}
}
func TestFailedScanAttemptIsReportedBeforeCachedHeartbeat(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, e := New(c, false, "")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	fail := false
	a.Commands = inventoryCommands(&count, &fail)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	reports := []Report{}
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var report Report
		if e := json.NewDecoder(request.Body).Decode(&report); e != nil {
			t.Fatal(e)
		}
		reports = append(reports, report)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})
	if e = a.report(context.Background()); e != nil {
		t.Fatal(e)
	}
	original := *reports[0].DiscoveredAt
	fail = true
	clock = clock.Add(900 * time.Second)
	if e = a.report(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(reports) != 2 || !reports[1].DiscoveryPerformed || reports[1].DiscoveryError == "" || !reports[1].DiscoveredAt.Equal(original) || len(reports[1].Listeners) != 1 {
		t.Fatal("actual scan error was hidden as a cached heartbeat or cleared successful inventory")
	}
	clock = clock.Add(time.Second)
	if e = a.report(context.Background()); e != nil {
		t.Fatal(e)
	}
	if reports[2].DiscoveryPerformed || count != 2 {
		t.Fatal("acknowledged failed attempt repeated or retried ss before control interval")
	}
}
func TestOldAcknowledgementCannotClearNewerDiscoveryAttempt(t *testing.T) {
	count := 0
	a := &Agent{Config: Config{IntervalSeconds: 60, DiscoveryIntervalSeconds: 900}, Commands: inventoryCommands(&count, nil)}
	start := time.Now().UTC()
	old := a.inventoryReport(context.Background(), start)
	a.forceDiscovery = true
	fresh := a.inventoryReport(context.Background(), start.Add(time.Second))
	a.ackInventoryReport(old)
	pending := a.inventoryReport(context.Background(), start.Add(2*time.Second))
	if !pending.DiscoveryPerformed {
		t.Fatal("old response cleared an unacknowledged newer snapshot")
	}
	a.ackInventoryReport(fresh)
	cached := a.inventoryReport(context.Background(), start.Add(3*time.Second))
	if cached.DiscoveryPerformed || count != 2 {
		t.Fatal("latest acknowledgement failed to clear pending snapshot")
	}
}

func TestConfiguredControlIntervalIsReportedWithCachedDiscovery(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 300, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, e := New(c, false, "")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	a.Commands = inventoryCommands(&count, nil)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	reports := []Report{}
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var report Report
		if e := json.NewDecoder(request.Body).Decode(&report); e != nil {
			t.Fatal(e)
		}
		reports = append(reports, report)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})
	if e = a.report(context.Background()); e != nil {
		t.Fatal(e)
	}
	clock = clock.Add(300 * time.Second)
	if e = a.report(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count != 1 || len(reports) != 2 || !reports[0].DiscoveryPerformed || reports[1].DiscoveryPerformed {
		t.Fatal("unexpected discovery cadence during control-interval reporting")
	}
	for _, report := range reports {
		if report.ControlIntervalSeconds != 300 {
			t.Fatalf("configured control interval lost on cached report: %d", report.ControlIntervalSeconds)
		}
	}
}
