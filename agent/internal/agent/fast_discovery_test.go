package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fastSSHRow = `tcp LISTEN 0 128 0.0.0.0:2022 0.0.0.0:* users:(("sshd",pid=9999999,fd=3))`
const fastWebRow = `tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("nginx",pid=9999998,fd=4))`
const fastUDPRow = `udp UNCONN 0 0 127.0.0.1:5353 0.0.0.0:* users:(("resolver",pid=9999997,fd=5))`

type fastDiscoveryFixture struct {
	rows, fingerprint string
	commandError      error
	probeError        error
	ssCalls, probes   int
	commands          []string
}

func newFastDiscoveryFixture(t *testing.T) (*Agent, *fastDiscoveryFixture, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 2, 1, 0, 0, 0, time.UTC)
	f := &fastDiscoveryFixture{rows: fastSSHRow, fingerprint: "initial"}
	a := &Agent{Config: Config{StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900}, fastDiscoveryEnabled: true}
	a.Commands = &fakeRunner{fn: func(name string, args []string) (string, error) {
		f.commands = append(f.commands, name+" "+strings.Join(args, " "))
		switch name {
		case "ss":
			f.ssCalls++
			return f.rows, f.commandError
		case "ufw":
			return "Status: inactive", nil
		case "firewall-cmd":
			return "running", nil
		}
		return "", nil
	}}
	a.listenerSnapshot = func(context.Context) (listenerSnapshot, error) {
		f.probes++
		return listenerSnapshot{fingerprint: f.fingerprint, ports: listenerPortSet(ParseSockets(f.rows)), bindings: listenerBindingSet(ParseSockets(f.rows))}, f.probeError
	}
	if a.fastDiscoveryTick(context.Background(), now) {
		t.Fatal("first baseline cannot publish an inventory")
	}
	a.inventory = &Report{Listeners: ParseSockets(f.rows), FirewallSnapshot: &FirewallSnapshot{CollectedAt: now, Status: "ok", Digest: "unchanged-firewall"}}
	a.lastDiscoveryAttempt, a.lastFullDiscoveryAttempt, a.lastDiscoverySuccess = now, now, now
	return a, f, now
}

func TestFastDiscoveryRefreshesNewStoppedAndUDPServicesWithoutFirewallInventory(t *testing.T) {
	a, f, now := newFastDiscoveryFixture(t)
	oldFirewall := *a.inventory.FirewallSnapshot
	f.rows += "\n" + fastWebRow + "\n" + fastUDPRow
	f.fingerprint = "web-and-udp-added"
	changedAt := now.Add(5 * time.Second)
	if !a.fastDiscoveryTick(context.Background(), changedAt) {
		t.Fatal("new listeners did not request an immediate report")
	}
	if len(a.inventory.Listeners) != 3 || a.inventory.Listeners[0].Service != "SSH" || a.inventory.Listeners[0].Port != 2022 {
		t.Fatalf("process service identity was not retained: %+v", a.inventory.Listeners)
	}
	if !reflect.DeepEqual(oldFirewall, *a.inventory.FirewallSnapshot) || !a.lastFullDiscoveryAttempt.Equal(now) {
		t.Fatal("fast listener refresh reset the full firewall inventory age")
	}
	for _, command := range f.commands {
		if strings.HasPrefix(command, "firewall-cmd") || strings.HasPrefix(command, "ufw") {
			t.Fatalf("fast tick queried firewall: %s", command)
		}
	}
	report := a.inventoryReport(context.Background(), changedAt)
	if !report.DiscoveryPerformed || !report.DiscoveredAt.Equal(changedAt) || report.FastDiscovery.Status != "active" || !report.FastDiscovery.LastChangeAt.Equal(changedAt) {
		t.Fatalf("fast refresh receipt missing: %+v", report)
	}
	a.ackInventoryReport(report)
	f.rows, f.fingerprint = fastSSHRow, "web-and-udp-stopped"
	if !a.fastDiscoveryTick(context.Background(), now.Add(10*time.Second)) || len(a.inventory.Listeners) != 1 {
		t.Fatal("stopped services were not removed after a verified refresh")
	}
	if !a.discoveryDue(now.Add(900*time.Second)) || a.discoveryDue(now.Add(899*time.Second)) {
		t.Fatal("fast refresh displaced the periodic full inventory fallback")
	}
}

func TestFastDiscoveryCoalescesAndDoesNoProcessScanForUnchangedListeners(t *testing.T) {
	a, f, now := newFastDiscoveryFixture(t)
	if a.fastDiscoveryTick(context.Background(), now.Add(time.Second)) || f.probes != 1 {
		t.Fatal("native checks were not coalesced")
	}
	if a.fastDiscoveryTick(context.Background(), now.Add(5*time.Second)) || f.ssCalls != 0 || f.probes != 2 {
		t.Fatal("unchanged native listeners triggered an expensive refresh")
	}
	f.rows, f.fingerprint = fastSSHRow+"\n"+fastWebRow, "changed"
	if a.fastDiscoveryTick(context.Background(), now.Add(6*time.Second)) || f.ssCalls != 0 {
		t.Fatal("changed service bypassed the five-second bound")
	}
}

func TestFastDiscoveryFailedRefreshRetainsInventoryAndRetries(t *testing.T) {
	a, f, now := newFastDiscoveryFixture(t)
	f.rows, f.fingerprint, f.commandError = fastSSHRow+"\n"+fastWebRow, "changed", errors.New("ss failed")
	if !a.fastDiscoveryTick(context.Background(), now.Add(5*time.Second)) || a.inventory.DiscoveryError == "" {
		t.Fatal("failed refresh was not reported as unknown")
	}
	if len(a.inventory.Listeners) != 1 || !a.lastDiscoverySuccess.Equal(now) {
		t.Fatal("failed refresh asserted disappeared listeners or advanced freshness")
	}
	sequence := a.discoverySequence
	if a.fastDiscoveryTick(context.Background(), now.Add(10*time.Second)) || a.discoverySequence != sequence {
		t.Fatal("identical refresh failures flooded the controller")
	}
	f.commandError = nil
	if !a.fastDiscoveryTick(context.Background(), now.Add(15*time.Second)) || a.inventory.DiscoveryError != "" || len(a.inventory.Listeners) != 2 {
		t.Fatal("native refresh did not retry and recover")
	}
}

func TestFastDiscoveryPartialProbeAndPartialBindingScanRetainListeners(t *testing.T) {
	a, f, now := newFastDiscoveryFixture(t)
	f.probeError = errors.New("truncated native dump")
	if a.fastDiscoveryTick(context.Background(), now.Add(5*time.Second)) || len(a.inventory.Listeners) != 1 || a.fastDiscoveryReport.Status != "error" {
		t.Fatal("partial native snapshot became an authoritative inventory")
	}
	f.probeError, f.fingerprint = nil, "same-port-extra-bind"
	a.listenerSnapshot = func(context.Context) (listenerSnapshot, error) {
		return listenerSnapshot{fingerprint: f.fingerprint, ports: map[string]bool{"tcp/2022": true}, bindings: map[string]bool{"tcp/2022/0.0.0.0": true, "tcp/2022/127.0.0.1": true}}, nil
	}
	if !a.fastDiscoveryTick(context.Background(), now.Add(10*time.Second)) || a.inventory.DiscoveryError == "" || len(a.inventory.Listeners) != 1 {
		t.Fatal("an incomplete address inventory was accepted")
	}
}

func TestFastDiscoveryUnstableSnapshotsNeverPublishVanishedService(t *testing.T) {
	a, _, now := newFastDiscoveryFixture(t)
	calls := 0
	a.listenerSnapshot = func(context.Context) (listenerSnapshot, error) {
		calls++
		return listenerSnapshot{fingerprint: strings.Repeat("x", calls), ports: map[string]bool{"tcp/2022": true}}, nil
	}
	if !a.fastDiscoveryTick(context.Background(), now.Add(5*time.Second)) || a.inventory.DiscoveryError == "" || !a.lastDiscoverySuccess.Equal(now) {
		t.Fatal("a changing snapshot was treated as stable")
	}
}

func TestFastDiscoveryUnsupportedSimulationAndOneShotMetadata(t *testing.T) {
	a, f, now := newFastDiscoveryFixture(t)
	f.probeError = errFastDiscoveryUnsupported
	a.fastDiscoveryTick(context.Background(), now.Add(5*time.Second))
	if a.fastDiscoveryReport.Status != "unsupported" || a.fastDiscoveryReport.IntervalSeconds != 5 {
		t.Fatal("unsupported backend was represented as successful")
	}
	a.Simulate = true
	before := f.probes
	a.fastDiscoveryTick(context.Background(), now.Add(10*time.Second))
	if f.probes != before || a.inventoryReport(context.Background(), now.Add(10*time.Second)).FastDiscovery != nil {
		t.Fatal("simulation claimed native fast discovery")
	}
	a.Simulate, a.fastDiscoveryEnabled = false, false
	if a.inventoryReport(context.Background(), now.Add(15*time.Second)).FastDiscovery != nil {
		t.Fatal("one-shot/cached inventory claimed a background detector")
	}
}

func TestDiscoverListenersRejectsMalformedAndBoundedOutput(t *testing.T) {
	for _, rows := range []string{fastSSHRow + "\ntcp incomplete", fastSSHRow + "\nwarning: truncated output", strings.Repeat("x", 4*1024*1024+1)} {
		commands := &fakeRunner{fn: func(string, []string) (string, error) { return rows, nil }}
		if _, err := DiscoverListeners(context.Background(), commands); err == nil {
			t.Fatal("malformed listener output was accepted")
		}
	}
}

func TestFullDiscoveryAlsoRetainsListenersForIncompleteSocketOutput(t *testing.T) {
	a, f, now := newFastDiscoveryFixture(t)
	f.rows = "tcp incomplete"
	report := a.inventoryReport(context.Background(), now.Add(900*time.Second))
	if report.DiscoveryError == "" || len(report.Listeners) != 1 || !report.DiscoveredAt.Equal(now) {
		t.Fatal("incomplete full discovery asserted a service outage")
	}
}

func TestListenerSnapshotFingerprintIsDeterministicAndBounded(t *testing.T) {
	left, _ := newListenerSnapshot([]string{"b", "a"}, nil)
	right, _ := newListenerSnapshot([]string{"a", "b"}, nil)
	if left.fingerprint != right.fingerprint {
		t.Fatal("kernel order changed the listener fingerprint")
	}
	if _, err := newListenerSnapshot(make([]string, maxFastListenerRecords+1), nil); err == nil {
		t.Fatal("unbounded listener snapshot accepted")
	}
	if listenerBindingKey("tcp", 443, "*") != listenerBindingKey("tcp", 443, "::") {
		t.Fatal("ss IPv6 wildcard does not match kernel bindings")
	}
}

func TestAgentRestartAlwaysReportsFreshFullInventory(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	old, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	old.Commands = inventoryCommands(&count, nil)
	now := time.Now().UTC()
	old.inventoryReport(context.Background(), now)
	// An old process may have observations that are no longer true after a
	// server reboot or package/service changes. Persistent policy state is
	// valid to reuse; discovery must be rebuilt from this process's host reads.
	old.inventory.OS, old.inventory.OSVersion = "obsolete-os", "obsolete-version"
	old.inventory.FirewalldVersion, old.inventory.FirewalldState = "obsolete-firewall", "not-running"
	old.inventory.IPs = []string{"192.0.2.254"}
	if err := old.save(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	restarted.Commands = &fakeRunner{fn: func(name string, args []string) (string, error) {
		switch name {
		case "ss":
			count++
			return fastWebRow, nil
		case "firewall-cmd":
			if len(args) == 1 && args[0] == "--version" {
				return "2.0.0", nil
			}
			return "running", nil
		case "ufw":
			return "Status: inactive", nil
		}
		return "", nil
	}}
	report := restarted.inventoryReport(context.Background(), now.Add(time.Second))
	currentOS := readKeyValues("/etc/os-release")
	if count != 2 || !report.DiscoveryPerformed || !report.DiscoveredAt.Equal(now.Add(time.Second)) || report.OS != currentOS["ID"] || report.OSVersion != currentOS["VERSION_ID"] || report.FirewalldVersion != "2.0.0" || report.FirewalldState != "running" || len(report.Listeners) != 1 || report.Listeners[0].Port != 8443 {
		t.Fatalf("first restarted report reused old discovery: %+v", report)
	}
	if report.FirewallSnapshot == nil || !report.FirewallSnapshot.CollectedAt.After(old.inventory.FirewallSnapshot.CollectedAt) {
		t.Fatal("restart did not attempt a fresh full firewall inventory")
	}
}

func TestInitialNativeBaselineDoesNotReplaceFreshStartupListeners(t *testing.T) {
	a, f, now := newFastDiscoveryFixture(t)
	a.inventory = nil
	a.fastListenerFingerprint = ""
	a.nextFastDiscovery = time.Time{}
	a.listenerSnapshot = func(context.Context) (listenerSnapshot, error) {
		return listenerSnapshot{fingerprint: "before-service-start", ports: map[string]bool{}, bindings: map[string]bool{}}, nil
	}
	if a.fastDiscoveryTick(context.Background(), now) {
		t.Fatal("initial empty baseline asserted empty discovery")
	}
	first := a.inventoryReport(context.Background(), now)
	if len(first.Listeners) != 1 || first.Listeners[0].Port != 2022 || f.ssCalls != 1 {
		t.Fatal("native baseline displaced fresh startup discovery")
	}
	a.listenerSnapshot = func(context.Context) (listenerSnapshot, error) {
		return listenerSnapshot{fingerprint: "after-service-start", ports: listenerPortSet(ParseSockets(f.rows)), bindings: listenerBindingSet(ParseSockets(f.rows))}, nil
	}
	if !a.fastDiscoveryTick(context.Background(), now.Add(5*time.Second)) || len(a.inventory.Listeners) != 1 {
		t.Fatal("service starting between baseline and first inventory was lost")
	}
}
