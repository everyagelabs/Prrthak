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

type protectionServiceRunner struct {
	CommandRunner
	firewalldState string
	firewalldError error
	ufwActive      bool
	ufwError       error
	socketScans    int
	inventoryReads int
	nftReads       int
	linkReads      int
}

func (r *protectionServiceRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "firewall-cmd" && len(args) == 1 && args[0] == "--state" {
		return r.firewalldState, r.firewalldError
	}
	if name == "ufw" && len(args) == 1 && args[0] == "status" {
		if r.ufwError != nil {
			return "", r.ufwError
		}
		if r.ufwActive {
			return "Status: active", nil
		}
		return "Status: inactive", nil
	}
	if name == "ss" {
		r.socketScans++
	}
	if name == "firewall-cmd" {
		for _, arg := range args {
			if arg == "--list-all-zones" {
				r.inventoryReads++
			}
		}
	}
	if name == "nft" {
		r.nftReads++
	}
	if name == "ip" && strings.Join(args, " ") == "-j link show" {
		r.linkReads++
	}
	return r.CommandRunner.Run(ctx, name, args...)
}

func protectionReportRecorder(t *testing.T, a *Agent) *[]Report {
	t.Helper()
	a.Config.Zone = "public"
	a.Config.IntervalSeconds = 60
	a.Config.DiscoveryIntervalSeconds = 900
	reports := []Report{}
	a.Client = &Client{config: a.Config, HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/agent/report" {
			t.Fatalf("unexpected report request %s %s", request.Method, request.URL.Path)
		}
		var report Report
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}}
	return &reports
}

func TestReportRefreshesProtectionOnFirewallServiceChangesWithoutDiscovery(t *testing.T) {
	a, native, _ := managedTestAgent(t)
	commands := &protectionServiceRunner{CommandRunner: native, firewalldState: "not-running"}
	a.Commands = commands
	reports := protectionReportRecorder(t, a)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	report := func() Report {
		t.Helper()
		if err := a.report(context.Background()); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(time.Minute)
		return (*reports)[len(*reports)-1]
	}
	first := report()
	if first.Protection == nil || first.Protection.Ready || !strings.Contains(strings.Join(first.Protection.Blockers, "; "), "firewalld is not running") {
		t.Fatalf("initial stopped firewall was not blocked: %+v", first.Protection)
	}
	digest, sequence, scanned := first.Protection.Digest, a.discoverySequence, first.DiscoveredAt
	inventoryReads := commands.inventoryReads
	assertProtection := func(got Report, ready bool, blocker string) {
		t.Helper()
		if got.Protection == nil || got.Protection.Ready != ready || got.Protection.Digest != digest {
			t.Fatalf("service observation changed binding digest or left stale readiness: %+v", got.Protection)
		}
		if blocker != "" && !strings.Contains(strings.Join(got.Protection.Blockers, "; "), blocker) {
			t.Fatalf("current blocker missing: %+v", got.Protection)
		}
		if got.DiscoveryPerformed || a.discoverySequence != sequence || got.DiscoveredAt == nil || !got.DiscoveredAt.Equal(*scanned) || commands.socketScans != 1 || commands.inventoryReads != inventoryReads {
			t.Fatalf("service observation required a full discovery: sequence=%d scans=%d inventory=%d", a.discoverySequence, commands.socketScans, commands.inventoryReads)
		}
	}
	commands.firewalldState = "running"
	running := report()
	assertProtection(running, true, "")
	readyProtection := a.protection
	assertProtection(report(), true, "")
	if a.protection != readyProtection {
		t.Fatal("stable service state rebuilt the protection cache")
	}
	commands.firewalldState = "not-running"
	assertProtection(report(), false, "firewalld is not running")
	commands.firewalldState = "running"
	commands.firewalldError = errors.New("state query timed out")
	assertProtection(report(), false, "firewalld is not running")
	commands.firewalldError = nil
	assertProtection(report(), true, "")
	commands.ufwActive = true
	assertProtection(report(), false, "UFW is active")
	commands.ufwError = errors.New("UFW status query failed")
	stillConflicted := report()
	assertProtection(stillConflicted, false, "UFW is active")
	if !stillConflicted.UFWActive || !a.inventory.UFWActive {
		t.Fatal("failed quick query erased a previously observed UFW conflict")
	}
	commands.ufwError = nil
	commands.ufwActive = false
	assertProtection(report(), true, "")
}

func TestStableProtectionServiceStateDoesNotRepeatWholeHostEnrichment(t *testing.T) {
	a, _, native, _ := hostDenyTestAgent(t)
	commands := &protectionServiceRunner{CommandRunner: native, firewalldState: "running"}
	a.Commands = commands
	protectionReportRecorder(t, a)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.protection == nil || !a.protection.HostDefaultDenyReady || commands.nftReads == 0 || commands.linkReads == 0 {
		t.Fatalf("initial native context not checked: %+v", a.protection)
	}
	initial, sequence := a.protection, a.discoverySequence
	scans, inventoryReads, nftReads, linkReads := commands.socketScans, commands.inventoryReads, commands.nftReads, commands.linkReads
	clock = clock.Add(time.Minute)
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.protection != initial || commands.socketScans != scans || commands.inventoryReads != inventoryReads || commands.nftReads != nftReads || commands.linkReads != linkReads {
		t.Fatal("stable heartbeat repeated native readiness enrichment or full inventory")
	}
	commands.firewalldState = "not-running"
	clock = clock.Add(time.Minute)
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.protection.Ready || a.protection.HostDefaultDenyReady || commands.nftReads <= nftReads || commands.linkReads <= linkReads || a.discoverySequence != sequence || commands.socketScans != scans {
		t.Fatalf("service transition bypassed native checks or retained whole-host readiness: %+v", a.protection)
	}
}

func TestManagedCommittedPolicyRecoversFromStoppedFirewallWithoutNewPolicyOrScan(t *testing.T) {
	a, native, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if err := a.applyManaged(context.Background(), p, protection); err != nil {
		t.Fatal(err)
	}
	committed := a.State.ManagedBundle
	mutations := native.mutations
	a.State.Policy = p
	commands := &protectionServiceRunner{CommandRunner: native, firewalldState: "not-running"}
	a.Commands = commands
	reports := protectionReportRecorder(t, a)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	sequence := a.discoverySequence
	if a.protection.Ready || a.protection.Digest != committed.ProtectionDigest {
		t.Fatalf("test did not reproduce same-digest stale protection: %+v", a.protection)
	}
	if err := a.processManaged(context.Background(), p); err == nil || !strings.Contains(err.Error(), "firewalld is not running") {
		t.Fatalf("stopped firewall did not fail closed: %v", err)
	}
	commands.firewalldState = "running"
	clock = clock.Add(time.Minute)
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	latest := (*reports)[len(*reports)-1]
	if latest.Protection == nil || !latest.Protection.Ready || latest.FirewalldState != "running" || latest.Protection.Digest != committed.ProtectionDigest || latest.DiscoveryPerformed || a.discoverySequence != sequence {
		t.Fatalf("current report retained stale protection: %+v", latest.Protection)
	}
	inventoryReads := commands.inventoryReads
	if err := a.processManaged(context.Background(), p); err != nil {
		t.Fatalf("unchanged committed policy did not recover: %v", err)
	}
	if a.State.ManagedEnforcement.Status != "enforced" || !a.State.ManagedEnforcement.AlreadyPresent || a.State.ManagedBundle.Generation != committed.Generation || a.State.ManagedBundle.Digest != committed.Digest || native.mutations != mutations || commands.socketScans != 1 || commands.inventoryReads <= inventoryReads {
		t.Fatalf("recovery changed the bundle, skipped live preflight, or rescanned: status=%+v generation=%s mutations=%d/%d scans=%d inventory=%d/%d", a.State.ManagedEnforcement, a.State.ManagedBundle.Generation, native.mutations, mutations, commands.socketScans, commands.inventoryReads, inventoryReads)
	}
	if err := a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	latest = (*reports)[len(*reports)-1]
	if latest.ManagedEnforcement == nil || latest.ManagedEnforcement.Status != "enforced" || latest.ManagedEnforcement.Generation != committed.Generation || latest.AppliedVersion != p.Version || !latest.Protection.Ready {
		t.Fatalf("recovered committed state not reported: %+v", latest.ManagedEnforcement)
	}
	for _, phase := range []struct {
		firewalldState string
		ufwActive      bool
		blocker        string
	}{
		{"not-running", false, "firewalld is not running"},
		{"running", true, "UFW is active"},
		{"running", false, ""},
	} {
		commands.firewalldState, commands.ufwActive = phase.firewalldState, phase.ufwActive
		clock = clock.Add(time.Minute)
		if err := a.report(context.Background()); err != nil {
			t.Fatal(err)
		}
		if a.protection.Ready != (phase.blocker == "") || a.protection.Digest != committed.ProtectionDigest || a.discoverySequence != sequence {
			t.Fatalf("reverse service transition left stale protection: %+v", a.protection)
		}
		err := a.processManaged(context.Background(), p)
		if phase.blocker == "" {
			if err != nil || a.State.ManagedEnforcement.Status != "enforced" {
				t.Fatalf("same committed policy did not recover from service conflict: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), phase.blocker) || a.State.ManagedEnforcement.Status != "error" {
			t.Fatalf("committed processing ignored current service blocker %q: %v", phase.blocker, err)
		}
		if native.mutations != mutations || a.State.ManagedBundle.Generation != committed.Generation || a.State.ManagedBundle.Digest != committed.Digest || commands.socketScans != 1 {
			t.Fatal("service-state refresh changed installed policy or repeated listener discovery")
		}
	}
	// Refreshed readiness does not relax the current topology checks.
	native.activeZones = "other\n  interfaces: eth0\n"
	if err := a.processManaged(context.Background(), p); err == nil || !strings.Contains(err.Error(), "configured zone") {
		t.Fatalf("readiness recovery bypassed native topology guard: %v", err)
	}
	if native.mutations != mutations || a.State.ManagedBundle.Generation != committed.Generation || a.State.ManagedBundle.Digest != committed.Digest || commands.socketScans != 1 {
		t.Fatal("failed live preflight changed a committed policy or forced listener discovery")
	}
}
