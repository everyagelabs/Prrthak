package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDenyLogCompatibilityInstallsOnlyScopedLogRulesAndCleansThem(t *testing.T) {
	a, firewall, protection := scaleManagedAgent(t)
	if err := a.applyManaged(context.Background(), managedTestPolicy(protection, 1, "198.51.100.0/24"), protection); err != nil {
		t.Fatal(err)
	}
	a.Commands = oldCaptureLanguageRunner{CommandRunner: &hostDenyFake{CommandRunner: firewall, nft: tailscaleKernelFixture(), forwarding: "0 0"}}
	a.trafficCapture = &deniedCaptureFixture{}
	now := time.Now().UTC()
	scopes := []capturePortScope{{Port: Port{18080, "tcp"}, Kind: captureDenied, StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), AllowDenyLogs: true}}
	if err := a.reconcileCaptureSidecars(context.Background(), scopes, now); err != nil {
		t.Fatal(err)
	}
	state, err := readCaptureSidecars(a.Config.StateDir)
	if err != nil || len(state.Rules) == 0 {
		t.Fatal("compatibility capture was not installed", state, err)
	}
	for _, rule := range state.Rules {
		if rule.Backend != "journal" || rule.Port != scopes[0].Port || !rule.StartedAt.Equal(now) || !strings.HasPrefix(rule.Prefix, "PRTN") || !strings.Contains(rule.text(), `limit value="5/s"`) || strings.Contains(rule.text(), "nflog") || strings.Contains(rule.text(), " reject") || strings.Contains(rule.text(), " accept") || strings.Contains(rule.text(), " drop") {
			t.Fatal("compatibility rule changed access or exceeded its reviewed scope", rule)
		}
		if !firewall.has("runtime", "rich_rule", rule.text()) || firewall.has("permanent", "rich_rule", rule.text()) {
			t.Fatal("compatibility rule must be temporary runtime instrumentation")
		}
	}
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		t.Fatal(err)
	}
	err = clearTrafficCaptureSidecars(withManagedLease(context.Background(), lock), a.Config.StateDir, a.Commands)
	unlockManaged(lock)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range state.Rules {
		if firewall.has("runtime", "rich_rule", rule.text()) {
			t.Fatal("compatibility logging survived cleanup")
		}
	}
}

func TestDenyLogCompatibilityCannotAcquireVerificationOnlyScope(t *testing.T) {
	now := time.Now().UTC()
	rule := captureSidecar{Zone: "public", Family: "ipv4", Port: Port{18080, "tcp"}, Group: 50000, Prefix: "PRTVaaaaaaaaaaaaaaaa:", Priority: managedCaptureReject, ExpiresAt: now.Add(time.Minute)}
	scope := capturePortScope{Port: rule.Port, Kind: captureDenied, StartsAt: now.Add(-time.Second), ExpiresAt: rule.ExpiresAt}
	if len(compatibilityCaptureSidecars([]captureSidecar{rule}, []capturePortScope{scope}, now)) != 0 {
		t.Fatal("unsigned compatibility acquired a native verification scope")
	}
	scope.AllowDenyLogs = true
	converted := compatibilityCaptureSidecars([]captureSidecar{rule}, []capturePortScope{scope}, now)
	if len(converted) != 1 || strings.HasPrefix(converted[0].Prefix, "PRTV") {
		t.Fatal("compatibility logs retained a native verification prefix")
	}
}

func TestDenyLogCompatibilitySpoolsOnlyToExplicitlyAuthorizedSessions(t *testing.T) {
	now := time.Now().UTC()
	session := Session{ID: "deny-log-test-session", StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), ObservationKinds: []string{captureDenied}, Ports: []Port{{18080, "tcp"}}}
	a := &Agent{Config: Config{StateDir: t.TempDir(), MaxSpoolBatches: 8}, State: State{Policy: &Policy{LearningSessions: []Session{session}}}}
	flow := capturedFlow{Flow: Flow{EventID: strings.Repeat("b", 64), SourceIP: "198.51.100.5", Port: 18080, Protocol: "tcp", CaptureKind: captureDeniedLog, CaptureBackend: "journal", CountUnit: "log_records", AddressFamily: "ipv4", Verdict: "denied", Count: 1, FirstSeen: now, LastSeen: now}}
	if err := a.storeCapturedFlows([]capturedFlow{flow}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(a.Config.StateDir, "spool", "*.json"))
	if len(files) != 0 {
		t.Fatal("compatibility evidence entered an unreviewed scope")
	}
	a.State.Policy.LearningSessions[0].DenyLogCompatibility = true
	if err := a.storeCapturedFlows([]capturedFlow{flow}); err != nil {
		t.Fatal(err)
	}
	files, _ = filepath.Glob(filepath.Join(a.Config.StateDir, "spool", "*.json"))
	if len(files) != 1 {
		t.Fatal("authorized compatibility evidence was not spooled")
	}
	data, err := os.ReadFile(files[0])
	if err != nil || !strings.Contains(string(data), `"capture_kind":"denied_log"`) || !strings.Contains(string(data), `"count_unit":"log_records"`) {
		t.Fatal("sampled deny record lost its evidence identity", err)
	}
}
