package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type managedFake struct {
	*firewallFake
	failAt               int
	mutations            int
	armFailed            bool
	activeZones          string
	failRollbackReadOnce bool
}

func (f *managedFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "firewall-cmd" && len(args) == 1 && args[0] == "--get-active-zones" {
		if f.activeZones != "" {
			return f.activeZones, nil
		}
		return "public\n  interfaces: eth0\n", nil
	}
	for _, arg := range args {
		if f.failRollbackReadOnce && strings.HasPrefix(arg, "--query-rich-rule=") {
			value := strings.TrimPrefix(arg, "--query-rich-rule=")
			if !f.has("runtime", "rich_rule", value) {
				f.failRollbackReadOnce = false
				return "", errors.New("injected rollback read-back error")
			}
		}
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--add-rich-rule=") || strings.HasPrefix(arg, "--remove-rich-rule=") {
			f.mutations++
			if f.failAt > 0 && f.mutations == f.failAt {
				return "", errors.New("injected managed mutation failure")
			}
		}
	}
	return f.firewallFake.Run(ctx, name, args...)
}
func managedTestAgent(t *testing.T) (*Agent, *managedFake, Protection) {
	t.Helper()
	f := &managedFake{firewallFake: newFirewallFake()}
	a := firewallAgent(t, f.firewallFake)
	a.Commands = f
	a.Config.Enforce = true
	a.Config.ControllerURL = "https://controller.example.internal:8787"
	fixturePolicyTrust(t, a)
	a.armManaged = func(_ context.Context, path string, j *managedJournal) error {
		loaded, e := readManagedJournal(path, j.Nonce)
		if e != nil {
			return e
		}
		if loaded.Phase != "armed" {
			return errors.New("not durably armed before timer")
		}
		if f.armFailed {
			return errors.New("systemd timer unavailable")
		}
		return nil
	}
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return nil }
	protection, e := a.managedProtection(context.Background())
	if e != nil || !protection.Ready {
		t.Fatalf("protection unavailable %+v %v", protection, e)
	}
	return a, f, protection
}
func managedTestPolicy(protection Protection, version int, sources ...string) *Policy {
	p := &Policy{ServerID: "test-managed-server", Version: version, Mode: "enforce", Services: []Service{{Port: 18080, Protocol: "tcp", Mode: "enforce", Sources: sources}}}
	p.Digest, _ = compiledPolicyDigest(p)
	p.Enforcement = &EnforcementAuthorization{Authorized: true, ApprovalID: "approval-" + strings.Repeat("a", version), ApprovedDigest: p.Digest, ApprovedVersion: p.Version, ProtectionDigest: protection.Digest, ConfirmationCount: 2, ExpiresAt: time.Now().Add(time.Hour)}
	p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
	return p
}
func TestManagedFreshPreflightDenialMakesNoFirewallWrite(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	checks := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		checks++
		if f.mutations != 0 {
			t.Fatal("fresh approval witness happened after a firewall mutation")
		}
		return errors.New("requester or checker authorization was revoked")
	}
	if err := a.applyManaged(context.Background(), p, protection); err == nil || checks != 1 || f.mutations != 0 || a.State.ManagedBundle != nil {
		t.Fatalf("revoked cached managed assignment wrote firewall: checks=%d mutations=%d error=%v", checks, f.mutations, err)
	}
}
func TestManagedDigestCrossLanguageFixture(t *testing.T) {
	p := &Policy{ServerID: "srv-1", Version: 7, Mode: "enforce", Services: []Service{{Port: 2022, Protocol: "tcp", Mode: "enforce", Sources: []string{"10.20.0.0/24"}}}}
	p.Digest, _ = compiledPolicyDigest(p)
	if p.Digest != "50dc53b2113dd1efea4171fd1aede923aee1125fa5bde70d92a4e7a221d9b229" || enforcementBinding(p, strings.Repeat("a", 64)) != "a22253beac3394755aad68a4c84ea523b3dbb84b0180787b5071ec2e612cea0f" {
		t.Fatal("cross-language digest fixture changed")
	}

	encoded, _ := json.Marshal(map[string]any{"mode": "enforce", "services": []map[string]any{{"mode": "enforce", "port": 2022, "protocol": "tcp", "sources": []string{"10.20.0.0/24"}}}})
	if p.Digest != shaText(string(encoded)) {
		t.Fatal("canonical hash mismatch")
	}
}
func TestManagedApprovalBindsSourcesAndProtection(t *testing.T) {
	_, _, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if e := validateEnforcement(p, protection, time.Now()); e != nil {
		t.Fatal(e)
	}
	p.Services[0].Sources = []string{"0.0.0.0/0"}
	if validateEnforcement(p, protection, time.Now()) == nil {
		t.Fatal("source mutation reused authorization")
	}
	p = managedTestPolicy(protection, 1, "10.30.0.0/24")
	changed := protection
	changed.Digest = strings.Repeat("0", 64)
	if validateEnforcement(p, changed, time.Now()) == nil {
		t.Fatal("baseline mutation reused authorization")
	}
	p.Enforcement.ConfirmationCount = 1
	if validateEnforcement(p, protection, time.Now()) == nil {
		t.Fatal("one confirmation accepted")
	}
}
func TestManagedRulesProtectActualSSH2022AndExcludeMonitorSources(t *testing.T) {
	_, _, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	p.Services = append(p.Services, Service{Port: 2022, Protocol: "tcp", Mode: "enforce", Sources: []string{"10.40.0.0/24"}}, Service{Port: 9090, Protocol: "tcp", Mode: "monitor", Sources: []string{"0.0.0.0/0"}})
	rules, e := managedRules(p, protection, strings.Repeat("a", 32), false)
	if e != nil {
		t.Fatal(e)
	}
	all := ""
	for _, rule := range rules {
		all += rule.Rule + "\n"
		if !managedOwned(rule.Rule) {
			t.Fatal("generated rule failed ownership validation")
		}
	}
	if !strings.Contains(all, `source address="10.20.0.0/24" port port="2022"`) {
		t.Fatal("actual SSH2022 baseline missing")
	}
	if strings.Contains(all, `port="9090"`) {
		t.Fatal("monitor-only source entered enforcement")
	}
	if _, e = canonicalSources([]string{"0.0.0.0/0"}, true); e == nil {
		t.Fatal("/0 management baseline accepted")
	}
}
func TestManagedRuntimeFirstCommitAndGenerationReplacement(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	f.set("runtime", "port", "18080/tcp", true)
	f.set("permanent", "port", "18080/tcp", true)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	if a.State.AppliedVersion != 1 || a.State.ManagedEnforcement.Status != "enforced" {
		t.Fatal("committed version missing")
	}
	old := append([]ManagedRule{}, a.State.ManagedBundle.Rules...)
	p = managedTestPolicy(protection, 2, "10.40.0.0/24")
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	for _, rule := range old {
		if f.has("runtime", "rich_rule", rule.Rule) || f.has("permanent", "rich_rule", rule.Rule) {
			t.Fatal("previous generation survived replacement")
		}
	}
	if !f.has("runtime", "port", "18080/tcp") || !f.has("permanent", "port", "18080/tcp") {
		t.Fatal("legacy broad rule mutated")
	}
	for _, scope := range []string{"runtime", "permanent"} {
		for _, rule := range a.State.ManagedBundle.Rules {
			if !f.has(scope, "rich_rule", rule.Rule) {
				t.Fatal("committed managed rule absent")
			}
		}
	}
	if !strings.Contains(f.writes[0], "runtime:add:rich_rule:rule priority=\"-31002\"") {
		t.Fatal("permanent change preceded runtime stage")
	}
}
func TestManagedFailureMatrixRestoresPriorBundle(t *testing.T) {
	for _, failAt := range []int{1, 2, 3, 4, 6, 9, 12, 15} {
		t.Run(string(rune('A'+failAt)), func(t *testing.T) {
			a, f, protection := managedTestAgent(t)
			first := managedTestPolicy(protection, 1, "10.30.0.0/24")
			if e := a.applyManaged(context.Background(), first, protection); e != nil {
				t.Fatal(e)
			}
			before := map[string]bool{}
			for key, value := range f.rules {
				if value {
					before[key] = true
				}
			}
			f.failAt = f.mutations + failAt
			second := managedTestPolicy(protection, 2, "10.40.0.0/24")
			e := a.applyManaged(context.Background(), second, protection)
			if e == nil {
				t.Fatalf("injected failure %d did not occur", failAt)
			}
			if a.State.AppliedVersion != 1 || a.State.ManagedEnforcement.Status != "rolled_back" {
				t.Fatalf("rollback status/version wrong %+v", a.State.ManagedEnforcement)
			}
			for key, value := range f.rules {
				if value != before[key] {
					t.Fatalf("rollback baseline differs at %s", key)
				}
			}
		})
	}
}
func TestManagedHealthFailureRollsBackAndTimerFailurePreventsWrites(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	f.armFailed = true
	if a.applyManaged(context.Background(), p, protection) == nil || f.mutations != 0 {
		t.Fatal("unarmed timer permitted mutation")
	}
	f.armFailed = false
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("fresh SSH route failed")
		}
		return nil
	}
	if a.applyManaged(context.Background(), p, protection) == nil {
		t.Fatal("health failure accepted")
	}
	for _, value := range f.rules {
		if value {
			t.Fatal("health rollback left access mutation")
		}
	}
	if a.State.AppliedVersion != 0 || a.State.ManagedEnforcement.Status != "rolled_back" {
		t.Fatal("health failure claimed applied")
	}
}
func TestManagedRuleCapBeforeAnyMutation(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	sources := []string{}
	for i := 1; i < 70; i++ {
		sources = append(sources, "10.30.0."+string(rune('A'+i))+"/32")
	}
	p := managedTestPolicy(protection, 1)
	for i := 0; i < 22; i++ {
		p.Services = append(p.Services, Service{Port: 20000 + i, Protocol: "tcp", Mode: "enforce", Sources: []string{"10.30.0.0/24"}})
	}
	p.Digest, _ = compiledPolicyDigest(p)
	p.Enforcement.ApprovedDigest = p.Digest
	p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
	if a.applyManaged(context.Background(), p, protection) == nil || f.mutations != 0 {
		t.Fatal("oversized bundle mutated firewall")
	}
}
func TestManagedInterruptedIntentReconcilesUnknownCompletion(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	nonce := strings.Repeat("a", 32)
	rules, _ := managedRules(p, protection, nonce, true)
	rule := rules[0]
	f.set("runtime", "rich_rule", rule.Rule, true)
	journal := &managedJournal{Nonce: nonce, Phase: "staging", PID: os.Getpid(), Deadline: time.Now().Add(-time.Second), Next: ManagedBundle{Version: 1, Digest: p.Digest}, Mutations: []managedMutation{{Scope: "runtime", Zone: rule.Zone, Rule: rule.Rule, Before: false, After: true}}}
	path := managedJournalPath(a.Config.StateDir, nonce)
	if e := saveManagedJournal(path, journal); e != nil {
		t.Fatal(e)
	}
	if e := RunManagedWatchdog(context.Background(), path, nonce, f); e != nil {
		t.Fatal(e)
	}
	if f.has("runtime", "rich_rule", rule.Rule) {
		t.Fatal("uncertain completed write was not compensated")
	}
	// A late old watchdog must not touch a newer unrelated rule or kill its process.
	f.set("runtime", "port", "18090/tcp", true)
	if e := RunManagedWatchdog(context.Background(), path, nonce, f); e != nil {
		t.Fatal(e)
	}
	if !f.has("runtime", "port", "18090/tcp") {
		t.Fatal("old watchdog touched unowned rule")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("journal not private")
	}
}
func TestManagedRecoveryReconstructsDurableCommit(t *testing.T) {
	a, _, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	a.State.ManagedBundle = nil
	a.State.AppliedVersion = 0
	_ = os.Remove(filepath.Join(a.Config.StateDir, "managed", "committed.json"))
	if e := a.recoverManaged(context.Background()); e != nil {
		t.Fatal(e)
	}
	if a.State.AppliedVersion != 1 || a.State.ManagedBundle == nil {
		t.Fatal("committed journal not recovered")
	}
}
func TestManagedSameVersionDriftAndReplayRefused(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 2, "10.30.0.0/24")
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	oldWrites := f.mutations
	older := managedTestPolicy(protection, 1, "10.40.0.0/24")
	if a.applyManaged(context.Background(), older, protection) == nil || f.mutations != oldWrites {
		t.Fatal("lower version replay permitted")
	}
	different := managedTestPolicy(protection, 2, "10.40.0.0/24")
	if a.applyManaged(context.Background(), different, protection) == nil {
		t.Fatal("same version different digest permitted")
	}
	missing := a.State.ManagedBundle.Rules[0]
	f.set("permanent", "rich_rule", missing.Rule, false)
	if a.applyManaged(context.Background(), p, protection) == nil || a.State.ManagedEnforcement.Status == "enforced" {
		t.Fatal("missing permanent rule reported enforced")
	}
}
func TestManagedExplicitCleanupRemovesOnlyOwnedRules(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	f.set("runtime", "port", "18080/tcp", true)
	f.set("permanent", "port", "18080/tcp", true)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	owned := append([]ManagedRule{}, a.State.ManagedBundle.Rules...)
	cleanup := managedTestPolicy(protection, 2)
	cleanup.Mode = "monitor"
	cleanup.Services = []Service{}
	cleanup.Digest, _ = compiledPolicyDigest(cleanup)
	cleanup.Enforcement.ApprovedDigest = cleanup.Digest
	cleanup.Enforcement.BindingDigest = enforcementBinding(cleanup, protection.Digest)
	if e := a.applyManaged(context.Background(), cleanup, protection); e == nil {
		t.Fatal("implicit monitor cleanup permitted")
	}
	cleanup.Enforcement.Intent = "remove_managed_rules"
	if e := a.applyManaged(context.Background(), cleanup, protection); e != nil {
		t.Fatal(e)
	}
	for _, rule := range owned {
		for _, scope := range []string{"runtime", "permanent"} {
			if f.has(scope, "rich_rule", rule.Rule) {
				t.Fatal("cleanup left owned deny")
			}
		}
	}
	if !f.has("runtime", "port", "18080/tcp") || a.State.AppliedVersion != 2 || len(a.State.ManagedBundle.Rules) != 0 {
		t.Fatal("cleanup mutated legacy policy or failed to commit empty bundle")
	}
}
func TestManagedFailedApprovalHeldAcrossRecoveryUntilNewApproval(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("staged SSH failure")
		}
		return nil
	}
	if a.applyManaged(context.Background(), p, protection) == nil {
		t.Fatal("staged failure accepted")
	}
	writes := f.mutations
	a.State.ManagedFailures = nil
	if e := a.recoverManaged(context.Background()); e != nil {
		t.Fatal(e)
	}
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return nil }
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	if f.mutations != writes || a.State.ManagedEnforcement.Status != "rolled_back" {
		t.Fatal("failed approval automatically replayed after restart")
	}
	p.Enforcement.ApprovalID = "replacement-approval"
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	if a.State.AppliedVersion != 1 || a.State.ManagedEnforcement.Status != "enforced" {
		t.Fatal("new explicit approval did not allow retry")
	}
}
func TestManagedHealthUsesFreshNonceAndRejectsEarlierPhaseWitness(t *testing.T) {
	a, _, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	nonces := []string{}
	a.checkManagedHealth = func(_ context.Context, _ *Policy, _ Protection, nonce string) error {
		nonces = append(nonces, nonce)
		return nil
	}
	for i := 0; i < 3; i++ {
		if e := a.managedHealth(context.Background(), p, protection, "same-transaction"); e != nil {
			t.Fatal(e)
		}
	}
	if nonces[0] == nonces[1] || nonces[1] == nonces[2] {
		t.Fatal("transaction reused witness nonce")
	}
	witness := managedWitness{Nonce: nonces[0], ServerID: p.ServerID, Version: p.Version, Digest: p.Digest, ProtectionDigest: protection.Digest, BindingDigest: p.Enforcement.BindingDigest, CheckedAt: time.Now(), ControllerOK: true, Status: "healthy"}
	if a.validateManagedWitness(witness, p, protection, nonces[1], time.Now()) == nil {
		t.Fatal("pre-stage healthy witness replayed in later phase")
	}
}
func TestManagedLegacyApplyStatusMapping(t *testing.T) {
	for detailed, legacy := range map[string]string{"enforced": "synced", "pending_approval": "pending", "staging": "applying", "runtime_healthchecking": "applying", "committing": "applying", "error": "error", "rolled_back": "rolled_back", "preview": "preview"} {
		if managedApplyStatus(detailed) != legacy {
			t.Fatalf("status %s incompatible with API", detailed)
		}
	}
}
func TestManagedRecoverySelectsVersionRatherThanWallClockDeadline(t *testing.T) {
	a, _, _ := managedTestAgent(t)
	for index, version := range []int{3, 2} {
		nonce := strings.Repeat(string(rune('a'+index)), 32)
		journal := &managedJournal{Nonce: nonce, Phase: "committed", PID: os.Getpid(), Deadline: time.Now().Add(time.Duration(index) * time.Hour), Next: ManagedBundle{Generation: nonce, Version: version, Digest: strings.Repeat(string(rune('c'+index)), 64), Rules: []ManagedRule{}}}
		if e := saveManagedJournal(managedJournalPath(a.Config.StateDir, nonce), journal); e != nil {
			t.Fatal(e)
		}
	}
	if e := a.recoverManaged(context.Background()); e != nil {
		t.Fatal(e)
	}
	if a.State.AppliedVersion != 3 {
		t.Fatal("wall-clock jump selected older committed version")
	}
}
func TestManagedCommittedTelemetryKeepsHistoricalApprovalAfterExpiryOrCleanup(t *testing.T) {
	a, _, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	approved := p.Enforcement.ApprovalID
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	p.Enforcement = &EnforcementAuthorization{Authorized: false}
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	if a.State.ManagedEnforcement.ApprovalID != approved {
		t.Fatal("expired delivery authorization erased historical approved identity")
	}
	cleanup := managedTestPolicy(protection, 2)
	cleanup.Mode = "monitor"
	cleanup.Services = []Service{}
	cleanup.Digest, _ = compiledPolicyDigest(cleanup)
	cleanup.Enforcement.ApprovedDigest = cleanup.Digest
	cleanup.Enforcement.BindingDigest = enforcementBinding(cleanup, protection.Digest)
	cleanup.Enforcement.Intent = "remove_managed_rules"
	cleanupApproved := cleanup.Enforcement.ApprovalID
	if e := a.applyManaged(context.Background(), cleanup, protection); e != nil {
		t.Fatal(e)
	}
	cleanup.Enforcement = &EnforcementAuthorization{Authorized: false}
	if e := a.applyManaged(context.Background(), cleanup, protection); e != nil {
		t.Fatal(e)
	}
	if a.State.ManagedEnforcement.ApprovalID != cleanupApproved {
		t.Fatal("post-cleanup telemetry lost its historical approval")
	}
	a.enrichManagedStatus()
	if a.State.ManagedEnforcement.LastGoodVersion != 2 || a.State.ManagedEnforcement.LastGoodDigest != cleanup.Digest {
		t.Fatal("last-good baseline missing from telemetry")
	}
}
func TestManagedSimulationRecoveryNeverExecutesFirewall(t *testing.T) {
	a, f, _ := managedTestAgent(t)
	a.Simulate = true
	if e := a.recoverManaged(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.mutations != 0 {
		t.Fatal("simulation performed recovery mutation")
	}
}
func TestManagedPendingRollbackReconciledBeforeNewGenerationAndLateWatchdogFenced(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	first := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if e := a.applyManaged(context.Background(), first, protection); e != nil {
		t.Fatal(e)
	}
	original := append([]ManagedRule{}, a.State.ManagedBundle.Rules...)
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			f.failRollbackReadOnce = true
			return errors.New("staged health failed")
		}
		return nil
	}
	second := managedTestPolicy(protection, 2, "10.40.0.0/24")
	if a.applyManaged(context.Background(), second, protection) == nil {
		t.Fatal("failure accepted")
	}
	paths, _ := filepath.Glob(filepath.Join(a.Config.StateDir, "managed", "transactions", "*.json"))
	var pending *managedJournal
	pendingPath := ""
	for _, path := range paths {
		nonce := strings.TrimSuffix(filepath.Base(path), ".json")
		j, _ := readManagedJournal(path, nonce)
		if j.Next.Version == 2 {
			pending = j
			pendingPath = path
		}
	}
	if pending == nil || pending.Phase != "rollback_failed" {
		t.Fatalf("transient read-back error did not leave pending rollback %+v", pending)
	}
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return nil }
	third := managedTestPolicy(protection, 3, "10.50.0.0/24")
	if e := a.applyManaged(context.Background(), third, protection); e != nil {
		t.Fatal(e)
	}
	pending, _ = readManagedJournal(pendingPath, pending.Nonce)
	if pending.Phase != "rolled_back" {
		t.Fatal("new generation bypassed pending compensation")
	}
	for _, rule := range original {
		if f.has("runtime", "rich_rule", rule.Rule) {
			t.Fatal("old allowance present after replacement")
		}
	}
	// Emulate an older release leaving a stale nonterminal journal despite C's
	// commit. Its late timer must recognize C's descendant and perform no writes.
	pending.Phase = "rollback_failed"
	pending.Deadline = time.Now().Add(-time.Second)
	pending.DeadlineBootSeconds = 0
	if e := saveManagedJournal(pendingPath, pending); e != nil {
		t.Fatal(e)
	}
	writes := f.mutations
	if e := RunManagedWatchdog(context.Background(), pendingPath, pending.Nonce, f); e != nil {
		t.Fatal(e)
	}
	if f.mutations != writes {
		t.Fatal("stale watchdog mutated a newer committed generation")
	}
	for _, rule := range original {
		if f.has("runtime", "rich_rule", rule.Rule) {
			t.Fatal("stale watchdog broadened newer policy")
		}
	}
}
func TestManagedCommittedExplicitZoneTopologyDriftReported(t *testing.T) {
	a, f, protection := managedTestAgent(t)
	a.Config.Zone = "public"
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	writes := f.mutations
	for _, topology := range []string{"public\n  interfaces: eth0\ntrusted\n  interfaces: eth1\n", "trusted\n  interfaces: eth0\n", "public\n  interfaces: eth9\n"} {
		f.activeZones = topology
		if a.applyManaged(context.Background(), p, protection) == nil || a.State.ManagedEnforcement.Status == "enforced" {
			t.Fatalf("topology drift silently reported enforced: %s", topology)
		}
		if f.mutations != writes {
			t.Fatal("binding drift triggered automatic relocation")
		}
	}
}
func TestManagedSimulationRefusesRealHistoryAndPublishesUnavailableProtection(t *testing.T) {
	dir := t.TempDir()
	if e := os.MkdirAll(filepath.Join(dir, "managed", "transactions"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "managed", "transactions", "pending.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := New(Config{StateDir: dir, ControllerURL: "http://127.0.0.1:8787"}, true, "demo"); e == nil {
		t.Fatal("simulation reused real mutation history")
	}
	a := &Agent{Simulate: true, Config: Config{ControllerURL: "http://127.0.0.1:8787"}}
	protection := a.managedProtectionFromReport(Report{})
	if protection.ControllerURL != "" || protection.ManagementProbeURL != "" || protection.Ready {
		t.Fatal("simulation published a trusted HTTP enforcement origin")
	}
}
