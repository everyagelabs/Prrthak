package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func learningTestAgent(t *testing.T) (*Agent, *managedFake, Protection, Session) {
	t.Helper()
	a, f, protection := managedTestAgent(t)
	a.Config.LearningAutoAllow = true
	a.inventory = &Report{IPs: []string{"10.1.0.1"}}
	session := Session{ID: "learning-session-123", PolicyAction: "auto_allow", ServerIDs: []string{"host-a"}, Ports: []Port{{Port: 443, Protocol: "tcp"}}, StartsAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), Status: "active"}
	a.State.Policy = &Policy{ServerID: "host-a", LearningSessions: []Session{session}}
	a.protection = &protection
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error { return nil }
	return a, f, protection, session
}
func learningTestAssignment(a *Agent, protection Protection, session Session, generation int, source string) *LearningAllow {
	service := Service{Port: 443, Protocol: "tcp", Sources: []string{source}}
	authority := LearningAuthority{PolicyID: "learn-a", SessionID: session.ID, Kind: "auto", ExpiresAt: session.ExpiresAt, Ports: session.Ports, Services: []Service{service}}
	p := &LearningAllow{ServerID: "host-a", Generation: generation, Services: []Service{service}, PolicyIDs: []string{"learn-a"}, Authorities: []LearningAuthority{authority}, ProtectionDigest: protection.Digest, TargetIPsDigest: targetIPsDigest(a.inventory.IPs), Authorized: true, ExpiresAt: session.ExpiresAt}
	p.Digest, _ = learningAllowDigest(p)
	p.BindingDigest = learningAllowBinding(p)
	return p
}
func learningEvidenceFor(a *Agent, session Session, source string, port int) {
	rememberLearningEvidence(&a.State, session, Flow{SourceIP: source, Port: port, Protocol: "tcp", FirstSeen: time.Now().Add(-time.Second), LastSeen: time.Now().Add(-time.Second)})
}
func TestLearningFreshPreflightDenialMakesNoFirewallWrite(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	p := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	checks := 0
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error {
		checks++
		if f.mutations != 0 {
			t.Fatal("fresh learning authorization happened after a firewall mutation")
		}
		return errors.New("requester or checker authorization was revoked")
	}
	_ = a.processLearningAllow(context.Background(), p)
	if checks != 1 || f.mutations != 0 || a.State.LearningAllowBundle != nil || a.State.LearningAllowOutcome.Status == "applied" {
		t.Fatalf("revoked cached learning assignment wrote firewall: checks=%d mutations=%d outcome=%+v", checks, f.mutations, a.State.LearningAllowOutcome)
	}
}
func TestLearningAllowCrossLanguageFixture(t *testing.T) {
	p := &LearningAllow{ServerID: "host-a", Generation: 1, Services: []Service{{Port: 80, Protocol: "tcp", Sources: []string{"10.20.0.1/32"}}}, PolicyIDs: []string{"learn-a"}, ProtectionDigest: "protection-test", TargetIPsDigest: targetIPsDigest([]string{"10.1.0.1"})}
	p.Digest, _ = learningAllowDigest(p)
	if p.Digest != "6f5626dffdf7e03e5f62a322cbabda6ba935b777c33278fb3b36fc84434ff894" || p.TargetIPsDigest != "0c8c396bc49b2dffac0490a868f7809cc5e23b931aa76fd5715bc06b2d51cf0c" || learningAllowBinding(p) != "f358e4b0e4f1fe50ed4aca8507a02fcf5ca11879e9259ef3416a5af7c0030a17" {
		t.Fatal("Go/Python learning assignment hash mismatch")
	}
}
func TestLearningIngressParsingExcludesForwardAndOtherPorts(t *testing.T) {
	session := Session{ID: "learning-session-123", Ports: []Port{{Port: 443, Protocol: "tcp"}}, StartsAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	message := RulePrefix(session.ID) + " IN=eth0 OUT= SRC=10.20.0.9 DST=10.1.0.1 PROTO=TCP DPT=443"
	if flow, ok := ParseKernelLog(message, time.Now(), session); !ok || flow.Port != 443 || flow.SourceIP != "10.20.0.9" {
		t.Fatal("exact ingress tuple rejected")
	}
	for _, bad := range []string{strings.Replace(message, "OUT= ", "OUT=eth1 ", 1), strings.Replace(message, "IN=eth0", "IN=", 1), strings.Replace(message, "OUT= ", "", 1), strings.Replace(message, "DPT=443", "DPT=22", 1), strings.Replace(message, "DPT=443", "DPT=80", 1)} {
		if _, ok := ParseKernelLog(bad, time.Now(), session); ok {
			t.Fatalf("unscoped/non-ingress flow accepted: %s", bad)
		}
	}
}
func TestLearningAllowExactPortEvidenceAndNoManagedRejects(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	p := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	if e := a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "applied" || a.State.LearningAllowOutcome.AppliedGeneration != 1 {
		t.Fatalf("overlay not applied %+v", a.State.LearningAllowOutcome)
	}
	if a.State.AppliedVersion != 0 || a.State.ManagedBundle != nil {
		t.Fatal("learning impersonated managed policy approval")
	}
	for _, write := range f.writes {
		if strings.Contains(write, "reject") || strings.Contains(write, "drop") || strings.Contains(write, `port="22"`) || strings.Contains(write, `port="80"`) {
			t.Fatalf("learning touched unrelated/deny rule: %s", write)
		}
	}
	for _, scope := range []string{"runtime", "permanent"} {
		for _, rule := range a.State.LearningAllowBundle.Rules {
			if !f.has(scope, "rich_rule", rule.Rule) {
				t.Fatal("overlay absent after commit")
			}
		}
	}
}
func TestLearningAllowRefusesUnobservedWrongPortExpiredAndOptOut(t *testing.T) {
	for _, condition := range []string{"unobserved", "wrongport", "expired", "observe", "optout", "enforceoff", "protectedssh", "wide", "multicast"} {
		t.Run(condition, func(t *testing.T) {
			a, f, protection, session := learningTestAgent(t)
			p := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
			learningEvidenceFor(a, session, "10.20.0.9", 443)
			switch condition {
			case "unobserved":
				a.State.LearningEvidence = nil
			case "wrongport":
				p.Services[0].Port = 80
				p.Authorities[0].Services[0].Port = 80
			case "expired":
				p.ExpiresAt = time.Now().Add(-time.Second)
			case "observe":
				a.State.Policy.LearningSessions[0].PolicyAction = "observe"
			case "optout":
				a.Config.LearningAutoAllow = false
			case "enforceoff":
				a.Config.Enforce = false
			case "protectedssh":
				p.Services[0].Port = 2022
				p.Authorities[0].Services[0].Port = 2022
			case "wide":
				p.Services[0].Sources = []string{"10.20.0.0/24"}
			case "multicast":
				p.Services[0].Sources = []string{"224.0.0.1/32"}
			}
			p.Digest, _ = learningAllowDigest(p)
			p.BindingDigest = learningAllowBinding(p)
			_ = a.processLearningAllow(context.Background(), p)
			if f.mutations != 0 || a.State.LearningAllowOutcome.Status == "applied" {
				t.Fatal("unsafe/ungranted tuple modified firewall")
			}
		})
	}
}
func TestLearningOnly443InstallsNo22Or80Instrumentation(t *testing.T) {
	a, f, _, session := learningTestAgent(t)
	a.confirmed = true
	a.State.Coverage = map[string]*Coverage{}
	a.State.Rules = []OwnedRule{}
	if e := a.LearningTick(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if len(a.State.Rules) != 1 || !strings.Contains(a.State.Rules[0].Rule, `port="443"`) {
		t.Fatalf("unexpected learning instrumentation %+v", a.State.Rules)
	}
	for _, write := range f.writes {
		if strings.Contains(write, `port="22"`) || strings.Contains(write, `port="80"`) {
			t.Fatal("selected443 learning instrumented another port")
		}
	}
	p := learningTestAssignment(a, *a.protection, session, 1, "10.20.0.9/32")
	p.Services[0].Port = 80
	p.Authorities[0].Services[0].Port = 80
	learningEvidenceFor(a, session, "10.20.0.9", 80)
	p.Digest, _ = learningAllowDigest(p)
	p.BindingDigest = learningAllowBinding(p)
	if a.validateLearningDelta(p, time.Now()) == nil {
		t.Fatal("forged port80 grant escaped frozen443 selection")
	}
}
func TestLearningOverlayPersistsAfterExpiryAndReviewedDelete(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	p := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	if e := a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	old := append([]ManagedRule{}, a.State.LearningAllowBundle.Rules...)
	writes := f.mutations
	p.Generation = 2
	p.Authorized = false
	p.ExpiresAt = time.Now().Add(-time.Second)
	p.Authorities[0].ExpiresAt = p.ExpiresAt
	p.BindingDigest = learningAllowBinding(p)
	if e := a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if f.mutations != writes || a.State.LearningAllowOutcome.Status != "applied" || a.State.LearningAllowOutcome.AppliedGeneration != 2 {
		t.Fatal("expiry removed or failed to retain durable accepts")
	}
	deletion := &LearningAllow{ServerID: "host-a", Generation: 3, Services: []Service{}, PolicyIDs: []string{}, Authorities: []LearningAuthority{{PolicyID: "learn-a", Kind: "reviewed", Services: []Service{}, ExpiresAt: time.Now().Add(time.Hour)}}, ProtectionDigest: protection.Digest, TargetIPsDigest: p.TargetIPsDigest, Authorized: true, ExpiresAt: time.Now().Add(time.Hour)}
	deletion.Digest, _ = learningAllowDigest(deletion)
	deletion.BindingDigest = learningAllowBinding(deletion)
	if e := a.processLearningAllow(context.Background(), deletion); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "applied" {
		t.Fatalf("reviewed removal blocked %+v", a.State.LearningAllowOutcome)
	}
	for _, rule := range old {
		if f.has("runtime", "rich_rule", rule.Rule) || f.has("permanent", "rich_rule", rule.Rule) {
			t.Fatal("reviewed deletion left overlay")
		}
	}
}
func TestLearningOverlayHealthRollbackFailureHeldAndCrashRecovery(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	p := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	calls := 0
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("lost fresh SSH/controller proof")
		}
		return nil
	}
	if e := a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "rolled_back" || a.State.LearningAllowOutcome.AppliedGeneration != 0 {
		t.Fatal("failed overlay claimed applied")
	}
	writes := f.mutations
	a.State.LearningAllowFailures = nil
	if e := a.recoverManaged(context.Background()); e != nil {
		t.Fatal(e)
	}
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error { return nil }
	_ = a.processLearningAllow(context.Background(), p)
	if f.mutations != writes {
		t.Fatal("failed overlay replayed automatically")
	}
	// An uncertain write with a durable intent is compensated by the common watchdog.
	nonce := strings.Repeat("b", 32)
	rule := learningAllowRules(p, "public", nonce, true)[0]
	f.set("runtime", "rich_rule", rule.Rule, true)
	bundle := &LearningAllowBundle{Assignment: *p, CommitNonce: nonce, Rules: []ManagedRule{rule}}
	journal := &managedJournal{Nonce: nonce, Phase: "staging", Deadline: time.Now().Add(-time.Second), PID: os.Getpid(), Next: *learningBundleRecord(bundle), Mutations: []managedMutation{{Scope: "runtime", Zone: "public", Rule: rule.Rule, Before: false, After: true}}}
	path := learningJournalPath(a.Config.StateDir, nonce)
	if e := saveManagedJournal(path, journal); e != nil {
		t.Fatal(e)
	}
	if e := RunManagedWatchdog(context.Background(), path, nonce, f); e != nil {
		t.Fatal(e)
	}
	if f.has("runtime", "rich_rule", rule.Rule) {
		t.Fatal("watchdog failed to remove unacknowledged learning accept")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("learning rollback journal not private")
	}
	_ = filepath.Base(path)
}
func TestLearningNoOverlaySentinelOmitsGenerationZeroOutcome(t *testing.T) {
	a, _, _, _ := learningTestAgent(t)
	a.State.LearningAllowOutcome = &LearningAllowOutcome{Generation: 0, Status: "blocked"}
	if e := a.processLearningAllow(context.Background(), &LearningAllow{Generation: 0, Services: []Service{}}); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome != nil {
		t.Fatal("empty overlay emitted invalid generation-zero history")
	}
	a.State.LearningAllowOutcome = &LearningAllowOutcome{Generation: 0}
	a.enrichLearningOutcome()
	if a.State.LearningAllowOutcome != nil {
		t.Fatal("report retained stale generation-zero outcome")
	}
}
func TestLearningOverlayDoesNotApproveUnrelatedPendingManagedRules(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	a.State.Policy.Version = 3
	a.State.Policy.Mode = "enforce"
	a.State.Policy.Services = []Service{{Port: 22, Protocol: "tcp", Mode: "enforce", Sources: []string{"0.0.0.0/0"}}, {Port: 80, Protocol: "tcp", Mode: "enforce", Sources: []string{"0.0.0.0/0"}}}
	a.State.Policy.Digest, _ = compiledPolicyDigest(a.State.Policy)
	if e := a.processManaged(context.Background(), a.State.Policy); e != nil {
		t.Fatal(e)
	}
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	p := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	if e := a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if a.State.ManagedBundle != nil || a.State.AppliedVersion != 0 {
		t.Fatal("learning authorized an ordinary pending bundle")
	}
	for _, write := range f.writes {
		if strings.Contains(write, `port="22"`) || strings.Contains(write, `port="80"`) || strings.Contains(write, "reject") {
			t.Fatal("learning applied unrelated managed intent")
		}
	}
}
func TestLearningOverlayFailureMatrixRestoresExactPriorOverlay(t *testing.T) {
	for position := 1; position <= 10; position++ {
		t.Run(string(rune('A'+position)), func(t *testing.T) {
			a, f, protection, session := learningTestAgent(t)
			learningEvidenceFor(a, session, "10.20.0.9", 443)
			first := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
			if e := a.processLearningAllow(context.Background(), first); e != nil {
				t.Fatal(e)
			}
			before := map[string]bool{}
			for key, present := range f.rules {
				if present {
					before[key] = true
				}
			}
			learningEvidenceFor(a, session, "10.20.0.10", 443)
			second := learningTestAssignment(a, protection, session, 2, "10.20.0.9/32")
			second.Services[0].Sources = append(second.Services[0].Sources, "10.20.0.10/32")
			second.Authorities[0].Services = second.Services
			second.Digest, _ = learningAllowDigest(second)
			second.BindingDigest = learningAllowBinding(second)
			f.failAt = f.mutations + position
			if e := a.processLearningAllow(context.Background(), second); e != nil {
				t.Fatal(e)
			}
			if a.State.LearningAllowOutcome.Status != "rolled_back" || a.State.LearningAllowOutcome.AppliedGeneration != 1 {
				t.Fatalf("failure%d claimed applied: %+v", position, a.State.LearningAllowOutcome)
			}
			for key, present := range f.rules {
				if present != before[key] {
					t.Fatalf("rollback%d did not restore exact baseline: %s", position, key)
				}
			}
		})
	}
}
func TestLearningOverlayWholeFailedSessionHeldUntilReviewedRetry(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	first := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	calls := 0
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("management route failed")
		}
		return nil
	}
	_ = a.processLearningAllow(context.Background(), first)
	writes := f.mutations
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error { return nil }
	learningEvidenceFor(a, session, "10.20.0.10", 443)
	second := learningTestAssignment(a, protection, session, 2, "10.20.0.10/32")
	_ = a.processLearningAllow(context.Background(), second)
	if f.mutations != writes || a.State.LearningAllowOutcome.Status != "blocked" {
		t.Fatal("incidental next source retried failed auto grant")
	}
	second.Generation = 3
	second.Authorities[0].Kind = "reviewed"
	second.BindingDigest = learningAllowBinding(second)
	if e := a.processLearningAllow(context.Background(), second); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "applied" {
		t.Fatal("explicit reviewed retry failed")
	}
}
func TestLearningOverlayReplayAndAutomaticRemovalRefused(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	first := learningTestAssignment(a, protection, session, 2, "10.20.0.9/32")
	_ = a.processLearningAllow(context.Background(), first)
	writes := f.mutations
	older := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	_ = a.processLearningAllow(context.Background(), older)
	if f.mutations != writes || a.State.LearningAllowOutcome.Status != "blocked" {
		t.Fatal("old overlay replayed")
	}
	removal := learningTestAssignment(a, protection, session, 3, "10.20.0.10/32")
	learningEvidenceFor(a, session, "10.20.0.10", 443)
	_ = a.processLearningAllow(context.Background(), removal)
	if f.mutations != writes || a.State.LearningAllowOutcome.Status != "blocked" {
		t.Fatal("auto authority restricted prior durable source")
	}
}
func TestLearningEvidenceRecoversFromDurableUndeliveredBatch(t *testing.T) {
	a, _, _, session := learningTestAgent(t)
	a.State.LearningEvidence = nil
	flow := Flow{SourceIP: "10.20.0.9", Port: 443, Protocol: "tcp", FirstSeen: time.Now().Add(-time.Second), LastSeen: time.Now().Add(-time.Second), Count: 1, Verdict: "observed"}
	if e := SpoolBatch(filepath.Join(a.Config.StateDir, "spool"), 100, Batch{BatchID: "crash-before-state", SessionID: session.ID, Events: []Flow{flow}}); e != nil {
		t.Fatal(e)
	}
	if e := a.restoreLearningEvidenceFromSpool(); e != nil {
		t.Fatal(e)
	}
	if _, ok := a.State.LearningEvidence[session.ID][learningTuple(flow.SourceIP, flow.Protocol, flow.Port)]; !ok {
		t.Fatal("persisted ingress batch lost local proof across crash")
	}
}
func TestLearningKernelPrefixAdjacentToINField(t *testing.T) {
	session := Session{ID: "learning-session-123", Ports: []Port{{Port: 443, Protocol: "tcp"}}, StartsAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	message := RulePrefix(session.ID) + "IN=eth0 OUT= SRC=10.20.0.9 DST=10.1.0.1 PROTO=TCP DPT=443"
	if _, ok := ParseKernelLog(message, time.Now(), session); !ok {
		t.Fatal("real nftables adjacent prefix/IN format rejected")
	}
}
func TestLearningOverlayBoundedExactUnicastAndHostScope(t *testing.T) {
	for _, source := range []string{"0.0.0.0/32", "127.0.0.1/32", "169.254.1.1/32", "224.0.0.1/32", "255.255.255.255/32", "::/128", "::1/128", "fe80::1/128", "ff02::1/128", "::ffff:10.20.0.9/128", "10.20.0.0/24"} {
		p := &LearningAllow{Services: []Service{{Port: 443, Protocol: "tcp", Sources: []string{source}}}, PolicyIDs: []string{"learn-a"}}
		if _, e := learningAllowDigest(p); e == nil {
			t.Fatalf("ineligible automatic source accepted: %s", source)
		}
	}
	a, f, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	p := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	a.State.Policy.LearningSessions[0].ServerIDs = []string{"another-host"}
	_ = a.processLearningAllow(context.Background(), p)
	if f.mutations != 0 || a.State.LearningAllowOutcome.Status != "blocked" {
		t.Fatal("other host's session authorized a local overlay")
	}
	sources := largeSources(0, maxLearningSourceEntries+1)
	p.Services[0].Sources = sources
	if _, e := learningAllowDigest(p); e == nil {
		t.Fatal("overlay exceeded bounded10000-source limit")
	}
}
