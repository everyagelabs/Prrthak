package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLearningWatchdogWindowBeginsAfterReadOnlyPreflight(t *testing.T) {
	a, fake, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	assignment := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	checks := 0
	var preflightReturned time.Time
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error {
		checks++
		if checks == 1 {
			if fake.mutations != 0 {
				t.Fatal("health preflight was not read-only")
			}
			// Ordering, rather than a sleep/timing tolerance, models completion
			// of an arbitrarily delayed health witness. The deadline must be
			// created after this callback returns, regardless of its duration.
			preflightReturned = time.Now()
		}
		return nil
	}
	armed := false
	arm := a.armManaged
	a.armManaged = func(ctx context.Context, path string, journal *managedJournal) error {
		if preflightReturned.IsZero() || journal.Deadline.Add(-120*time.Second).Before(preflightReturned) {
			t.Fatal("read-only preflight consumed the independent rollback window")
		}
		if fake.mutations != 0 {
			t.Fatal("firewall changed before independent watchdog arming")
		}
		armed = true
		return arm(ctx, path, journal)
	}
	if err := a.processLearningAllow(context.Background(), assignment); err != nil || !armed || checks != 3 || a.State.LearningAllowOutcome.Status != "applied" {
		t.Fatal("learning failed after fresh full-window arming", err, a.State.LearningAllowOutcome)
	}
}

func deadlineCleanupPolicy(protection Protection, version int) *Policy {
	p := managedTestPolicy(protection, version)
	p.Mode = "monitor"
	p.Services = []Service{}
	p.Digest, _ = compiledPolicyDigest(p)
	p.Enforcement.ApprovedDigest = p.Digest
	p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
	p.Enforcement.Intent = "remove_managed_rules"
	return p
}

func assertExpiredCleanupRestored(t *testing.T, a *Agent, fake *managedFake, path string, journal *managedJournal, old []ManagedRule) {
	t.Helper()
	if err := saveManagedJournal(path, journal); err != nil {
		t.Fatal(err)
	}
	// Deterministic interrupted cleanup: one runtime rule was removed before
	// an actual expired deadline. No sleeps or host CPU assumptions are needed.
	fake.set("runtime", "rich_rule", old[0].Rule, false)
	if err := RunManagedWatchdog(context.Background(), path, journal.Nonce, fake); err != nil {
		t.Fatal(err)
	}
	loaded, err := readManagedJournal(path, journal.Nonce)
	if err != nil || loaded.Phase != "rolled_back" || loaded.Error != "independent rollback deadline exceeded" {
		t.Fatal("real expiry was not preserved as a failed cleanup", loaded, err)
	}
	for _, rule := range old {
		for _, scope := range []string{"runtime", "permanent"} {
			if !fake.has(scope, "rich_rule", rule.Rule) {
				t.Fatal("deadline rollback lost a previously committed rule", scope, rule)
			}
		}
	}
	if err := a.recoverManaged(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManagedCleanupExpiryRetainsOldRulesAndRequiresFreshReviewToRetry(t *testing.T) {
	a, fake, protection := managedTestAgent(t)
	oldPolicy := managedTestPolicy(protection, 1, "198.51.100.0/24")
	if err := a.applyManaged(context.Background(), oldPolicy, protection); err != nil {
		t.Fatal(err)
	}
	old := a.State.ManagedBundle
	cleanup := deadlineCleanupPolicy(protection, 2)
	a.State.Policy = cleanup
	nonce := strings.Repeat("b", 32)
	journal := &managedJournal{Nonce: nonce, Phase: "committing", PID: os.Getpid(), Deadline: time.Now().Add(-time.Second), Previous: old, Next: ManagedBundle{Generation: nonce, Version: cleanup.Version, Digest: cleanup.Digest, ApprovalID: cleanup.Enforcement.ApprovalID, ProtectionDigest: protection.Digest, Rules: []ManagedRule{}}, Mutations: []managedMutation{{Scope: "runtime", Zone: old.Rules[0].Zone, Rule: old.Rules[0].Rule, Before: true, After: false}}}
	assertExpiredCleanupRestored(t, a, fake, managedJournalPath(a.Config.StateDir, nonce), journal, old.Rules)
	if a.State.AppliedVersion != 1 || a.State.ManagedEnforcement.Status != "rolled_back" || a.State.ManagedEnforcement.RollbackReason != "independent rollback deadline exceeded" {
		t.Fatal("expired cleanup was reported as applied", a.State.ManagedEnforcement)
	}
	writes := fake.mutations
	if err := a.applyManaged(context.Background(), cleanup, protection); err != nil || fake.mutations != writes || !strings.Contains(a.State.ManagedEnforcement.RollbackReason, "held for administrative review") {
		t.Fatal("failed cleanup approval was automatically retried", err, a.State.ManagedEnforcement)
	}
	fresh := deadlineCleanupPolicy(protection, 3)
	a.State.Policy = fresh
	if err := a.applyManaged(context.Background(), fresh, protection); err != nil || a.State.AppliedVersion != 3 || len(a.State.ManagedBundle.Rules) != 0 || a.State.ManagedEnforcement.Status != "enforced" {
		t.Fatal("fresh reviewed cleanup could not safely retry after rollback", err, a.State.ManagedEnforcement)
	}
	for _, rule := range old.Rules {
		if fake.has("runtime", "rich_rule", rule.Rule) || fake.has("permanent", "rich_rule", rule.Rule) {
			t.Fatal("fresh committed cleanup retained an old owned rule")
		}
	}
}

func deadlineLearningCleanup(a *Agent, protection Protection, generation int) *LearningAllow {
	p := &LearningAllow{ServerID: "host-a", Generation: generation, Services: []Service{}, PolicyIDs: []string{}, Authorities: []LearningAuthority{{PolicyID: "learn-a", Kind: "reviewed", Services: []Service{}, ExpiresAt: time.Now().Add(time.Hour)}}, ProtectionDigest: protection.Digest, TargetIPsDigest: targetIPsDigest(a.inventory.IPs), Authorized: true, ExpiresAt: time.Now().Add(time.Hour)}
	p.Digest, _ = learningAllowDigest(p)
	p.BindingDigest = learningAllowBinding(p)
	return p
}

func TestLearningCleanupExpiryRetainsOldRulesAndRequiresFreshReviewToRetry(t *testing.T) {
	a, fake, protection, session := learningTestAgent(t)
	learningEvidenceFor(a, session, "10.20.0.9", 443)
	if err := a.processLearningAllow(context.Background(), learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")); err != nil {
		t.Fatal(err)
	}
	old := a.State.LearningAllowBundle
	cleanup := deadlineLearningCleanup(a, protection, 2)
	nonce := strings.Repeat("c", 32)
	journal := &managedJournal{Nonce: nonce, Phase: "committing", PID: os.Getpid(), Deadline: time.Now().Add(-time.Second), Previous: learningBundleRecord(old), Next: *learningBundleRecord(&LearningAllowBundle{Assignment: *cleanup, CommitNonce: nonce, TopologyDigest: old.TopologyDigest, Rules: []ManagedRule{}}), Mutations: []managedMutation{{Scope: "runtime", Zone: old.Rules[0].Zone, Rule: old.Rules[0].Rule, Before: true, After: false}}}
	assertExpiredCleanupRestored(t, a, fake, learningJournalPath(a.Config.StateDir, nonce), journal, old.Rules)
	if a.State.LearningAllowOutcome.Status != "rolled_back" || a.State.LearningAllowOutcome.AppliedGeneration != 1 || a.State.LearningAllowOutcome.Error != "independent rollback deadline exceeded" {
		t.Fatal("expired learned cleanup was reported as applied", a.State.LearningAllowOutcome)
	}
	writes := fake.mutations
	if err := a.processLearningAllow(context.Background(), cleanup); err != nil || fake.mutations != writes || !strings.Contains(a.State.LearningAllowOutcome.Error, "held for administrative review") {
		t.Fatal("failed learned cleanup binding was automatically retried", err, a.State.LearningAllowOutcome)
	}
	fresh := deadlineLearningCleanup(a, protection, 3)
	if err := a.processLearningAllow(context.Background(), fresh); err != nil || a.State.LearningAllowOutcome.Status != "applied" || a.State.LearningAllowOutcome.AppliedGeneration != 3 || len(a.State.LearningAllowBundle.Rules) != 0 {
		t.Fatal("fresh reviewed learned cleanup could not safely retry", err, a.State.LearningAllowOutcome)
	}
	for _, rule := range old.Rules {
		if fake.has("runtime", "rich_rule", rule.Rule) || fake.has("permanent", "rich_rule", rule.Rule) {
			t.Fatal("fresh learned cleanup left an old owned rule")
		}
	}
}
