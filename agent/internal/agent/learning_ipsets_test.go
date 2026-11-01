package agent

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func largeLearningAssignment(t *testing.T, a *Agent, protection Protection, session Session, generation, offset, count int) *LearningAllow {
	t.Helper()
	sources := largeSources(offset, count)
	p := learningTestAssignment(a, protection, session, generation, sources[0])
	p.Services[0].Sources = sources
	p.Authorities[0].Services[0].Sources = sources
	for _, source := range sources {
		prefix, _ := netip.ParsePrefix(source)
		learningEvidenceFor(a, session, prefix.Addr().String(), 443)
	}
	p.Digest, _ = learningAllowDigest(p)
	p.BindingDigest = learningAllowBinding(p)
	return p
}
func TestLearningIPSetsFiveThousandSourcesAreAdditiveAndUseSeparateBanks(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	setFake := &managedSetFake{managedFake: f, sets: map[string][]string{}}
	a.Commands = setFake
	p := largeLearningAssignment(t, a, protection, session, 1, 0, 5000)
	if e := a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "applied" {
		t.Fatalf("not applied %+v", a.State.LearningAllowOutcome)
	}
	bundle := a.State.LearningAllowBundle
	if len(bundle.IPSets) != 1 || len(bundle.Rules) != 1 || !strings.HasPrefix(bundle.IPSets[0].Name, "prthak_la4_") {
		t.Fatalf("wrong learned source-set shape %+v", bundle)
	}
	if a.State.ManagedBundle != nil || a.State.AppliedVersion != 0 {
		t.Fatal("learned overlay changed ordinary managed authority")
	}
	for _, rule := range bundle.Rules {
		if strings.Contains(rule.Rule, "reject") || !learningAllowOwned(rule.Rule) {
			t.Fatal("overlay introduced rejects or lost ownership")
		}
	}
	for key := range setFake.sets {
		if !strings.Contains(key, "prthak_l") {
			t.Fatal("learning modified ordinary managed source bank")
		}
	}
	// Stop/expiry never revoke the already committed additive set.
	a.State.Policy.LearningSessions[0].Status = "stopped"
	p.Authorized = false
	if e := a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if len(setFake.sets["runtime|"+bundle.IPSets[0].Name]) != 5000 {
		t.Fatal("stop unexpectedly erased committed allows")
	}
}
func TestLearningIPSetPartialCommitFailureRestoresBothBanksAndHoldsAuthority(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	setFake := &managedSetFake{managedFake: f, sets: map[string][]string{}}
	a.Commands = setFake
	first := largeLearningAssignment(t, a, protection, session, 1, 0, 5000)
	if e := a.processLearningAllow(context.Background(), first); e != nil {
		t.Fatal(e)
	}
	second := largeLearningAssignment(t, a, protection, session, 2, 0, 5001)
	setFake.failBulk = setFake.bulk + 2
	if e := a.processLearningAllow(context.Background(), second); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "rolled_back" || a.State.LearningAllowBundle.Assignment.Generation != 1 {
		t.Fatalf("wrong rollback %+v", a.State.LearningAllowOutcome)
	}
	if len(setFake.sets["runtime|prthak_lb4_00"]) != 0 || len(setFake.sets["permanent|prthak_lb4_00"]) != 0 {
		t.Fatal("partial next bank survived rollback")
	}
	if len(setFake.sets["runtime|prthak_la4_00"]) != 5000 || a.State.LearningAllowFailedSessions[session.ID] == "" {
		t.Fatal("previous bank or failed authority hold lost")
	}
}
func TestLearningIPSetCrashBeforeFirstRuleStillHoldsFailedAuthority(t *testing.T) {
	a, f, protection, session := learningTestAgent(t)
	setFake := &managedSetFake{managedFake: f, sets: map[string][]string{}}
	a.Commands = setFake
	p := largeLearningAssignment(t, a, protection, session, 1, 0, 5000)
	nonce := strings.Repeat("c", 32)
	rules, sets, e := a.learningRulePlan(p, protection.Zone, nonce, false)
	if e != nil {
		t.Fatal(e)
	}
	bundle := &LearningAllowBundle{Assignment: *p, CommitNonce: nonce, Rules: rules, IPSets: sets}
	j := &managedJournal{Nonce: nonce, Phase: "staging", PID: os.Getpid(), Deadline: time.Now().Add(-time.Second), Next: *learningBundleRecord(bundle), SetMutations: []managedIPSetMutation{{Scope: "runtime", Set: sets[0], Before: []string{}}}}
	path := learningJournalPath(a.Config.StateDir, nonce)
	if e = saveManagedJournal(path, j); e != nil {
		t.Fatal(e)
	}
	setFake.sets["runtime|"+sets[0].Name] = sets[0].Entries[:100]
	if e = a.recoverLearningAllowLocked(context.Background()); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowFailedSessions[session.ID] == "" || len(setFake.sets["runtime|"+sets[0].Name]) != 0 || a.State.LearningAllowOutcome.Status != "rolled_back" {
		t.Fatal("interrupted bulk-only generation did not roll back and hold authority")
	}
}
