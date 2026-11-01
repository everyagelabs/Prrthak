package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func learningAllowDirectory(stateDir string) string { return filepath.Join(stateDir, "learning-allow") }
func learningJournalPath(stateDir, nonce string) string {
	return filepath.Join(learningAllowDirectory(stateDir), "transactions", nonce+".json")
}
func learningBundleRecord(bundle *LearningAllowBundle) *ManagedBundle {
	if bundle == nil {
		return nil
	}
	return &ManagedBundle{Generation: bundle.CommitNonce, Version: bundle.Assignment.Generation, Digest: bundle.Assignment.Digest, ProtectionDigest: bundle.Assignment.ProtectionDigest, TopologyDigest: bundle.TopologyDigest, Rules: bundle.Rules, IPSets: bundle.IPSets, Learning: bundle}
}
func (a *Agent) enrichLearningOutcome() {
	if a.State.LearningAllowOutcome == nil {
		return
	}
	if a.State.LearningAllowOutcome.Generation < 1 {
		a.State.LearningAllowOutcome = nil
		return
	}
	a.State.LearningAllowOutcome.AppliedGeneration = 0
	a.State.LearningAllowOutcome.AppliedDigest = ""
	if a.State.LearningAllowBundle != nil {
		a.State.LearningAllowOutcome.AppliedGeneration = a.State.LearningAllowBundle.Assignment.Generation
		a.State.LearningAllowOutcome.AppliedDigest = a.State.LearningAllowBundle.Assignment.Digest
	}
}
func (a *Agent) learningOutcome(p *LearningAllow, status, message string) {
	out := &LearningAllowOutcome{Status: status, Error: message, UpdatedAt: time.Now().UTC()}
	if p != nil {
		out.Generation = p.Generation
		out.Digest = p.Digest
		out.BindingDigest = p.BindingDigest
	}
	a.State.LearningAllowOutcome = out
	a.enrichLearningOutcome()
}
func (a *Agent) recoverLearningAllowLocked(ctx context.Context) error {
	paths, e := filepath.Glob(filepath.Join(learningAllowDirectory(a.Config.StateDir), "transactions", "*.json"))
	if e != nil {
		return e
	}
	var latest, failed *managedJournal
	for _, path := range paths {
		nonce := strings.TrimSuffix(filepath.Base(path), ".json")
		journal, e := readManagedJournal(path, nonce)
		if e != nil {
			return e
		}
		if journal.Next.Learning == nil {
			return errors.New("learning journal lacks durable assignment")
		}
		if journal.Phase == "committed" {
			if latest == nil || journal.Next.Version > latest.Next.Version {
				latest = journal
			} else if journal.Next.Version == latest.Next.Version && journal.Next.Digest != latest.Next.Digest {
				return errors.New("divergent learning overlays share one generation")
			}
			continue
		}
		if journal.Phase == "superseded" {
			continue
		}
		if journal.Phase != "rolled_back" && managedCommittedSuccessor(path, journal) {
			journal.Phase = "superseded"
			journal.Error = "newer learning generation fences stale rollback"
			if e = saveManagedJournal(path, journal); e != nil {
				return e
			}
			continue
		}
		if journal.Phase != "rolled_back" {
			journal.Error = "interrupted learning overlay recovered"
			if e = rollbackManaged(ctx, a.Commands, path, journal); e != nil {
				return e
			}
		}
		if len(journal.Mutations) > 0 || len(journal.SetMutations) > 0 {
			if a.State.LearningAllowFailures == nil {
				a.State.LearningAllowFailures = map[string]string{}
			}
			a.State.LearningAllowFailures[journal.Next.Learning.Assignment.BindingDigest] = journal.Error
			a.holdLearningSessions(&journal.Next.Learning.Assignment, journal.Error)
			if failed == nil || journal.Next.Version > failed.Next.Version {
				failed = journal
			}
		}
	}
	if latest != nil {
		a.State.LearningAllowBundle = latest.Next.Learning
		a.learningOutcome(&latest.Next.Learning.Assignment, "applied", "")
		if e = atomicJSON(filepath.Join(learningAllowDirectory(a.Config.StateDir), "committed.json"), latest.Next); e != nil {
			return e
		}
	}
	if failed != nil && (latest == nil || failed.Next.Version > latest.Next.Version) {
		a.learningOutcome(&failed.Next.Learning.Assignment, "rolled_back", failed.Error)
	}
	return nil
}
func (a *Agent) validateLearningAssignment(p *LearningAllow, protection Protection) error {
	if p.ServerID == "" || p.Generation < 1 || a.State.Policy == nil || p.ServerID != a.State.Policy.ServerID {
		return errors.New("learning assignment endpoint/generation mismatch")
	}
	digest, e := learningAllowDigest(p)
	if e != nil {
		return e
	}
	if digest != p.Digest || !validDigest(p.BindingDigest) || p.BindingDigest != learningAllowBinding(p) {
		return errors.New("learning assignment content/binding digest mismatch")
	}
	if p.ProtectionDigest != protection.Digest {
		return errors.New("learning assignment protection configuration changed")
	}
	if a.inventory == nil || p.TargetIPsDigest != targetIPsDigest(a.inventory.IPs) {
		return errors.New("learning assignment endpoint IP binding changed")
	}
	if old := a.State.LearningAllowBundle; old != nil && (p.Generation < old.Assignment.Generation || p.Generation == old.Assignment.Generation && p.BindingDigest != old.Assignment.BindingDigest) {
		return errors.New("learning overlay replay rejected")
	}
	return nil
}
func (a *Agent) processLearningAllow(ctx context.Context, p *LearningAllow) error {
	if p == nil {
		return nil
	}
	if p.Generation == 0 && len(p.Services) == 0 && a.State.LearningAllowBundle == nil {
		a.State.LearningAllowOutcome = nil
		return a.save()
	}
	if !a.Config.Enforce || !a.Config.LearningAutoAllow || a.Simulate {
		status := "preview"
		if a.State.LearningAllowBundle != nil && len(a.State.LearningAllowBundle.Rules) > 0 {
			status = "blocked"
		}
		a.learningOutcome(p, status, "learning auto-allow requires enforce=true and learning_auto_allow=true on this endpoint; existing accepts remain")
		return a.save()
	}
	protection := Protection{}
	if a.protection != nil {
		protection = *a.protection
	}
	// New mutations get fresh SSH/topology discovery; ordinary no-change polls do
	// not disturb the independent15-minute service inventory cadence.
	noChange := a.State.LearningAllowBundle != nil && learningServicesKey(p.Services) == learningServicesKey(a.State.LearningAllowBundle.Assignment.Services) && p.ProtectionDigest == a.State.LearningAllowBundle.Assignment.ProtectionDigest && p.TargetIPsDigest == a.State.LearningAllowBundle.Assignment.TargetIPsDigest
	if !noChange {
		protection, _ = a.managedProtection(ctx)
		a.protection = &protection
	}
	blocked := func(message string) error { a.learningOutcome(p, "blocked", message); return a.save() }
	if e := a.validateLearningAssignment(p, protection); e != nil {
		return blocked(e.Error())
	}
	lock, e := managedLock(a.Config.StateDir, true)
	if e != nil {
		return blocked("enforcement mutation lock busy")
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if e = a.recoverAllEnforcementLocked(ctx); e != nil {
		return blocked("pending enforcement rollback must complete: " + e.Error())
	}
	if e = a.validateLearningAssignment(p, protection); e != nil {
		return blocked(e.Error())
	}
	if e = a.learningAllowPreflight(ctx, p, protection); e != nil {
		return blocked(e.Error())
	}
	old := a.State.LearningAllowBundle
	noChange = old != nil && learningServicesKey(p.Services) == learningServicesKey(old.Assignment.Services) && p.ProtectionDigest == old.Assignment.ProtectionDigest && p.TargetIPsDigest == old.Assignment.TargetIPsDigest
	if noChange && old.Assignment.Generation == p.Generation {
		a.learningOutcome(p, "applied", "")
		return a.save()
	}
	if !noChange {
		if !p.Authorized || !time.Now().Before(p.ExpiresAt) {
			return blocked("learning authority is inactive or expired; committed accepts are retained")
		}
		if reason, failed := a.State.LearningAllowFailures[p.BindingDigest]; failed {
			return blocked("failed learning generation is held for administrative review: " + reason)
		}
		if e = a.validateLearningDelta(p, time.Now().UTC()); e != nil {
			return blocked(e.Error())
		}
	}
	bytes := make([]byte, 16)
	if _, e = rand.Read(bytes); e != nil {
		return e
	}
	nonce := hex.EncodeToString(bytes)
	_, topology, e := a.managedTopology(ctx)
	if e != nil {
		return blocked(e.Error())
	}
	rules, sets, e := a.learningRulePlan(p, protection.Zone, nonce, false)
	if e != nil {
		return blocked(e.Error())
	}
	bundle := &LearningAllowBundle{Assignment: *p, CommitNonce: nonce, TopologyDigest: topology, Rules: rules, IPSets: sets}
	if noChange {
		bundle.Rules = append([]ManagedRule{}, old.Rules...)
		bundle.IPSets = append([]ManagedIPSet{}, old.IPSets...)
	}
	journal := &managedJournal{Nonce: nonce, Phase: "armed", PID: os.Getpid(), ProcessIdentity: processIdentity(os.Getpid()), Deadline: time.Now().Add(120 * time.Second), DeadlineBootSeconds: bootElapsedSeconds() + 120, Previous: learningBundleRecord(old), Next: *learningBundleRecord(bundle), Mutations: []managedMutation{}}
	path := learningJournalPath(a.Config.StateDir, nonce)
	if noChange {
		journal.Phase = "committed"
		if e = saveManagedJournal(path, journal); e != nil {
			return e
		}
		a.State.LearningAllowBundle = bundle
		a.learningOutcome(p, "applied", "")
		return a.save()
	}
	if e = a.managedSetPreflight(ctx, bundle.IPSets); e != nil {
		return blocked(e.Error())
	}
	if e = a.learningAllowHealth(ctx, p, protection); e != nil {
		return blocked("preflight management health: " + e.Error())
	}
	if e = saveManagedJournal(path, journal); e != nil {
		return e
	}
	if e = a.armManagedWatchdog(ctx, path, journal); e != nil {
		journal.Phase = "rolled_back"
		journal.Error = e.Error()
		_ = saveManagedJournal(path, journal)
		return blocked(e.Error())
	}
	fail := func(cause error) error {
		journal.Error = cause.Error()
		if len(journal.Mutations) > 0 || len(journal.SetMutations) > 0 {
			if a.State.LearningAllowFailures == nil {
				a.State.LearningAllowFailures = map[string]string{}
			}
			a.State.LearningAllowFailures[p.BindingDigest] = cause.Error()
			a.holdLearningSessions(p, cause.Error())
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		rollbackCtx = withManagedLease(rollbackCtx, lock)
		rollbackErr := rollbackManaged(rollbackCtx, a.Commands, path, journal)
		a.State.LearningAllowBundle = old
		status := "rolled_back"
		message := cause.Error()
		if rollbackErr != nil {
			status = "error"
			message += "; rollback incomplete: " + rollbackErr.Error()
		}
		a.learningOutcome(p, status, message)
		return a.save()
	}
	staged, _, e := a.learningRulePlan(p, protection.Zone, nonce, true)
	if e != nil {
		return fail(e)
	}
	journal.Phase = "staging"
	if e = saveManagedJournal(path, journal); e != nil {
		return fail(e)
	}
	for _, set := range bundle.IPSets {
		if e = a.managedSetMutation(ctx, path, journal, "runtime", set); e != nil {
			return fail(e)
		}
	}
	for _, rule := range staged {
		if e = a.managedMutation(ctx, path, journal, "runtime", rule, true); e != nil {
			return fail(e)
		}
	}
	if e = a.learningAllowHealth(ctx, p, protection); e != nil {
		return fail(fmt.Errorf("staged management health: %w", e))
	}
	journal.Phase = "committing"
	if e = saveManagedJournal(path, journal); e != nil {
		return fail(e)
	}
	for _, set := range bundle.IPSets {
		if e = a.managedSetMutation(ctx, path, journal, "permanent", set); e != nil {
			return fail(e)
		}
	}
	for _, rule := range bundle.Rules {
		if e = a.managedMutation(ctx, path, journal, "permanent", rule, true); e != nil {
			return fail(e)
		}
	}
	if old != nil {
		for _, rule := range old.Rules {
			if e = a.managedMutation(ctx, path, journal, "permanent", rule, false); e != nil {
				return fail(e)
			}
		}
	}
	for _, rule := range bundle.Rules {
		if e = a.managedMutation(ctx, path, journal, "runtime", rule, true); e != nil {
			return fail(e)
		}
	}
	if old != nil {
		for _, rule := range old.Rules {
			if e = a.managedMutation(ctx, path, journal, "runtime", rule, false); e != nil {
				return fail(e)
			}
		}
	}
	for _, rule := range staged {
		if e = a.managedMutation(ctx, path, journal, "runtime", rule, false); e != nil {
			return fail(e)
		}
	}
	for _, rule := range bundle.Rules {
		for _, scope := range []string{"runtime", "permanent"} {
			present, e := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
			if e != nil || !present {
				return fail(errors.New("learning overlay final read-back failed"))
			}
		}
	}
	if e = validateManagedCommittedSets(ctx, a.Commands, learningBundleRecord(bundle)); e != nil {
		return fail(e)
	}
	if e = a.learningAllowHealth(ctx, p, protection); e != nil {
		return fail(fmt.Errorf("final management health: %w", e))
	}
	if time.Until(journal.Deadline) < 5*time.Second {
		return fail(errors.New("learning rollback deadline approaching"))
	}
	journal.Phase = "committed"
	if e = saveManagedJournal(path, journal); e != nil {
		return fail(e)
	}
	a.State.LearningAllowBundle = bundle
	a.learningOutcome(p, "applied", "")
	if e = atomicJSON(filepath.Join(learningAllowDirectory(a.Config.StateDir), "committed.json"), journal.Next); e != nil {
		return e
	}
	return a.save()
}

func (a *Agent) holdLearningSessions(p *LearningAllow, reason string) {
	if a.State.LearningAllowFailedSessions == nil {
		a.State.LearningAllowFailedSessions = map[string]string{}
	}
	for _, authority := range p.Authorities {
		if authority.Kind == "auto" && authority.SessionID != "" && time.Now().Before(authority.ExpiresAt) {
			a.State.LearningAllowFailedSessions[authority.SessionID] = reason
		}
	}
}
