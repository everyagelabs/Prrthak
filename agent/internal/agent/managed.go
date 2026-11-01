package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (a *Agent) managedStatus(status string, p *Policy, message string) {
	result := &ManagedEnforcement{Status: status, UpdatedAt: time.Now().UTC(), Error: message}
	if p != nil {
		result.Version = p.Version
		result.Digest = p.Digest
		if p.Enforcement != nil {
			result.ApprovalID = p.Enforcement.ApprovalID
		}
	}
	a.State.ManagedEnforcement = result
}
func validateEnforcement(p *Policy, protection Protection, now time.Time) error {
	if p.Enforcement == nil || !p.Enforcement.Authorized {
		return errors.New("exact compiled policy requires explicit managed-enforcement approval")
	}
	auth := p.Enforcement
	minimum := 2 // Retained legacy independent assignments keep their old shape.
	if len(auth.ApprovalProof) > 0 {
		var proof endpointApprovalProof
		if json.Unmarshal(auth.ApprovalProof, &proof) == nil && proof.Mode == "single_admin" {
			if err := validateEndpointApproval(Config{}, auth.ApprovalProof, p.ServerID, now, false, "managed_policy", "managed_rollout"); err != nil {
				return err
			}
			minimum = 1
		}
	}
	if !changeIDValid(auth.ApprovalID) || auth.ConfirmationCount < minimum || !now.Before(auth.ExpiresAt) {
		return errors.New("managed approval is expired, unconfirmed or invalid")
	}
	digest, e := compiledPolicyDigest(p)
	if e != nil || digest != p.Digest {
		return errors.New("compiled policy digest does not match its actual source lists")
	}
	if auth.ApprovedDigest != p.Digest || auth.ApprovedVersion != p.Version || auth.ProtectionDigest != protection.Digest || auth.BindingDigest != enforcementBinding(p, protection.Digest) {
		return errors.New("approval no longer matches policy version, source digest or protected management configuration")
	}
	return nil
}
func (a *Agent) managedMutation(ctx context.Context, path string, journal *managedJournal, scope string, rule ManagedRule, after bool) error {
	if time.Until(journal.Deadline) < 10*time.Second {
		return errors.New("rollback deadline approaching; mutation refused")
	}
	if !managedOwned(rule.Rule) || !firewallName.MatchString(rule.Zone) {
		return errors.New("invalid owned managed rule")
	}
	before, e := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
	if e != nil {
		return e
	}
	if before == after {
		return nil
	}
	journal.Mutations = append(journal.Mutations, managedMutation{Scope: scope, Zone: rule.Zone, Rule: rule.Rule, Before: before, After: after})
	if e = saveManagedJournal(path, journal); e != nil {
		return e
	}
	operation := "remove"
	if after {
		operation = "add"
	}
	if e = firewallMutate(ctx, a.Commands, firewallMutation{Scope: scope, Zone: rule.Zone, Kind: "rich_rule", Value: rule.Rule, Operation: operation}); e != nil {
		return e
	}
	present, e := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
	if e != nil || present != after {
		return errors.New("managed rule read-back failed")
	}
	return nil
}
func (a *Agent) applyManaged(ctx context.Context, p *Policy, protection Protection) error {
	if !a.Config.Enforce || a.Simulate {
		if !a.Simulate && a.State.ManagedBundle != nil && len(a.State.ManagedBundle.Rules) > 0 {
			old := a.State.ManagedBundle
			a.State.ManagedEnforcement = &ManagedEnforcement{Status: "enforced", Version: old.Version, Digest: old.Digest, ApprovalID: old.ApprovalID, Error: "local enforcement disabled; committed restrictions remain until reviewed cleanup", UpdatedAt: time.Now().UTC()}
		} else {
			a.managedStatus("preview", p, "")
		}
		return nil
	}
	if p.Mode == "monitor" && a.State.ManagedBundle == nil {
		a.managedStatus("preview", p, "")
		return nil
	}
	if p.Enforcement != nil {
		if err := validateEndpointApproval(a.Config, p.Enforcement.ApprovalProof, p.ServerID, time.Now().UTC(), false, "managed_policy", "managed_rollout"); err != nil {
			a.managedStatus("error", p, err.Error())
			return err
		}
	}
	digest, digestErr := compiledPolicyDigest(p)
	if digestErr != nil || digest != p.Digest {
		e := errors.New("compiled policy digest does not match its actual source lists")
		a.managedStatus("error", p, e.Error())
		return e
	}
	lock, e := managedLock(a.Config.StateDir, true)
	if e != nil {
		a.managedStatus("error", p, "managed mutation lock busy")
		return e
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if e = a.recoverAllEnforcementLocked(ctx); e != nil {
		a.managedStatus("error", p, "pending managed rollback must complete before another generation: "+e.Error())
		return e
	}
	if a.State.ManagedBundle != nil && (p.Version < a.State.ManagedBundle.Version || p.Version == a.State.ManagedBundle.Version && p.Digest != a.State.ManagedBundle.Digest) {
		e := errors.New("managed policy replay rejected; rollback requires a new higher version")
		a.managedStatus("error", p, e.Error())
		return e
	}
	if a.State.ManagedBundle != nil && a.State.ManagedBundle.Digest == p.Digest && a.State.ManagedBundle.Version == p.Version && a.State.ManagedBundle.ProtectionDigest == protection.Digest {
		if e := a.managedPreflight(ctx, protection); e != nil {
			a.managedStatus("error", p, e.Error())
			return e
		}
		a.State.AppliedVersion = p.Version
		committed := a.State.ManagedBundle
		a.State.ManagedEnforcement = &ManagedEnforcement{Status: "enforced", Version: committed.Version, Digest: committed.Digest, ApprovalID: committed.ApprovalID, UpdatedAt: time.Now().UTC()}
		return nil
	}
	if e := validateEnforcement(p, protection, time.Now()); e != nil {
		a.managedStatus("pending_approval", p, e.Error())
		return nil
	}
	if failure, exists := a.State.ManagedFailures[p.Enforcement.ApprovalID]; exists {
		a.managedStatus("rolled_back", p, "")
		a.State.ManagedEnforcement.RollbackReason = "failed approval is held for administrative review: " + failure.Reason
		return nil
	}
	enforcedServices := 0
	for _, service := range p.Services {
		mode := service.Mode
		if mode == "" {
			mode = p.Mode
		}
		if mode == "enforce" {
			enforcedServices++
		}
	}
	if enforcedServices == 0 && p.Enforcement.Intent != "remove_managed_rules" {
		e := errors.New("removing managed rules requires explicit reviewed cleanup intent")
		a.managedStatus("pending_approval", p, e.Error())
		return e
	}
	if e = a.managedPreflight(ctx, protection); e != nil {
		a.managedStatus("error", p, e.Error())
		return e
	}
	raw := make([]byte, 16)
	if _, e = rand.Read(raw); e != nil {
		return e
	}
	nonce := hex.EncodeToString(raw)
	canonical, sets, e := a.managedRulePlan(p, protection, nonce, false)
	if e != nil {
		a.managedStatus("error", p, e.Error())
		return e
	}
	staged, _, e := a.managedRulePlan(p, protection, nonce, true)
	if e != nil {
		return e
	}
	if e = a.managedSetPreflight(ctx, sets); e != nil {
		a.managedStatus("error", p, e.Error())
		return e
	}
	// Detect an agent controlling its own controller's inbound port. The first
	// version refuses this topology rather than treating outbound health as proof.
	if a.controllerIngressTargeted(p) {
		e = errors.New("policy targets a local controller ingress port; unsupported self-controller topology")
		a.managedStatus("error", p, e.Error())
		return e
	}
	if e = a.managedHealth(ctx, p, protection, nonce); e != nil {
		a.managedStatus("error", p, "preflight management health: "+e.Error())
		return e
	}
	_, topology, e := a.managedTopology(ctx)
	if e != nil {
		return e
	}
	journal := &managedJournal{Nonce: nonce, Phase: "armed", Deadline: time.Now().Add(120 * time.Second), DeadlineBootSeconds: bootElapsedSeconds() + 120, PID: os.Getpid(), ProcessIdentity: processIdentity(os.Getpid()), Previous: a.State.ManagedBundle, Next: ManagedBundle{TopologyDigest: topology, Generation: nonce, ProtectionDigest: protection.Digest, Version: p.Version, Digest: p.Digest, ApprovalID: p.Enforcement.ApprovalID, Rules: canonical, IPSets: sets}, Mutations: []managedMutation{}}
	path := managedJournalPath(a.Config.StateDir, nonce)
	if e = saveManagedJournal(path, journal); e != nil {
		return e
	}
	if e = a.armManagedWatchdog(ctx, path, journal); e != nil {
		journal.Phase = "rolled_back"
		journal.Error = e.Error()
		_ = saveManagedJournal(path, journal)
		a.managedStatus("error", p, e.Error())
		return e
	}
	fail := func(cause error) error {
		journal.Error = cause.Error()
		if len(journal.Mutations) > 0 || len(journal.SetMutations) > 0 {
			a.latchManagedFailure(journal)
		}
		// Cancellation must not cancel compensation; the independent timer remains
		// armed until the journal has a durable terminal state.
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		rollbackCtx = withManagedLease(rollbackCtx, lock)
		rollbackError := rollbackManaged(rollbackCtx, a.Commands, path, journal)
		a.State.ManagedBundle = journal.Previous
		if journal.Previous != nil {
			a.State.AppliedVersion = journal.Previous.Version
		} else {
			a.State.AppliedVersion = 0
		}
		if rollbackError != nil {
			a.managedStatus("error", p, cause.Error()+"; automatic rollback incomplete: "+rollbackError.Error())
		} else {
			a.managedStatus("rolled_back", p, "")
			a.State.ManagedEnforcement.RollbackReason = cause.Error()
		}
		_ = a.save()
		return cause
	}
	a.managedStatus("staging", p, "")
	journal.Phase = "staging"
	if e = saveManagedJournal(path, journal); e != nil {
		return fail(e)
	}
	for _, set := range sets {
		if e = a.managedSetMutation(ctx, path, journal, "runtime", set); e != nil {
			return fail(e)
		}
	}
	for _, rule := range staged {
		if e = a.managedMutation(ctx, path, journal, "runtime", rule, true); e != nil {
			return fail(e)
		}
	}
	if p.Enforcement.Intent == "remove_managed_rules" && len(canonical) == 0 && journal.Previous != nil {
		for _, rule := range journal.Previous.Rules {
			if e = a.managedMutation(ctx, path, journal, "runtime", rule, false); e != nil {
				return fail(e)
			}
		}
	}
	a.managedStatus("runtime_healthchecking", p, "")
	if e = a.managedHealth(ctx, p, protection, nonce); e != nil {
		return fail(fmt.Errorf("staged management health: %w", e))
	}
	a.managedStatus("committing", p, "")
	journal.Phase = "committing"
	if e = saveManagedJournal(path, journal); e != nil {
		return fail(e)
	}
	for _, set := range sets {
		if e = a.managedSetMutation(ctx, path, journal, "permanent", set); e != nil {
			return fail(e)
		}
	}
	for _, rule := range canonical {
		if e = a.managedMutation(ctx, path, journal, "permanent", rule, true); e != nil {
			return fail(e)
		}
	}
	if journal.Previous != nil {
		for _, rule := range journal.Previous.Rules {
			if e = a.managedMutation(ctx, path, journal, "permanent", rule, false); e != nil {
				return fail(e)
			}
		}
	}
	for _, rule := range canonical {
		if e = a.managedMutation(ctx, path, journal, "runtime", rule, true); e != nil {
			return fail(e)
		}
	}
	if journal.Previous != nil {
		for _, rule := range journal.Previous.Rules {
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
	for _, rule := range canonical {
		for _, scope := range []string{"runtime", "permanent"} {
			present, e := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
			if e != nil || !present {
				return fail(errors.New("final managed-bundle read-back failed"))
			}
		}
	}
	if e = validateManagedCommittedSets(ctx, a.Commands, &journal.Next); e != nil {
		return fail(e)
	}
	if e = a.managedHealth(ctx, p, protection, nonce); e != nil {
		return fail(fmt.Errorf("final management health: %w", e))
	}
	if time.Now().After(journal.Deadline.Add(-5 * time.Second)) {
		return fail(errors.New("health completed too near rollback deadline"))
	}
	journal.Phase = "committed"
	if e = saveManagedJournal(path, journal); e != nil {
		return fail(e)
	}
	// The committed journal is authoritative if the following cache writes fail.
	a.State.ManagedBundle = &journal.Next
	a.State.AppliedVersion = p.Version
	a.managedStatus("enforced", p, "")
	if e = atomicJSON(filepath.Join(managedDirectory(a.Config.StateDir), "committed.json"), journal.Next); e != nil {
		return e
	}
	return a.save()
}
func (a *Agent) processManaged(ctx context.Context, p *Policy) error {
	protection := Protection{}
	if a.protection != nil {
		protection = *a.protection
	}
	needsApply := p != nil && (a.State.ManagedBundle == nil || a.State.ManagedBundle.Version != p.Version || a.State.ManagedBundle.Digest != p.Digest || a.State.ManagedBundle.ProtectionDigest != protection.Digest)
	if a.Config.Enforce && needsApply && p.Enforcement != nil && p.Enforcement.Authorized {
		protection, _ = a.managedProtection(ctx)
	}
	a.protection = &protection
	if p == nil {
		return nil
	}
	err := a.applyManaged(ctx, p, protection)
	if a.State.ManagedEnforcement != nil {
		a.applyError = a.State.ManagedEnforcement.Error
		if a.State.ManagedEnforcement.RollbackReason != "" {
			a.applyError = a.State.ManagedEnforcement.RollbackReason
		}
	}
	if saveErr := a.save(); saveErr != nil {
		return saveErr
	}
	return err
}
func (a *Agent) controllerIngressTargeted(p *Policy) bool {
	// Implemented in managed_topology.go to keep controller DNS checks bounded.
	for _, origin := range []string{a.Config.ControllerURL, a.Config.ControlURL, a.Config.DiscoveryURL} {
		if origin != "" && controllerIngressTargeted(origin, p) {
			return true
		}
	}
	return false
}

func managedApplyStatus(status string) string {
	switch status {
	case "enforced":
		return "synced"
	case "pending_approval":
		return "pending"
	case "staging", "runtime_healthchecking", "committing":
		return "applying"
	case "rolled_back", "error", "preview":
		return status
	}
	return "error"
}

func (a *Agent) latchManagedFailure(journal *managedJournal) {
	if a.State.ManagedFailures == nil {
		a.State.ManagedFailures = map[string]ManagedFailure{}
	}
	a.State.ManagedFailures[journal.Next.ApprovalID] = ManagedFailure{Version: journal.Next.Version, Digest: journal.Next.Digest, ApprovalID: journal.Next.ApprovalID, Reason: journal.Error}
}

func (a *Agent) enrichManagedStatus() {
	if a.State.ManagedEnforcement == nil {
		return
	}
	a.State.ManagedEnforcement.LastGoodVersion = 0
	a.State.ManagedEnforcement.LastGoodDigest = ""
	if a.State.ManagedBundle != nil {
		a.State.ManagedEnforcement.LastGoodVersion = a.State.ManagedBundle.Version
		a.State.ManagedEnforcement.LastGoodDigest = a.State.ManagedBundle.Digest
	}
}
