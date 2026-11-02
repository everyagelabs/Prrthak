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
	"strings"
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
			kinds := []string{"managed_policy", "managed_rollout"}
			if p.HostDefaultDeny || auth.Intent == "remove_host_default_deny" {
				kinds = []string{"host_default_deny"}
			}
			if err := validateEndpointApproval(Config{}, auth.ApprovalProof, p.ServerID, now, false, kinds...); err != nil {
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
	a.invalidatePolicyVerificationAccess()
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
	a.managedOptOutRemovalAttested = false
	removal := !p.HostDefaultDeny && p.Enforcement != nil && p.Enforcement.Intent == "remove_host_default_deny"
	cleanup := p.Enforcement != nil && p.Enforcement.Intent == "remove_managed_rules" && a.State.ManagedBundle != nil && len(a.State.ManagedBundle.Rules) > 0
	if !a.Config.Enforce && !removal || a.Simulate {
		if !a.Simulate && a.State.ManagedBundle != nil && len(a.State.ManagedBundle.Rules) > 0 {
			return a.observeOptedOutManaged(ctx, p, protection)
		} else {
			a.managedStatus("preview", p, "")
		}
		return nil
	}
	if p.Mode == "monitor" && a.State.ManagedBundle == nil && !removal {
		a.managedStatus("preview", p, "")
		return nil
	}
	if p.Enforcement != nil {
		kinds := []string{"managed_policy", "managed_rollout"}
		if p.HostDefaultDeny || removal {
			kinds = []string{"host_default_deny"}
		}
		if err := validateEndpointApproval(a.Config, p.Enforcement.ApprovalProof, p.ServerID, time.Now().UTC(), false, kinds...); err != nil {
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
		a.managedStatus("error", p, "managed mutation authority unavailable: "+e.Error())
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
	if !removal && !cleanup && a.State.ManagedBundle != nil && a.State.ManagedBundle.Digest == p.Digest && a.State.ManagedBundle.Version == p.Version && a.State.ManagedBundle.ProtectionDigest == protection.Digest {
		if e := a.managedPreflight(ctx, protection, p.HostDefaultDeny); e != nil {
			a.managedStatus("error", p, e.Error())
			if p.HostDefaultDeny {
				a.refreshHostDefaultDenyProtection(ctx)
			}
			return e
		}
		if p.HostDefaultDeny {
			digest, blockers := a.hostDefaultDenyContext(ctx, protection)
			if len(blockers) != 0 || digest != protection.HostDefaultDenyContextDigest {
				e := errors.New("committed whole-server firewall context drift detected")
				a.refreshHostDefaultDenyProtection(ctx)
				a.managedStatus("error", p, e.Error())
				return e
			}
		}
		a.State.AppliedVersion = p.Version
		committed := a.State.ManagedBundle
		approvalID := committed.ApprovalID
		if p.Enforcement != nil && p.Enforcement.ApprovalID != committed.ApprovalID && validateEnforcement(p, protection, time.Now().UTC()) == nil {
			// An exact already-installed bundle can satisfy a new valid rollout
			// authority through fresh readback; its historical commit is unchanged.
			approvalID = p.Enforcement.ApprovalID
		}
		a.State.ManagedEnforcement = &ManagedEnforcement{AlreadyPresent: true, Status: "enforced", Version: committed.Version, Digest: committed.Digest, ApprovalID: approvalID, UpdatedAt: time.Now().UTC()}
		return nil
	}
	if e = checkNewEnforcementJournalBudget(a.Config.StateDir, "managed"); e != nil {
		a.managedStatus("error", p, e.Error())
		return e
	}
	// A generic reconciliation/cleanup can neither add nor remove whole-host
	// authority. A fresh explicit acknowledgement is needed for every new bundle.
	if p.HostDefaultDeny || removal || a.State.ManagedBundle != nil && a.State.ManagedBundle.HostDefaultDeny {
		if e := a.validateHostDefaultDeny(p, protection, removal); e != nil {
			a.managedStatus("pending_approval", p, e.Error())
			return e
		}
		contextDigest, blockers := a.hostDefaultDenyContext(ctx, protection)
		if len(blockers) != 0 || contextDigest != protection.HostDefaultDenyContextDigest {
			e := errors.New("whole-server firewall context changed or is unsupported: " + strings.Join(blockers, "; "))
			a.managedStatus("error", p, e.Error())
			a.refreshHostDefaultDenyProtection(ctx)
			return e
		}
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
	if enforcedServices == 0 && !p.HostDefaultDeny && !removal && p.Enforcement.Intent != "remove_managed_rules" {
		e := errors.New("removing managed rules requires explicit reviewed cleanup intent")
		a.managedStatus("pending_approval", p, e.Error())
		return e
	}
	if e = clearTrafficCaptureSidecars(ctx, a.Config.StateDir, a.Commands); e != nil {
		a.managedStatus("error", p, e.Error())
		return e
	}
	a.nextCaptureCheck = time.Time{}
	if e = a.managedPreflight(ctx, protection, p.HostDefaultDeny || removal); e != nil {
		a.managedStatus("error", p, e.Error())
		if p.HostDefaultDeny || removal {
			a.refreshHostDefaultDenyProtection(ctx)
		}
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
	if removal {
		old := a.State.ManagedBundle
		canonical, staged, sets = []ManagedRule{}, nil, nil
		if old == nil {
			if len(p.Services) != 0 {
				return errors.New("unapplied whole-server cancellation requires an empty retained policy")
			}
		} else {
			if old.HostDefaultDeny {
				frozen := &Policy{Version: p.Version, Mode: old.HostDefaultDenyMode, Digest: "frozen", Services: old.HostDefaultDenyServices}
				if len(frozen.Services) == 0 && len(p.Services) == 0 {
					frozen.Mode = p.Mode
				}
				expected, err := compiledPolicyDigest(frozen)
				if err != nil || expected != p.Digest {
					return errors.New("whole-server removal must retain the last applied approved source/port matrix")
				}
			} else if old.Digest != p.Digest {
				return errors.New("whole-server cancellation must retain the existing managed matrix")
			}
			sets = append([]ManagedIPSet{}, old.IPSets...)
			for _, rule := range old.Rules {
				if !hostDefaultDenyFallback(rule) {
					canonical = append(canonical, rule)
				}
			}
		}
	}
	if !removal {
		e = a.managedSetPreflight(ctx, sets)
	}
	if e != nil {
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
	journal.Next.HostDefaultDeny = p.HostDefaultDeny
	if p.HostDefaultDeny {
		journal.Next.HostDefaultDenyServices = append([]Service{}, p.Services...)
		journal.Next.HostDefaultDenyMode = p.Mode
	}
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
		if p.HostDefaultDeny || removal {
			a.refreshHostDefaultDenyProtection(rollbackCtx)
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
	if removal && journal.Previous != nil {
		for _, rule := range journal.Previous.Rules {
			if hostDefaultDenyFallback(rule) {
				if e = a.managedMutation(ctx, path, journal, "runtime", rule, false); e != nil {
					return fail(e)
				}
			}
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
	if p.HostDefaultDeny || removal {
		fresh, blockers := a.hostDefaultDenyContext(ctx, protection, staged, canonical)
		if len(blockers) != 0 || fresh != protection.HostDefaultDenyContextDigest {
			return fail(errors.New("whole-server context changed while staging"))
		}
	}
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
			if managedRulesContain(canonical, rule) {
				continue
			}
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
			if managedRulesContain(canonical, rule) {
				continue
			}
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
	if p.HostDefaultDeny || removal {
		fresh, blockers := a.hostDefaultDenyContext(ctx, protection, canonical)
		if len(blockers) != 0 || fresh != protection.HostDefaultDenyContextDigest {
			return fail(errors.New("whole-server context changed before final commit"))
		}
	}
	if e = a.managedHealth(ctx, p, protection, nonce); e != nil {
		return fail(fmt.Errorf("final management health: %w", e))
	}
	if removal {
		if e = a.verifyHostDefaultDenyRemoved(ctx); e != nil {
			return fail(e)
		}
	}
	if time.Now().After(journal.Deadline.Add(-5 * time.Second)) {
		return fail(errors.New("health completed too near rollback deadline"))
	}
	committedAt := time.Now().UTC()
	journal.Next.CommittedAt = &committedAt
	journal.Phase = "committed"
	if e = saveManagedJournal(path, journal); e != nil {
		return fail(e)
	}
	// The committed journal is authoritative if the following cache writes fail.
	a.State.ManagedBundle = &journal.Next
	a.State.AppliedVersion = p.Version
	a.managedStatus("enforced", p, "")
	// Explicit reviewed removal is allowed after a local opt-out. Its actual
	// final readback remains a current outcome for this process; cached startup
	// state never inherits this attestation.
	a.managedOptOutRemovalAttested = removal && !a.Config.Enforce
	if e = atomicJSON(filepath.Join(managedDirectory(a.Config.StateDir), "committed.json"), journal.Next); e != nil {
		return e
	}
	return a.save()
}

const managedOptOutMessage = "local enforcement is disabled; last-good policy is historical and restrictions require readback or reviewed cleanup"

// Opting out does not remove existing restrictions. It also cannot attest a
// fresh apply from the cache. Continue read-only drift detection under the same
// lease as every access mutation, without recovering or repairing the firewall.
func (a *Agent) observeOptedOutManaged(ctx context.Context, p *Policy, protection Protection) error {
	a.managedOptOutRulesPresent = nil
	a.managedStatus("error", p, managedOptOutMessage)
	fail := func(err error) error {
		a.State.ManagedEnforcement.Error = managedOptOutMessage + "; read-only drift check failed: " + err.Error()
		return err
	}
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return fail(err)
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if configurationMutationBlocked(a.Config) {
		return fail(errors.New("endpoint configuration recovery is unfinished"))
	}
	if err = checkEnforcementJournals(a.Config); err != nil {
		return fail(err)
	}
	if err = a.managedPreflight(ctx, protection, a.State.ManagedBundle.HostDefaultDeny); err != nil {
		return fail(err)
	}
	present := true
	a.managedOptOutRulesPresent = &present
	a.State.ManagedEnforcement.Error = "local enforcement is disabled; last-good restrictions are present by read-only inspection; no policy was applied"
	return nil
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
	result := a.State.ManagedEnforcement
	result.LastGoodVersion = 0
	a.State.ManagedEnforcement.LastGoodDigest = ""
	a.State.ManagedEnforcement.Generation = ""
	a.State.ManagedEnforcement.CommittedAt = nil
	a.State.ManagedEnforcement.VerificationID = ""
	a.State.ManagedEnforcement.VerificationReadbackAt = nil
	if a.State.ManagedBundle != nil {
		a.State.ManagedEnforcement.LastGoodVersion = a.State.ManagedBundle.Version
		a.State.ManagedEnforcement.LastGoodDigest = a.State.ManagedBundle.Digest
		if result.Status == "enforced" {
			a.State.ManagedEnforcement.Generation = a.State.ManagedBundle.Generation
			a.State.ManagedEnforcement.CommittedAt = a.State.ManagedBundle.CommittedAt
		}
		if verification := a.State.PolicyVerification; result.Status == "enforced" && verification != nil && verification.ReadbackAt != nil && verification.Report.AppliedGeneration == a.State.ManagedBundle.Generation && verification.Assignment.Version == a.State.ManagedBundle.Version && verification.Assignment.Digest == a.State.ManagedBundle.Digest && verification.Assignment.ApprovalID == a.State.ManagedEnforcement.ApprovalID {
			a.State.ManagedEnforcement.VerificationID = verification.Assignment.ID
			a.State.ManagedEnforcement.VerificationReadbackAt = verification.ReadbackAt
		}
	}
	a.State.ManagedEnforcement.HostDefaultDenyActive = a.State.ManagedBundle != nil && a.State.ManagedBundle.HostDefaultDeny
	present := a.State.ManagedBundle != nil && len(a.State.ManagedBundle.Rules) > 0
	a.State.ManagedEnforcement.ManagedRulesPresent = &present
	if !a.Config.Enforce && present && !a.Simulate && !a.managedOptOutRemovalAttested {
		// This also normalizes startup/cache receipts before the first sync.
		// A current generation/readback witness must never be reconstructed
		// from the last-good bundle while local application is disabled.
		if result.Status == "enforced" {
			result.Status = "error"
			result.Error = managedOptOutMessage
		}
		result.AlreadyPresent = false
		result.Generation = ""
		result.CommittedAt = nil
		result.VerificationID = ""
		result.VerificationReadbackAt = nil
		result.ManagedRulesPresent = a.managedOptOutRulesPresent
		if result.ManagedRulesPresent == nil {
			// On status=error this bool is not an absence proof; controllers
			// retain the last known whole-host ownership conservatively.
			result.HostDefaultDenyActive = false
		}
	}
}
