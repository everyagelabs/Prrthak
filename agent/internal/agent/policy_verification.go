package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"time"
)

func (a *Agent) verificationTimestampAvailable() bool {
	if a.policyVerificationTimestampAvailable != nil {
		return a.policyVerificationTimestampAvailable()
	}
	raw, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_timestamp")
	return err == nil && strings.TrimSpace(string(raw)) == "1"
}

func verificationLeaseLive(state *policyVerificationState, now time.Time) bool {
	return state != nil && state.Confirmed && state.Report.State == "observing" && state.Report.ArmedAt != nil && now.Before(state.Assignment.ExpiresAt) && !state.Deadline.IsZero() && time.Now().Before(state.Deadline)
}

func boundedVerificationReason(reason string) string {
	if len(reason) > 1024 {
		return "Native verification prerequisites could not be proved. The applied policy is unchanged; inspect endpoint diagnostics."
	}
	return reason
}

func verificationReceipt(item PolicyVerificationAssignment, at time.Time) PolicyVerificationReport {
	result := PolicyVerificationReport{SchemaVersion: item.SchemaVersion, ID: item.ID, DeploymentID: item.DeploymentID, ServerID: item.ServerID, Version: item.Version, Digest: item.Digest, ApprovalID: item.ApprovalID, ProtectionDigest: item.ProtectionDigest, TargetIPsDigest: item.TargetIPsDigest, StartsAt: item.StartsAt, ExpiresAt: item.ExpiresAt, WindowSeconds: item.WindowSeconds, Sequence: 1, State: "waiting_apply", CheckedAt: at, Ports: []PolicyVerificationPort{}}
	for _, port := range item.Ports {
		result.Ports = append(result.Ports, PolicyVerificationPort{Port: port.Port, Protocol: port.Protocol, Allow: PolicyVerificationCase{Status: "awaiting", Reason: "Waiting for exact applied policy readback."}, Deny: PolicyVerificationCase{Status: "awaiting", Reason: "Waiting for exact applied policy readback."}})
	}
	return result
}

func (a *Agent) invalidatePolicyVerification(reason string) {
	state := a.State.PolicyVerification
	if state == nil || state.Report.State == "superseded" {
		return
	}
	state.Confirmed = false
	state.Report.State = "superseded"
	state.Report.Error = reason
	state.Report.CheckedAt = a.currentTime()
	state.Report.Sequence++
	a.nextCaptureCheck = time.Time{}
}

func (a *Agent) invalidatePolicyVerificationAccess() {
	if state := a.State.PolicyVerification; state != nil && state.Report.ArmedAt != nil {
		a.invalidatePolicyVerification("An access transaction started; prior traffic evidence is historical.")
	}
}

func (a *Agent) verificationContextMatches() bool {
	v, p, b := a.State.PolicyVerification, a.State.Policy, a.State.ManagedBundle
	return v != nil && v.Confirmed && p != nil && p.PolicyVerification != nil && p.PolicyVerification.ID == v.Assignment.ID && p.Version == v.Assignment.Version && p.Digest == v.Assignment.Digest && b != nil && b.Generation == v.Report.AppliedGeneration && b.Version == v.Assignment.Version && b.Digest == v.Assignment.Digest && b.ProtectionDigest == v.Assignment.ProtectionDigest && a.inventory != nil && targetIPsDigest(a.inventory.IPs) == v.Assignment.TargetIPsDigest && a.protection != nil && a.protection.Digest == v.Assignment.ProtectionDigest && (a.State.LearningAllowBundle == nil || len(a.State.LearningAllowBundle.Rules) == 0) && a.State.ManagedEnforcement != nil && a.State.ManagedEnforcement.Status == "enforced"
}

// Arm only after all access transactions in this sync have finished. Failure
// here is a diagnostic outcome and never changes or rolls back access policy.
func (a *Agent) preparePolicyVerification(ctx context.Context, p *Policy) error {
	if p == nil || p.PolicyVerification == nil {
		if state := a.State.PolicyVerification; state != nil && p != nil && (state.Report.State == "verified" || state.Report.State == "expired" || state.Report.State == "unavailable") && p.Version == state.Assignment.Version && p.Digest == state.Assignment.Digest && a.inventory != nil && targetIPsDigest(a.inventory.IPs) == state.Assignment.TargetIPsDigest && a.protection != nil && a.protection.Digest == state.Assignment.ProtectionDigest {
			// Completed leases are normally withdrawn by the controller. Retain
			// their historical result without retaining any collection authority.
			return nil
		}
		a.invalidatePolicyVerification("The signed observation lease was removed or superseded.")
		return nil
	}
	item := p.PolicyVerification
	if prior := a.State.PolicyVerification; prior != nil && prior.Assignment.ID == item.ID && !a.currentTime().Before(prior.Assignment.ExpiresAt) {
		if a.updatePolicyVerification(a.currentTime(), nil) {
			return a.save()
		}
		return nil
	}
	if err := a.validatePolicyVerification(p, item, a.currentTime()); err != nil {
		a.invalidatePolicyVerification("The exact observation lease is invalid or expired.")
		return err
	}
	state := a.State.PolicyVerification
	if state != nil && state.Assignment.ID == item.ID {
		old, _ := json.Marshal(state.Assignment)
		current, _ := json.Marshal(item)
		if string(old) != string(current) {
			a.invalidatePolicyVerification("Observation ID was reused with changed bindings.")
			return errors.New("policy verification lease identity reused")
		}
		if state.Report.State == "superseded" {
			return nil
		}
		if !state.Confirmed && state.Report.ArmedAt != nil {
			a.invalidatePolicyVerification("The observer process restarted; request a fresh verification lease.")
			return a.save()
		}
		if state.Confirmed && a.verificationContextMatches() {
			return nil
		}
	} else {
		state = &policyVerificationState{Assignment: *item, Report: verificationReceipt(*item, a.currentTime())}
		a.State.PolicyVerification = state
	}
	if a.currentTime().Before(item.StartsAt) {
		return a.save()
	}
	bundle := a.State.ManagedBundle
	if bundle == nil || bundle.Version != item.Version || bundle.Digest != item.Digest || bundle.ProtectionDigest != item.ProtectionDigest || a.State.ManagedEnforcement == nil || a.State.ManagedEnforcement.Status != "enforced" {
		state.Report.State = "waiting_apply"
		state.Report.CheckedAt = a.currentTime()
		state.Report.Sequence++
		return a.save()
	}
	frozenIPs := append([]string{}, a.inventory.IPs...)
	expectedProtection := a.protection
	protection := a.sourceBankProtection(ctx) // Fresh native discovery, addresses and local protection pins.
	caseProtection := protection
	if expectedProtection != nil && expectedProtection.Digest == item.ProtectionDigest {
		caseProtection = *expectedProtection
	}
	rows, sources := verificationCases(p, caseProtection, item.Ports, frozenIPs)
	state.Report.Ports = rows
	state.Matchers = verificationBuildMatchers(sources)
	unavailable := func(reason string) error {
		reason = boundedVerificationReason(reason)
		state.Confirmed = false
		state.Report.State = "unavailable"
		state.Report.Error = reason
		state.Report.CheckedAt = a.currentTime()
		state.Report.Sequence++
		for i := range state.Report.Ports {
			for _, test := range []*PolicyVerificationCase{&state.Report.Ports[i].Allow, &state.Report.Ports[i].Deny} {
				if test.Status == "awaiting" {
					test.Status, test.Reason = "unavailable", reason
				}
			}
		}
		return a.save()
	}
	if a.Simulate || configurationMutationBlocked(a.Config) || !protection.Ready || protection.Digest != item.ProtectionDigest || targetIPsDigest(a.inventory.IPs) != item.TargetIPsDigest {
		return unavailable("Fresh native policy protection and endpoint identity are unavailable or changed.")
	}
	if a.State.LearningAllowBundle != nil && len(a.State.LearningAllowBundle.Rules) > 0 {
		return unavailable("Additive learned grants prevent attribution to this managed policy alone.")
	}
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return unavailable("Another firewall transaction is active; no observation scope was armed.")
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if err := a.managedPreflight(ctx, protection, bundle.HostDefaultDeny); err != nil {
		return unavailable("Fresh policy readback failed: " + boundedSourceBankError(err))
	}
	if err := a.managedHealth(ctx, p, protection, bundle.Generation); err != nil {
		return unavailable("Fresh management health failed: " + boundedSourceBankError(err))
	}
	// This attests actual post-publication readback under the current authority,
	// including the already-installed path; it does not invent a fresh commit.
	alreadyPresent := a.State.ManagedEnforcement.AlreadyPresent
	a.managedStatus("enforced", p, "")
	a.State.ManagedEnforcement.AlreadyPresent = alreadyPresent
	a.enrichManagedStatus()
	readbackAt := a.State.ManagedEnforcement.UpdatedAt
	state.ReadbackAt = &readbackAt
	// A new observer epoch fences pre-arm NFLOG queues, including process restart.
	state.ArmEpoch = shaText("prthak-policy-verification-arm-v1\x00" + item.ID + "\x00" + bundle.Generation + "\x00" + batchID())
	armed := a.currentTime()
	if !armed.Before(item.ExpiresAt) {
		a.updatePolicyVerification(armed, nil)
		return a.save()
	}
	if armed.Before(item.StartsAt) {
		return unavailable("Clock changed during readback; no native observation scope was armed.")
	}
	remaining := min(item.ExpiresAt.Sub(armed), 10*time.Minute)
	state.Deadline = time.Now().Add(remaining)
	state.Report.ArmedAt = &armed
	state.Report.CommittedAt = bundle.CommittedAt // Never invent legacy commit time.
	state.Report.AppliedGeneration = bundle.Generation
	state.Report.State = "observing"
	state.Report.Error = ""
	state.Report.CheckedAt = armed
	state.Report.Sequence++
	state.Confirmed = true
	a.protection = &protection
	a.nextCaptureCheck = time.Time{}
	if !a.verificationTimestampAvailable() {
		for i := range state.Report.Ports {
			if state.Report.Ports[i].Allow.Status == "awaiting" {
				state.Report.Ports[i].Allow = PolicyVerificationCase{Status: "unavailable", Reason: "Kernel conntrack birth timestamps are unavailable; observer time cannot prove a post-arm connection. No sysctl was changed."}
			}
		}
	}
	a.updatePolicyVerification(a.currentTime(), nil)
	return a.save()
}

func (a *Agent) policyVerificationScopes(now time.Time) []capturePortScope {
	state := a.State.PolicyVerification
	if !verificationLeaseLive(state, now) || !a.verificationContextMatches() {
		return nil
	}
	result := []capturePortScope{}
	for _, row := range state.Report.Ports {
		for _, test := range []struct{ status, kind string }{{row.Allow.Status, captureAccepted}, {row.Deny.Status, captureDenied}} {
			if test.status == "awaiting" {
				port := Port{row.Port, row.Protocol}
				result = append(result, capturePortScope{Port: port, Kind: test.kind, StartsAt: *state.Report.ArmedAt, ExpiresAt: state.Assignment.ExpiresAt, Deadline: state.Deadline, RequireBirth: test.kind == captureAccepted, BusinessSources: state.Matchers["business/"+capturePortKey(port)]})
			}
		}
	}
	return result
}

func (a *Agent) policyVerificationPrefix(port Port, family string) string {
	state := a.State.PolicyVerification
	if !verificationLeaseLive(state, a.currentTime()) {
		return ""
	}
	for _, row := range state.Report.Ports {
		if row.Port == port.Port && row.Protocol == port.Protocol && row.Deny.Status == "awaiting" {
			return verificationDeniedPrefix(state.Assignment.ID, state.Report.AppliedGeneration, state.ArmEpoch, port.Protocol, port.Port, family)
		}
	}
	return ""
}

func (a *Agent) observePolicyVerification(flows []capturedFlow) bool {
	state := a.State.PolicyVerification
	if !verificationLeaseLive(state, a.currentTime()) || !a.verificationContextMatches() {
		return false
	}
	changed := false
	locals := map[netip.Addr]bool{}
	for _, value := range a.inventory.IPs {
		if address, err := netip.ParseAddr(value); err == nil {
			locals[address] = true
		}
	}
	for _, flow := range flows {
		source, sourceErr := netip.ParseAddr(flow.SourceIP)
		target, targetErr := netip.ParseAddr(flow.DestinationIP)
		if sourceErr != nil || targetErr != nil || source.IsLoopback() || source.IsUnspecified() || source.Is4In6() || locals[source] || !locals[target] || source.Is4() != target.Is4() || !validTypedCapture(flow.Flow, flow.EventID) || flow.CaptureEpoch == "" || flow.ReceivedAt.IsZero() || flow.ReceivedAt.Before(*state.Report.ArmedAt) || !flow.ReceivedAt.Before(state.Assignment.ExpiresAt) || flow.FirstSeen.Before(*state.Report.ArmedAt) || !flow.FirstSeen.Before(state.Assignment.ExpiresAt) || flow.FirstSeen.After(flow.ReceivedAt) {
			continue
		}
		for i := range state.Report.Ports {
			row := &state.Report.Ports[i]
			if flow.Port != row.Port || flow.Protocol != row.Protocol {
				continue
			}
			port := Port{row.Port, row.Protocol}
			key := capturePortKey(port)
			if state.Matchers[key] == nil || state.Matchers["business/"+key] == nil {
				continue // Missing private scope cannot prove a source complement.
			}
			var test *PolicyVerificationCase
			if flow.CaptureKind == captureAccepted && row.Allow.Status == "awaiting" && state.Matchers["business/"+key].contains(source) && flow.ConnectionStartedAt.After(*state.Report.ArmedAt) && !flow.ConnectionStartedAt.After(flow.FirstSeen) {
				test = &row.Allow
			} else if flow.CaptureKind == captureDenied && row.Deny.Status == "awaiting" && !state.Matchers[key].contains(source) && flow.RulePrefix == a.policyVerificationPrefix(port, flow.AddressFamily) {
				test = &row.Deny
			}
			if test == nil {
				continue
			}
			evidence := &PolicyVerificationEvidence{EventID: flow.EventID, SourceIP: flow.SourceIP, DestinationIP: flow.DestinationIP, Port: flow.Port, Protocol: flow.Protocol, AddressFamily: flow.AddressFamily, CaptureKind: flow.CaptureKind, CaptureBackend: flow.CaptureBackend, CountUnit: flow.CountUnit, ExpectedAction: flow.Verdict, ObservedAt: flow.FirstSeen, ReceivedAt: flow.ReceivedAt, CaptureEpoch: state.ArmEpoch}
			if flow.CaptureKind == captureAccepted {
				born := flow.ConnectionStartedAt
				evidence.ConnectionStartedAt = &born
			} else {
				evidence.RulePrefix = flow.RulePrefix
			}
			test.Status, test.Reason, test.Evidence = "verified", "One matching native observation after arm; this is sampled evidence, not complete coverage or application health.", evidence
			changed = true
		}
	}
	if changed {
		state.Report.Sequence++
		state.Report.CheckedAt = a.currentTime()
		a.nextCaptureCheck = time.Time{}
	}
	return changed
}

func (a *Agent) updatePolicyVerification(now time.Time, coverage *TrafficCaptureCoverage) bool {
	state := a.State.PolicyVerification
	if state == nil || state.Report.State != "observing" && state.Report.State != "waiting_apply" {
		return false
	}
	if !now.Before(state.Assignment.ExpiresAt) || !state.Deadline.IsZero() && !time.Now().Before(state.Deadline) {
		for i := range state.Report.Ports {
			for _, test := range []*PolicyVerificationCase{&state.Report.Ports[i].Allow, &state.Report.Ports[i].Deny} {
				if test.Status == "awaiting" {
					test.Status, test.Reason = "unverified", "Observation window ended without a qualifying sample; access policy remains unchanged."
				}
			}
		}
		state.Report.State, state.Report.CheckedAt = "expired", now
		state.Report.Sequence++
		state.Confirmed = false
		a.nextCaptureCheck = time.Time{}
		return true
	}
	if state.Report.State == "waiting_apply" {
		return false
	}
	before, _ := json.Marshal(state.Report)
	if !a.verificationContextMatches() {
		a.invalidatePolicyVerification("Applied policy, protection or endpoint context changed during observation.")
		return true
	}
	if coverage != nil {
		for _, backend := range coverage.Backends {
			if backend.Status != "unsupported" {
				continue
			}
			for i := range state.Report.Ports {
				test := &state.Report.Ports[i].Allow
				if backend.Backend == "nflog" {
					test = &state.Report.Ports[i].Deny
				}
				if test.Status == "awaiting" {
					test.Status, test.Reason = "unavailable", boundedVerificationReason("Native observer unavailable: "+backend.Error)
				}
			}
		}
	}
	pending, unavailable, verified := 0, 0, 0
	for i := range state.Report.Ports {
		for _, test := range []*PolicyVerificationCase{&state.Report.Ports[i].Allow, &state.Report.Ports[i].Deny} {
			if test.Status == "awaiting" && !now.Before(state.Assignment.ExpiresAt) {
				test.Status, test.Reason = "unverified", "Observation window ended without a qualifying matching sample; the applied policy remains unchanged."
			}
			switch test.Status {
			case "awaiting":
				pending++
			case "unavailable":
				unavailable++
			case "verified", "not_applicable":
				verified++
			}
		}
	}
	if !now.Before(state.Assignment.ExpiresAt) {
		state.Report.State = "expired"
	} else if verified == len(state.Report.Ports)*2 {
		state.Report.State = "verified"
	} else if pending == 0 && unavailable > 0 {
		state.Report.State = "unavailable"
	}
	after, _ := json.Marshal(state.Report)
	changed := string(before) != string(after)
	if changed {
		state.Report.Sequence++
		state.Report.CheckedAt = now
		a.nextCaptureCheck = time.Time{}
	}
	return changed
}
