package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"
)

func ReadFirewallActivationStatus(stateDir string) *FirewallActivationReport {
	raw, err := readPrivateSetupBound(firewallActivationStatusPath(stateDir), 131072)
	var value FirewallActivationReport
	if err != nil || json.Unmarshal(raw, &value) != nil || validateFirewallActivationReport(value) != nil {
		return nil
	}
	return &value
}
func validateFirewallActivationReport(value FirewallActivationReport) error {
	if value.SchemaVersion != 1 || !changeIDValid(value.ID) || !validDigest(value.PlanDigest) || !validDigest(value.ConfigurationDigest) || value.CheckedAt.IsZero() || len(value.Error) > 1024 || !firewallActivationOperation(value.TargetOperation) || value.Operation != "assess" && value.Operation != value.TargetOperation {
		return errors.New("invalid firewall maintenance receipt")
	}
	if value.BaselineDigest != "" && !validDigest(value.BaselineDigest) || value.ProtectionDigest != "" && !validDigest(value.ProtectionDigest) {
		return errors.New("invalid firewall maintenance receipt binding")
	}
	switch value.Status {
	case "assessed", "blocked", "applying", "completed", "rolled_back", "error":
	default:
		return errors.New("invalid firewall maintenance receipt status")
	}
	if value.Assessment != nil {
		facts := value.Assessment
		if len(facts.IPs) > 64 || len(facts.SSHPorts) > 8 || len(facts.ManagementSources) > 100 || len(facts.DiscoveredPorts) > 100 || len(facts.TranslatedRules) > 128 || len(facts.Blockers) > 32 || len(facts.Notes) > 32 {
			return errors.New("firewall maintenance receipt exceeds bound")
		}
		for _, rule := range facts.TranslatedRules {
			if err := validateActivationRule(rule); err != nil {
				return err
			}
		}
	}
	return nil
}
func (a *Agent) firewallActivationStatus(value FirewallActivationReport) error {
	value.CheckedAt = a.currentTime()
	if err := validateFirewallActivationReport(value); err != nil {
		return err
	}
	return atomicJSON(firewallActivationStatusPath(a.Config.StateDir), value)
}

func (a *Agent) checkBroadFirewallMaintenance(policy *Policy) error {
	managed, learned := a.State.ManagedBundle, a.State.LearningAllowBundle
	if a.Config.Enforce || managed != nil && (managed.HostDefaultDeny || len(managed.Rules) != 0 || len(managed.IPSets) != 0) ||
		learned != nil && (len(learned.Rules) != 0 || len(learned.IPSets) != 0) ||
		policy.HostDefaultDeny || policy.Enforcement != nil && policy.Enforcement.Authorized ||
		policy.LearningAllow != nil || len(policy.FirewallChanges) != 0 ||
		policy.EgressBundle != nil || policy.Quarantine != nil {
		return errors.New("remove active or pending firewall enforcement before stopping firewalld or enabling the default inbound allow")
	}
	network, err := readNetworkState(a.Config.StateDir)
	if err != nil {
		return errors.New("local egress and quarantine state cannot be verified")
	}
	if len(network.EgressRules) != 0 || network.QuarantinePlan != nil {
		return errors.New("remove active egress and quarantine controls before this firewall operation")
	}
	return nil
}

func activationReceipt(request *FirewallActivationAssignment) FirewallActivationReport {
	return FirewallActivationReport{SchemaVersion: 1, ID: request.ID, Operation: request.Operation, TargetOperation: request.TargetOperation, PlanDigest: request.PlanDigest, BaselineDigest: request.BaselineDigest, ProtectionDigest: request.ProtectionDigest, ConfigurationDigest: request.ConfigurationDigest, Status: "blocked", CheckedAt: time.Now().UTC()}
}

func (a *Agent) validateFirewallActivationAssignment(policy *Policy, request *FirewallActivationAssignment) error {
	if request == nil || a.Simulate || !changeIDValid(request.ID) || !validDigest(request.PlanDigest) || !validDigest(request.ConfigurationDigest) || !firewallActivationOperation(request.TargetOperation) || request.Operation != "assess" && request.Operation != request.TargetOperation || !a.currentTime().Before(request.ExpiresAt) || request.ExpiresAt.After(a.currentTime().Add(20*time.Minute)) {
		return errors.New("firewall maintenance assignment is invalid, simulated or expired")
	}
	if configDigest(a.Config) != request.ConfigurationDigest {
		return errors.New("local endpoint configuration differs from the signed maintenance scope")
	}
	strict := a.Config
	strict.Enforce = true
	if err := ValidatePolicySignature(strict, policy); err != nil {
		return err
	}
	if err := a.validateAssignmentIdentity(policy); err != nil {
		return err
	}
	if request.Operation != "assess" {
		if !validDigest(request.BaselineDigest) || !validDigest(request.ProtectionDigest) || len(request.ApprovalProof) == 0 {
			return errors.New("firewall mutation needs its exact reviewed native baseline and current Admin proof")
		}
		if err := validateEndpointApproval(a.Config, request.ApprovalProof, policy.ServerID, a.currentTime(), false, "firewall_activation"); err != nil {
			return err
		}
		var proof endpointApprovalProof
		if json.Unmarshal(request.ApprovalProof, &proof) != nil || proof.Mode != "single_admin" || proof.PlanID != request.ID || proof.PlanDigest != request.PlanDigest {
			return errors.New("firewall maintenance proof lost its exact operation binding")
		}
	}
	return nil
}

func (a *Agent) processFirewallActivation(ctx context.Context, policy *Policy) (bool, error) {
	request := policy.FirewallActivation
	if request == nil {
		return false, nil
	}
	if prior := ReadFirewallActivationStatus(a.Config.StateDir); prior != nil && prior.ID == request.ID {
		if prior.PlanDigest != request.PlanDigest || prior.Operation != request.Operation || prior.TargetOperation != request.TargetOperation {
			return true, errors.New("firewall maintenance ID reused with different content")
		}
		if prior.Status != "applying" {
			return true, nil
		}
	}
	result := activationReceipt(request)
	fail := func(err error) (bool, error) {
		result.Status = "blocked"
		result.Error = boundedSourceBankError(err)
		if e := a.firewallActivationStatus(result); e != nil {
			return true, e
		}
		return true, err
	}
	if err := a.validateFirewallActivationAssignment(policy, request); err != nil {
		return fail(err)
	}
	if runtime.GOOS != "linux" && a.firewallActivation == nil {
		return fail(errors.New("native Linux systemd maintenance is required"))
	}
	var lease *os.File
	var err error
	if a.firewallActivation != nil && a.firewallActivation.ConfigurationLease != nil {
		lease, err = a.firewallActivation.ConfigurationLease()
	} else {
		lease, err = configurationLeaseUnder("", 0)
	}
	if err != nil {
		return fail(errors.New("endpoint configuration maintenance is active"))
	}
	defer lease.Close()
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return fail(err)
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if err := a.recoverAllEnforcementLocked(ctx); err != nil {
		return fail(err)
	}
	if previous, err := a.previousFirewallActivation(request.ID, request.PlanDigest); err != nil {
		return fail(err)
	} else if previous {
		return true, nil
	}
	if err := checkEnforcementJournals(a.Config); err != nil {
		return fail(err)
	}
	if reason := a.sourceBankActivityBlocker(a.currentTime()); reason != "" {
		return fail(errors.New(reason))
	}
	if request.TargetOperation == "deactivate_existing" || request.TargetOperation == "activate_allow_all" {
		if err := a.checkBroadFirewallMaintenance(policy); err != nil {
			return fail(err)
		}
	}
	bounded, cancel := context.WithDeadline(ctx, request.ExpiresAt)
	defer cancel()
	ctx = bounded
	baseline, protection, err := a.firewallActivationBaseline(ctx, request.TargetOperation)
	result.Assessment = &baseline.Assessment
	if request.Operation == "assess" {
		result.BaselineDigest = baseline.Digest
		result.ProtectionDigest = protection.Digest
		result.Status = "assessed"
		if err != nil {
			result.Status = "blocked"
			result.Error = boundedSourceBankError(err)
		}
		if e := a.firewallActivationStatus(result); e != nil {
			return true, e
		}
		return true, err
	}
	if err != nil {
		return fail(err)
	}
	if !baseline.Assessment.CanApply || request.BaselineDigest != baseline.Digest || request.ProtectionDigest != protection.Digest {
		return fail(errors.New("native firewall maintenance baseline changed; assess and review again"))
	}
	if err := a.firewallActivationHealth(ctx, policy, *request, protection); err != nil {
		return fail(err)
	}
	if err := a.applyFirewallActivation(ctx, policy, request, baseline, protection, &result); err != nil {
		if saved := ReadFirewallActivationStatus(a.Config.StateDir); saved == nil || saved.ID != request.ID || saved.Status == "blocked" {
			result.Status = "error"
			result.Error = boundedSourceBankError(err)
			_ = a.firewallActivationStatus(result)
		}
		return true, err
	}
	a.forceDiscovery = true
	return true, nil
}

type firewallActivationWitness struct {
	ConfigurationDigest string `json:"configuration_digest"`
	HealthMode          string `json:"health_mode"`
	sourceBankWitness
}

func (a *Agent) firewallActivationHealth(ctx context.Context, policy *Policy, request FirewallActivationAssignment, protection Protection) error {
	if a.firewallActivation != nil && a.firewallActivation.Health != nil {
		return a.firewallActivation.Health(request, protection)
	}
	if a.Client == nil || a.Client.simulate {
		return errors.New("fresh authenticated firewall-maintenance witness unavailable")
	}
	fresh, err := NewClient(a.Config, false)
	if err != nil {
		return err
	}
	transport := fresh.HTTP.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	nonce := hex.EncodeToString(raw)
	ports := protection.SSHPorts
	if agentOnlyFirewallActivation(request.Operation) {
		ports = []int{}
	}
	response, err := fresh.request(ctx, "POST", "/api/v1/agent/firewall-activation/check", map[string]any{"id": request.ID, "plan_digest": request.PlanDigest, "baseline_digest": request.BaselineDigest, "protection_digest": request.ProtectionDigest, "configuration_digest": request.ConfigurationDigest, "nonce": nonce, "ssh_ports": ports}, "")
	if err != nil {
		return err
	}
	var witness firewallActivationWitness
	if err := decodeResponse(response, &witness); err != nil {
		return err
	}
	return a.validateFirewallActivationWitness(witness, policy, request, protection, nonce, time.Now().UTC())
}

func (a *Agent) validateFirewallActivationWitness(witness firewallActivationWitness, policy *Policy, request FirewallActivationAssignment, protection Protection, nonce string, now time.Time) error {
	if witness.ConfigurationDigest != request.ConfigurationDigest {
		return errors.New("firewall maintenance witness configuration changed")
	}
	if agentOnlyFirewallActivation(request.Operation) {
		if witness.HealthMode != "agent_controller_mtls" || len(witness.SSHChecks) != 0 {
			return errors.New("firewalld service maintenance requires the agent/controller mTLS health witness")
		}
		// Use the exact protection digest while verifying the controller path
		// independently of any SSH listeners discovered in the native baseline.
		protection.SSHPorts = nil
	} else if witness.HealthMode != "" {
		return errors.New("this firewall maintenance operation requires its SSH management witness")
	}
	return a.validateSourceBankWitness(witness.sourceBankWitness, policy, &SourceBankPreparationAssignment{ID: request.ID, PlanDigest: request.PlanDigest, BaselineDigest: request.BaselineDigest}, protection, nonce, now)
}

func (a *Agent) applyFirewallActivation(ctx context.Context, policy *Policy, request *FirewallActivationAssignment, baseline firewallActivationBaseline, protection Protection, result *FirewallActivationReport) error {
	if err := checkNewEnforcementJournalBudget(a.Config.StateDir, "firewall-activation"); err != nil {
		return err
	}
	if err := a.firewallActivationHealth(ctx, policy, *request, protection); err != nil {
		return err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	nonce := hex.EncodeToString(raw)
	if err := os.MkdirAll(firewallActivationDirectory(a.Config.StateDir), 0700); err != nil {
		return err
	}
	journal := &managedJournal{Nonce: nonce, Phase: "prepared", PID: os.Getpid(), ProcessIdentity: processIdentity(os.Getpid()), Deadline: time.Now().Add(3 * time.Minute), DeadlineBootSeconds: bootElapsedSeconds() + 180, FirewallActivation: &firewallActivationJournal{Assignment: *request, Baseline: baseline, ChangedFiles: map[string]firewallActivationFile{}, Report: *result}}
	path := filepath.Join(firewallActivationDirectory(a.Config.StateDir), nonce+".json")
	if err := a.prepareActivationFiles(ctx, journal); err != nil {
		return err
	}
	if err := validateFirewallActivationJournal(journal); err != nil {
		return err
	}
	if err := saveManagedJournal(path, journal); err != nil {
		return err
	}
	arm := a.armManagedWatchdog
	if a.firewallActivation != nil && a.firewallActivation.Arm != nil {
		arm = func(ctx context.Context, path string, journal *managedJournal) error {
			return a.firewallActivation.Arm(path, journal)
		}
	}
	if err := arm(ctx, path, journal); err != nil {
		journal.Phase = "rolled_back"
		journal.Error = boundedSourceBankError(err)
		journal.FirewallActivation.Report.Status = "rolled_back"
		journal.FirewallActivation.Report.Error = journal.Error
		_ = saveManagedJournal(path, journal)
		_ = a.firewallActivationStatus(journal.FirewallActivation.Report)
		return err
	}
	bounded, cancel := context.WithDeadline(ctx, journal.Deadline.Add(-30*time.Second))
	defer cancel()
	ctx = bounded
	rollback := func(cause error) error {
		journal.Error = boundedSourceBankError(cause)
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cleanup = withManagedLease(cleanup, managedLeaseFromContext(ctx))
		if err := rollbackFirewallActivation(cleanup, a.Commands, path, journal, a.firewallActivation); err != nil {
			return fmt.Errorf("firewall maintenance failed; automatic rollback is unverified: %w", err)
		}
		return cause
	}
	journal.Phase = "applying"
	journal.FirewallActivation.Report.Status = "applying"
	if err := saveManagedJournal(path, journal); err != nil {
		return rollback(err)
	}
	if err := a.firewallActivationStatus(journal.FirewallActivation.Report); err != nil {
		return rollback(err)
	}
	if err := activationFilesMatch(a.activationRoot(), baseline.Files, nil, false); err != nil {
		return rollback(err)
	}
	for name, change := range journal.FirewallActivation.ChangedFiles {
		if err := writeActivationFile(a.activationRoot(), name, change, true); err != nil {
			return rollback(err)
		}
	}
	operation := request.Operation
	if operation == "activate_allow_all" {
		if _, err := a.Commands.Run(ctx, "firewall-offline-cmd", "--check-config"); err != nil {
			return rollback(errors.New("firewalld did not validate the complete staged permanent configuration"))
		}
	}
	if operation == "migrate_ufw" {
		journal.FirewallActivation.UFWDisabled = true
		journal.FirewallActivation.ServiceChanged = true
		if err := saveManagedJournal(path, journal); err != nil {
			return rollback(err)
		}
		if _, err := a.Commands.Run(ctx, "systemctl", "stop", "ufw.service"); err != nil {
			return rollback(err)
		}
		text, _ := a.Commands.Run(ctx, "ufw", "status")
		if !strings.HasPrefix(strings.TrimSpace(text), "Status: inactive") {
			return rollback(errors.New("UFW did not become inactive after its exact reviewed disable"))
		}
	}
	if startsFirewalld(operation) || operation == "deactivate_existing" {
		if operation == "deactivate_existing" {
			readback, err := firewallDeactivationCommands(ctx, a.Commands, baseline.Files)
			if err != nil {
				return rollback(err)
			}
			current, err := activationOriginalPolicyBaseline(ctx, readback, a.Config.StateDir, *baseline.SourceBanks, baseline.Global, false)
			if err != nil || !reflect.DeepEqual(current, *baseline.SourceBanks) {
				return rollback(errors.New("live firewall configuration changed since review; stopping it could lose runtime rules"))
			}
		}
		journal.FirewallActivation.ServiceChanged = true
		if err := saveManagedJournal(path, journal); err != nil {
			return rollback(err)
		}
		if operation == "deactivate_existing" {
			if _, err := a.Commands.Run(ctx, "systemctl", "stop", "firewalld.service"); err != nil {
				return rollback(err)
			}
			if baseline.NativeTopology != "" {
				if _, err := activationInactiveContext(ctx, a.Commands, a.activationRoot(), false, nil); err != nil {
					return rollback(err)
				}
			}
		} else {
			if _, err := a.Commands.Run(ctx, "systemctl", "start", "firewalld.service"); err != nil {
				return rollback(err)
			}
			if text, err := a.Commands.Run(ctx, "firewall-cmd", "--state"); err != nil || strings.TrimSpace(text) != "running" {
				return rollback(errors.New("firewalld startup read-back failed"))
			}
		}
	} else {
		if operation == "prepare_egress" {
			journal.FirewallActivation.CreatedPolicy = true
			if err := saveManagedJournal(path, journal); err != nil {
				return rollback(err)
			}
			xml, err := activationEgressXML(nonce)
			if err != nil {
				return rollback(err)
			}
			temporary := filepath.Join(filepath.Dir(path), nonce+"-prt-egress.xml")
			if err := atomicPrivateFile(temporary, xml); err != nil {
				return rollback(err)
			}
			defer os.Remove(temporary)
			if _, err := a.Commands.Run(ctx, "firewall-cmd", "--permanent", "--new-policy-from-file="+temporary, "--name="+activationEgressPolicy); err != nil {
				return rollback(err)
			}
			if err := activationEgressOwnedEmpty(ctx, a.Commands, "permanent", nonce); err != nil {
				return rollback(err)
			}
		}
		if _, err := a.Commands.Run(ctx, "firewall-cmd", "--check-config"); err != nil {
			return rollback(err)
		}
		journal.FirewallActivation.Reloaded = true
		if err := saveManagedJournal(path, journal); err != nil {
			return rollback(err)
		}
		if _, err := a.Commands.Run(ctx, "firewall-cmd", "--reload"); err != nil {
			return rollback(err)
		}
		if err := restoreSourceBankBindings(ctx, a.Commands, baseline.SourceBanks.RuntimeBindings); err != nil {
			return rollback(err)
		}
		if operation == "prepare_egress" {
			for _, scope := range []string{"runtime", "permanent"} {
				if err := activationEgressOwnedEmpty(ctx, a.Commands, scope, nonce); err != nil {
					return rollback(err)
				}
			}
		}
		verified, err := activationOriginalPolicyBaseline(ctx, a.Commands, a.Config.StateDir, *baseline.SourceBanks, baseline.Global, journal.FirewallActivation.CreatedPolicy)
		if err != nil || !reflect.DeepEqual(verified, *baseline.SourceBanks) {
			return rollback(errors.New("reviewed reload did not preserve the original runtime/permanent firewall baseline"))
		}
		if operation == "enable_native_counters" {
			if err := activationCounterRuntime(ctx, a.Commands, true); err != nil {
				return rollback(err)
			}
			if a.firewallActivation != nil && a.firewallActivation.CounterReadback != nil {
				err = a.firewallActivation.CounterReadback()
			} else {
				sample := CollectFirewallCounters(ctx, a.Commands, "nftables", "running", nil, time.Now().UTC())
				found := false
				for _, rule := range sample.Rules {
					if rule.CounterStatus == "available" {
						found = true
						break
					}
				}
				if !found {
					err = errors.New("native counter objects were not observed after the reviewed reload")
				}
			}
			if err != nil {
				return rollback(err)
			}
		}
	}
	if err := a.firewallActivationHealth(ctx, policy, *request, protection); err != nil {
		return rollback(err)
	}
	if startsFirewalld(operation) {
		if _, err := a.Commands.Run(ctx, "systemctl", "enable", "firewalld.service"); err != nil {
			return rollback(err)
		}
		if operation == "migrate_ufw" {
			if _, err := a.Commands.Run(ctx, "systemctl", "disable", "ufw.service"); err != nil {
				return rollback(err)
			}
		}
	}
	if operation == "deactivate_existing" {
		if _, err := a.Commands.Run(ctx, "systemctl", "disable", "firewalld.service"); err != nil {
			return rollback(err)
		}
	}
	if operation == "activate_existing" || operation == "activate_allow_all" {
		if err := activationDefaultZoneReadback(ctx, a.Commands, baseline.Assessment.Zone); err != nil {
			return rollback(err)
		}
	}
	if operation == "activate_allow_all" {
		if err := activationDefaultAllowReadback(ctx, a.Commands, baseline.Assessment.Zone); err != nil {
			return rollback(err)
		}
	}
	if err := a.firewallActivationHealth(ctx, policy, *request, protection); err != nil {
		return rollback(err)
	}
	if baseline.NativeTopology != "" {
		var topology string
		var err error
		if a.firewallActivation != nil && a.firewallActivation.Topology != nil {
			topology, err = a.firewallActivation.Topology()
		} else {
			topology, err = activationHostContext(ctx, a.Commands, a.activationRoot())
		}
		if err != nil || topology != baseline.NativeTopology {
			return rollback(errors.New("host namespace, routing, links or forwarding changed during activation"))
		}
	}
	if err := activationAppliedFilesMatch(a.activationRoot(), journal.FirewallActivation); err != nil {
		return rollback(err)
	}
	if startsFirewalld(operation) || operation == "deactivate_existing" {
		active, enabled, err := activationUnitState(ctx, a.Commands, "firewalld")
		wantActive, wantEnabled := startsFirewalld(operation), "disabled"
		if wantActive {
			wantEnabled = "enabled"
		}
		if err != nil || active != wantActive || enabled != wantEnabled {
			return rollback(errors.New("firewalld service activity/enablement did not verify"))
		}
		if operation == "migrate_ufw" {
			active, enabled, err = activationUnitState(ctx, a.Commands, "ufw")
			if err != nil || active || enabled != "disabled" {
				return rollback(errors.New("UFW cutover activity/enablement did not verify"))
			}
		}
	}
	if operation == "prepare_egress" {
		if err := activationEgressMarker(a.Config.StateDir, nonce); err != nil {
			return rollback(err)
		}
	}
	if operation == "enable_native_counters" {
		if a.firewallActivation != nil && a.firewallActivation.Attestation != nil {
			if err := a.firewallActivation.Attestation(true); err != nil {
				return rollback(err)
			}
		} else if err := recordActivationCounterAttestation(ctx, a.Config.StateDir, a.activationRoot(), a.Commands, true); err != nil {
			return rollback(err)
		}
	}
	journal.Phase = "committed"
	journal.FirewallActivation.Report.Status = "completed"
	journal.FirewallActivation.Report.Error = ""
	journal.FirewallActivation.Report.CheckedAt = time.Now().UTC()
	if err := saveManagedJournal(path, journal); err != nil {
		return rollback(err)
	}
	*result = journal.FirewallActivation.Report
	return a.firewallActivationStatus(*result)
}
