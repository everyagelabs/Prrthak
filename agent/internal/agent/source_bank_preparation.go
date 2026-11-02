package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

func sourceBankDirectory(stateDir string) string {
	return filepath.Join(managedDirectory(stateDir), "source-bank-transactions")
}
func sourceBankStatusPath(stateDir string) string {
	return filepath.Join(managedDirectory(stateDir), "source-bank-status.json")
}

func ReadSourceBankPreparationStatus(stateDir string) *SourceBankPreparationReport {
	path := sourceBankStatusPath(stateDir)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	raw, err := readPrivateSetupBound(path, 32768)
	var result SourceBankPreparationReport
	if err != nil || json.Unmarshal(raw, &result) != nil || validateSourceBankReport(result) != nil {
		return nil
	}
	return &result
}

func validateSourceBankReport(result SourceBankPreparationReport) error {
	if result.SchemaVersion != 1 || !changeIDValid(result.ID) || !validDigest(result.PlanDigest) || result.CheckedAt.IsZero() || (result.Operation != "assess" && result.Operation != "prepare_activate") || len(result.Blockers) > 16 || len(result.Error) > 1024 {
		return errors.New("invalid source-bank receipt")
	}
	switch result.Status {
	case "assessed", "blocked", "preparing", "prepared", "rolled_back", "error":
	default:
		return errors.New("invalid source-bank receipt state")
	}
	for _, count := range []int{result.MissingBanks, result.ActiveBanks, result.PermanentBanks, result.CreatedBanks} {
		if count < 0 || count > sourceBankCount {
			return errors.New("invalid source-bank receipt count")
		}
	}
	for _, message := range result.Blockers {
		if len(message) > 1024 {
			return errors.New("source-bank blocker exceeds bound")
		}
	}
	if result.BaselineDigest != "" && !validDigest(result.BaselineDigest) || result.ProtectionDigest != "" && !validDigest(result.ProtectionDigest) {
		return errors.New("invalid source-bank receipt digest")
	}
	return nil
}

func (a *Agent) sourceBankStatus(result SourceBankPreparationReport) error {
	result.CheckedAt = a.currentTime()
	if result.Blockers == nil {
		result.Blockers = []string{}
	}
	if err := validateSourceBankReport(result); err != nil {
		return err
	}
	return atomicJSON(sourceBankStatusPath(a.Config.StateDir), &result)
}

func sourceBankReceipt(request *SourceBankPreparationAssignment) SourceBankPreparationReport {
	return SourceBankPreparationReport{SchemaVersion: 1, ID: request.ID, Operation: request.Operation, PlanDigest: request.PlanDigest, Status: "blocked", CheckedAt: time.Now().UTC(), BaselineDigest: request.BaselineDigest, ProtectionDigest: request.ProtectionDigest, Blockers: []string{}}
}

func fillSourceBankReceipt(result *SourceBankPreparationReport, baseline sourceBankBaseline) {
	if result.Operation != "prepare_activate" {
		result.BaselineDigest = baseline.Digest
	}
	result.ActiveBanks = len(baseline.Runtime)
	result.PermanentBanks = len(baseline.Permanent)
	result.MissingBanks = sourceBankCount - len(baseline.Runtime)
	result.ActivationRequired = result.MissingBanks != 0
}

func (a *Agent) validateSourceBankAssignment(p *Policy, request *SourceBankPreparationAssignment, now time.Time) error {
	if request == nil || !changeIDValid(request.ID) || !validDigest(request.PlanDigest) || !now.Before(request.ExpiresAt) || request.ExpiresAt.After(now.Add(20*time.Minute)) || request.Operation != "assess" && request.Operation != "prepare_activate" {
		return errors.New("source-bank assignment is invalid or expired")
	}
	if a.Simulate {
		return errors.New("simulation cannot assess or prepare native source banks")
	}
	strict := a.Config
	strict.Enforce = true
	if err := ValidatePolicySignature(strict, p); err != nil {
		return err
	}
	if err := a.validateAssignmentIdentity(p); err != nil {
		return err
	}
	if request.Operation == "assess" {
		return nil
	}
	if !validDigest(request.BaselineDigest) || !validDigest(request.ProtectionDigest) || len(request.ApprovalProof) == 0 {
		return errors.New("source-bank activation requires exact reviewed baseline and authority")
	}
	if err := validateEndpointApproval(a.Config, request.ApprovalProof, p.ServerID, now, false, "source_bank_preparation"); err != nil {
		return err
	}
	var proof endpointApprovalProof
	if json.Unmarshal(request.ApprovalProof, &proof) != nil || proof.Mode != "single_admin" || proof.PlanID != request.ID || proof.PlanDigest != request.PlanDigest {
		return errors.New("source-bank authority no longer matches the reviewed plan")
	}
	return nil
}

func (a *Agent) sourceBankProtection(ctx context.Context) Protection {
	report := Discover(ctx, a.Commands, false, "")
	report.FirewallSnapshot = CollectFirewallSnapshot(ctx, a.Commands, nil)
	protection := a.managedProtectionFromReport(report)
	a.enrichHostDefaultDenyProtection(ctx, &protection)
	zone, _, topologyErr := a.managedTopology(ctx)
	if topologyErr != nil || zone != protection.Zone {
		protection.Blockers = append(protection.Blockers, "one unambiguous protected active zone is required")
	}
	if report.DiscoveryError != "" {
		protection.Blockers = append(protection.Blockers, "fresh service discovery incomplete")
	}
	protection.Ready = len(protection.Blockers) == 0
	protection.Digest = protectionDigest(protection)
	// Keep witness targets at the exact freshly observed interfaces, never the
	// controller's HTTP peer/SNAT address or an administrator-supplied address.
	if report.DiscoveryError == "" {
		a.inventory = &report
		now := a.currentTime()
		a.lastFullDiscoveryAttempt = now
		a.lastDiscoveryAttempt = now
		a.lastDiscoverySuccess = now
		a.discoverySequence++
		a.discoveryPending = true
	}
	return protection
}

func (a *Agent) sourceBankActivityBlocker(now time.Time) string {
	if a.State.ManagedBundle != nil && a.State.ManagedBundle.HostDefaultDeny {
		return "disable whole-server default deny through its reviewed GUI workflow before reload maintenance"
	}
	if len(a.State.Rules) > 0 || len(ActiveSessions(a.State.Policy, now)) > 0 || len(a.State.PendingDrains) > 0 || a.trafficCapture != nil || a.probe != nil && a.Config.UnexpectedPortMonitorEnabled {
		return "stop traffic learning and monitoring before source-bank maintenance"
	}
	if a.State.Policy != nil {
		for _, monitor := range a.State.Policy.HitMonitors {
			if now.Before(monitor.ExpiresAt) {
				return "stop continuous hit monitoring before source-bank maintenance"
			}
		}
	}
	return ""
}

// processSourceBankPreparation is an explicit signed auxiliary assignment.
// It never changes Config.Enforce or the saved allowed-source policy matrix.
func (a *Agent) processSourceBankPreparation(ctx context.Context, p *Policy) (bool, error) {
	request := p.SourceBankPreparation
	if request == nil {
		return false, nil
	}
	if previous, err := a.previousSourceBankOperation(request.ID, request.PlanDigest); err != nil {
		if errors.Is(err, errSourceBankPending) {
			return true, a.recoverPendingSourceBankOperation(ctx)
		}
		result := sourceBankReceipt(request)
		result.Status = "error"
		result.Error = boundedSourceBankError(err)
		_ = a.sourceBankStatus(result)
		return true, err
	} else if previous {
		return true, nil
	}
	if prior := ReadSourceBankPreparationStatus(a.Config.StateDir); prior != nil && prior.ID == request.ID {
		if prior.PlanDigest != request.PlanDigest || prior.Operation != request.Operation {
			return true, errors.New("source-bank plan ID reused with different content")
		}
		if prior.Status != "preparing" {
			return true, nil
		} // Never replay a completed or failed operation.
	}
	result := sourceBankReceipt(request)
	fail := func(err error) (bool, error) {
		result.Status = "blocked"
		result.Error = boundedSourceBankError(err)
		result.Blockers = []string{result.Error}
		if e := a.sourceBankStatus(result); e != nil {
			return true, e
		}
		return true, err
	}
	if err := a.validateSourceBankAssignment(p, request, a.currentTime()); err != nil {
		return fail(err)
	}
	bounded, cancelAssessment := context.WithDeadline(ctx, request.ExpiresAt)
	defer cancelAssessment()
	ctx = bounded
	a.sourceBankHeartbeatAt = time.Now()
	var configurationLock *os.File
	var err error
	if a.sourceBankConfigurationLease != nil {
		configurationLock, err = a.sourceBankConfigurationLease()
	} else {
		configurationLock, err = configurationLeaseUnder("", 0)
	}
	if err != nil {
		return fail(errors.New("endpoint configuration maintenance is active"))
	}
	defer configurationLock.Close()
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return fail(errors.New("firewall maintenance is already active or uncertain"))
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if err := a.recoverAllEnforcementLocked(ctx); err != nil {
		return fail(err)
	}
	if prior := ReadSourceBankPreparationStatus(a.Config.StateDir); prior != nil && prior.ID == request.ID && prior.Status != "preparing" {
		return true, nil
	}
	if err := checkEnforcementJournals(a.Config); err != nil {
		return fail(err)
	}
	protection := a.sourceBankProtection(ctx)
	if request.Operation == "assess" {
		result.ProtectionDigest = protection.Digest
	}
	if message := a.sourceBankActivityBlocker(a.currentTime()); message != "" {
		return fail(errors.New(message))
	}
	baseline, err := a.sourceBankBaseline(ctx)
	if err != nil {
		return fail(err)
	}
	fillSourceBankReceipt(&result, baseline)
	if request.Operation == "assess" {
		result.Status = "assessed"
		if !protection.Ready {
			result.Status = "blocked"
			result.Blockers = append([]string{}, protection.Blockers...)
		}
		return true, a.sourceBankStatus(result)
	}
	if !protection.Ready || request.ProtectionDigest != protection.Digest || request.BaselineDigest != baseline.Digest {
		return fail(errors.New("protected configuration or exact firewall baseline changed; assess and review again"))
	}
	if err := a.sourceBankHealth(ctx, p, request, protection); err != nil {
		return fail(err)
	}
	if len(baseline.Runtime) == sourceBankCount && len(baseline.Permanent) == sourceBankCount {
		result.Status = "prepared"
		return true, a.sourceBankStatus(result)
	}
	if err := a.applySourceBanks(ctx, p, request, protection, baseline, &result); err != nil {
		if prior := ReadSourceBankPreparationStatus(a.Config.StateDir); prior == nil || prior.Status == "preparing" {
			result.Status = "error"
			result.Error = boundedSourceBankError(err)
			_ = a.sourceBankStatus(result)
		}
		return true, err
	}
	a.forceDiscovery = true
	return true, nil
}

func boundedSourceBankError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 1024 {
		return "Source-bank operation failed; inspect its private endpoint journal."
	}
	return text
}

func (a *Agent) sourceBankProgress(ctx context.Context) error {
	if a.Client == nil || a.Client.HTTP == nil || time.Since(a.sourceBankHeartbeatAt) < 20*time.Second {
		return nil
	}
	a.sourceBankHeartbeatAt = time.Now()
	return a.report(ctx)
}

func (a *Agent) applySourceBanks(ctx context.Context, p *Policy, request *SourceBankPreparationAssignment, protection Protection, baseline sourceBankBaseline, result *SourceBankPreparationReport) error {
	if err := checkNewEnforcementJournalBudget(a.Config.StateDir, "source-banks"); err != nil {
		return err
	}
	// The fresh controller/SSH witness is deliberately inside the mutator too:
	// no alternate caller can stage even a permanent definition without it.
	if err := a.sourceBankHealth(ctx, p, request, protection); err != nil {
		return err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	nonce := hex.EncodeToString(raw)
	if err := os.MkdirAll(sourceBankDirectory(a.Config.StateDir), 0700); err != nil {
		return err
	}
	journal := &managedJournal{Nonce: nonce, Phase: "prepared", PID: os.Getpid(), ProcessIdentity: processIdentity(os.Getpid()), Deadline: time.Now().Add(10 * time.Minute), DeadlineBootSeconds: bootElapsedSeconds() + 600, SourceBankPreparation: &sourceBankJournal{Assignment: *request, Baseline: baseline, Created: []string{}, Report: *result}}
	bounded, cancelOperation := context.WithDeadline(ctx, journal.Deadline.Add(-time.Minute))
	defer cancelOperation()
	ctx = bounded
	path := filepath.Join(sourceBankDirectory(a.Config.StateDir), nonce+".json")
	if err := saveManagedJournal(path, journal); err != nil {
		return err
	}
	if err := a.armManagedWatchdog(ctx, path, journal); err != nil {
		journal.Phase = "rolled_back"
		journal.Error = boundedSourceBankError(err)
		_ = saveManagedJournal(path, journal)
		result.Status = "rolled_back"
		result.Error = journal.Error
		_ = a.sourceBankStatus(*result)
		return err
	}
	result.Status = "preparing"
	journal.SourceBankPreparation.Report = *result
	if err := a.sourceBankStatus(*result); err != nil {
		return err
	}
	rollback := func(cause error) error {
		journal.Error = boundedSourceBankError(cause)
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cleanup = withManagedLease(cleanup, managedLeaseFromContext(ctx))
		if err := rollbackSourceBanks(cleanup, a.Commands, path, journal, a.sourceBankConfigDigest); err != nil {
			return fmt.Errorf("source-bank preparation failed and rollback is not verified: %w", err)
		}
		return cause
	}
	journal.Phase = "creating"
	if err := saveManagedJournal(path, journal); err != nil {
		return rollback(err)
	}
	lastProgress := time.Now()
	for _, set := range sourceBankDefinitions() {
		if _, exists := baseline.Permanent[set.Name]; exists {
			continue
		}
		if time.Until(journal.Deadline) < 45*time.Second {
			return rollback(errors.New("source-bank rollback deadline approaching"))
		}
		// The atomic create refuses existing names; its embedded nonce marker
		// separately prevents recovery from deleting a raced foreign definition.
		journal.SourceBankPreparation.Created = append(journal.SourceBankPreparation.Created, set.Name)
		if err := saveManagedJournal(path, journal); err != nil {
			return rollback(err)
		}
		if err := createSourceBankDefinition(ctx, a.Commands, filepath.Dir(path), nonce, set); err != nil {
			return rollback(err)
		}
		definition, err := bankDefinition(ctx, a.Commands, "permanent", set.Name)
		if err != nil || len(definition.Entries) != 0 {
			return rollback(errors.New("empty source-bank creation read-back failed"))
		}
		result.CreatedBanks = len(journal.SourceBankPreparation.Created)
		result.PermanentBanks = len(baseline.Permanent) + result.CreatedBanks
		journal.SourceBankPreparation.Report = *result
		if time.Since(lastProgress) >= 20*time.Second {
			if err := a.sourceBankStatus(*result); err != nil {
				return rollback(err)
			}
			if err := a.sourceBankProgress(ctx); err != nil {
				return rollback(err)
			}
			lastProgress = time.Now()
		}
	}
	current, err := a.sourceBankBaselineState(ctx, true)
	if err != nil {
		return rollback(err)
	}
	if !sameSourceBankContext(current, baseline) || !reflect.DeepEqual(current.Runtime, baseline.Runtime) || len(current.Permanent) != sourceBankCount {
		return rollback(errors.New("firewall baseline changed while preparing source banks"))
	}
	for name, old := range baseline.Permanent {
		if !reflect.DeepEqual(current.Permanent[name], old) {
			return rollback(errors.New("existing source bank changed during preparation"))
		}
	}
	if err := a.sourceBankHealth(ctx, p, request, protection); err != nil {
		return rollback(err)
	}
	journal.Phase = "activating"
	journal.SourceBankPreparation.Reloaded = true
	if err := saveManagedJournal(path, journal); err != nil {
		return rollback(err)
	}
	if _, err := a.Commands.Run(ctx, "firewall-cmd", "--check-config"); err != nil {
		return rollback(errors.New("permanent configuration check failed"))
	}
	if _, err := a.Commands.Run(ctx, "firewall-cmd", "--reload"); err != nil {
		return rollback(errors.New("reviewed source-bank activation reload failed"))
	}
	if err := a.sourceBankHealth(ctx, p, request, protection); err != nil {
		return rollback(err)
	}
	if err := restoreSourceBankBindings(ctx, a.Commands, baseline.RuntimeBindings); err != nil {
		return rollback(err)
	}
	verified, err := a.sourceBankBaseline(ctx)
	if err != nil || !sameSourceBankContext(verified, baseline) || len(verified.Runtime) != sourceBankCount || !reflect.DeepEqual(verified.Runtime, verified.Permanent) {
		return rollback(errors.New("activated firewall/source-bank baseline did not verify"))
	}
	if err := a.sourceBankHealth(ctx, p, request, protection); err != nil {
		return rollback(err)
	}
	fillSourceBankReceipt(result, verified)
	result.CheckedAt = time.Now().UTC()
	result.Status = "prepared"
	result.Error = ""
	result.CreatedBanks = len(journal.SourceBankPreparation.Created)
	journal.SourceBankPreparation.Report = *result
	journal.Phase = "committed"
	if err := saveManagedJournal(path, journal); err != nil {
		return rollback(err)
	}
	return a.sourceBankStatus(*result)
}

func sourceBankOwner(nonce, name string) string { return "PRTHAK-SOURCE-BANK-V1:" + nonce + ":" + name }

func createSourceBankDefinition(ctx context.Context, commands CommandRunner, directory, nonce string, set ManagedIPSet) error {
	if !validManagedNonce(nonce) || !validManagedSet(set) || len(set.Entries) != 0 {
		return errors.New("invalid empty source-bank definition")
	}
	type option struct {
		Name  string `xml:"name,attr"`
		Value string `xml:"value,attr"`
	}
	definition := struct {
		XMLName     xml.Name `xml:"ipset"`
		Type        string   `xml:"type,attr"`
		Description string   `xml:"description"`
		Options     []option `xml:"option"`
	}{Type: "hash:net", Description: sourceBankOwner(nonce, set.Name), Options: []option{{"family", set.Family}, {"hashsize", "1024"}, {"maxelem", "16384"}}}
	raw, err := xml.Marshal(definition)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "empty-"+nonce+"-"+set.Name+".xml")
	if err := atomicPrivateFile(path, raw); err != nil {
		return err
	}
	defer os.Remove(path)
	// The atomic create includes an ownership marker. If an external writer wins
	// the name race, recovery cannot delete that writer's unmarked object.
	if _, err := commands.Run(ctx, "firewall-cmd", "--permanent", "--new-ipset-from-file="+path, "--name="+set.Name); err != nil {
		return errors.New("empty source-bank creation failed")
	}
	return nil
}

func (a *Agent) sourceBankHealth(ctx context.Context, p *Policy, request *SourceBankPreparationAssignment, protection Protection) error {
	if a.checkSourceBankHealth != nil {
		return a.checkSourceBankHealth(ctx, p, request, protection)
	}
	if a.Client == nil || a.Client.simulate {
		return errors.New("fresh source-bank mTLS witness unavailable")
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
	response, err := fresh.request(ctx, "POST", "/api/v1/agent/source-banks/check", map[string]any{"id": request.ID, "plan_digest": request.PlanDigest, "baseline_digest": request.BaselineDigest, "protection_digest": request.ProtectionDigest, "nonce": nonce, "ssh_ports": protection.SSHPorts}, "")
	if err != nil {
		return err
	}
	var witness sourceBankWitness
	if err := decodeResponse(response, &witness); err != nil {
		return err
	}
	return a.validateSourceBankWitness(witness, p, request, protection, nonce, time.Now().UTC())
}

type sourceBankWitness struct {
	ID             string `json:"id"`
	PlanDigest     string `json:"plan_digest"`
	BaselineDigest string `json:"baseline_digest"`
	managedWitness
}

func (a *Agent) validateSourceBankWitness(witness sourceBankWitness, p *Policy, request *SourceBankPreparationAssignment, protection Protection, nonce string, now time.Time) error {
	if witness.ID != request.ID || witness.PlanDigest != request.PlanDigest || witness.BaselineDigest != request.BaselineDigest {
		return errors.New("source-bank management witness lost its exact plan binding")
	}
	copy := *p
	copy.Version = 0
	copy.Digest = request.PlanDigest
	copy.HostDefaultDeny = false
	copy.Enforcement = &EnforcementAuthorization{BindingDigest: request.PlanDigest}
	witness.Version = 0
	witness.Digest = request.PlanDigest
	witness.BindingDigest = request.PlanDigest
	return a.validateManagedWitness(witness.managedWitness, &copy, protection, nonce, now)
}
