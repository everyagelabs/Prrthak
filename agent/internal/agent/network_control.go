package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

type networkControlState struct {
	SchemaVersion        int                   `json:"schema_version"`
	EgressGeneration     int                   `json:"egress_generation"`
	QuarantineGeneration int                   `json:"quarantine_generation"`
	Egress               *EgressAssignment     `json:"egress"`
	EgressRules          []string              `json:"egress_rules"`
	EgressNonce          string                `json:"egress_nonce"`
	Quarantine           *QuarantineAssignment `json:"quarantine"`
	QuarantinePlan       *quarantinePlan       `json:"quarantine_plan"`
	QuarantineAuthority  *Policy               `json:"quarantine_authority"`
	QuarantineNonce      string                `json:"quarantine_nonce"`
}

func readNetworkState(stateDir string) (*networkControlState, error) {
	path := networkStatePath(stateDir)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return &networkControlState{SchemaVersion: 1, EgressRules: []string{}}, nil
	}
	raw, err := readPrivateSetupBound(path, 8*1024*1024)
	if err != nil {
		return nil, err
	}
	var state networkControlState
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || state.SchemaVersion != 1 || len(state.EgressRules) > 256 || state.EgressGeneration < 0 || state.QuarantineGeneration < 0 {
		return nil, errors.New("invalid privately owned network state")
	}
	if state.QuarantinePlan != nil && (!validManagedNonce(state.QuarantinePlan.Nonce) || state.Quarantine == nil || state.QuarantineNonce != state.QuarantinePlan.Nonce) {
		return nil, errors.New("quarantine state ownership mismatch")
	}
	return &state, nil
}
func cloneNetworkState(state *networkControlState) *networkControlState {
	raw, _ := json.Marshal(state)
	var copy networkControlState
	_ = json.Unmarshal(raw, &copy)
	return &copy
}

type networkControlRequest struct {
	Kind, ID, Digest, ProtectionDigest, ContextDigest string
	Generation                                        int
	ApprovalExpiresAt                                 time.Time
	Egress                                            *EgressAssignment
	Quarantine                                        *QuarantineAssignment
}

func egressRequest(r *EgressAssignment) networkControlRequest {
	return networkControlRequest{Kind: "egress", ID: r.ID, Digest: r.PlanDigest, ProtectionDigest: r.ProtectionDigest, ContextDigest: r.ContextDigest, Generation: r.Generation, ApprovalExpiresAt: r.ApprovalExpiresAt, Egress: r}
}
func quarantineRequest(r *QuarantineAssignment) networkControlRequest {
	return networkControlRequest{Kind: "quarantine", ID: r.ID, Digest: r.PlanDigest, ProtectionDigest: r.ProtectionDigest, ContextDigest: r.ContextDigest, Generation: r.Generation, ApprovalExpiresAt: r.ApprovalExpiresAt, Quarantine: r}
}

type networkControlEngine struct {
	Commands    CommandRunner
	Config      Config
	Now         func() time.Time
	Assess      func(context.Context) (networkNativeContext, error)
	Health      func(context.Context, networkControlRequest, networkNativeContext) error
	Arm         func(context.Context, string, *networkControlJournal, bool) error
	PrepareBoot func(context.Context) error
}

func (e *networkControlEngine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}
func (e *networkControlEngine) saveReport(report NetworkControlReport) error {
	report.SchemaVersion = 1
	if len(report.Blockers) > 24 {
		return errors.New("network readiness report exceeds bound")
	}
	if state, err := readNetworkState(e.Config.StateDir); err == nil {
		fillNetworkActiveState(&report, state, e.now())
	} else {
		return err
	}
	return atomicJSON(networkReportPath(e.Config.StateDir), report)
}
func (e *networkControlEngine) feature(report *NetworkControlReport, request networkControlRequest, status string, cause error) {
	value := &report.Egress
	if request.Kind == "quarantine" {
		value = &report.Quarantine
	}
	value.ID = request.ID
	value.PlanDigest = request.Digest
	value.Generation = request.Generation
	value.Status = status
	value.Error = ""
	if cause != nil {
		value.Error = boundedSourceBankError(cause)
	}
	if request.Quarantine != nil && request.Quarantine.Operation == "enable" {
		expiry := request.Quarantine.ExpiresAt
		value.ExpiresAt = &expiry
	}
	report.CheckedAt = e.now()
}

func (e *networkControlEngine) process(ctx context.Context, p *Policy, request networkControlRequest) (bool, error) {
	state, err := readNetworkState(e.Config.StateDir)
	if err != nil {
		return false, err
	}
	priorReport := ReadNetworkControlReport(e.Config.StateDir)
	if priorReport != nil {
		feature := priorReport.Egress
		if request.Kind == "quarantine" {
			feature = priorReport.Quarantine
		}
		if feature.ID == request.ID {
			if feature.PlanDigest != request.Digest {
				return false, errors.New("network request identity reused with changed content")
			}
			switch feature.Status {
			case "assessed", "enforced", "removed", "quarantined", "released", "expired", "rolled_back", "error", "blocked":
				return false, nil
			}
		}
	}
	minimum := state.EgressGeneration
	if request.Kind == "quarantine" {
		minimum = state.QuarantineGeneration
	}
	if request.Generation <= minimum {
		return false, errors.New("stale network-control generation rejected")
	}
	contextValue, assessmentErr := e.Assess(ctx)
	report := contextValue.Report
	if priorReport != nil {
		report.Egress = mergeNetworkOutcome(report.Egress, priorReport.Egress)
		report.Quarantine = mergeNetworkOutcome(report.Quarantine, priorReport.Quarantine)
	}
	assess := request.Egress != nil && request.Egress.Operation == "assess" || request.Quarantine != nil && request.Quarantine.Operation == "assess"
	if assess {
		status := "assessed"
		if assessmentErr != nil {
			status = "blocked"
		}
		e.feature(&report, request, status, assessmentErr)
		if request.Kind == "egress" {
			state.EgressGeneration = request.Generation
		} else {
			state.QuarantineGeneration = request.Generation
		}
		if err := atomicJSON(networkStatePath(e.Config.StateDir), state); err != nil {
			return true, err
		}
		if err := e.saveReport(report); err != nil {
			return true, err
		}
		return true, assessmentErr
	}
	fail := func(cause error) (bool, error) {
		e.feature(&report, request, "blocked", cause)
		if err := e.saveReport(report); err != nil {
			return true, err
		}
		return true, cause
	}
	if assessmentErr != nil {
		return fail(assessmentErr)
	}
	feature := report.Egress
	if request.Kind == "quarantine" {
		feature = report.Quarantine
	}
	if !feature.Supported || !feature.Ready {
		return fail(errors.New("native feature readiness is not verified: " + feature.Error))
	}
	if request.ContextDigest != report.ContextDigest || request.ProtectionDigest != contextValue.Protection.Digest {
		return fail(errors.New("native host/protected management context changed; obtain a new GUI assessment and review"))
	}
	if request.Kind == "egress" && state.Quarantine != nil && state.Quarantine.ExpiresAt.After(e.now()) {
		return fail(errors.New("release emergency quarantine before changing ordinary outbound policy"))
	}
	if e.Health == nil || e.Arm == nil {
		return fail(errors.New("independent rollback and fresh controller/SSH witness are required"))
	}
	if err := e.Health(ctx, request, contextValue); err != nil {
		return fail(err)
	}
	if err := checkNewEnforcementJournalBudget(e.Config.StateDir, "network-control"); err != nil {
		return fail(err)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fail(err)
	}
	nonce := hex.EncodeToString(raw)
	deadline := e.now().Add(120 * time.Second)
	if request.ApprovalExpiresAt.Before(deadline) {
		deadline = request.ApprovalExpiresAt
	}
	if request.Quarantine != nil && request.Quarantine.Operation == "enable" && request.Quarantine.ExpiresAt.Before(deadline) {
		deadline = request.Quarantine.ExpiresAt
	}
	if deadline.Before(e.now().Add(30 * time.Second)) {
		return fail(errors.New("network review authority expires too soon for safe apply"))
	}
	stageCtx, stageCancel := context.WithDeadline(ctx, deadline)
	defer stageCancel()
	ctx = stageCtx
	before := cloneNetworkState(state)
	journal := &networkControlJournal{SchemaVersion: 1, Nonce: nonce, Kind: request.Kind, Phase: "prepared", PID: os.Getpid(), ProcessIdentity: processIdentity(os.Getpid()), Deadline: deadline, DeadlineBootSeconds: bootElapsedSeconds() + deadline.Sub(e.now()).Seconds(), Before: before, After: cloneNetworkState(state), Request: request, Report: report}
	if request.Kind == "egress" {
		journal.After.EgressGeneration = request.Generation
	} else {
		journal.After.QuarantineGeneration = request.Generation
	}
	path := networkJournalPath(e.Config.StateDir, nonce)
	if err := atomicJSON(path, journal); err != nil {
		return fail(err)
	}
	if err := e.Arm(ctx, path, journal, false); err != nil {
		journal.Phase = "rolled_back"
		journal.Error = boundedSourceBankError(err)
		_ = atomicJSON(path, journal)
		return fail(err)
	}
	rollback := func(cause error) (bool, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cleanup = withManagedLease(cleanup, managedLeaseFromContext(ctx))
		journal.Error = boundedSourceBankError(cause)
		if err := rollbackNetworkJournal(cleanup, e.Commands, e.Config.StateDir, path, journal); err != nil {
			if request.Kind == "egress" {
				report.Egress.Ready = false
			} else {
				report.Quarantine.Ready = false
			}
			report.Blockers = append(report.Blockers, "Network rollback is unverified; current access state requires review.")
			e.feature(&report, request, "error", fmt.Errorf("rollback could not be verified: %w", err))
			_ = e.saveReport(report)
			return true, err
		}
		e.feature(&report, request, "rolled_back", cause)
		_ = e.saveReport(report)
		return true, cause
	}
	if request.Kind == "egress" {
		err = e.applyEgress(ctx, path, journal, contextValue)
	} else {
		err = e.applyQuarantine(ctx, p, path, journal, contextValue)
	}
	if err != nil {
		return rollback(err)
	}
	post, err := e.Assess(ctx)
	if err != nil || post.Report.ContextDigest != request.ContextDigest {
		if err == nil {
			err = errors.New("protected host topology changed during network apply")
		}
		return rollback(err)
	}
	if err := e.Health(ctx, request, post); err != nil {
		return rollback(err)
	}
	if request.Quarantine != nil && request.Quarantine.Operation == "enable" && !e.now().Before(request.Quarantine.ExpiresAt) {
		return rollback(errors.New("original quarantine lease expired before commit"))
	}
	if err := atomicJSON(networkStatePath(e.Config.StateDir), journal.After); err != nil {
		return rollback(err)
	}
	journal.Phase = "committed"
	committedAt := e.now()
	journal.CommittedAt = &committedAt
	if err := atomicJSON(path, journal); err != nil {
		return rollback(err)
	}
	status := "enforced"
	if request.Egress != nil && request.Egress.Operation == "remove" {
		status = "removed"
	}
	if request.Quarantine != nil {
		status = "quarantined"
		if request.Quarantine.Operation == "disable" {
			status = "released"
		}
	}
	e.feature(&report, request, status, nil)
	if err := e.saveReport(report); err != nil {
		return true, err
	}
	return true, nil
}

func fillNetworkActiveState(report *NetworkControlReport, state *networkControlState, now time.Time) {
	report.Egress.Active = state.Egress != nil
	report.Egress.ActiveID = ""
	report.Egress.ActivePlanDigest = ""
	report.Egress.ActiveGeneration = 0
	report.Egress.ActiveExpiresAt = nil
	if state.Egress != nil {
		report.Egress.ActiveID = state.Egress.ID
		report.Egress.ActivePlanDigest = state.Egress.PlanDigest
		report.Egress.ActiveGeneration = state.Egress.Generation
	}
	report.Quarantine.Active = state.Quarantine != nil && now.Before(state.Quarantine.ExpiresAt)
	report.Quarantine.ActiveID = ""
	report.Quarantine.ActivePlanDigest = ""
	report.Quarantine.ActiveGeneration = 0
	report.Quarantine.ActiveExpiresAt = nil
	if state.Quarantine != nil {
		report.Quarantine.ActiveID = state.Quarantine.ID
		report.Quarantine.ActivePlanDigest = state.Quarantine.PlanDigest
		report.Quarantine.ActiveGeneration = state.Quarantine.Generation
		expiry := state.Quarantine.ExpiresAt
		report.Quarantine.ActiveExpiresAt = &expiry
	}
}
func mergeNetworkOutcome(fresh, previous NetworkFeatureReport) NetworkFeatureReport {
	fresh.ID = previous.ID
	fresh.PlanDigest = previous.PlanDigest
	fresh.Generation = previous.Generation
	fresh.ExpiresAt = previous.ExpiresAt
	if previous.Status != "ready" && previous.Status != "blocked" {
		fresh.Status = previous.Status
	}
	if !fresh.Ready && (previous.Active || previous.Status == "enforced" || previous.Status == "quarantined") {
		fresh.Status = "unverified"
	}
	return fresh
}

func (e *networkControlEngine) applyEgress(ctx context.Context, path string, journal *networkControlJournal, native networkNativeContext) error {
	request := journal.Request.Egress
	before := journal.Before.EgressRules
	if err := verifyOwnedEgressPolicy(ctx, e.Commands, e.Config.StateDir, before); err != nil {
		return err
	}
	after, err := egressRichRules(request, native.Report.ProtectedEgress, native.Protection.ManagementSources, native.Protection.SSHPorts)
	if err != nil {
		return err
	}
	journal.After.EgressRules = after
	journal.After.Egress = request
	journal.After.EgressNonce = journal.Nonce
	if request.Operation == "remove" {
		journal.After.Egress = nil
	}
	if err := atomicJSON(path, journal); err != nil {
		return err
	}
	beforeSet := map[string]bool{}
	afterSet := map[string]bool{}
	for _, rule := range before {
		beforeSet[rule] = true
	}
	for _, rule := range after {
		afterSet[rule] = true
	}
	add := []string{}
	remove := []string{}
	for _, rule := range after {
		if !beforeSet[rule] {
			add = append(add, rule)
		}
	}
	for _, rule := range before {
		if !afterSet[rule] {
			remove = append(remove, rule)
		}
	}
	// Allows precede newly introduced rejects. The final set is read back in
	// both scopes; a duplicate existing rule is a successful no-op.
	sort.SliceStable(add, func(i, j int) bool {
		return strings.HasSuffix(add[i], " accept") && !strings.HasSuffix(add[j], " accept")
	})
	for _, group := range []struct {
		rules   []string
		present bool
	}{{add, true}, {remove, false}} {
		for _, rule := range group.rules {
			for _, scope := range []string{"runtime", "permanent"} {
				if !e.now().Before(journal.Deadline.Add(-5 * time.Second)) {
					return errors.New("network rollback deadline approaching")
				}
				mutation := networkRuleMutation{Scope: scope, Rule: rule, Before: !group.present, After: group.present}
				journal.Mutations = append(journal.Mutations, mutation)
				if err := atomicJSON(path, journal); err != nil {
					return err
				}
				operation := "--remove-rich-rule="
				if group.present {
					operation = "--add-rich-rule="
				}
				if _, err := e.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+egressPolicyName, operation+rule)...); err != nil {
					return errors.New("owned outbound rich-rule update failed")
				}
			}
		}
	}
	return verifyOwnedEgressPolicy(ctx, e.Commands, e.Config.StateDir, after)
}

func (e *networkControlEngine) applyQuarantine(ctx context.Context, p *Policy, path string, journal *networkControlJournal, native networkNativeContext) error {
	request := journal.Request.Quarantine
	handle, err := verifyQuarantineTable(ctx, e.Commands, journal.Before.QuarantinePlan, e.now(), journal.Before.QuarantinePlan != nil && !journal.Before.QuarantinePlan.ExpiresAt.After(e.now()))
	if err != nil {
		return err
	}
	journal.BeforeTableHandle = handle
	objects := []map[string]any{}
	if request.Operation == "enable" {
		authority, err := json.Marshal(p)
		if err != nil || len(authority) > 1024*1024 {
			return errors.New("signed assignment exceeds the bounded durable quarantine journal budget")
		}
		remaining := request.ExpiresAt.Sub(e.now())
		if remaining < 30*time.Second || remaining > time.Hour {
			return errors.New("quarantine lease expires too soon")
		}
		plan := &quarantinePlan{Nonce: journal.Nonce, ExpiresAt: request.ExpiresAt, Protected: native.Report.ProtectedEgress, ManagementSources: native.Protection.ManagementSources, SSHPorts: native.Protection.SSHPorts, LeaseSeconds: int64(remaining / time.Second)}
		objects, err = quarantineNFTObjects(*plan, time.Duration(plan.LeaseSeconds)*time.Second)
		if err != nil {
			return err
		}
		journal.After.QuarantinePlan = plan
		journal.After.Quarantine = request
		journal.After.QuarantineAuthority = p
		journal.After.QuarantineNonce = journal.Nonce
	} else {
		journal.After.QuarantinePlan = nil
		journal.After.Quarantine = nil
		journal.After.QuarantineAuthority = nil
		journal.After.QuarantineNonce = ""
	}
	if err := atomicJSON(path, journal); err != nil {
		return err
	}
	if err := runQuarantineBatch(ctx, e.Commands, e.Config.StateDir, journal.Nonce, objects, handle, true); err != nil {
		return err
	}
	if request.Operation == "enable" {
		if e.PrepareBoot == nil {
			return errors.New("independent boot reconciliation is unavailable")
		}
		if err := e.PrepareBoot(ctx); err != nil {
			return err
		}
		if err := e.Arm(ctx, path, journal, true); err != nil {
			return err
		}
		// JSON set timeouts are SECONDS, not milliseconds. Recompute after
		// preparation and leave a command-time safety margin; kernel expiry
		// must never extend the original reviewed deadline.
		remaining := request.ExpiresAt.Sub(e.now())
		if remaining < 8*time.Second {
			return errors.New("quarantine lease expired during local preparation")
		}
		journal.After.QuarantinePlan.LeaseSeconds = int64(remaining/time.Second) - 4
		objects, err = quarantineNFTObjects(*journal.After.QuarantinePlan, time.Duration(journal.After.QuarantinePlan.LeaseSeconds)*time.Second)
		if err != nil {
			return err
		}
	}
	journal.TableMutationAttempted = true
	if err := atomicJSON(path, journal); err != nil {
		return err
	}
	if handle != "" || len(objects) > 0 {
		if err := runQuarantineBatch(ctx, e.Commands, e.Config.StateDir, journal.Nonce, objects, handle, false); err != nil {
			return err
		}
	}
	_, err = verifyQuarantineTable(ctx, e.Commands, journal.After.QuarantinePlan, e.now(), false)
	return err
}

func (a *Agent) networkEngine() *networkControlEngine {
	return &networkControlEngine{Commands: a.Commands, Config: a.Config, Now: a.currentTime, Assess: a.assessNetworkControl, Health: a.networkControlHealth, Arm: armNetworkControlTimer, PrepareBoot: func(ctx context.Context) error { return prepareQuarantineBoot(ctx, a.Commands, a.Config) }}
}

func (a *Agent) processNetworkControls(ctx context.Context, p *Policy) (bool, error) {
	if p == nil {
		return false, nil
	}
	if p.EgressBundle == nil && p.Quarantine == nil {
		state, err := readNetworkState(a.Config.StateDir)
		if err != nil {
			return false, err
		}
		return state.Quarantine != nil && state.Quarantine.ExpiresAt.After(a.currentTime()), nil
	}
	if a.Simulate || runtime.GOOS != "linux" {
		return true, errors.New("native Linux network control is unavailable")
	}
	strict := a.Config
	strict.Enforce = true
	if err := ValidatePolicySignature(strict, p); err != nil {
		return true, err
	}
	if err := a.validateAssignmentIdentity(p); err != nil {
		return true, err
	}
	if err := a.validateAssignmentReplay(p, a.currentTime()); err != nil {
		return true, err
	}
	requests := []networkControlRequest{}
	if p.Quarantine != nil {
		if err := validateQuarantineAssignment(a.Config, p.ServerID, p.Quarantine, a.currentTime()); err != nil {
			return true, err
		}
		requests = append(requests, quarantineRequest(p.Quarantine))
	}
	if p.EgressBundle != nil {
		if err := validateEgressAssignment(a.Config, p.ServerID, p.EgressBundle, a.currentTime()); err != nil {
			return true, err
		}
		requests = append(requests, egressRequest(p.EgressBundle))
	}
	configuration, err := configurationLeaseUnder("", 0)
	if err != nil {
		return true, errors.New("endpoint configuration maintenance is active")
	}
	defer configuration.Close()
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return true, err
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if err := a.recoverAllEnforcementLocked(ctx); err != nil {
		return true, err
	}
	if err := recoverNetworkJournalsLocked(ctx, a.Commands, a.Config.StateDir); err != nil {
		return true, err
	}
	engine := a.networkEngine()
	handled := false
	for _, request := range requests {
		changed, err := engine.process(ctx, p, request)
		handled = handled || changed
		if err != nil {
			return true, err
		}
	}
	state, err := readNetworkState(a.Config.StateDir)
	if err != nil {
		return true, err
	}
	return handled || state.Quarantine != nil && state.Quarantine.ExpiresAt.After(a.currentTime()), nil
}

type networkControlWitness struct {
	Kind                string    `json:"kind"`
	ID                  string    `json:"id"`
	PlanDigest          string    `json:"plan_digest"`
	Generation          int       `json:"generation"`
	ProtectionDigest    string    `json:"protection_digest"`
	ContextDigest       string    `json:"context_digest"`
	ConfigurationDigest string    `json:"configuration_digest"`
	ServerID            string    `json:"server_id"`
	Nonce               string    `json:"nonce"`
	CheckedAt           time.Time `json:"checked_at"`
	Status              string    `json:"status"`
	ControllerOK        bool      `json:"controller_ok"`
	SSHChecks           []struct {
		TargetIP          string `json:"target_ip"`
		Port              int    `json:"port"`
		SourceIP          string `json:"source_ip"`
		SSHBannerVerified bool   `json:"ssh_banner_verified"`
	} `json:"ssh_checks"`
}

func (a *Agent) networkControlHealth(ctx context.Context, request networkControlRequest, native networkNativeContext) error {
	if a.Client == nil || a.Client.simulate {
		return errors.New("fresh native mTLS network witness is unavailable")
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	fresh, err := NewClient(a.Config, false)
	if err != nil {
		return err
	}
	transport, ok := fresh.HTTP.Transport.(*http.Transport)
	if !ok {
		return errors.New("fresh native TLS transport unavailable")
	}
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	body := map[string]any{"kind": request.Kind, "id": request.ID, "plan_digest": request.Digest, "generation": request.Generation, "protection_digest": request.ProtectionDigest, "context_digest": request.ContextDigest, "nonce": nonce, "ssh_ports": native.Protection.SSHPorts}
	response, err := fresh.request(ctx, "POST", "/api/v1/agent/network-control/check", body, "")
	if err != nil {
		return err
	}
	var witness networkControlWitness
	if err := decodeResponse(response, &witness); err != nil {
		return err
	}
	return a.validateNetworkControlWitness(witness, request, native, nonce, a.currentTime())
}
func (a *Agent) validateNetworkControlWitness(w networkControlWitness, r networkControlRequest, native networkNativeContext, nonce string, now time.Time) error {
	if a.State.Policy == nil || w.ServerID != a.State.Policy.ServerID || w.Kind != r.Kind || w.ID != r.ID || w.PlanDigest != r.Digest || w.Generation != r.Generation || w.ProtectionDigest != r.ProtectionDigest || w.ContextDigest != r.ContextDigest || w.ConfigurationDigest != configDigest(a.Config) || w.Nonce != nonce || w.Status != "healthy" || !w.ControllerOK || w.CheckedAt.Before(now.Add(-30*time.Second)) || w.CheckedAt.After(now.Add(5*time.Second)) {
		return errors.New("fresh network-control witness identity/context mismatch")
	}
	allowed := map[string]bool{}
	if a.inventory != nil {
		for _, address := range a.inventory.IPs {
			allowed[address] = true
		}
	}
	verified := map[int]bool{}
	for _, check := range w.SSHChecks {
		source, err := netip.ParseAddr(check.SourceIP)
		if err != nil || !check.SSHBannerVerified || !allowed[check.TargetIP] {
			continue
		}
		for _, raw := range native.Protection.ManagementSources {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil && prefix.Contains(source) {
				verified[check.Port] = true
			}
		}
	}
	if len(native.Protection.SSHPorts) == 0 {
		return errors.New("actual SSH listeners are unavailable for the network witness")
	}
	for _, port := range native.Protection.SSHPorts {
		if !verified[port] {
			return errors.New("fresh protected SSH-banner checks did not verify every actual SSH port")
		}
	}
	return nil
}

func (a *Agent) recoverNetworkControls(ctx context.Context) error {
	if a.Simulate {
		return nil
	}
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return err
	}
	err = recoverNetworkJournalsLocked(withManagedLease(ctx, lock), a.Commands, a.Config.StateDir)
	unlockManaged(lock)
	if err != nil {
		return err
	}
	state, err := readNetworkState(a.Config.StateDir)
	if err != nil || state.Quarantine == nil {
		return err
	}
	return RestoreQuarantine(a.Config.StateDir, a.Commands)
}
