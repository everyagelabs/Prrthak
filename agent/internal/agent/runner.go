package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Agent struct {
	firewallActivation                   *firewallActivationHooks
	policyVerificationTimestampAvailable func() bool
	checkSourceBankHealth                func(context.Context, *Policy, *SourceBankPreparationAssignment, Protection) error
	sourceBankConfigDigest               func() (string, error)
	sourceBankConfigurationLease         func() (*os.File, error)
	sourceBankHeartbeatAt                time.Time
	sourceBankSkipInventory              bool
	sourceBankOwnedRulesOverride         []ManagedRule
	fastDiscoveryEnabled                 bool
	nextFastDiscovery                    time.Time
	fastListenerFingerprint              string
	fastDiscoveryReport                  FastDiscoveryReport
	listenerSnapshot                     func(context.Context) (listenerSnapshot, error)
	trafficCapture                       nativeCapture
	trafficMinuteSamples                 trafficMinuteSampler
	nextCaptureCheck                     time.Time
	captureCoverage                      TrafficCaptureCoverage
	captureScopeKey                      string
	timingMu                             sync.RWMutex
	resourceSampler                      agentResourceSampler
	managedOptOutRulesPresent            *bool
	managedOptOutRemovalAttested         bool
	remotePolling                        *PollingSettings
	pollingError                         string
	checkLearningHealth                  func(context.Context, *LearningAllow, Protection, string) error
	protection                           *Protection
	protectionDiscoverySequence          uint64
	armManaged                           func(context.Context, string, *managedJournal) error
	checkManagedHealth                   func(context.Context, *Policy, Protection, string) error
	Config                               Config
	Client                               *Client
	checkFirewallAuthorization           func(context.Context, FirewallChange, string) error
	Commands                             CommandRunner
	State                                State
	Simulate                             bool
	SimulateHostname                     string
	Generation                           string
	confirmed                            bool
	applyError                           string
	collectorError                       string
	nextRuleCheck                        time.Time
	inventory                            *Report
	lastDiscoveryAttempt                 time.Time
	lastFullDiscoveryAttempt             time.Time
	lastDiscoverySuccess                 time.Time
	forceDiscovery                       bool
	discoveryPending                     bool
	discoverySequence                    uint64
	learningDiscoveryAttempts            map[string]time.Time
	clock                                func() time.Time
	firewallRecoveryError                string
	AdditionalObservationRules           func() []OwnedRule
	probe                                *ProbeMonitor
	hitMonitor                           *HitMonitor
	lastProbeError                       string
}

func New(c Config, simulate bool, hostname string) (*Agent, error) {
	if simulate {
		for _, directory := range []string{filepath.Join(c.StateDir, "managed"), filepath.Join(c.StateDir, "firewall-changes"), filepath.Join(c.StateDir, "learning-allow")} {
			entries, err := os.ReadDir(directory)
			if err == nil && len(entries) > 0 {
				return nil, errors.New("simulation requires a separate state_dir; real firewall mutation history exists")
			}
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		}
		for _, identityPath := range []string{c.Certificate, c.PrivateKey} {
			if identityPath != "" {
				if _, err := os.Stat(identityPath); err == nil {
					return nil, errors.New("simulation requires a separate state_dir and identity paths")
				}
			}
		}
	}
	if e := os.MkdirAll(c.StateDir, 0700); e != nil {
		return nil, e
	}
	client, e := NewClient(c, simulate)
	if e != nil {
		return nil, e
	}
	a := &Agent{Config: c, Client: client, Commands: ExecRunner{}, Simulate: simulate, SimulateHostname: hostname, State: State{Coverage: map[string]*Coverage{}, Rules: []OwnedRule{}}}
	b, e := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
	if e == nil {
		if e = json.Unmarshal(b, &a.State); e != nil {
			return nil, fmt.Errorf("invalid cached state: %w", e)
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if state := a.State.PolicyVerification; state != nil && state.Report.ArmedAt != nil {
		a.invalidatePolicyVerification("The agent restarted; previous traffic evidence is historical. Request a fresh observation lease.")
	}
	a.loadPollingSettings()
	if a.State.Coverage == nil {
		a.State.Coverage = map[string]*Coverage{}
	}
	if a.State.PendingDrains == nil {
		a.State.PendingDrains = map[string]Session{}
	}
	if a.State.Policy != nil {
		if e = a.validateAssignmentIdentity(a.State.Policy); e != nil && !simulate && client.identity.Load() != nil {
			return nil, fmt.Errorf("invalid cached endpoint binding: %w", e)
		}
		if e = ValidatePolicy(a.State.Policy); e != nil {
			return nil, fmt.Errorf("invalid cached policy: %w", e)
		}
	}
	if e = a.ensureProbe(); e != nil {
		return nil, e
	}
	if e = a.ensureHitMonitor(); e != nil {
		return nil, e
	}
	a.Generation, e = PrepareReadiness(c)
	if e != nil {
		return nil, e
	}
	return a, nil
}
func (a *Agent) save() error {
	a.enrichManagedStatus()
	a.enrichLearningOutcome()
	return atomicJSON(filepath.Join(a.Config.StateDir, "state.json"), a.State)
}
func (a *Agent) ensureProbe() error {
	if a.probe == nil {
		monitor, err := NewProbeMonitor(a.Config.StateDir, ProbeSettings{Enabled: a.Config.UnexpectedPortMonitorEnabled, RatePerSecond: a.Config.ProbeLogRatePerSecond, Zone: a.Config.Zone}, a.Commands, a.Simulate)
		if err != nil {
			return err
		}
		a.probe = monitor
		previous := a.AdditionalObservationRules
		a.AdditionalObservationRules = func() []OwnedRule {
			rules := monitor.OwnedRules()
			if previous != nil {
				rules = append(rules, previous()...)
			}
			return rules
		}
	}
	a.probe.commands = a.Commands
	return nil
}
func (a *Agent) Shutdown(ctx context.Context) error {
	if state := a.State.PolicyVerification; state != nil && state.Report.ArmedAt != nil {
		a.invalidatePolicyVerification("The observer stopped; previous traffic evidence is historical. Request a fresh observation lease.")
	}
	var first error
	if a.trafficCapture != nil {
		lock, err := managedLock(a.Config.StateDir, true)
		if err == nil {
			err = clearTrafficCaptureSidecars(withManagedLease(ctx, lock), a.Config.StateDir, a.Commands)
			unlockManaged(lock)
		}
		if err != nil {
			first = err
		}
		if err := a.trafficCapture.Close(); err != nil && first == nil {
			first = err
		}
		flows, coverage := a.trafficCapture.Drain()
		a.captureCoverage = coverage
		if err := a.storeCapturedFlows(flows); err != nil && first == nil {
			first = err
		}
		a.trafficCapture = nil
	}
	if a.probe != nil {
		if err := a.probe.Close(ctx); err != nil && first == nil {
			first = err
		}
	}
	if a.hitMonitor != nil {
		if err := a.hitMonitor.Close(ctx); err != nil && first == nil {
			first = err
		}
	}
	now := time.Now().UTC()
	for _, rule := range a.State.Rules {
		if session, ok := a.sessionByID(rule.SessionID); ok {
			cutoff := SessionCutoff(session)
			if now.Before(cutoff) {
				cutoff = now
			}
			a.queueDrain(session, cutoff)
		}
	}
	if e := a.drainJournal(ctx, nil, now); e != nil {
		first = e
	}
	failed := []OwnedRule{}
	if !a.Simulate {
		for _, rule := range a.State.Rules {
			if e := RemoveObservation(ctx, a.Commands, rule); e != nil {
				failed = append(failed, rule)
				if first == nil {
					first = e
				}
			}
		}
	}
	a.State.Rules = failed
	// Read again after rule removal so the final kernel messages are not abandoned.
	if e := a.drainJournal(ctx, nil, time.Now().UTC()); e != nil && first == nil {
		first = e
	}
	for id, cov := range a.State.Coverage {
		if cov.EndedAt == nil {
			end := now
			if session, ok := a.State.PendingDrains[id]; ok && SessionCutoff(session).Before(end) {
				end = SessionCutoff(session)
			}
			cov.EndedAt = &end
		}
	}
	if e := a.save(); e != nil {
		return e
	}
	return first
}
func (a *Agent) Startup(ctx context.Context) error {
	// Remove saved learning instrumentation before fetching fresh session assignments.
	if e := a.Shutdown(ctx); e != nil {
		log.Printf("startup cleanup: %v (firewalld timeout remains the fallback)", e)
	}
	a.State.Cursor = ""
	a.State.JournalSince = time.Now().UTC()
	if e := a.recoverNetworkControls(ctx); e != nil {
		return fmt.Errorf("network controls recovery failed: %w", e)
	}
	if e := a.recoverFirewallChanges(ctx); e != nil {
		a.firewallRecoveryError = e.Error()
		log.Printf("approved firewall-change recovery: %v", e)
	}
	if e := a.recoverManaged(ctx); e != nil {
		return fmt.Errorf("managed enforcement recovery failed: %w", e)
	}
	if !a.Simulate {
		lock, e := managedLock(a.Config.StateDir, true)
		if e != nil {
			return e
		}
		e = clearTrafficCaptureSidecars(withManagedLease(ctx, lock), a.Config.StateDir, a.Commands)
		unlockManaged(lock)
		if e != nil {
			return e
		}
	}
	if e := a.restoreLearningEvidenceFromSpool(); e != nil {
		return e
	}
	return a.Client.Enroll(ctx)
}
func (a *Agent) Sync(ctx context.Context) error {
	if !a.Simulate {
		if e := a.Client.RenewIdentity(ctx); e != nil {
			log.Printf("certificate renewal pending: %v", e)
		}
	}
	if e := a.report(ctx); e != nil {
		return e
	}
	if a.agentUpgradeFenced() {
		return nil
	}
	// A candidate daemon must report successfully before its independent local
	// configuration transaction can commit. No firewall authority runs in that window.
	if configurationMutationBlocked(a.Config) {
		return nil
	}
	// The first report already acknowledges all pre-existing outcomes. Only an
	// assignment/discovery/result change needs another immediate receipt.
	previousReceipt := a.syncReceipt()
	if e := a.refreshAssignment(ctx); e != nil {
		return e
	}
	if a.State.Policy != nil {
		if e := ValidatePolicySignature(a.Config, a.State.Policy); e != nil {
			return e
		}
		if e := a.validateAssignmentIdentity(a.State.Policy); e != nil {
			return e
		}
		if e := a.validateAssignmentReplay(a.State.Policy, time.Now().UTC()); e != nil {
			return e
		}
		if !a.Simulate && a.State.Policy.CertificateRenewal != nil && a.State.Policy.Signature != nil && policySigningRequired(a.Config) {
			if e := a.Client.renewIdentity(ctx, a.State.Policy.CertificateRenewal); e != nil {
				log.Printf("scheduled certificate renewal pending: %v", e)
			}
		}
		if handled, err := a.processAgentUpgrade(ctx, a.State.Policy); handled || err != nil {
			if reportErr := a.report(ctx); reportErr != nil {
				return reportErr
			}
			return err
		}
		for _, process := range []func(context.Context, *Policy) (bool, error){a.processFirewallActivation, a.processNetworkControls} {
			if handled, err := process(ctx, a.State.Policy); handled {
				if reportErr := a.report(ctx); reportErr != nil {
					return reportErr
				}
				if err != nil {
					return err
				}
				return a.writeReadyStatus("ready", nil)
			}
		}
		if handled, err := a.processSourceBankPreparation(ctx, a.State.Policy); handled {
			if reportErr := a.report(ctx); reportErr != nil {
				return reportErr
			}
			if err != nil {
				return err
			}
			return a.writeReadyStatus("ready", nil)
		}
		if e := a.processManaged(ctx, a.State.Policy); e != nil {
			_ = a.report(ctx)
			return e
		}
		if e := a.processLearningAllow(ctx, a.State.Policy.LearningAllow); e != nil {
			_ = a.report(ctx)
			return e
		}
		if e := a.processApprovedChanges(ctx, a.State.Policy.FirewallChanges); e != nil {
			_ = a.report(ctx)
			return e
		}
		if e := a.preparePolicyVerification(ctx, a.State.Policy); e != nil {
			log.Printf("policy verification unavailable: %v", e)
		}
	}
	// A newly received automatic-learning request forces actual discovery here.
	// Fetch its per-host frozen ports immediately after the report acknowledgement.
	discoveryRequested := len(a.pendingLearningDiscovery(a.currentTime())) > 0
	if discoveryRequested || a.receiptChanged(previousReceipt) {
		if e := a.report(ctx); e != nil {
			return e
		}
	}
	if discoveryRequested {
		if e := a.refreshAssignment(ctx); e != nil {
			return e
		}
	}
	return a.writeReadyStatus("ready", nil)
}
func (a *Agent) refreshAssignment(ctx context.Context) error {
	p, etag, e := a.Client.Policy(ctx, a.State.ETag)
	if e != nil {
		return e
	}
	if p != nil {
		a.confirmed = false
		if e := ValidatePolicySignature(a.Config, p); e != nil {
			return e
		}
		if e := a.validateAssignmentIdentity(p); e != nil {
			return e
		}
		if e := a.validateAssignmentReplay(p, time.Now().UTC()); e != nil {
			return e
		}
		if e := a.rememberAssignmentSecurity(p, time.Now().UTC()); e != nil {
			return e
		}
		a.rememberLearningTransition(p, time.Now().UTC())
		a.State.Policy = p
		a.State.ETag = etag
		// The replay floor and session cutoffs must survive a crash before any
		// auxiliary setting, collection or access change is acted on.
		if e = a.save(); e != nil {
			return e
		}
		a.confirmed = true
		if err := a.acceptHitAssignments(p, time.Now().UTC()); err != nil {
			log.Printf("hit-monitor lease rejected: %v", err)
		}
		if err := a.applyPollingSettings(p.PollingSettings); err != nil {
			log.Printf("polling settings rejected: %v; retaining last valid timing", err)
		}
		plan := BuildPlan(p, a.Config)
		if e = atomicJSON(filepath.Join(a.Config.StateDir, "policy-plan.json"), plan); e != nil {
			return e
		}
		a.applyError = ""

		if e = a.save(); e != nil {
			return e
		}
	} else if a.State.Policy != nil {
		if e := a.validateAssignmentIdentity(a.State.Policy); e != nil {
			return e
		}
		if e := ValidatePolicySignature(a.Config, a.State.Policy); e != nil {
			return e
		}
		if e := a.validateAssignmentReplay(a.State.Policy, time.Now().UTC()); e != nil {
			return e
		}
		a.confirmed = true
	}
	return nil
}
func (a *Agent) report(ctx context.Context) error {
	if e := a.ensureProbe(); e != nil {
		return e
	}
	r := a.inventoryReport(ctx, a.currentTime())
	if len(a.captureCoverage.Backends) > 0 {
		coverage := a.captureCoverage
		r.TrafficCapture = &coverage
	}
	securityEvents, securityError := a.probe.Pending(time.Now().UTC())
	if securityError != nil {
		a.probe.state.Coverage.Status = "degraded"
		a.probe.state.Coverage.Error = "security observation spool unavailable"
	}
	r.SecurityEvents = securityEvents
	coverage := a.probe.Coverage()
	r.SecurityMonitor = &coverage
	if a.hitMonitor != nil {
		hitCoverage := a.hitMonitor.Coverage()
		r.HitMonitor = &hitCoverage
		r.HitMonitoring = a.hitMonitor.Statuses()
	}
	r.FirewallChangeResults = []FirewallChangeResult{}
	for _, result := range a.State.FirewallChangeResults {
		if !result.Acknowledged {
			r.FirewallChangeResults = append(r.FirewallChangeResults, result)
		}
	}
	r.ControlIntervalSeconds = a.controlIntervalSeconds()
	r.PollingSettings = a.pollingSettingsReport()
	r.AppliedVersion = a.State.AppliedVersion
	r.ApplyStatus = "preview"
	r.ApplyError = a.applyError
	if a.protection == nil || a.protectionDiscoverySequence != r.discoverySequence {
		protection := a.managedProtectionFromReport(r)
		a.enrichHostDefaultDenyProtection(ctx, &protection)
		a.protection = &protection
		a.protectionDiscoverySequence = r.discoverySequence
	}
	r.Protection = a.protection
	a.enrichManagedStatus()
	r.ManagedEnforcement = a.State.ManagedEnforcement
	a.enrichLearningOutcome()
	r.LearningAllowOutcome = a.State.LearningAllowOutcome
	if a.State.ManagedEnforcement != nil {
		r.ApplyStatus = managedApplyStatus(a.State.ManagedEnforcement.Status)
	}

	if a.collectorError != "" {
		if r.ApplyError != "" {
			r.ApplyError += "; "
		}
		r.ApplyError += "collector: " + a.collectorError
	}
	if a.State.SpoolError != "" {
		if r.ApplyError != "" {
			r.ApplyError += "; "
		}
		r.ApplyError += "traffic spool: " + a.State.SpoolError
	}
	now := time.Now().UTC()
	active := ActiveSessions(a.State.Policy, now)
	// Report installed instrumentation until cleanup is acknowledged, even if the
	// latest controller assignment has already removed/stopped the session.
	for _, rule := range a.State.Rules {
		if now.Before(rule.ExpiresAt) {
			r.CollectorStatus = "learning"
		}
	}
	// One summary per report; all session coverage remains persisted locally.
	for _, s := range active {
		if s.ObservationKinds != nil && a.confirmed {
			r.CollectorStatus = "learning"
		}
		if cov := a.State.Coverage[s.ID]; cov != nil {
			r.LearningCoverage = cov
			break
		}
	}
	if r.LearningCoverage == nil {
		for _, cov := range a.State.Coverage {
			if r.LearningCoverage == nil || cov.StartedAt.After(r.LearningCoverage.StartedAt) {
				r.LearningCoverage = cov
			}
		}
	}
	if e := a.Client.Report(ctx, r); e != nil {
		return e
	}
	a.ackInventoryReport(r)
	acked := map[string]bool{}
	for _, id := range a.Client.FirewallAcks {
		acked[id] = true
	}
	changedAcknowledgements := false
	for index, result := range a.State.FirewallChangeResults {
		if !result.Acknowledged && acked[result.ID] {
			for _, sent := range r.FirewallChangeResults {
				if sent.ID == result.ID && sent.PlanDigest == result.PlanDigest {
					a.State.FirewallChangeResults[index].Acknowledged = true
					changedAcknowledgements = true
					break
				}
			}
		}
	}
	if changedAcknowledgements {
		if e := a.save(); e != nil {
			return e
		}
	}
	if e := a.probe.Acknowledge(a.Client.SecurityAcks); e != nil {
		a.probe.state.Coverage.Status = "degraded"
		a.probe.state.Coverage.Error = "security receipt could not be persisted; observations may be replayed"
	}
	a.probe.Reported(time.Now().UTC(), coverage)
	if a.hitMonitor != nil {
		a.hitMonitor.Reported()
	}
	return nil
}
func (a *Agent) LearningTick(ctx context.Context, now time.Time) error {
	if configurationMutationBlocked(a.Config) {
		return nil
	}
	a.collectorError = ""
	if err := a.tickTrafficCapture(ctx, now); err != nil {
		a.collectorError = err.Error()
	}
	sessions := ActiveSessions(a.State.Policy, now)
	if !a.confirmed {
		sessions = nil
	}
	checkRules := !now.Before(a.nextRuleCheck)
	if checkRules {
		a.nextRuleCheck = now.Add(30 * time.Second)
	}
	active := map[string]Session{}
	for _, s := range sessions {
		if len(s.ObservationKinds) > 0 {
			continue
		}
		active[s.ID] = s
	}
	for _, rule := range a.State.Rules {
		if _, ok := active[rule.SessionID]; !ok || !now.Before(rule.ExpiresAt) {
			if session, found := a.sessionByID(rule.SessionID); found {
				a.queueDrain(session, SessionCutoff(session))
			}
		}
	}
	collectedThisTick := false
	if len(a.State.PendingDrains) > 0 {
		if e := a.drainJournal(ctx, sessions, now); e != nil {
			a.collectorError = e.Error()
		}
		collectedThisTick = true
	}
	kept := []OwnedRule{}
	for _, rule := range a.State.Rules {
		_, ok := active[rule.SessionID]
		if !ok || !now.Before(rule.ExpiresAt) {
			if !a.Simulate {
				if e := RemoveObservation(ctx, a.Commands, rule); e != nil {
					a.collectorError = e.Error()
					kept = append(kept, rule)
				}
			}
		} else {
			if checkRules && !a.Simulate {
				exists, e := ObservationExists(ctx, a.Commands, rule)
				if e != nil {
					a.collectorError = e.Error()
				} else if !exists {
					if cov := a.State.Coverage[rule.SessionID]; cov != nil {
						cov.Error = "observation rule disappeared; coverage gap possible before reinstall"
					}
					continue
				}
			}
			kept = append(kept, rule)
		}
	}
	a.State.Rules = kept
	for id, cov := range a.State.Coverage {
		if _, ok := active[id]; !ok && cov.EndedAt == nil {
			ended := now
			if stopping, ok := a.State.PendingDrains[id]; ok && SessionCutoff(stopping).Before(ended) {
				ended = SessionCutoff(stopping)
			}
			cov.EndedAt = &ended
		}
	}
	for _, s := range sessions {
		if len(s.ObservationKinds) > 0 {
			continue
		}
		if a.State.Coverage[s.ID] == nil {
			a.State.Coverage[s.ID] = &Coverage{SessionID: s.ID, StartedAt: now, RateLimited: true}
		} else if a.State.Coverage[s.ID].EndedAt != nil {
			cov := a.State.Coverage[s.ID]
			cov.Error = "collection resumed after a stop/restart; interval since " + cov.EndedAt.Format(time.RFC3339) + " may have missing events"
			cov.EndedAt = nil
		}
		for _, port := range s.Ports {
			exists := false
			ruleText := ObservationRule(s, port)
			for _, r := range a.State.Rules {
				if r.SessionID == s.ID && r.Rule == ruleText {
					exists = true
					break
				}
			}
			if exists {
				continue
			}
			zone := "simulated"
			var e error
			if !a.Simulate {
				zone, e = LearningZone(ctx, a.Config, a.Commands)
				if e != nil {
					a.collectorError = e.Error()
					a.State.Coverage[s.ID].Error = e.Error()
					continue
				}
			}
			intent := OwnedRule{s.ID, zone, ruleText, s.ExpiresAt}
			a.State.Rules = append(a.State.Rules, intent)
			if e = a.save(); e != nil {
				return e
			}
			if !a.Simulate {
				if _, e = AddObservation(ctx, a.Commands, zone, s, port, time.Now().UTC()); e != nil {
					a.State.Rules = a.State.Rules[:len(a.State.Rules)-1]
					a.collectorError = e.Error()
					a.State.Coverage[s.ID].Error = e.Error()
					continue
				}
			}
		}
	}
	if !collectedThisTick && len(sessions) > 0 && len(a.State.Rules) > 0 {
		if e := a.drainJournal(ctx, sessions, now); e != nil {
			a.collectorError = e.Error()
		}
	}
	return a.save()
}
func (a *Agent) Run(ctx context.Context, once bool) error {
	_ = a.writeReadyStatus("enrollment_pending", nil)
	// A newly launched binary proves its authenticated report before any
	// startup recovery or policy/capture tick can modify the firewall.
	if !a.awaitAgentUpgradeCommit(ctx) {
		return nil
	}
	for attempt := 0; ; attempt++ {
		if e := a.Startup(ctx); e != nil {
			_ = a.writeReadyStatus("enrollment_retrying", e)
			if once {
				return e
			}
			delay := BootstrapBackoff(attempt)
			delay += time.Duration(rand.Int64N(max(int64(1), int64(delay/5))))
			log.Printf("Prṛthak (पृथक्) enrollment pending; retrying in %s: %v", delay.Round(time.Second), e)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		break
	}
	if _, e := a.consumeDiscoveryRequest(); e != nil {
		log.Printf("manual service discovery request: %v", e)
	}
	if once {
		e := a.Sync(ctx)
		if e != nil {
			return e
		}
		return nil
	} // one-shot sync never leaves a background collector running.
	a.fastDiscoveryEnabled = !a.Simulate
	// Baseline precedes the first full inventory, closing the startup race.
	a.fastDiscoveryTick(ctx, a.currentTime())
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if e := a.Shutdown(cleanup); e != nil {
			log.Printf("shutdown cleanup: %v", e)
		}
	}()
	nextSync := time.Time{}
	nextFlush := time.Time{}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		now := time.Now().UTC()
		if a.agentUpgradeFenced() {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				continue
			}
		}
		fastChanged := a.fastDiscoveryTick(ctx, a.currentTime())
		if !now.Before(nextSync) {
			if e := a.Sync(ctx); e != nil {
				_ = a.writeReadyStatus("sync_retrying", e)
				log.Printf("sync failed: %v; cached access policy remains unchanged", e)
			}
			controlSeconds := a.controlIntervalSeconds()
			jitter := rand.IntN(max(1, controlSeconds/5))
			delay := time.Duration(controlSeconds+jitter) * time.Second
			if a.hitMonitor != nil && len(a.hitMonitor.active) > 0 && delay > 30*time.Second {
				delay = 30 * time.Second
			}
			if len(a.pendingLearningDiscovery(a.currentTime())) > 0 && delay > a.learningDiscoveryRetryInterval() {
				delay = a.learningDiscoveryRetryInterval()
			}
			nextSync = now.Add(delay)
			fastChanged = false // Sync already reports the exact pending scan.
		}
		if a.agentUpgradeFenced() {
			continue
		}
		if requested, e := a.consumeDiscoveryRequest(); e != nil {
			log.Printf("manual service discovery request: %v", e)
		} else if requested || a.discoveryDue(a.currentTime()) {
			if e = a.report(ctx); e != nil {
				log.Printf("manual service discovery report: %v", e)
			}
			fastChanged = false
		}
		if fastChanged {
			if e := a.report(ctx); e != nil {
				log.Printf("fast listener discovery report: %v", e)
			}
		}
		now = time.Now().UTC()
		if err := a.tickHitMonitor(ctx, now); err != nil {
			log.Printf("hit monitor: %v", err)
		}
		if a.hitMonitor != nil && a.hitMonitor.ShouldReport(now) {
			if err := a.report(ctx); err != nil {
				log.Printf("hit monitor outcome report: %v", err)
			}
		}
		if e := a.probe.Tick(ctx, now); e != nil {
			if e.Error() != a.lastProbeError {
				log.Printf("unexpected-port monitor: %v", e)
				a.lastProbeError = e.Error()
			}
		} else {
			a.lastProbeError = ""
		}
		if a.probe.ShouldReport(now) {
			if e := a.report(ctx); e != nil {
				log.Printf("security observation report: %v", e)
			}
		}
		beforeRules := len(a.State.Rules)
		beforeVerification := 0
		if a.State.PolicyVerification != nil {
			beforeVerification = a.State.PolicyVerification.Report.Sequence
		}
		if e := a.LearningTick(ctx, now); e != nil {
			log.Printf("learning: %v", e)
		}
		if beforeRules != len(a.State.Rules) {
			if e := a.report(ctx); e != nil {
				log.Printf("collector status acknowledgement: %v", e)
			}
		}
		if a.State.PolicyVerification != nil && a.State.PolicyVerification.Report.Sequence != beforeVerification {
			if e := a.report(ctx); e != nil {
				log.Printf("policy verification outcome report: %v", e)
			}
		}
		if !now.Before(nextFlush) {
			a.flushTrafficSpools(ctx, now)
			nextFlush = now.Add(10 * time.Second)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (a *Agent) flushTrafficSpools(ctx context.Context, now time.Time) {
	// Separate deadlines keep a blocked discovery upload from consuming the
	// other stream's slot or the policy poller's entire request timeout.
	if a.hitMonitor != nil {
		upload, cancel := context.WithTimeout(ctx, trafficUploadBudget)
		_, err := a.hitMonitor.Flush(upload, a.Client, now)
		cancel()
		if err != nil {
			log.Printf("hit upload: %v", err)
		}
	}
	upload, cancel := context.WithTimeout(ctx, trafficUploadBudget)
	_, err := FlushSpool(upload, a.Client, filepath.Join(a.Config.StateDir, "spool"), now)
	cancel()
	if err == nil {
		return
	}
	var dropped *DiscardedBatchError
	if errors.As(err, &dropped) {
		for _, loss := range dropped.Losses {
			if coverage := a.State.Coverage[loss.SessionID]; coverage != nil {
				coverage.DroppedEvents += loss.Count
				coverage.Error = loss.Reason
			}
		}
		a.State.SpoolError = dropped.Error()
		_ = a.save()
	}
	log.Printf("traffic upload: %v", err)
}
