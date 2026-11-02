package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *Agent) nativeCaptureScopes(at time.Time) []capturePortScope {
	scopes := a.policyVerificationScopes(at)
	appendScope := func(scope capturePortScope) {
		if len(scopes) <= 2048 {
			scopes = append(scopes, scope)
		}
	}
	if a.confirmed {
		for _, session := range ActiveSessions(a.State.Policy, at) {
			for _, kind := range session.ObservationKinds {
				for _, port := range session.Ports {
					appendScope(capturePortScope{Port: port, Kind: kind, StartsAt: session.StartsAt, ExpiresAt: SessionCutoff(session)})
				}
			}
		}
	}
	if a.hitMonitor != nil {
		for _, assignment := range a.hitMonitor.active {
			if a.hitMonitor.remaining(assignment, at) <= 0 {
				continue
			}
			for _, kind := range assignment.ObservationKinds {
				for _, port := range assignment.Ports {
					appendScope(capturePortScope{Port: port, Kind: kind, StartsAt: assignment.StartsAt, ExpiresAt: assignment.ExpiresAt})
				}
			}
		}
	}
	return scopes
}
func (a *Agent) tickTrafficCapture(ctx context.Context, now time.Time) error {
	if a.Simulate {
		return nil
	}
	scopes := a.nativeCaptureScopes(now)
	if len(scopes) == 0 && a.trafficCapture == nil {
		if a.updatePolicyVerification(now, nil) {
			return a.save()
		}
		return nil
	}
	if a.trafficCapture == nil {
		a.trafficCapture = newNativeCapture()
	}
	var first error
	scopeRefused := false
	if err := a.trafficCapture.Configure(scopes); err != nil {
		first = err
		scopeRefused = errors.Is(err, errCaptureScope)
	}
	scopeKey := canonicalCaptureScope(scopes)
	if !now.Before(a.nextCaptureCheck) || len(scopes) == 0 || scopeKey != a.captureScopeKey {
		a.captureScopeKey = scopeKey
		a.nextCaptureCheck = now.Add(30 * time.Second)
		plannedScopes := scopes
		if scopeRefused {
			plannedScopes = nil
		}
		if err := a.reconcileCaptureSidecars(ctx, plannedScopes, now); err != nil {
			if first == nil {
				first = err
			}
			a.captureCoverage.Gaps = append(a.captureCoverage.Gaps, err.Error())
			if native, ok := a.trafficCapture.(interface{ SetDeniedFailure(string) }); ok {
				native.SetDeniedFailure(err.Error())
			}
		}
	}
	flows, coverage := a.trafficCapture.Drain()
	coverage.Gaps = append(coverage.Gaps, a.captureCoverage.Gaps...)
	if len(coverage.Gaps) > 16 {
		coverage.Gaps = coverage.Gaps[:16]
	}
	a.captureCoverage = coverage
	verificationChanged := a.observePolicyVerification(flows)
	verificationChanged = a.updatePolicyVerification(now, &coverage) || verificationChanged
	if err := a.storeCapturedFlows(flows); err != nil && first == nil {
		first = err
	}
	if verificationChanged {
		if err := a.save(); err != nil && first == nil {
			first = err
		}
	}
	a.updateCaptureReceipts(now, first)
	if len(scopes) == 0 {
		if err := a.trafficCapture.Close(); err != nil && first == nil {
			first = err
		}
		a.trafficCapture = nil
		a.nextCaptureCheck = time.Time{}
		a.captureScopeKey = ""
	}
	return first
}
func (a *Agent) reconcileCaptureSidecars(ctx context.Context, scopes []capturePortScope, now time.Time) error {
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return fmt.Errorf("NFLOG mutation lease unavailable: %w", err)
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	// This also removes any prior-process LOG-only instrumentation before a
	// new scope is admitted; orphan rules are bounded by native timeouts.
	if err = clearTrafficCaptureSidecars(ctx, a.Config.StateDir, a.Commands); err != nil {
		return err
	}
	rules, gaps, err := a.plannedCaptureSidecars(ctx, scopes, now)
	a.captureCoverage.Gaps = gaps
	controller, ok := a.trafficCapture.(interface{ SetDeniedPrefixes(uint16, []string) error })
	if err != nil {
		if ok {
			_ = controller.SetDeniedPrefixes(captureGroup(a.Config.StateDir), nil)
		}
		return err
	}
	prefixes := []string{}
	for _, rule := range rules {
		prefixes = append(prefixes, rule.Prefix)
	}
	if !ok {
		if len(rules) > 0 {
			return errors.New("NFLOG native collector is unavailable")
		}
		return nil
	}
	if err = controller.SetDeniedPrefixes(captureGroup(a.Config.StateDir), prefixes); err != nil {
		return err
	}
	if len(rules) == 0 {
		return nil
	}
	directory := filepath.Dir(captureSidecarPath(a.Config.StateDir))
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if _, err = setupPath(directory, true); err != nil {
		return err
	}
	state := captureSidecarState{Version: 1, Rules: rules}
	// Exact LOG-only intents are durable before the first native write, so
	// another access transaction can remove even an interrupted add safely.
	if err = atomicJSON(captureSidecarPath(a.Config.StateDir), state); err != nil {
		return err
	}
	for _, rule := range rules {
		seconds := int(time.Until(rule.ExpiresAt) / time.Second)
		if seconds < 1 || seconds > 120 {
			return errors.New("NFLOG lease expired before native instrumentation")
		}
		out, err := a.Commands.Run(ctx, "firewall-cmd", "--zone="+rule.Zone, "--add-rich-rule="+rule.text(), fmt.Sprintf("--timeout=%ds", seconds))
		if err != nil || strings.Contains(out, "ALREADY_ENABLED") {
			_ = clearTrafficCaptureSidecars(ctx, a.Config.StateDir, a.Commands)
			return errors.New("NFLOG rich language unavailable or instrumentation ownership conflicted; no journal fallback")
		}
		present, err := firewallQuery(ctx, a.Commands, "runtime", rule.Zone, "rich_rule", rule.text())
		if err != nil || !present {
			_ = clearTrafficCaptureSidecars(ctx, a.Config.StateDir, a.Commands)
			return errors.New("NFLOG rich-rule readback unavailable")
		}
	}
	return nil
}
func (a *Agent) storeCapturedFlows(flows []capturedFlow) error {
	for _, flow := range flows {
		if flow.VerificationOnly {
			normal := make([]capturedFlow, 0, len(flows))
			for _, item := range flows {
				if !item.VerificationOnly {
					normal = append(normal, item)
				}
			}
			flows = normal
			break
		}
	}
	if len(flows) == 0 {
		return nil
	}
	var first error
	if a.State.Coverage == nil {
		a.State.Coverage = map[string]*Coverage{}
	}
	sessions := map[string]Session{}
	for id, session := range a.State.PendingDrains {
		sessions[id] = session
	}
	if a.State.Policy != nil {
		for _, session := range append(append([]Session{}, a.State.Policy.LearningSessions...), a.State.Policy.LearningTombstones...) {
			if previous, ok := sessions[session.ID]; !ok || SessionCutoff(session).Before(SessionCutoff(previous)) {
				sessions[session.ID] = session
			}
		}
	}
	{
		for _, session := range sessions {
			items := []Flow{}
			for _, captured := range flows {
				if captureSelected(captured.Flow, session.ObservationKinds, session.Ports, session.StartsAt, SessionCutoff(session)) {
					flow := captured.Flow
					flow.EventID = shaText("prthak-learning-capture-v1\x00" + session.ID + "\x00" + flow.EventID)
					items = append(items, flow)
				}
			}
			if len(items) == 0 {
				continue
			}
			for len(items) > 0 {
				count := min(1000, len(items))
				part := append([]Flow{}, items[:count]...)
				batch := Batch{SessionID: session.ID, Events: part}
				raw, _ := json.Marshal(batch)
				batch.BatchID = shaText("prthak-native-learning-batch-v1\x00" + string(raw))
				if err := SpoolBatch(filepath.Join(a.Config.StateDir, "spool"), a.Config.MaxSpoolBatches, batch); err != nil {
					if first == nil {
						first = err
					}
					if a.State.Coverage[session.ID] != nil {
						a.State.Coverage[session.ID].DroppedEvents += count
					}
				} else {
					for _, flow := range part {
						rememberLearningEvidence(&a.State, session, flow)
					}
				}
				items = items[count:]
			}
		}
	}
	if m := a.hitMonitor; m != nil {
		matched := map[string]bool{}
		for index := len(m.state.Grants) - 1; index >= 0; index-- {
			grant := m.state.Grants[index]
			batch := HitBatch{MonitorID: grant.Assignment.ID, LeaseStartsAt: grant.Assignment.StartsAt, LeaseExpiresAt: grant.Assignment.ExpiresAt}
			for _, captured := range flows {
				key := grant.Assignment.ID + "/" + captured.EventID
				if !matched[key] && captureSelected(captured.Flow, grant.Assignment.ObservationKinds, grant.Assignment.Ports, grant.CaptureFrom, grant.CaptureUntil) {
					matched[key] = true
					flow := captured.Flow
					id := shaText("prthak-hit-capture-v1\x00" + grant.Assignment.ID + "\x00" + flow.EventID)
					flow.EventID = id
					batch.Events = append(batch.Events, HitEvent{EventID: id, Flow: flow})
				}
			}
			for len(batch.Events) > 0 {
				count := min(maxHitEvents, len(batch.Events))
				part := batch
				part.Events = append([]HitEvent{}, batch.Events[:count]...)
				part.BatchID = hitBatchDigest(part)
				if err := m.spool(part); err != nil {
					m.drop(count)
					if first == nil {
						first = err
					}
				}
				batch.Events = batch.Events[count:]
			}
		}
	}
	if err := a.save(); err != nil && first == nil {
		first = err
	}
	return first
}
func (a *Agent) updateCaptureReceipts(now time.Time, failure error) {
	if a.State.Coverage == nil {
		a.State.Coverage = map[string]*Coverage{}
	}
	for _, session := range ActiveSessions(a.State.Policy, now) {
		if session.ObservationKinds == nil {
			continue
		}
		if a.State.Coverage[session.ID] == nil {
			a.State.Coverage[session.ID] = &Coverage{SessionID: session.ID, StartedAt: now}
		}
		coverage := a.State.Coverage[session.ID]
		coverage.TrafficCaptureCoverage = scopedCaptureCoverage(session.ObservationKinds, a.captureCoverage)
		coverage.RateLimited = captureKindSelected(session.ObservationKinds, captureDenied)
		coverage.Error = ""
		for _, backend := range coverage.Backends {
			if backend.Status != "active" {
				coverage.Error = backend.Error
			}
		}
	}
	if m := a.hitMonitor; m != nil {
		for index := range m.state.Statuses {
			status := &m.state.Statuses[index]
			item, active := m.active[status.ID]
			if !active || item.ObservationKinds == nil {
				continue
			}
			status.TrafficCaptureCoverage = scopedCaptureCoverage(item.ObservationKinds, a.captureCoverage)
			status.Status = "observing"
			status.Error = ""
			status.CheckedAt = now
			for _, backend := range status.Backends {
				if backend.Status != "active" {
					status.Status = "error"
					status.Error = backend.Error
				}
			}
		}
		coverage := a.captureCoverage
		m.coverage.Capture = &coverage
		m.coverage.RateLimited = false
		for _, item := range m.active {
			if item.ObservationKinds == nil || captureKindSelected(item.ObservationKinds, captureDenied) {
				m.coverage.RateLimited = true
			}
		}
		m.coverage.CoverageLimited = len(coverage.Gaps) > 0
		_ = m.save()
	}
}
