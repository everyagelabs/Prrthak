package agent

import (
	"context"
	"errors"
	"time"
)

func (a *Agent) ensureHitMonitor() error {
	if a.hitMonitor == nil {
		maximum := a.Config.MaxSpoolBatches
		if maximum == 0 || maximum > 128 {
			maximum = 128
		}
		monitor, err := NewHitMonitor(a.Config.StateDir, a.Config.Zone, maximum, a.Commands, a.Simulate)
		if err != nil {
			return err
		}
		a.hitMonitor = monitor
		previous := a.AdditionalObservationRules
		a.AdditionalObservationRules = func() []OwnedRule {
			rules := monitor.OwnedRules()
			if previous != nil {
				rules = append(rules, previous()...)
			}
			return rules
		}
	}
	a.hitMonitor.commands = a.Commands
	a.hitMonitor.clock = a.currentTime
	return nil
}
func (a *Agent) acceptHitAssignments(p *Policy, at time.Time) error {
	if p == nil {
		return errors.New("fresh signed policy required for hit assignments")
	}
	if len(p.HitMonitors) > 0 && !policySigningRequired(a.Config) {
		return a.rejectHitAssignments(p, at, errors.New("hit monitoring requires independently pinned signed assignments"))
	}
	if len(p.HitMonitors) > 0 {
		if err := ValidatePolicySignature(a.Config, p); err != nil {
			return a.rejectHitAssignments(p, at, err)
		}
	}
	if len(p.HitMonitors) == 0 && a.hitMonitor == nil {
		return nil
	}
	if err := a.ensureHitMonitor(); err != nil {
		return err
	}
	// The caller has durably accepted signature, endpoint binding and replay
	// generation. A cached policy/304 never calls this lease acceptance method.
	if err := a.hitMonitor.SetAssignments(p.ServerID, p.HitMonitors, at); err != nil {
		return a.rejectHitAssignments(p, at, err)
	}
	return nil
}
func (a *Agent) rejectHitAssignments(p *Policy, at time.Time, cause error) error {
	if a.hitMonitor == nil {
		return cause
	}
	_ = a.hitMonitor.SetAssignments(p.ServerID, nil, at)
	a.hitMonitor.state.Rejections = map[string]string{}
	a.hitMonitor.state.LastAssigned = nil
	for index, item := range p.HitMonitors {
		if index >= maxHitMonitors {
			break
		}
		if hitID.MatchString(item.ID) {
			a.hitMonitor.state.Rejections[item.ID] = cause.Error()
			a.hitMonitor.state.LastAssigned = append(a.hitMonitor.state.LastAssigned, item.ID)
		}
	}
	a.hitMonitor.coverage.Status = "degraded"
	a.hitMonitor.coverage.Error = cause.Error()
	a.hitMonitor.updateStatuses(at, cause)
	_ = a.hitMonitor.save()
	return cause
}
func (a *Agent) tickHitMonitor(ctx context.Context, at time.Time) error {
	if a.hitMonitor == nil {
		return nil
	}
	a.hitMonitor.commands = a.Commands
	if configurationMutationBlocked(a.Config) {
		return a.hitMonitor.Close(ctx)
	}
	return a.hitMonitor.Tick(ctx, at)
}
