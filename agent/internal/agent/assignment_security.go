package agent

import (
	"errors"
	"time"
)

func (a *Agent) validateAssignmentIdentity(p *Policy) error {
	if p == nil {
		return errors.New("missing endpoint assignment")
	}
	if !a.Simulate {
		if a.Client == nil || a.Client.identity == nil || a.Client.identity.Load() == nil || a.Client.identity.Load().Leaf == nil {
			return errors.New("authenticated local endpoint identity is unavailable")
		}
		if own := a.Client.identity.Load().Leaf.Subject.CommonName; own == "" || p.ServerID != own {
			return errors.New("signed assignment belongs to a different authenticated endpoint")
		}
	}
	if a.State.Policy != nil && p.ServerID != a.State.Policy.ServerID {
		return errors.New("controller identity changed unexpectedly")
	}
	return nil
}

func (a *Agent) validateAssignmentReplay(p *Policy, instant time.Time) error {
	if p.AssignmentGeneration == 0 && p.AssignmentDigest == "" && !policySigningRequired(a.Config) && a.State.AssignmentGeneration == 0 {
		return nil // Explicit unsigned monitoring/lab compatibility only.
	}
	if p.AssignmentGeneration < 1 || !validDigest(p.AssignmentDigest) {
		return errors.New("controller must supply a signed monotonic assignment generation")
	}
	if p.AssignmentGeneration < a.State.AssignmentGeneration || p.AssignmentGeneration == a.State.AssignmentGeneration && p.AssignmentDigest != a.State.AssignmentDigest {
		return errors.New("stale or divergent auxiliary assignment replay rejected")
	}
	for _, session := range p.LearningSessions {
		if cutoff, exists := a.State.SessionCutoffs[session.ID]; exists && SessionCutoff(session).After(cutoff) {
			return errors.New("a previously stopped or bounded learning session cannot be prolonged or reactivated")
		}
	}
	return nil
}

func (a *Agent) rememberAssignmentSecurity(p *Policy, instant time.Time) error {
	cutoffs := make(map[string]time.Time, len(a.State.SessionCutoffs))
	for id, cutoff := range a.State.SessionCutoffs {
		if !instant.After(cutoff.Add(30 * time.Minute)) {
			cutoffs[id] = cutoff
		}
	}
	present := map[string]bool{}
	for _, session := range append(append([]Session{}, p.LearningSessions...), p.LearningTombstones...) {
		present[session.ID] = true
		cutoff := SessionCutoff(session)
		if prior, exists := cutoffs[session.ID]; !exists || cutoff.Before(prior) {
			cutoffs[session.ID] = cutoff
		}
	}
	if a.State.Policy != nil {
		for _, session := range a.State.Policy.LearningSessions {
			if !present[session.ID] {
				cutoff := SessionCutoff(session)
				if instant.Before(cutoff) {
					cutoff = instant
				}
				if prior, exists := cutoffs[session.ID]; !exists || cutoff.Before(prior) {
					cutoffs[session.ID] = cutoff
				}
			}
		}
	}
	if len(cutoffs) > 4096 {
		return errors.New("learning session replay ledger is at capacity; new assignments are paused")
	}
	a.State.SessionCutoffs = cutoffs
	if p.AssignmentGeneration > 0 {
		a.State.AssignmentGeneration = p.AssignmentGeneration
		a.State.AssignmentDigest = p.AssignmentDigest
	}
	return nil
}
