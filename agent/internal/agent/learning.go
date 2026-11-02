package agent

import (
	"context"
	"path/filepath"
	"sort"
	"time"
)

// Pending discovery assignments carry no collection ports. A request is fulfilled
// only by an actual discovery attempt after the assignment reached this endpoint.
func (a *Agent) pendingLearningDiscovery(now time.Time) []Session {
	result := []Session{}
	if a.State.Policy == nil {
		return result
	}
	for _, s := range a.State.Policy.LearningSessions {
		if s.SelectionMode == "discovered" && s.DiscoveryPending && s.Status != "stopped" && s.Status != "expired" && !now.Before(s.StartsAt) && now.Before(SessionCutoff(s)) {
			result = append(result, s)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (a *Agent) learningDiscoveryRetryInterval() time.Duration {
	seconds := a.controlIntervalSeconds()
	if seconds <= 0 || seconds > 60 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

func (a *Agent) learningDiscoveryDue(now time.Time) bool {
	for _, s := range a.pendingLearningDiscovery(now) {
		attempt, seen := a.learningDiscoveryAttempts[s.ID]
		if !seen || now.Before(attempt) || (!a.discoveryPending && now.Sub(attempt) >= a.learningDiscoveryRetryInterval()) {
			return true
		}
	}
	return false
}

func SessionCutoff(s Session) time.Time {
	cutoff := s.ExpiresAt
	if s.StoppedAt != nil && s.StoppedAt.Before(cutoff) {
		cutoff = *s.StoppedAt
	}
	return cutoff
}
func (a *Agent) sessionByID(id string) (Session, bool) {
	if s, ok := a.State.PendingDrains[id]; ok {
		return s, true
	}
	if a.State.Policy != nil {
		for _, s := range a.State.Policy.LearningSessions {
			if s.ID == id {
				return s, true
			}
		}
	}
	return Session{}, false
}
func (a *Agent) queueDrain(s Session, cutoff time.Time) {
	if a.State.PendingDrains == nil {
		a.State.PendingDrains = map[string]Session{}
	}
	if cutoff.Before(SessionCutoff(s)) {
		stop := cutoff
		s.StoppedAt = &stop
	}
	if existing, ok := a.State.PendingDrains[s.ID]; ok && SessionCutoff(existing).Before(SessionCutoff(s)) {
		s = existing
	}
	a.State.PendingDrains[s.ID] = s
}
func (a *Agent) rememberLearningTransition(next *Policy, now time.Time) {
	if a.State.Policy == nil {
		return
	}
	assigned := map[string]Session{}
	for _, s := range next.LearningSessions {
		assigned[s.ID] = s
	}
	for _, s := range next.LearningTombstones {
		assigned[s.ID] = s
	}
	for _, old := range a.State.Policy.LearningSessions {
		current, present := assigned[old.ID]
		if present && current.Status != "stopped" && current.Status != "expired" && now.Before(SessionCutoff(current)) {
			continue
		}
		// Only sessions with installed instrumentation need a final drain.
		installed := old.ObservationKinds != nil && a.trafficCapture != nil
		for _, rule := range a.State.Rules {
			if rule.SessionID == old.ID {
				installed = true
				break
			}
		}
		if !installed {
			continue
		}
		cutoff := SessionCutoff(old)
		if present {
			if SessionCutoff(current).Before(cutoff) {
				cutoff = SessionCutoff(current)
			}
		} else if now.Before(cutoff) {
			cutoff = now
			if cov := a.State.Coverage[old.ID]; cov != nil {
				cov.Error = "controller removed learning assignment without stop timestamp; tail cutoff is receipt time"
			}
		}
		a.queueDrain(old, cutoff)
	}
}
func (a *Agent) drainJournal(ctx context.Context, active []Session, now time.Time) error {
	if a.Simulate {
		for id, s := range a.State.PendingDrains {
			if !now.Before(SessionCutoff(s).Add(5 * time.Second)) {
				delete(a.State.PendingDrains, id)
			}
		}
		return nil
	}
	combined := map[string]Session{}
	for id, s := range a.State.PendingDrains {
		combined[id] = s
	}
	for _, s := range active {
		combined[s.ID] = s
	}
	sessions := []Session{}
	for _, s := range combined {
		sessions = append(sessions, s)
	}
	if len(sessions) == 0 {
		return nil
	}
	if e := CollectJournal(ctx, a.Commands, &a.State, sessions, filepath.Join(a.Config.StateDir, "spool"), a.Config.MaxSpoolBatches, now); e != nil {
		for _, s := range sessions {
			if cov := a.State.Coverage[s.ID]; cov != nil {
				cov.Error = e.Error()
			}
		}
		return e
	}
	// A brief final read window catches journal delivery slightly behind kernel logging.
	// The original event timestamp is still strictly bounded by each session cutoff.
	for id, s := range a.State.PendingDrains {
		if !now.Before(SessionCutoff(s).Add(5 * time.Second)) {
			delete(a.State.PendingDrains, id)
		}
	}
	return nil
}
