package agent

import (
	"reflect"
	"sort"
	"strings"
	"time"
)

// syncReceipt names only meaningful control/outcome fields. Routine status
// UpdatedAt refreshes and locally persisted acknowledgement bits do not require
// another HTTP write. This is deliberately not a hash of the whole agent state.
type syncReceipt struct {
	PolicyVerificationSequence             int
	DesiredVersion, AppliedVersion         int
	DesiredDigest, DesiredMode             string
	ApplyError, CollectorError, SpoolError string
	ProtectionDigest, ProtectionBlockers   string
	ProtectionReady                        bool
	Polling                                *PollingSettingsReport
	Managed                                *ManagedEnforcement
	Learning                               *LearningAllowOutcome
	FirewallResults                        []FirewallChangeResult
	LearningCoverage                       []syncCoverageReceipt
}

type syncCoverageReceipt struct {
	SessionID, Error   string
	StartedAt, EndedAt time.Time
	DroppedEvents      int
	RateLimited        bool
}

func (a *Agent) syncReceipt() syncReceipt {
	a.enrichManagedStatus()
	a.enrichLearningOutcome()
	r := syncReceipt{AppliedVersion: a.State.AppliedVersion, ApplyError: a.applyError, CollectorError: a.collectorError, SpoolError: a.State.SpoolError, Polling: a.pollingSettingsReport()}
	if a.State.PolicyVerification != nil {
		r.PolicyVerificationSequence = a.State.PolicyVerification.Report.Sequence
	}
	if p := a.State.Policy; p != nil {
		r.DesiredVersion, r.DesiredDigest, r.DesiredMode = p.Version, p.Digest, p.Mode
	}
	if p := a.protection; p != nil {
		r.ProtectionDigest, r.ProtectionReady = p.Digest, p.Ready
		r.ProtectionBlockers = strings.Join(p.Blockers, "\n")
	}
	if value := a.State.ManagedEnforcement; value != nil {
		copy := *value
		copy.UpdatedAt = time.Time{}
		r.Managed = &copy
	}
	if value := a.State.LearningAllowOutcome; value != nil {
		copy := *value
		copy.UpdatedAt = time.Time{}
		r.Learning = &copy
	}
	for _, value := range a.State.FirewallChangeResults {
		value.Acknowledged = false
		r.FirewallResults = append(r.FirewallResults, value)
	}
	ids := make([]string, 0, len(a.State.Coverage))
	for id := range a.State.Coverage {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		value := a.State.Coverage[id]
		if value == nil {
			continue
		}
		copy := syncCoverageReceipt{SessionID: value.SessionID, Error: value.Error, StartedAt: value.StartedAt, DroppedEvents: value.DroppedEvents, RateLimited: value.RateLimited}
		if value.EndedAt != nil {
			copy.EndedAt = *value.EndedAt
		}
		r.LearningCoverage = append(r.LearningCoverage, copy)
	}
	return r
}

func (a *Agent) receiptChanged(previous syncReceipt) bool {
	return !reflect.DeepEqual(previous, a.syncReceipt())
}
