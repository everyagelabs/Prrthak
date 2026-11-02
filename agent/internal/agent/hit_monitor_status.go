package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

func (m *HitMonitor) verifyPendingStops(ctx context.Context, at time.Time) error {
	if len(m.state.PendingStops) == 0 {
		return nil
	}
	present := map[string]bool{}
	if !m.simulate {
		text, err := m.commands.Run(ctx, "firewall-cmd", "--list-all-zones")
		if err != nil || len(text) > maxFirewallSnapshotBytes {
			return errors.New("fresh hit-stop native inventory unavailable")
		}
		zones, err := parseFirewallZones(text)
		if err != nil {
			return errors.New("fresh hit-stop native inventory is incomplete")
		}
		for _, zone := range zones {
			for _, rule := range zone.Rich {
				for id := range m.state.PendingStops {
					if strings.Contains(rule, HitRulePrefix(id)) {
						present[id] = true
					}
				}
			}
		}
	}
	for id := range m.state.PendingStops {
		if !present[id] {
			delete(m.state.PendingStops, id)
			m.freshOff[id] = at
		}
	}
	if len(present) > 0 {
		return errors.New("stopped hit-monitor instrumentation is still present; cleanup remains unverified")
	}
	return nil
}

func (m *HitMonitor) Statuses() []HitMonitorStatus {
	return append([]HitMonitorStatus{}, m.state.Statuses...)
}
func (m *HitMonitor) ShouldReport(at time.Time) bool {
	if len(m.state.Statuses) == 0 {
		return false
	}
	raw, _ := json.Marshal(m.state.Statuses)
	key := shaText(string(raw))
	if key == m.lastReceipt || at.Before(m.nextReceipt) {
		return false
	}
	m.nextReceipt = at.Add(10 * time.Second)
	return true
}
func (m *HitMonitor) Reported() {
	raw, _ := json.Marshal(m.state.Statuses)
	m.lastReceipt = shaText(string(raw))
}
func (m *HitMonitor) updateStatuses(now time.Time, failure error) {
	previous := map[string]HitMonitorStatus{}
	ids := map[string]bool{}
	latest := map[string]HitMonitorAssignment{}
	for _, status := range m.state.Statuses {
		previous[status.ID] = status
		ids[status.ID] = true
	}
	for _, grant := range m.state.Grants {
		ids[grant.Assignment.ID] = true
		if old, present := latest[grant.Assignment.ID]; !present || grant.Assignment.ExpiresAt.After(old.ExpiresAt) {
			latest[grant.Assignment.ID] = grant.Assignment
		}
	}
	for id, assignment := range m.active {
		ids[id] = true
		latest[id] = assignment
	}
	for _, rule := range m.state.Rules {
		ids[rule.MonitorID] = true
	}
	for id := range m.state.Rejections {
		ids[id] = true
	}
	for id := range m.state.PendingStops {
		ids[id] = true
	}
	for id := range m.freshOff {
		ids[id] = true
	}
	statuses := []HitMonitorStatus{}
	for id := range ids {
		status := HitMonitorStatus{ID: id, Status: "off", CheckedAt: now, DroppedEvents: m.state.DroppedEvents}
		assignment, known := latest[id]
		if known {
			expiry := assignment.ExpiresAt
			status.LeaseExpiresAt = &expiry
		}
		live, present := m.active[id]
		active := present && !now.Before(live.StartsAt) && m.remaining(live, now) > 0
		owned, pending := 0, 0
		verified := now
		for _, rule := range m.state.Rules {
			if rule.MonitorID != id {
				continue
			}
			pending++
			if rule.Confirmed && active && rule.ExpiresAt.Equal(live.ExpiresAt) {
				owned++
				if rule.CheckedAt.Before(verified) {
					verified = rule.CheckedAt
				}
			}
		}
		if active && live.ObservationKinds != nil && !m.simulate {
			status.Status = "observing"
			if m.coverage.Capture == nil {
				status.Status = "error"
				status.Error = "native traffic capture is awaiting verification"
			} else {
				status.TrafficCaptureCoverage = scopedCaptureCoverage(live.ObservationKinds, *m.coverage.Capture)
				for _, backend := range status.Backends {
					if backend.Status != "active" {
						status.Status = "error"
						status.Error = backend.Error
					}
				}
			}
		} else if active && owned == len(live.Ports) && !m.simulate {
			status.Status = "observing"
			status.CheckedAt = verified
		} else if active && !m.simulate {
			status.Status = "error"
			status.Error = "assigned LOG instrumentation is not fully verified"
		} else if pending > 0 {
			status.Status = "error"
			status.Error = "owned LOG rule cleanup remains unverified"
		} else if known && (!now.Before(assignment.ExpiresAt) || (!m.deadlines[hitLeaseKey(assignment)].IsZero() && m.remaining(assignment, now) <= 0)) {
			status.Status = "expired"
		} else if previous[id].Status == "expired" && !present {
			status.Status = "expired"
		}
		if failure != nil && (active || pending > 0) {
			status.Status = "error"
			status.Error = failure.Error()
		}
		if message := m.state.Rejections[id]; message != "" {
			status.Status = "error"
			status.Error = message
		}
		if m.state.PendingStops[id] {
			status.Status = "error"
			status.Error = "awaiting fresh native stop verification"
		}
		old := previous[id]
		if !active && pending == 0 && old.Status == status.Status && old.Error == status.Error && old.DroppedEvents == status.DroppedEvents && !old.CheckedAt.IsZero() && m.freshOff[id].IsZero() {
			status.CheckedAt = old.CheckedAt
		}
		if checked, verified := m.freshOff[id]; verified && m.state.Rejections[id] == "" {
			status.Status = "off"
			status.Error = ""
			status.CheckedAt = checked
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool {
		_, a := m.active[statuses[i].ID]
		_, b := m.active[statuses[j].ID]
		if a != b {
			return a
		}
		if !statuses[i].CheckedAt.Equal(statuses[j].CheckedAt) {
			return statuses[i].CheckedAt.After(statuses[j].CheckedAt)
		}
		return statuses[i].ID < statuses[j].ID
	})
	if len(statuses) > 16 {
		statuses = statuses[:16]
	}
	m.state.Statuses = statuses
}
