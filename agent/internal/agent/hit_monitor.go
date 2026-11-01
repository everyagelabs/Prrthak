package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type hitGrant struct {
	Assignment   HitMonitorAssignment `json:"assignment"`
	CaptureFrom  time.Time            `json:"capture_from"`
	CaptureUntil time.Time            `json:"capture_until"`
}
type hitOwnedRule struct {
	MonitorID string    `json:"monitor_id"`
	Zone      string    `json:"zone"`
	Port      Port      `json:"port"`
	Rule      string    `json:"rule"`
	ExpiresAt time.Time `json:"expires_at"`
	Confirmed bool      `json:"confirmed"`
	CheckedAt time.Time `json:"checked_at"`
}
type hitState struct {
	Version       int                `json:"version"`
	Simulation    bool               `json:"simulation"`
	ServerID      string             `json:"server_id"`
	Cursor        string             `json:"cursor"`
	Since         time.Time          `json:"since"`
	Grants        []hitGrant         `json:"grants"`
	Rules         []hitOwnedRule     `json:"rules"`
	DroppedEvents int                `json:"dropped_events"`
	Limited       bool               `json:"coverage_limited"`
	Statuses      []HitMonitorStatus `json:"statuses"`
	Rejections    map[string]string  `json:"rejections,omitempty"`
	LastAssigned  []string           `json:"last_assigned,omitempty"`
	PendingStops  map[string]bool    `json:"pending_stops,omitempty"`
}
type HitMonitor struct {
	dir, zone   string
	maxSpool    int
	commands    CommandRunner
	simulate    bool
	state       hitState
	active      map[string]HitMonitorAssignment // Fresh payloads only; never restored.
	coverage    HitMonitorCoverage
	clock       func() time.Time
	monotonic   func() time.Time
	deadlines   map[string]time.Time
	lastReceipt string
	nextReceipt time.Time
	freshOff    map[string]time.Time
}

func NewHitMonitor(stateDir, zone string, maxSpool int, commands CommandRunner, simulate bool) (*HitMonitor, error) {
	if maxSpool < 1 || maxSpool > 1000 {
		return nil, errors.New("hit spool limit must be1..1000")
	}
	if maxSpool > 128 {
		maxSpool = 128
	}
	if zone != "" && !firewallName.MatchString(zone) {
		return nil, errors.New("invalid hit-monitor zone")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return nil, err
	}
	if _, err = setupPath(resolved, true); err != nil {
		return nil, err
	}
	dir := filepath.Join(resolved, "hit-monitor")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := setupPath(dir, true)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("hit-monitor state directory must be private")
	}
	m := &HitMonitor{dir: dir, zone: zone, maxSpool: maxSpool, commands: commands, simulate: simulate, active: map[string]HitMonitorAssignment{}, deadlines: map[string]time.Time{}, state: hitState{Version: 1, Simulation: simulate}}
	raw, err := readPrivateSetupBound(filepath.Join(dir, "state.json"), maxHitStateBytes)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, "state.json")); !os.IsNotExist(statErr) {
			return nil, err
		}
	} else {
		if json.Unmarshal(raw, &m.state) != nil || m.state.Version != 1 || len(m.state.Grants) > 256 || len(m.state.Rules) > maxHitPorts || len(m.state.Statuses) > 16 || len(m.state.Cursor) > 4096 || m.state.DroppedEvents < 0 || m.state.DroppedEvents > 1000000000 {
			return nil, errors.New("invalid persisted hit-monitor state")
		}
		if m.state.Simulation != simulate {
			return nil, errors.New("hit monitoring simulation requires a separate state directory")
		}
		if len(m.state.LastAssigned) > maxHitMonitors || len(m.state.PendingStops) > 16 {
			return nil, errors.New("invalid saved hit stop scope")
		}
		for _, id := range m.state.LastAssigned {
			if !hitID.MatchString(id) {
				return nil, errors.New("invalid saved hit ID")
			}
		}
		for id := range m.state.PendingStops {
			if !hitID.MatchString(id) {
				return nil, errors.New("invalid saved hit stop ID")
			}
		}
		if len(m.state.Rejections) > maxHitMonitors {
			return nil, errors.New("too many persisted hit rejections")
		}
		for id, message := range m.state.Rejections {
			if !hitID.MatchString(id) || len(message) > 4096 {
				return nil, errors.New("invalid persisted hit rejection")
			}
		}
		for _, status := range m.state.Statuses {
			if !hitID.MatchString(status.ID) || (status.Status != "observing" && status.Status != "off" && status.Status != "expired" && status.Status != "error") || len(status.Error) > 4096 || status.DroppedEvents < 0 || status.DroppedEvents > 1000000000 {
				return nil, errors.New("invalid persisted hit-monitor receipt")
			}
		}
		for _, grant := range m.state.Grants {
			if validateHitAssignment(grant.Assignment, m.state.ServerID, time.Time{}, false) != nil || grant.CaptureFrom.Before(grant.Assignment.StartsAt) || grant.CaptureUntil.After(grant.Assignment.ExpiresAt) {
				return nil, errors.New("invalid saved hit grant")
			}
		}
		for _, rule := range m.state.Rules {
			if !validHitOwnedRule(rule) {
				return nil, errors.New("unowned hit-monitor rule in saved state")
			}
		}
		for index := range m.state.Grants {
			if m.state.Grants[index].CaptureUntil.After(time.Now().UTC()) {
				m.state.Grants[index].CaptureUntil = time.Now().UTC()
			}
		}
	}
	m.coverage = HitMonitorCoverage{Status: "off", RateLimited: true, DroppedEvents: m.state.DroppedEvents}
	return m, nil
}
func (m *HitMonitor) save() error {
	raw, err := json.Marshal(m.state)
	if err != nil || len(raw) > maxHitStateBytes {
		return errors.New("hit-monitor state exceeds byte bound")
	}
	return atomicJSON(filepath.Join(m.dir, "state.json"), m.state)
}
func (m *HitMonitor) Coverage() HitMonitorCoverage { return m.coverage }
func hitLeaseKey(assignment HitMonitorAssignment) string {
	return assignment.ID + "\x00" + assignment.StartsAt.UTC().Format(time.RFC3339Nano) + "\x00" + assignment.ExpiresAt.UTC().Format(time.RFC3339Nano)
}
func (m *HitMonitor) monotonicNow() time.Time {
	if m.monotonic != nil {
		return m.monotonic()
	}
	return time.Now()
}
func (m *HitMonitor) remaining(assignment HitMonitorAssignment, at time.Time) time.Duration {
	deadline, present := m.deadlines[hitLeaseKey(assignment)]
	if !present {
		return 0
	}
	return min(assignment.ExpiresAt.Sub(at), deadline.Sub(m.monotonicNow()))
}
func (m *HitMonitor) OwnedRules() []OwnedRule {
	result := []OwnedRule{}
	for _, rule := range m.state.Rules {
		if rule.Confirmed {
			result = append(result, OwnedRule{SessionID: "hit:" + rule.MonitorID, Zone: rule.Zone, Rule: rule.Rule, ExpiresAt: rule.ExpiresAt})
		}
	}
	return result
}
func validHitOwnedRule(rule hitOwnedRule) bool {
	return hitID.MatchString(rule.MonitorID) && firewallName.MatchString(rule.Zone) && rule.Port.Port >= 1 && rule.Port.Port <= 65535 && (rule.Port.Protocol == "tcp" || rule.Port.Protocol == "udp") && rule.Rule == HitObservationRule(rule.MonitorID, rule.Port)
}
func (m *HitMonitor) SetAssignments(server string, assignments []HitMonitorAssignment, now time.Time) error {
	if !hitServerID.MatchString(server) || (m.state.ServerID != "" && m.state.ServerID != server) {
		return errors.New("hit state belongs to another endpoint")
	}
	if len(assignments) > maxHitMonitors {
		return errors.New("at most8 hit monitors may be assigned")
	}
	next := map[string]HitMonitorAssignment{}
	portCount := 0
	for _, assignment := range assignments {
		if err := validateHitAssignment(assignment, server, now, true); err != nil {
			return err
		}
		if _, duplicate := next[assignment.ID]; duplicate {
			return errors.New("duplicate hit-monitor ID")
		}
		assignment.Ports = append([]Port{}, assignment.Ports...)
		next[assignment.ID] = assignment
		portCount += len(assignment.Ports)
	}
	if portCount > maxHitPorts {
		return errors.New("hit monitoring supports at most64 assigned port scopes")
	}
	previous := m.state
	m.state.PendingStops = map[string]bool{}
	for id, pending := range previous.PendingStops {
		m.state.PendingStops[id] = pending
	}
	for _, id := range previous.LastAssigned {
		if _, present := next[id]; !present {
			m.state.PendingStops[id] = true
		}
	}
	if len(m.state.PendingStops) > 16 {
		m.state = previous
		return errors.New("hit stop receipt capacity awaits native verification")
	}
	m.state.LastAssigned = nil
	for id := range next {
		m.state.LastAssigned = append(m.state.LastAssigned, id)
	}
	sort.Strings(m.state.LastAssigned)
	m.state.ServerID = server
	m.state.Grants = append([]hitGrant{}, m.state.Grants...)
	for index := range m.state.Grants {
		grant := &m.state.Grants[index]
		current, present := next[grant.Assignment.ID]
		if (!present || hitPortsKey(current.Ports) != hitPortsKey(grant.Assignment.Ports)) && now.Before(grant.CaptureUntil) {
			grant.CaptureUntil = now
		}
	}
	for _, assignment := range assignments {
		assignment = next[assignment.ID]
		seen := false
		for _, grant := range m.state.Grants {
			if grant.Assignment.ID == assignment.ID && grant.Assignment.StartsAt.Equal(assignment.StartsAt) && grant.Assignment.ExpiresAt.Equal(assignment.ExpiresAt) {
				if hitPortsKey(grant.Assignment.Ports) != hitPortsKey(assignment.Ports) {
					m.state = previous
					return errors.New("a hit lease cannot change its exact ports")
				}
				seen = seen || grant.CaptureUntil.Equal(assignment.ExpiresAt)
			}
		}
		if !seen {
			from := now
			if from.Before(assignment.StartsAt) {
				from = assignment.StartsAt
			}
			m.state.Grants = append(m.state.Grants, hitGrant{assignment, from, assignment.ExpiresAt})
		}
	}
	// Keep bounded overlapping grant history so renewal never re-labels the
	// journal tail as learning or drops the previous lease's buffered events.
	kept := []hitGrant{}
	counts := map[string]int{}
	for index := len(m.state.Grants) - 1; index >= 0; index-- {
		grant := m.state.Grants[index]
		if counts[grant.Assignment.ID] < 32 && len(kept) < 256 {
			kept = append(kept, grant)
			counts[grant.Assignment.ID]++
		} else {
			m.state.Limited = true
		}
	}
	for left, right := 0, len(kept)-1; left < right; left, right = left+1, right-1 {
		kept[left], kept[right] = kept[right], kept[left]
	}
	m.state.Grants = kept
	m.state.Rejections = nil
	if m.state.Since.IsZero() {
		m.state.Since = now
	}
	if err := m.save(); err != nil {
		m.state = previous
		return err
	}
	for _, assignment := range assignments {
		key := hitLeaseKey(assignment)
		deadline := m.monotonicNow().Add(assignment.ExpiresAt.Sub(now))
		if previous, exists := m.deadlines[key]; !exists || deadline.Before(previous) {
			m.deadlines[key] = deadline
		}
	}
	retained := map[string]bool{}
	for _, grant := range m.state.Grants {
		retained[hitLeaseKey(grant.Assignment)] = true
	}
	for key := range m.deadlines {
		if !retained[key] {
			delete(m.deadlines, key)
		}
	}
	m.active = next
	m.coverage.Enabled = len(next) > 0
	return nil
}
func (m *HitMonitor) drop(count int) {
	m.state.DroppedEvents = min(1000000000, m.state.DroppedEvents+count)
	m.coverage.DroppedEvents = m.state.DroppedEvents
}
func (m *HitMonitor) remove(ctx context.Context, rule hitOwnedRule) error {
	if !validHitOwnedRule(rule) {
		return errors.New("refusing unowned hit-rule removal")
	}
	if !rule.Confirmed {
		return nil
	} // Unacknowledged installation is timeout-only.
	if m.simulate {
		return nil
	}
	out, err := m.commands.Run(ctx, "firewall-cmd", "--zone="+rule.Zone, "--remove-rich-rule="+rule.Rule)
	if strings.Contains(out, "NOT_ENABLED") {
		return nil
	}
	if err != nil {
		return err
	}
	present, err := ObservationExists(ctx, m.commands, OwnedRule{Zone: rule.Zone, Rule: rule.Rule})
	if err != nil || present {
		return errors.New("hit-rule cleanup absence could not be verified")
	}
	return nil
}
func (m *HitMonitor) Tick(ctx context.Context, now time.Time) error {
	m.freshOff = map[string]time.Time{}
	m.coverage.Error = ""
	m.coverage.Status = "off"
	m.coverage.ActiveMonitors = 0
	var first error
	// Collect before removal/renewal, and retain each record's original grant.
	if err := m.collect(ctx, now); err != nil {
		first = err
	}
	desired := map[string]hitOwnedRule{}
	for id, assignment := range m.active {
		if !now.Before(assignment.StartsAt) && m.remaining(assignment, now) > 0 {
			m.coverage.ActiveMonitors++
			for _, port := range assignment.Ports {
				rule := hitOwnedRule{MonitorID: id, Port: port, Rule: HitObservationRule(id, port), ExpiresAt: assignment.ExpiresAt}
				desired[id+"\x00"+rule.Rule] = rule
			}
		}
	}
	kept := []hitOwnedRule{}
	for _, rule := range m.state.Rules {
		if !rule.Confirmed {
			present, err := ObservationExists(ctx, m.commands, OwnedRule{Zone: rule.Zone, Rule: rule.Rule})
			if err != nil || present {
				kept = append(kept, rule)
				delete(desired, rule.MonitorID+"\x00"+rule.Rule)
				if first == nil {
					first = errors.New("unacknowledged hit rule awaits verified absence/native timeout")
				}
			}
			continue
		}
		key := rule.MonitorID + "\x00" + rule.Rule
		want, present := desired[key]
		if present && rule.ExpiresAt.Equal(want.ExpiresAt) && now.Before(rule.ExpiresAt) {
			if !m.simulate && (rule.CheckedAt.IsZero() || !now.Before(rule.CheckedAt.Add(30*time.Second))) {
				present, err := ObservationExists(ctx, m.commands, OwnedRule{Zone: rule.Zone, Rule: rule.Rule})
				if err != nil {
					kept = append(kept, rule)
					delete(desired, key)
					if first == nil {
						first = err
					}
					continue
				}
				if !present {
					continue
				}
				rule.CheckedAt = now
			}
			kept = append(kept, rule)
			delete(desired, key)
			continue
		}
		if err := m.remove(ctx, rule); err != nil {
			kept = append(kept, rule)
			delete(desired, key)
			if first == nil {
				first = err
			}
		}
	}
	m.state.Rules = kept
	if err := m.save(); err != nil {
		return err
	}
	if len(desired) > 0 && !m.simulate {
		zone, err := LearningZone(ctx, Config{Zone: m.zone}, m.commands)
		if err != nil {
			if first == nil {
				first = err
			}
		} else {
			keys := []string{}
			for key := range desired {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if len(m.state.Rules) >= maxHitPorts {
					if first == nil {
						first = errors.New("hit-rule capacity retained by unresolved cleanup")
					}
					break
				}
				rule := desired[key]
				rule.Zone = zone
				assignment := m.active[rule.MonitorID]
				if m.remaining(assignment, now) <= 0 {
					continue
				}
				present, err := ObservationExists(ctx, m.commands, OwnedRule{Zone: zone, Rule: rule.Rule})
				if err != nil || present {
					if first == nil {
						first = errors.New("hit LOG rule already exists without confirmed ownership")
					}
					continue
				}
				// Persist intent before LOG-only mutation. Kernel timeout bounds an
				// orphan even when sync/this process stops running entirely.
				m.state.Rules = append(m.state.Rules, rule)
				if err := m.save(); err != nil {
					return err
				}
				// Recalculate AFTER blocking preflight/durability work. Wall-clock
				// rollback can never extend the receipt's monotonic deadline.
				actual := time.Now().UTC()
				if m.clock != nil {
					actual = m.clock().UTC()
				}
				if actual.Before(now) {
					actual = now
				}
				seconds := int(m.remaining(assignment, actual) / time.Second)
				if seconds < 1 || seconds > 120 {
					m.state.Rules = m.state.Rules[:len(m.state.Rules)-1]
					if err = m.save(); err != nil {
						return err
					}
					continue
				}
				out, err := m.commands.Run(ctx, "firewall-cmd", "--zone="+zone, "--add-rich-rule="+rule.Rule, fmt.Sprintf("--timeout=%ds", seconds))
				if strings.Contains(out, "ALREADY_ENABLED") {
					m.state.Rules = m.state.Rules[:len(m.state.Rules)-1]
					_ = m.save()
					if first == nil {
						first = errors.New("hit LOG rule installation raced another owner")
					}
					continue
				}
				if err != nil {
					if first == nil {
						first = errors.New("hit LOG rule installation failed; native timeout retained")
					}
					continue
				}
				present, err = ObservationExists(ctx, m.commands, OwnedRule{Zone: zone, Rule: rule.Rule})
				if err != nil || !present {
					if first == nil {
						first = errors.New("hit LOG rule read-back failed")
					}
				} else {
					m.state.Rules[len(m.state.Rules)-1].Confirmed = true
					m.state.Rules[len(m.state.Rules)-1].CheckedAt = actual
					if err = m.save(); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := m.collect(ctx, now); err != nil && first == nil {
		first = err
	}
	if first == nil && m.coverage.Error == "" && len(m.active) == 0 && len(m.state.Rules) == 0 {
		latest := time.Time{}
		for _, grant := range m.state.Grants {
			if grant.CaptureUntil.After(latest) {
				latest = grant.CaptureUntil
			}
		}
		if now.After(latest.Add(30 * time.Second)) {
			m.state.Grants = nil
		}
	}
	if err := m.verifyPendingStops(ctx, now); err != nil && first == nil {
		first = err
	}
	m.updateStatuses(now, first)
	for id, item := range m.active {
		if m.remaining(item, now) <= 0 {
			delete(m.active, id)
		}
	}
	m.coverage.Enabled = len(m.active) > 0
	if m.coverage.ActiveMonitors > 0 {
		m.coverage.Status = "active"
	}
	if m.simulate && m.coverage.ActiveMonitors > 0 {
		m.coverage.Status = "simulation"
	}
	if first != nil {
		m.coverage.Status = "degraded"
		m.coverage.Error = first.Error()
	}
	if m.state.Limited {
		m.coverage.CoverageLimited = true
		m.coverage.Status = "degraded"
		if m.coverage.Error == "" {
			m.coverage.Error = "bounded journal/grant history may omit older logged packets"
		}
	}
	if err := m.save(); err != nil {
		return err
	}
	return first
}
func (m *HitMonitor) Close(ctx context.Context) error {
	now := time.Now().UTC()
	for index := range m.state.Grants {
		if now.Before(m.state.Grants[index].CaptureUntil) {
			m.state.Grants[index].CaptureUntil = now
		}
	}
	m.active = map[string]HitMonitorAssignment{}
	return m.Tick(ctx, now)
}
func (m *HitMonitor) collect(ctx context.Context, now time.Time) error {
	if m.simulate || len(m.state.Grants) == 0 {
		return nil
	}
	args := []string{"-k", "-o", "json", "--no-pager", "-n", "5000"}
	if m.state.Cursor != "" {
		args = append(args, "--after-cursor="+m.state.Cursor)
	} else {
		args = append(args, "--since="+m.state.Since.Format(time.RFC3339Nano))
	}
	text, err := m.commands.Run(ctx, "journalctl", args...)
	if err != nil {
		if strings.Contains(strings.ToLower(text+err.Error()), "cursor") {
			m.state.Cursor = ""
			m.state.Since = now
			m.state.Limited = true
			if saveErr := m.save(); saveErr != nil {
				return saveErr
			}
		}
		return fmt.Errorf("hit kernel journal read: %w", err)
	}
	if len(text) > 8*1024*1024 {
		return errors.New("hit kernel journal exceeds bounded page")
	}
	groups := map[string]*HitBatch{}
	cursor := m.state.Cursor
	lines := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		lines++
		if lines > 5000 {
			return errors.New("hit journal page exceeds5000records")
		}
		var entry JournalEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue
		}
		if entry.Cursor != "" && len(entry.Cursor) <= 4096 {
			cursor = entry.Cursor
		}
		micro, err := strconv.ParseInt(entry.Timestamp, 10, 64)
		if err != nil {
			continue
		}
		when := time.UnixMicro(micro).UTC()
		if when.After(now.Add(time.Minute)) {
			continue
		}
		matched := map[string]bool{}
		for index := len(m.state.Grants) - 1; index >= 0; index-- {
			grant := m.state.Grants[index]
			id := grant.Assignment.ID
			if matched[id] || when.Before(grant.CaptureFrom) || !when.Before(grant.CaptureUntil) {
				continue
			}
			event, ok := ParseHitKernelLog(entry.Message, when, grant.Assignment, entry.Cursor)
			if !ok {
				continue
			}
			matched[id] = true
			key := id + "\x00" + grant.Assignment.StartsAt.Format(time.RFC3339Nano) + "\x00" + grant.Assignment.ExpiresAt.Format(time.RFC3339Nano)
			if groups[key] == nil {
				groups[key] = &HitBatch{MonitorID: id, LeaseStartsAt: grant.Assignment.StartsAt, LeaseExpiresAt: grant.Assignment.ExpiresAt}
			}
			groups[key].Events = append(groups[key].Events, event)
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		batch := groups[key]
		sort.Slice(batch.Events, func(i, j int) bool { return batch.Events[i].EventID < batch.Events[j].EventID })
		for len(batch.Events) > 0 {
			count := min(maxHitEvents, len(batch.Events))
			part := *batch
			part.Events = append([]HitEvent{}, batch.Events[:count]...)
			part.BatchID = hitBatchDigest(part)
			if err = m.spool(part); err != nil {
				return err
			}
			batch.Events = batch.Events[count:]
		}
	}
	// Durable spool comes first. If a crash repeats this page, stable event IDs
	// let the controller deduplicate even when page/batch boundaries change.
	m.state.Cursor = cursor
	if lines >= 5000 {
		m.state.Limited = true
		m.coverage.Error = "hit journal page cap reached; sampled counts may omit earlier records"
	}
	return m.save()
}
