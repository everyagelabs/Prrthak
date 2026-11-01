package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *Agent) currentTime() time.Time {
	if a.clock != nil {
		return a.clock().UTC()
	}
	return time.Now().UTC()
}
func (a *Agent) discoveryInterval() time.Duration {
	seconds := a.discoveryIntervalSeconds()
	return time.Duration(seconds) * time.Second
}
func (a *Agent) discoveryDue(now time.Time) bool {
	if a.inventory == nil || a.forceDiscovery || a.learningDiscoveryDue(now) || now.Before(a.lastDiscoveryAttempt) || now.Sub(a.lastDiscoveryAttempt) >= a.discoveryInterval() {
		return true
	}
	retry := time.Duration(a.controlIntervalSeconds()) * time.Second
	if retry <= 0 {
		retry = 60 * time.Second
	}
	return a.inventory.DiscoveryError != "" && now.Sub(a.lastDiscoveryAttempt) >= retry
}
func (a *Agent) inventoryReport(ctx context.Context, now time.Time) Report {
	interval := a.discoveryInterval()
	due := a.discoveryDue(now)
	if due {
		a.forceDiscovery = false
		previous := a.inventory
		snapshot := Discover(ctx, a.Commands, a.Simulate, a.SimulateHostname)
		if a.learningDiscoveryAttempts == nil {
			a.learningDiscoveryAttempts = map[string]time.Time{}
		}
		for _, s := range a.pendingLearningDiscovery(now) {
			a.learningDiscoveryAttempts[s.ID] = now
			snapshot.LearningDiscoverySessionIDs = append(snapshot.LearningDiscoverySessionIDs, s.ID)
		}
		if a.Simulate {
			snapshot.FirewallSnapshot = &FirewallSnapshot{CollectedAt: now, Status: "ok", Rules: []FirewallRule{}, Capabilities: []string{"simulation", "view-only"}}
			finishFirewallDigest(snapshot.FirewallSnapshot)
		} else {
			snapshot.FirewallSnapshot = CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules())
			if previous != nil {
				snapshot.FirewallSnapshot = retainFirewallSnapshot(previous.FirewallSnapshot, snapshot.FirewallSnapshot)
			}
		}
		a.lastDiscoveryAttempt = now
		if snapshot.DiscoveryError == "" {
			a.lastDiscoverySuccess = now
		} else if previous != nil {
			// A failed scan never asserts that previously discovered listeners vanished.
			snapshot.Listeners = append([]Listener{}, previous.Listeners...)
		}
		a.inventory = &snapshot
		// Both successful and failed scan attempts must reach the controller.
		// A cached retry must retain this flag until the HTTP report is acknowledged.
		a.discoverySequence++
		a.discoveryPending = true
	}
	report := *a.inventory
	report.AgentVersion = Version
	if !a.Simulate {
		report.ConfigurationState = configurationState(a.Config)
	}
	report.Capabilities = []string{LearningDiscoveryCapability, LearningAutoAllowCapability, PollingSettingsCapability, "managed_ipsets_v1", "signed_assignments_v1", LearningIPSetCapability}
	if !a.Simulate {
		report.Capabilities = append(report.Capabilities, "endpoint_configuration_v1", "approval_mode_proof_v1")
	}
	report.Capabilities = append(report.Capabilities, "imported_zone_target_v1", "imported_direct_v1", "imported_nat_v1")
	report.Capabilities = append(report.Capabilities, HitMonitorCapability)
	report.IPs = append([]string{}, a.inventory.IPs...)
	report.Listeners = append([]Listener{}, a.inventory.Listeners...)
	report.DiscoveryPerformed = a.discoveryPending
	report.LearningDiscoverySessionIDs = nil
	if report.DiscoveryPerformed {
		pending := map[string]bool{}
		for _, s := range a.pendingLearningDiscovery(now) {
			pending[s.ID] = true
		}
		for _, id := range a.inventory.LearningDiscoverySessionIDs {
			if pending[id] {
				report.LearningDiscoverySessionIDs = append(report.LearningDiscoverySessionIDs, id)
			}
		}
	}
	report.discoverySequence = a.discoverySequence
	report.DiscoveryIntervalSeconds = int(interval / time.Second)
	if !a.lastDiscoverySuccess.IsZero() {
		scanned := a.lastDiscoverySuccess
		report.DiscoveredAt = &scanned
	}
	if !due && !a.Simulate {
		// Quick firewall state checks continue without repeating ss, process or OS discovery.
		if text, e := a.Commands.Run(ctx, "firewall-cmd", "--state"); e == nil {
			report.FirewalldState = strings.TrimSpace(text)
		} else {
			report.FirewalldState = "not-running"
		}
		if text, e := a.Commands.Run(ctx, "ufw", "status"); e == nil {
			report.UFWActive = strings.Contains(strings.ToLower(text), "status: active")
		}
	}
	return report
}
func (a *Agent) ackInventoryReport(report Report) {
	if report.DiscoveryPerformed && report.discoverySequence == a.discoverySequence {
		a.discoveryPending = false
	}
}
func RequestDiscovery(c Config) error {
	return atomicJSON(filepath.Join(c.StateDir, "discovery.request.json"), map[string]time.Time{"requested_at": time.Now().UTC()})
}
func (a *Agent) consumeDiscoveryRequest() (bool, error) {
	path := filepath.Join(a.Config.StateDir, "discovery.request.json")
	if _, e := os.Stat(path); os.IsNotExist(e) {
		return false, nil
	} else if e != nil {
		return false, e
	}
	if e := os.Remove(path); e != nil {
		return false, e
	}
	a.forceDiscovery = true
	return true, nil
}
