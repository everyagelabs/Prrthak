package agent

import (
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

type captureSidecar struct {
	Zone      string    `json:"zone"`
	Family    string    `json:"family"`
	Port      Port      `json:"port"`
	Group     uint16    `json:"group"`
	Prefix    string    `json:"prefix"`
	Priority  int       `json:"priority"`
	ExpiresAt time.Time `json:"expires_at"`
}
type captureSidecarState struct {
	Version int              `json:"version"`
	Rules   []captureSidecar `json:"rules"`
}

func captureGroup(stateDir string) uint16 {
	value, _ := strconv.ParseUint(shaText(stateDir)[:4], 16, 16)
	return uint16(48000 + value%10000)
}
func (rule captureSidecar) text() string {
	return fmt.Sprintf(`rule priority="%d" family="%s" port port="%d" protocol="%s" nflog group="%d" prefix="%s" queue-size="1" limit value="200/s"`, rule.Priority, rule.Family, rule.Port.Port, rule.Port.Protocol, rule.Group, rule.Prefix)
}
func validCaptureSidecar(rule captureSidecar) bool {
	return firewallName.MatchString(rule.Zone) && (rule.Family == "ipv4" || rule.Family == "ipv6") && rule.Port.Port >= 1 && rule.Port.Port <= 65535 && (rule.Port.Protocol == "tcp" || rule.Port.Protocol == "udp") && (rule.Priority == managedCaptureReject || rule.Priority == 32767) && rule.Group >= 48000 && rule.Group < 58000 && len(rule.Prefix) == 21 && (strings.HasPrefix(rule.Prefix, "PRTN") || strings.HasPrefix(rule.Prefix, "PRTV")) && strings.HasSuffix(rule.Prefix, ":") && validDigest(strings.Repeat(rule.Prefix[4:20], 4))
}
func captureSidecarPath(stateDir string) string {
	return filepath.Join(stateDir, "traffic-capture", "sidecars.json")
}
func readCaptureSidecars(stateDir string) (captureSidecarState, error) {
	state := captureSidecarState{Version: 1}
	path := captureSidecarPath(stateDir)
	raw, err := readPrivateSetupBound(path, 128*1024)
	if err != nil {
		if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
			return state, nil
		}
		return state, err
	}
	if json.Unmarshal(raw, &state) != nil || state.Version != 1 || len(state.Rules) > 128 {
		return state, errors.New("invalid private NFLOG sidecar ledger")
	}
	for _, rule := range state.Rules {
		if !validCaptureSidecar(rule) {
			return state, errors.New("unowned NFLOG sidecar in private ledger")
		}
	}
	return state, nil
}

// Call only under the same enforced mutation lease as the following access
// change. Removal is LOG-only, exact and absence-verified; there is no verdict.
func clearTrafficCaptureSidecars(ctx context.Context, stateDir string, commands CommandRunner) error {
	state, err := readCaptureSidecars(stateDir)
	if err != nil {
		return err
	}
	if len(state.Rules) == 0 {
		return nil
	}
	if managedLeaseFromContext(ctx) == nil {
		return errors.New("NFLOG cleanup requires the existing enforcement mutation lease")
	}
	for _, rule := range state.Rules {
		present, err := firewallQuery(ctx, commands, "runtime", rule.Zone, "rich_rule", rule.text())
		if err != nil {
			return fmt.Errorf("NFLOG cleanup query: %w", err)
		}
		if present {
			if err = firewallMutate(ctx, commands, firewallMutation{Scope: "runtime", Zone: rule.Zone, Kind: "rich_rule", Value: rule.text(), Operation: "remove"}); err != nil {
				return err
			}
		}
		present, err = firewallQuery(ctx, commands, "runtime", rule.Zone, "rich_rule", rule.text())
		if err != nil || present {
			return errors.New("NFLOG cleanup absence could not be verified before access mutation")
		}
	}
	return atomicJSON(captureSidecarPath(stateDir), captureSidecarState{Version: 1, Rules: []captureSidecar{}})
}
func ownedCaptureObservation(value string, records []OwnedRule) bool {
	for _, record := range records {
		if strings.HasPrefix(record.SessionID, "capture:") && captureRuleEqual(value, record.Rule) {
			return true
		}
	}
	return false
}
func captureRuleEqual(left, right string) bool {
	a, err := richTokens(left)
	if err != nil {
		return false
	}
	b, err := richTokens(right)
	if err != nil || len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
func (a *Agent) captureObservationRules() []OwnedRule {
	state, err := readCaptureSidecars(a.Config.StateDir)
	if err != nil {
		return nil
	}
	rules := []OwnedRule{}
	for _, rule := range state.Rules {
		rules = append(rules, OwnedRule{SessionID: "capture:" + rule.Prefix, Zone: rule.Zone, Rule: rule.text(), ExpiresAt: rule.ExpiresAt})
	}
	return rules
}
func capturePortKey(port Port) string { return port.Protocol + "/" + strconv.Itoa(port.Port) }

// Only new, already applied generations have the reserved slot. A complete
// native snapshot and base INPUT proof constrain zone fallback classification.
// Earlier foreign/direct denies are reported as coverage gaps, never relabelled.
func (a *Agent) plannedCaptureSidecars(ctx context.Context, scopes []capturePortScope, now time.Time) ([]captureSidecar, []string, error) {
	ports := map[Port]time.Time{}
	for _, scope := range scopes {
		if scope.Kind == captureDenied && !now.Before(scope.StartsAt) && now.Before(scope.ExpiresAt) {
			if previous, ok := ports[scope.Port]; !ok || scope.ExpiresAt.After(previous) {
				ports[scope.Port] = scope.ExpiresAt
			}
		}
	}
	if len(ports) == 0 {
		return nil, nil, nil
	}
	zone, err := LearningZone(ctx, a.Config, a.Commands)
	if err != nil {
		return nil, nil, err
	}
	snapshot := CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules())
	if snapshot.Status != "ok" {
		return nil, nil, errors.New("complete native inventory required before NFLOG deny classification")
	}
	raw, err := a.Commands.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, nil, err
	}
	if _, err = hostDefaultDenyKernelContext(raw, zone); err != nil {
		return nil, nil, err
	}
	gaps := []string{"Earlier unmanaged/direct rejects and untracked traffic may be absent; NFLOG is not a complete packet ledger."}
	owned := map[string]bool{}
	if a.State.ManagedBundle != nil {
		for _, rule := range a.State.ManagedBundle.Rules {
			owned[rule.Zone+"\x00"+managedSemanticKey(rule.Rule)] = true
		}
	}
	if bundle := a.State.LearningAllowBundle; bundle != nil {
		// Learned allowances run before the terminal managed reject. Only
		// exact rules in our committed ledger, present in both scopes with
		// unchanged source-set contents, can be excluded from foreign-order
		// blockers. A PRTL prefix alone never establishes ownership.
		if err := validateManagedCommittedSets(ctx, a.Commands, learningBundleRecord(bundle)); err != nil {
			return nil, gaps, fmt.Errorf("learning overlay prevents exact NFLOG verdict classification: %w", err)
		}
		sets := map[string]string{}
		for _, set := range bundle.IPSets {
			if !strings.HasPrefix(set.Name, "prthak_l") || sets[set.Name] != "" {
				return nil, gaps, errors.New("ambiguous learning source-set ownership prevents exact NFLOG verdict classification")
			}
			sets[set.Name] = set.Family
		}
		for _, rule := range bundle.Rules {
			if !a.ownsLearningAllowRule(rule.Zone, rule.Rule) {
				return nil, gaps, errors.New("invalid owned learning overlay for exact NFLOG verdict classification")
			}
			info, _ := parseManagedRich(rule.Rule) // ownsLearningAllowRule already validated the exact shape.
			if info.SourceIPSet != "" && (sets[info.SourceIPSet] == "" || (sets[info.SourceIPSet] == "inet") != (info.Family == "ipv4")) {
				return nil, gaps, errors.New("missing learning source-set ownership prevents exact NFLOG verdict classification")
			}
			for _, scope := range []string{"runtime", "permanent"} {
				present, err := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
				if err != nil || !present {
					return nil, gaps, errors.New("committed learning overlay rule drift prevents exact NFLOG verdict classification")
				}
			}
			owned[rule.Zone+"\x00"+managedSemanticKey(rule.Rule)] = true
		}
	}
	for _, observation := range a.ownedFirewallObservationRules() {
		owned[observation.Zone+"\x00"+observation.Rule] = true
	}
	for _, rule := range snapshot.Rules {
		if rule.Scope != "runtime" {
			continue
		}
		if rule.Kind == "direct" || rule.Kind == "source" || rule.Kind == "forward_port" {
			return nil, gaps, errors.New("unsupported direct/source-zone/NAT context for exact NFLOG verdicts")
		}
		if rule.Kind == "policy" {
			_, detail, ok := strings.Cut(rule.Value, "\n")
			if !ok || !safeHostIPv6Policy(detail) {
				return nil, gaps, errors.New("unsupported policy ordering for exact NFLOG verdicts")
			}
		}
		if rule.Kind == "rich_rule" && !owned[rule.Zone+"\x00"+managedSemanticKey(rule.Value)] && !ownedObservation(rule.Value, a.ownedFirewallObservationRules()) {
			info, err := parseRich(rule.Value)
			if err != nil || info.Priority < 0 || info.Priority == 32767 && info.Action == "accept" {
				return nil, gaps, errors.New("unmanaged rule ordering prevents exact NFLOG verdict classification")
			}
		}
	}
	zoneText, err := a.Commands.Run(ctx, "firewall-cmd", "--list-all-zones")
	if err != nil {
		return nil, gaps, err
	}
	zones, err := parseFirewallZones(zoneText)
	if err != nil {
		return nil, gaps, err
	}
	fallback := false
	for _, z := range zones {
		if z.Name == zone {
			fallback = z.Target == "default" || z.Target == "DROP" || z.Target == "REJECT"
		}
	}
	result := []captureSidecar{}
	keys := []Port{}
	for port := range ports {
		keys = append(keys, port)
	}
	sort.Slice(keys, func(i, j int) bool { return capturePortKey(keys[i]) < capturePortKey(keys[j]) })
	for _, port := range keys {
		for _, family := range []string{"ipv4", "ipv6"} {
			if family == "ipv6" {
				if raw, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil && strings.TrimSpace(string(raw)) == "1" {
					continue
				}
			}
			priority := 32767
			proven := fallback
			if a.State.ManagedBundle != nil {
				for _, rule := range a.State.ManagedBundle.Rules {
					info, err := parseManagedRich(rule.Rule)
					if err != nil || info.Family != family || info.Action != "reject" {
						continue
					}
					if info.Port != "" && (info.Port != strconv.Itoa(port.Port) || info.Transport != port.Protocol) {
						continue
					}
					if info.Priority != managedCanonicalReject {
						gaps = append(gaps, "Legacy managed generation lacks a reserved NFLOG slot; explicitly review and refresh that policy to collect its denies.")
						proven = false
						priority = 0
						break
					}
					present, err := firewallQuery(ctx, a.Commands, "runtime", rule.Zone, "rich_rule", rule.Rule)
					if err != nil || !present {
						return nil, gaps, errors.New("exact terminal managed reject is no longer present")
					}
					priority = managedCaptureReject
					proven = true
					break
				}
			}
			if !proven {
				continue
			}
			if len(result) >= 128 {
				return nil, gaps, errors.New("NFLOG exact port/family rule capacity exceeded")
			}
			expiry := ports[port]
			if limit := now.Add(120 * time.Second); expiry.After(limit) {
				expiry = limit
			}
			prefix := "PRTN" + shaText(zone + "/" + family + "/" + capturePortKey(port) + "/" + strconv.Itoa(priority))[:16] + ":"
			if verificationPrefix := a.policyVerificationPrefix(port, family); verificationPrefix != "" {
				// Verification requires an exact owned terminal reject. A generic
				// zone fallback cannot prove that the selected managed policy denied.
				if priority != managedCaptureReject {
					gaps = append(gaps, "Verification has no exact owned terminal reject for this port/family.")
					continue
				}
				prefix = verificationPrefix
			}
			result = append(result, captureSidecar{Zone: zone, Family: family, Port: port, Priority: priority, Group: captureGroup(a.Config.StateDir), Prefix: prefix, ExpiresAt: expiry})
		}
	}
	if len(result) == 0 {
		return nil, gaps, errors.New("no verifiable terminal deny path exists for selected ports")
	}
	return result, gaps, nil
}
