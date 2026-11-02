package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const maxFirewallRules = 1500
const maxFirewallSnapshotBytes = 512 * 1024

func shaText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func FirewallFingerprint(scope, zone, kind, value string) string {
	return shaText(scope + "\x00" + zone + "\x00" + kind + "\x00" + value)
}
func FirewallLogicalKey(zone, kind, value string) string {
	return shaText(zone + "\x00" + kind + "\x00" + value)
}
func finishFirewallDigest(snapshot *FirewallSnapshot) {
	sort.Slice(snapshot.Rules, func(i, j int) bool { return snapshot.Rules[i].Fingerprint < snapshot.Rules[j].Fingerprint })
	fingerprints := []string{}
	for _, rule := range snapshot.Rules {
		fingerprints = append(fingerprints, rule.Fingerprint)
	}
	snapshot.Digest = shaText(strings.Join(fingerprints, "\n"))
	sort.Strings(snapshot.Capabilities)
}
func firewallArgs(scope string, args ...string) []string {
	if scope == "permanent" {
		return append([]string{"--permanent"}, args...)
	}
	return args
}
func unsupportedFirewallCommand(out string) bool {
	out = strings.ToLower(out)
	return strings.Contains(out, "unrecognized arguments") || strings.Contains(out, "invalid option") || strings.Contains(out, "unknown option")
}

type parsedZone struct {
	Name   string
	Target string
	Active bool
	Fields map[string][]string
	Rich   []string
}

func parseFirewallZones(text string) ([]parsedZone, error) {
	zones := []parsedZone{}
	current := -1
	rich := false
	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if raw[0] != ' ' && raw[0] != '\t' {
			fields := strings.Fields(trimmed)
			if len(fields) == 0 || !firewallName.MatchString(fields[0]) {
				return nil, fmt.Errorf("unexpected zone inventory format")
			}
			zones = append(zones, parsedZone{Name: fields[0], Active: strings.Contains(trimmed, "(active)"), Fields: map[string][]string{}})
			current = len(zones) - 1
			rich = false
			if len(zones) > 128 {
				return nil, fmt.Errorf("zone inventory exceeds safety limit")
			}
			continue
		}
		if current < 0 {
			return nil, fmt.Errorf("zone inventory lacks a zone header")
		}
		if rich && strings.HasPrefix(trimmed, "rule ") {
			zones[current].Rich = append(zones[current].Rich, trimmed)
			continue
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, fmt.Errorf("unexpected zone field")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		rich = key == "rich rules"
		if key == "target" {
			zones[current].Target = value
		} else if !rich {
			zones[current].Fields[key] = strings.Fields(value)
		}
	}
	if len(zones) == 0 {
		return nil, fmt.Errorf("no firewalld zones returned")
	}
	for _, zone := range zones {
		if zone.Target == "" {
			return nil, fmt.Errorf("zone target missing")
		}
	}
	return zones, nil
}
func CollectFirewallSnapshot(ctx context.Context, runner CommandRunner, owned []OwnedRule) *FirewallSnapshot {
	snapshot := &FirewallSnapshot{CollectedAt: time.Now().UTC(), Status: "ok", Rules: []FirewallRule{}, Capabilities: []string{"runtime-zones", "permanent-zones", "service-port-simple-rich-changes", "imported_zone_target_v1", "imported_direct_v1", "imported_nat_v1"}}
	issues := []string{}
	contexts := []string{}
	policyDetails := map[string]string{}
	knownIPv6ControlPolicy := false
	seen := map[string]bool{}
	bytes := 0
	zonesRead := 0
	ambiguous := false
	issue := func(message string) {
		if len(issues) < 12 {
			issues = append(issues, message)
		}
	}
	add := func(scope, zone, kind, value, action, risk, reason string, editable bool) {
		if len(value) > 2048 || len(snapshot.Rules) >= maxFirewallRules {
			issue("firewall inventory truncated at safety limit")
			return
		}
		rule := FirewallRule{Fingerprint: FirewallFingerprint(scope, zone, kind, value), LogicalKey: FirewallLogicalKey(zone, kind, value), Scope: scope, Zone: zone, Kind: kind, Value: value, Action: action, Risk: risk, Editable: editable, Reason: reason}
		if seen[rule.Fingerprint] {
			return
		}
		encoded, _ := json.Marshal(rule)
		if bytes+len(encoded) > maxFirewallSnapshotBytes-4096 {
			issue("firewall inventory exceeds bounded report budget")
			return
		}
		bytes += len(encoded)
		seen[rule.Fingerprint] = true
		snapshot.Rules = append(snapshot.Rules, rule)
	}
	state, e := runner.Run(ctx, "firewall-cmd", "--state")
	if e != nil || strings.TrimSpace(state) != "running" {
		snapshot.Status = "error"
		snapshot.Error = "firewalld is not running or inventory is unavailable"
		finishFirewallDigest(snapshot)
		return snapshot
	}
	if text, _ := runner.Run(ctx, "ufw", "status"); strings.Contains(strings.ToLower(text), "status: active") {
		ambiguous = true
		contexts = append(contexts, "UFW is active; automatic migration and changes are refused")
	}
	defaultZone, e := runner.Run(ctx, "firewall-cmd", "--get-default-zone")
	if e == nil && firewallName.MatchString(strings.TrimSpace(defaultZone)) {
		add("runtime", "", "default_zone", strings.TrimSpace(defaultZone), "view-only", "low", "default-zone assignment is view-only", false)
	} else {
		issue("default-zone inventory unavailable")
	}
	for _, scope := range []string{"runtime", "permanent"} {
		text, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--list-all-zones")...)
		if e != nil {
			issue(scope + " zone inventory unavailable")
			continue
		}
		zones, e := parseFirewallZones(text)
		if e != nil {
			issue(scope + " zone inventory could not be parsed")
			continue
		}
		zonesRead++
		active := 0
		for _, zone := range zones {
			if scope == "runtime" && (zone.Active || len(zone.Fields["interfaces"])+len(zone.Fields["sources"]) > 0) {
				active++
			}
			if len(zone.Fields["sources"]) > 0 {
				ambiguous = true
				contexts = append(contexts, "source-bound zones are view-only")
			}
			reason := ""
			editable := !strings.EqualFold(zone.Target, "ACCEPT")
			if !editable {
				reason = "zone target ACCEPT makes access changes ambiguous; view-only"
			}
			targetEditable := scope == "permanent" && validZoneTarget(zone.Target)
			targetReason := "runtime target changes require a global reload and remain view-only"
			if targetEditable {
				targetReason = ""
			}
			targetAction := "view-only"
			if zone.Target == "ACCEPT" {
				targetAction = "allow"
			} else if zone.Target == "DROP" || zone.Target == "REJECT" {
				targetAction = "deny"
			}
			add(scope, zone.Name, "target", zone.Target, targetAction, "high", targetReason, targetEditable)
			for _, service := range zone.Fields["services"] {
				add(scope, zone.Name, "service", service, "allow", "medium", reason, editable && firewallName.MatchString(service))
			}
			for _, port := range zone.Fields["ports"] {
				add(scope, zone.Name, "port", port, "allow", "medium", reason, editable && validPortValue(port))
			}
			for _, value := range zone.Rich {
				zoneOwned := []OwnedRule{}
				if scope == "runtime" {
					for _, record := range owned {
						if record.Zone == zone.Name {
							zoneOwned = append(zoneOwned, record)
						}
					}
				}
				if ownedObservation(value, zoneOwned) {
					continue
				}
				action := "view-only"
				risk := "high"
				canEdit := false
				why := "rich rule uses constructs outside the safe editing subset"
				if info, e := parseRich(value); e == nil {
					if info.Action == "accept" {
						action = "allow"
						risk = "medium"
					} else if info.Action == "drop" || info.Action == "reject" {
						action = "deny"
					} else if info.HasLog {
						action = "observe"
						risk = "low"
					}
					canEdit = editable && richEditable(info)
					if canEdit {
						why = ""
					}
					if info.Priority < 0 {
						ambiguous = true
						contexts = append(contexts, "unmanaged negative-priority rich rules are view-only")
					}
				} else {
					ambiguous = true
					contexts = append(contexts, "unsupported rich-rule context requires manual review")
				}
				if reason != "" {
					why = reason
				}
				add(scope, zone.Name, "rich_rule", value, action, risk, why, canEdit)
			}
			for _, mapping := range [][2]string{{"interfaces", "interface"}, {"sources", "source"}, {"protocols", "protocol"}, {"forward-ports", "forward_port"}, {"source-ports", "source_port"}, {"icmp-blocks", "icmp_block"}, {"masquerade", "masquerade"}, {"forward", "forward"}, {"icmp-block-inversion", "icmp_inversion"}} {
				for _, value := range zone.Fields[mapping[0]] {
					if mapping[1] == "forward_port" {
						_, err := parseForwardPort(value)
						if err != nil {
							ambiguous = true
							contexts = append(contexts, "remote or unsupported forwarding requires manual review")
						}
						why := "remote routing and unsupported redirects are view-only"
						if err == nil && editable {
							why = ""
						} else if reason != "" {
							why = reason
						}
						add(scope, zone.Name, "forward_port", value, "redirect", "high", why, err == nil && editable)
						continue
					}
					add(scope, zone.Name, mapping[1], value, "view-only", "low", "binding/routing/control configuration is view-only", false)
				}
			}
		}
		if scope == "runtime" && active > 1 {
			ambiguous = true
			contexts = append(contexts, "multiple active zones require manual review")
		}
		direct, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--direct", "--get-all-rules")...)
		if e != nil {
			issue(scope + " direct-rule inventory unavailable")
		} else {
			snapshot.Capabilities = append(snapshot.Capabilities, scope+"-direct-visible")
			for _, value := range strings.Split(direct, "\n") {
				value = strings.TrimSpace(value)
				if value == "" || strings.HasPrefix(strings.ToLower(value), "warning") {
					continue
				}
				info, err := parseDirect(value)
				action, why := "view-only", "direct rules outside the typed INPUT filter grammar require manual review"
				if err != nil {
					ambiguous = true
					contexts = append(contexts, "unsupported direct-rule context requires manual review")
				} else {
					action = strings.ToLower(info.Action)
					why = ""
				}
				add(scope, "", "direct", value, action, "high", why, err == nil)
			}
		}
		names, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-policies")...)
		if e != nil {
			if unsupportedFirewallCommand(names) {
				snapshot.Capabilities = append(snapshot.Capabilities, scope+"-policies-unsupported")
			} else {
				issue(scope + " policy inventory unavailable")
			}
		} else {
			snapshot.Capabilities = append(snapshot.Capabilities, scope+"-policies-visible")
			for _, name := range strings.Fields(names) {
				if !firewallName.MatchString(name) {
					issue("unexpected policy name")
					continue
				}
				details, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+name, "--list-all")...)
				if e != nil {
					issue(scope + " policy details unavailable")
					continue
				}
				policyDetails[scope+"|"+name] = details
				add(scope, "", "policy", name+"\n"+strings.TrimSpace(details), "view-only", "high", "policy objects are view-only", false)
			}
		}
	}
	if conflictingDirectRules(snapshot.Rules) {
		ambiguous = true
		contexts = append(contexts, "overlapping conflicting direct rules at equal priority require manual review")
	}
	activePolicies, e := runner.Run(ctx, "firewall-cmd", "--get-active-policies")
	if e == nil {
		names, valid := activePolicyNames(activePolicies)
		if !valid {
			issue("active-policy output is ambiguous")
		}
		for _, name := range names {
			if safeHostIPv6Policy(policyDetails["runtime|"+name]) {
				knownIPv6ControlPolicy = true
				snapshot.Capabilities = append(snapshot.Capabilities, "known-icmpv6-host-policy-nonoverlap")
				continue
			}
			ambiguous = true
			contexts = append(contexts, "active policy objects require manual review")
		}
	} else if !unsupportedFirewallCommand(activePolicies) {
		issue("active-policy inventory unavailable")
	}
	// Definitions are view-only digest inputs: changing a named service's ports
	// must invalidate an approved snapshot even when the service name is unchanged.
	definitions := map[string][]FirewallServicePort{}
	complexDefinitions := map[string]bool{}
	for i, rule := range snapshot.Rules {
		if rule.Kind != "service" {
			continue
		}
		key := rule.Scope + "\x00" + rule.Value
		resolved, seenDefinition := definitions[key]
		if !seenDefinition {
			raw, err := runner.Run(ctx, "firewall-cmd", firewallArgs(rule.Scope, "--info-service="+rule.Value)...)
			if err != nil {
				issue("named service definition unavailable")
				definitions[key] = nil
				continue
			}
			add(rule.Scope, "", "service_definition", rule.Value+"\n"+strings.TrimSpace(raw), "view-only", "low", "service definitions are view-only", false)
			values, err := parseServicePortValues(raw)
			if err != nil || len(values) > 64 {
				complexDefinitions[key] = true
			}
			if err == nil && len(values) <= 64 {
				for _, value := range values {
					parts := strings.Split(value, "/")
					resolved = append(resolved, FirewallServicePort{parts[0], parts[1]})
				}
			}
			definitions[key] = resolved
		}
		if complexDefinitions[key] {
			snapshot.Rules[i].Editable = false
			snapshot.Rules[i].Reason = "complex named-service definition is view-only"
		}
		encoded, _ := json.Marshal(resolved)
		if bytes+len(encoded) > maxFirewallSnapshotBytes-4096 {
			issue("resolved service ports exceed report budget")
			continue
		}
		bytes += len(encoded)
		snapshot.Rules[i].Ports = resolved
	}
	if knownIPv6ControlPolicy {
		for i, rule := range snapshot.Rules {
			if rule.Kind != "rich_rule" || !rule.Editable {
				continue
			}
			info, err := parseRich(rule.Value)
			if err != nil || info.Port == "" && info.Service == "" {
				snapshot.Rules[i].Editable = false
				snapshot.Rules[i].Reason = "IPv6 control policy overlaps protocol-wide rich rules; only TCP/UDP-scoped edits are supported"
			}
		}
	}
	if len(issues) > 0 {
		snapshot.Status = "partial"
		if zonesRead == 0 {
			snapshot.Status = "error"
		}
		snapshot.Error = strings.Join(issues, "; ")
	}
	if ambiguous || snapshot.Status != "ok" {
		for i := range snapshot.Rules {
			if snapshot.Rules[i].Editable {
				snapshot.Rules[i].Editable = false
				snapshot.Rules[i].Reason = "inventory context requires manual review: " + snapshot.Error
				if snapshot.Error == "" {
					snapshot.Rules[i].Reason = "direct or unmanaged rule context is view-only"
				}
				if len(contexts) > 0 {
					snapshot.Rules[i].Reason = strings.Join(contexts, "; ")
				}
			}
		}
	}
	finishFirewallDigest(snapshot)
	for attempts := 0; attempts < 4; attempts++ {
		encoded, _ := json.Marshal(snapshot)
		if len(encoded) <= maxFirewallSnapshotBytes {
			break
		}
		snapshot.Status = "partial"
		snapshot.Error = "firewall inventory truncated to bounded report budget"
		keep := len(snapshot.Rules) * (maxFirewallSnapshotBytes - 4096) / len(encoded)
		if keep >= len(snapshot.Rules) {
			keep = len(snapshot.Rules) - 1
		}
		if keep < 0 {
			keep = 0
		}
		snapshot.Rules = snapshot.Rules[:keep]
		for i := range snapshot.Rules {
			snapshot.Rules[i].Editable = false
			snapshot.Rules[i].Reason = "incomplete bounded inventory is view-only"
		}
		finishFirewallDigest(snapshot)
	}
	return snapshot
}
func retainFirewallSnapshot(previous, next *FirewallSnapshot) *FirewallSnapshot {
	if next == nil {
		return previous
	}
	if next.Status == "ok" || previous == nil || len(previous.Rules) == 0 {
		return next
	}
	next.Rules = append([]FirewallRule{}, previous.Rules...)
	next.Digest = previous.Digest
	for i := range next.Rules {
		next.Rules[i].Editable = false
		next.Rules[i].Reason = "prior inventory retained after an incomplete read"
	}
	next.Error += "; prior snapshot retained"
	return next
}
func (a *Agent) ownedFirewallObservationRules() []OwnedRule {
	// Read the private exact ledger so independent rollback/startup observes the
	// same ownership as the running collector, including pending native cleanup.
	captureOwned := a.captureObservationRules()
	owned := append([]OwnedRule{}, a.State.Rules...)
	if a.AdditionalObservationRules != nil {
		owned = append(owned, a.AdditionalObservationRules()...)
	}
	return append(owned, captureOwned...)
}
