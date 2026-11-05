package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

type captureStockGateway struct{ target, ingress, egress, services string }

// Exact semantic definitions from firewalld v2.4.3, commit
// 865b0da0a73927b152ab6d2f7c1da9a03f5d4a51/config/policies/*.xml.
// These definitions alone do not prove inactivity: both scopes, fresh active
// readbacks and unchanged live INPUT proof are required by the planner below.
var captureStockGateways = map[string]captureStockGateway{
	"gateway-dmz-to-HOST":   {"CONTINUE", "dmz", "HOST", "dhcp dns"},
	"gateway-lan-to-HOST":   {"CONTINUE", "home internal trusted", "HOST", "dhcp dns ssh"},
	"gateway-lan-to-work":   {"ACCEPT", "home internal trusted", "work", "ftp tftp"},
	"gateway-lan-to-world":  {"ACCEPT", "home internal trusted", "external public", "ftp tftp"},
	"gateway-world-to-HOST": {"CONTINUE", "external public", "HOST", "dhcpv6-client"},
}

func captureStockGatewayDefinition(name, detail, scope string) bool {
	stock, known := captureStockGateways[name]
	if !known || scope != "runtime" && scope != "permanent" || len(detail) > 16384 {
		return false
	}
	header := name
	if scope == "runtime" {
		header += " (disabled)"
	}
	lines := strings.Split(strings.TrimSpace(detail), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != header {
		return false
	}
	expected := map[string]string{"disable": "yes", "priority": "1000", "target": stock.target,
		"ingress-zones": stock.ingress, "egress-zones": stock.egress, "services": stock.services,
		"ports": "", "protocols": "", "masquerade": "no", "forward-ports": "", "source-ports": "", "icmp-blocks": "", "rich rules": ""}
	seen := map[string]bool{}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, raw, ok := strings.Cut(strings.TrimSpace(line), ":")
		want, known := expected[key]
		if !ok || !known || seen[key] {
			return false
		}
		seen[key] = true
		values := strings.Fields(raw)
		if key == "ingress-zones" || key == "egress-zones" || key == "services" {
			sort.Strings(values)
		}
		if strings.Join(values, " ") != want {
			return false
		}
	}
	return len(seen) == len(expected)
}

type captureGatewayPolicyProof struct {
	namesByScope  map[string][]string
	definitions   map[string]map[string]string
	gateways      []string
	active        string
	allowedActive []string
}

// Inventory includes inactive policy templates. Only exact upstream disabled
// templates can be excluded from ordering blockers. Custom or incomplete policy
// objects remain unsupported even when their names resemble stock policies.
func beginCaptureGatewayPolicyProof(ctx context.Context, runner CommandRunner, snapshot *FirewallSnapshot) (*captureGatewayPolicyProof, error) {
	definitions := map[string]map[string]string{"runtime": {}, "permanent": {}}
	proof := &captureGatewayPolicyProof{namesByScope: map[string][]string{}, definitions: definitions}
	for _, rule := range snapshot.Rules {
		if rule.Kind != "policy" {
			continue
		}
		name, detail, ok := strings.Cut(rule.Value, "\n")
		if !ok || !firewallName.MatchString(name) || definitions[rule.Scope] == nil || definitions[rule.Scope][name] != "" {
			return nil, errors.New("ambiguous policy inventory prevents exact NFLOG verdicts")
		}
		definitions[rule.Scope][name] = detail
	}
	for name, detail := range definitions["runtime"] {
		if safeHostIPv6Policy(detail) {
			proof.allowedActive = append(proof.allowedActive, name)
			continue
		}
		if !captureStockGatewayDefinition(name, detail, "runtime") || !captureStockGatewayDefinition(name, definitions["permanent"][name], "permanent") {
			return nil, fmt.Errorf("unsupported policy ordering for exact NFLOG verdicts: %s must match the disabled stock definition in both scopes", name)
		}
		proof.gateways = append(proof.gateways, name)
	}
	if len(proof.gateways) == 0 {
		return nil, nil
	}
	// Also reject a custom permanent-only policy in this compatibility path.
	for name, detail := range definitions["permanent"] {
		if definitions["runtime"][name] == "" || !safeHostIPv6Policy(detail) && !captureStockGatewayDefinition(name, detail, "permanent") {
			return nil, fmt.Errorf("unsupported permanent policy context for exact NFLOG verdicts: %s", name)
		}
	}
	sort.Strings(proof.gateways)
	sort.Strings(proof.allowedActive)
	for _, scope := range []string{"runtime", "permanent"} {
		// This compatibility proof is for the five stock gateway templates
		// alongside the stock control policy, not an unbounded policy graph.
		if len(definitions[scope]) > len(captureStockGateways)+1 {
			return nil, errors.New("policy context exceeds the bounded stock-gateway NFLOG proof")
		}
		for name := range definitions[scope] {
			proof.namesByScope[scope] = append(proof.namesByScope[scope], name)
		}
		sort.Strings(proof.namesByScope[scope])
		if err := proof.verifyNames(ctx, runner, scope); err != nil {
			return nil, err
		}
	}
	active, err := captureActivePolicyContext(ctx, runner, proof.gateways, proof.allowedActive)
	if err != nil {
		return nil, err
	}
	proof.active = active
	return proof, nil
}

func (proof *captureGatewayPolicyProof) verifyNames(ctx context.Context, runner CommandRunner, scope string) error {
	raw, err := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-policies")...)
	if err != nil || len(raw) > 16384 {
		return errors.New("complete policy-name readback is required for exact NFLOG verdicts")
	}
	names := strings.Fields(raw)
	if len(names) > 128 {
		return errors.New("policy-name inventory exceeds the NFLOG proof bound")
	}
	sort.Strings(names)
	if !slices.Equal(names, proof.namesByScope[scope]) {
		return errors.New("policy inventory changed during exact NFLOG ordering proof")
	}
	return nil
}

func captureActivePolicyContext(ctx context.Context, runner CommandRunner, disabled, allowed []string) (string, error) {
	raw, err := runner.Run(ctx, "firewall-cmd", "--get-active-policies")
	if err != nil || len(raw) > 65536 {
		return "", errors.New("active-policy readback is required for exact NFLOG verdicts")
	}
	policies := map[string]map[string]string{}
	current := ""
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if rawLine[0] != ' ' && rawLine[0] != '\t' {
			if !firewallName.MatchString(line) || policies[line] != nil || len(policies) >= 128 || slices.Contains(disabled, line) || !slices.Contains(allowed, line) {
				return "", errors.New("disabled stock gateway is active or active-policy readback is ambiguous")
			}
			current = line
			policies[current] = map[string]string{}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || current == "" || key != "ingress-zones" && key != "egress-zones" || policies[current][key] != "" {
			return "", errors.New("active-policy bindings are ambiguous")
		}
		zones := strings.Fields(value)
		if len(zones) == 0 || len(zones) > 128 {
			return "", errors.New("active-policy bindings are empty or unbounded")
		}
		sort.Strings(zones)
		for i, zone := range zones {
			if !firewallName.MatchString(zone) || i > 0 && zones[i-1] == zone {
				return "", errors.New("active-policy bindings are invalid or duplicate")
			}
		}
		policies[current][key] = strings.Join(zones, " ")
	}
	for _, bindings := range policies {
		if len(bindings) != 2 || bindings["ingress-zones"] != "ANY" || bindings["egress-zones"] != "HOST" {
			return "", errors.New("active-policy bindings do not match the proved IPv6 control policy")
		}
	}
	return directApprovalDigest(policies), nil
}

func (proof *captureGatewayPolicyProof) finish(ctx context.Context, runner CommandRunner, zone, kernelDigest string) error {
	if proof == nil {
		return nil
	}
	for _, scope := range []string{"runtime", "permanent"} {
		for _, name := range proof.namesByScope[scope] {
			detail, err := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+name, "--list-all")...)
			if err != nil {
				return fmt.Errorf("policy definition readback failed during NFLOG proof: %s/%s", scope, name)
			}
			if slices.Contains(proof.gateways, name) {
				if !captureStockGatewayDefinition(name, detail, scope) {
					return fmt.Errorf("disabled stock gateway definition changed during NFLOG proof: %s/%s", scope, name)
				}
			} else if !safeHostIPv6Policy(detail) || strings.Join(strings.Fields(detail), " ") != strings.Join(strings.Fields(proof.definitions[scope][name]), " ") {
				return fmt.Errorf("IPv6 control policy definition changed during NFLOG proof: %s/%s", scope, name)
			}
		}
	}
	raw, err := runner.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return errors.New("final live INPUT readback is required for exact NFLOG verdicts")
	}
	current, err := liveHostDefaultDenyKernelContext(ctx, runner, raw, zone)
	if err != nil || current != kernelDigest {
		return errors.New("live INPUT context changed during exact NFLOG ordering proof")
	}
	for _, scope := range []string{"runtime", "permanent"} {
		if err := proof.verifyNames(ctx, runner, scope); err != nil {
			return err
		}
	}
	active, err := captureActivePolicyContext(ctx, runner, proof.gateways, proof.allowedActive)
	if err != nil || active != proof.active {
		return errors.New("active policy context changed during exact NFLOG ordering proof")
	}
	return nil
}
