package agent

// Whole-host authority is independent of ordinary per-port enforcement. It is
// carried by the exact signed generation, never inferred from a generic grant.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const hostDefaultDenyControlProfile = "host-inbound-control-v1"

func (a *Agent) hostDefaultDenyGuarded() bool {
	return a.State.ManagedBundle != nil && a.State.ManagedBundle.HostDefaultDeny || a.State.Policy != nil && a.State.Policy.HostDefaultDeny
}

func hostDefaultDenyRulePolicy(p *Policy, protection Protection) *Policy {
	if !p.HostDefaultDeny {
		return p
	}
	copyPolicy := *p
	copyPolicy.Services = append([]Service{}, p.Services...)
	// SSH remains explicitly protected even if no application policy mentions it.
	for _, port := range protection.SSHPorts {
		present := false
		for _, svc := range copyPolicy.Services {
			if svc.Port == port && svc.Protocol == "tcp" && (svc.Mode == "enforce" || svc.Mode == "" && p.Mode == "enforce") {
				present = true
			}
		}
		if !present {
			copyPolicy.Services = append(copyPolicy.Services, Service{Port: port, Protocol: "tcp", Mode: "enforce", Sources: append([]string{}, protection.ManagementSources...)})
		}
	}
	return &copyPolicy
}

func hostDefaultDenyControlRules(protection Protection, nonce string, stage bool) []ManagedRule {
	allow, reject := managedCanonicalAllow, managedCanonicalReject
	if stage {
		allow, reject = managedStageAllow, managedStageReject
	}
	rules := []ManagedRule{}
	for _, family := range []string{"ipv4", "ipv6"} {
		protocol, dhcp := "icmp", 68
		if family == "ipv6" {
			protocol, dhcp = "ipv6-icmp", 546
		}
		// These declared control exceptions preserve PMTU/errors, diagnostics,
		// IPv6 neighbour/router discovery, and DHCP client renewal. They do not
		// expose a DHCP server or grant arbitrary application TCP/UDP ports.
		text := fmt.Sprintf(`rule priority="%d" family="%s" protocol value="%s" log prefix="PRTM%s:" level="debug" limit value="1/m" accept`, allow, family, protocol, nonce[:12])
		rules = append(rules, ManagedRule{protection.Zone, text}, ManagedRule{protection.Zone, managedRuleText(nonce, allow, family, "", Service{Port: dhcp, Protocol: "udp"}, "accept")})
	}
	// All application, SSH and control accepts precede both family fallbacks.
	for _, family := range []string{"ipv4", "ipv6"} {
		rules = append(rules, ManagedRule{protection.Zone, fmt.Sprintf(`rule priority="%d" family="%s" log prefix="PRTM%s:" level="debug" limit value="1/m" reject`, reject, family, nonce[:12])})
	}
	return rules
}

// Imported rich-rule editing deliberately keeps its smaller TCP/UDP grammar.
// Only owned managed control rules admit these two exact protocol elements.
func parseHostDefaultDenyControl(value string) (richInfo, bool) {
	tokens, err := richTokens(value)
	if err != nil {
		return richInfo{}, false
	}
	protocol := ""
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] == "protocol" && (tokens[i+1] == "value=icmp" || tokens[i+1] == "value=ipv6-icmp") {
			protocol = strings.TrimPrefix(tokens[i+1], "value=")
			tokens[i+1] = "value=tcp"
		}
	}
	if protocol == "" {
		return richInfo{}, false
	}
	info, err := parseRich(strings.Join(tokens, " "))
	info.Protocol = protocol
	return info, err == nil && hostDefaultDenyOwnedControl(info)
}

func hostDefaultDenyOwnedControl(info richInfo) bool {
	if info.Source != "" || info.SourceIPSet != "" || info.Service != "" || info.Port != "" || info.LogLevel != "debug" || info.LogLimit != "1/m" || len(info.LogPrefix) != 17 || !strings.HasPrefix(info.LogPrefix, "PRTM") || !strings.HasSuffix(info.LogPrefix, ":") || !validDigest(strings.Repeat(info.LogPrefix[4:16], 5)+info.LogPrefix[4:8]) {
		return false
	}
	if info.Family != "ipv4" && info.Family != "ipv6" {
		return false
	}
	if info.Action == "reject" && info.Protocol == "" {
		return info.Priority == managedCanonicalReject || info.Priority == managedStageReject || info.Priority == -30999 || info.Priority == -31001
	}
	return info.Action == "accept" && (info.Priority == managedCanonicalAllow || info.Priority == managedStageAllow || info.Priority == -31002) && (info.Family == "ipv4" && info.Protocol == "icmp" || info.Family == "ipv6" && info.Protocol == "ipv6-icmp")
}

func hostDefaultDenyFallback(rule ManagedRule) bool {
	info, err := parseManagedRich(rule.Rule)
	return err == nil && info.Action == "reject" && info.Port == "" && hostDefaultDenyOwnedControl(info)
}

func protectionDigest(protection Protection) string {
	value := map[string]any{"management_sources": protection.ManagementSources, "ssh_ports": protection.SSHPorts, "controller_url": protection.ControllerURL, "management_probe_url": protection.ManagementProbeURL, "zone": protection.Zone}
	if protection.HostDefaultDenyContextDigest != "" || protection.HostDefaultDenyControlProfile != "" {
		value["host_default_deny_context_digest"] = protection.HostDefaultDenyContextDigest
		value["host_default_deny_control_profile"] = protection.HostDefaultDenyControlProfile
	}
	encoded, _ := json.Marshal(value)
	return shaText(string(encoded))
}

func (a *Agent) enrichHostDefaultDenyProtection(ctx context.Context, protection *Protection) {
	pendingRemoval := a.State.Policy != nil && a.State.Policy.Enforcement != nil && a.State.Policy.Enforcement.Intent == "remove_host_default_deny"
	if !a.Config.AllowHostDefaultDeny && !a.hostDefaultDenyGuarded() && !pendingRemoval {
		return
	}
	digest, blockers := a.hostDefaultDenyContext(ctx, *protection)
	protection.HostDefaultDenyContextDigest = digest
	protection.HostDefaultDenyControlProfile = hostDefaultDenyControlProfile
	protection.HostDefaultDenyBlockers = blockers
	if !a.Config.AllowHostDefaultDeny {
		protection.HostDefaultDenyBlockers = append(protection.HostDefaultDenyBlockers, "local allow_host_default_deny opt-in is disabled; reviewed removal remains available")
	}
	protection.HostDefaultDenyReady = protection.Ready && a.Config.AllowHostDefaultDeny && len(blockers) == 0
	protection.Digest = protectionDigest(*protection)
}

func (a *Agent) hostDefaultDenyContext(ctx context.Context, protection Protection, pending ...[]ManagedRule) (string, []string) {
	blockers := []string{}
	add := func(message string) { blockers = append(blockers, message) }
	zone, topology, err := a.managedTopology(ctx)
	if err != nil || zone != protection.Zone {
		add("whole-server deny requires one stable interface-bound management zone")
	}
	defaultZone, err := a.Commands.Run(ctx, "firewall-cmd", "--get-default-zone")
	if err != nil || strings.TrimSpace(defaultZone) != protection.Zone {
		add("the management zone must also be the default zone")
	}
	links, err := a.Commands.Run(ctx, "ip", "-j", "link", "show")
	linkDigest, linkNames, linkError := hostDefaultDenyLinkContext(links)
	if err != nil || linkError != nil {
		add("complete non-bridge/non-VRF interface context is required")
	}
	forwardArgs := []string{"-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv4.conf.default.forwarding", "net.ipv6.conf.default.forwarding"}
	for _, name := range linkNames {
		// Slash syntax preserves dots in VLAN interface names as literal names.
		forwardArgs = append(forwardArgs, "net/ipv4/conf/"+name+"/forwarding", "net/ipv6/conf/"+name+"/forwarding")
	}
	forward, err := a.Commands.Run(ctx, "sysctl", forwardArgs...)
	values := strings.Fields(forward)
	forwardSafe := err == nil && len(values) == len(forwardArgs)-1
	for _, value := range values {
		if value != "0" {
			forwardSafe = false
		}
	}
	if !forwardSafe {
		add("whole-server deny does not support global, default or per-interface IP forwarding/router contexts")
	}
	if a.State.LearningAllowBundle != nil && (len(a.State.LearningAllowBundle.Rules) > 0 || len(a.State.LearningAllowBundle.Assignment.Services) > 0) {
		add("remove active learned additive grants before enabling whole-server deny")
	}
	if a.Config.AllowHostDefaultDeny && (!a.Config.Enforce || a.Config.LearningAutoAllow) {
		add("whole-server deny requires enforcement and no local automatic-learning authority")
	}
	if a.State.Policy != nil {
		if a.State.Policy.LearningAllow != nil && len(a.State.Policy.LearningAllow.Services) > 0 {
			add("pending learned additive grants conflict with whole-server deny")
		}
		for _, session := range a.State.Policy.LearningSessions {
			if session.PolicyAction == "auto_allow" && session.Status != "stopped" && session.Status != "expired" && !time.Now().Before(session.StartsAt) && time.Now().Before(SessionCutoff(session)) {
				add("stop active automatic access learning before enabling whole-server deny")
				break
			}
		}
	}
	snapshot := CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules(), a.Config.StateDir)
	if snapshot.Status != "ok" {
		add("complete fresh firewall inventory is required")
	}
	owned := map[string]bool{}
	if a.State.ManagedBundle != nil {
		for _, rule := range a.State.ManagedBundle.Rules {
			owned[rule.Zone+"\x00"+managedSemanticKey(rule.Rule)] = true
		}
	}
	for _, rules := range pending {
		for _, rule := range rules {
			owned[rule.Zone+"\x00"+managedSemanticKey(rule.Rule)] = true
		}
	}
	fingerprints := []string{}
	for _, rule := range snapshot.Rules {
		if rule.Kind == "rich_rule" && owned[rule.Zone+"\x00"+managedSemanticKey(rule.Value)] {
			continue
		}
		fingerprints = append(fingerprints, rule.Fingerprint)
		switch rule.Kind {
		case "source", "direct", "forward_port":
			add("source-zone, direct and NAT/forward-port configuration require migration")
		case "interface":
			if rule.Zone != protection.Zone {
				add("all permanent and runtime interface bindings must use the management zone")
			}
		case "masquerade":
			if rule.Value != "no" && rule.Zone == protection.Zone {
				add("masquerading is unsupported for whole-server deny")
			}
		case "policy":
			name, _, _ := strings.Cut(rule.Value, "\n")
			if name == egressPolicyName && OwnedEgressPolicyContext(ctx, a.Commands, a.Config.StateDir) == nil {
				continue
			}
			_, detail, ok := strings.Cut(rule.Value, "\n")
			if !ok || !safeHostIPv6Policy(detail) {
				add("only the verified default host IPv6 control policy is supported")
			}
		case "rich_rule":
			info, e := parseRich(rule.Value)
			if e != nil || info.Priority < 0 {
				add("unmanaged rich-rule constructs/negative priorities conflict with whole-server deny")
			}
		}
	}
	// This proof also detects out-of-band kernel hooks/tables and verifies that
	// loopback/stateful returns precede zone pre-rules in the running backend.
	raw, err := a.Commands.Run(ctx, "nft", "-j", "list", "ruleset")
	base, kernelError := hostDefaultDenyKernelContext(raw, protection.Zone)
	if err != nil || kernelError != nil {
		add("verified nftables host-input ordering without unrecognized hooks or inbound NAT is required")
	}
	sort.Strings(fingerprints)
	encoded, _ := json.Marshal(map[string]any{"topology": topology, "firewall": fingerprints, "kernel": base, "links": linkDigest, "forwarding": strings.Fields(forward), "profile": hostDefaultDenyControlProfile})
	return shaText(string(encoded)), blockers
}

func (a *Agent) validateHostDefaultDeny(p *Policy, protection Protection, removal bool) error {
	auth := p.Enforcement
	if auth == nil || !auth.HostDefaultDenyAck || auth.HostDefaultDenyRevision < 1 || auth.HostDefaultDenyConfigurationDigest != configurationState(a.Config).Digest || !validDigest(protection.HostDefaultDenyContextDigest) || protection.HostDefaultDenyControlProfile != hostDefaultDenyControlProfile {
		return errors.New("whole-server deny needs exact signed acknowledgement of the current endpoint configuration and context")
	}
	var proof endpointApprovalProof
	if json.Unmarshal(auth.ApprovalProof, &proof) != nil || proof.Mode != "single_admin" || validateEndpointApproval(a.Config, auth.ApprovalProof, p.ServerID, time.Now(), false, "host_default_deny") != nil {
		return errors.New("whole-server deny requires its own exact single-admin scope")
	}
	var action string
	_ = json.Unmarshal(proof.Scope["action"], &action)
	if action != "enable" && p.HostDefaultDeny || action != "disable" && removal {
		return errors.New("whole-server proof action does not match its exact enable/removal intent")
	}
	if p.HostDefaultDeny {
		if removal || !a.Config.AllowHostDefaultDeny || !a.Config.Enforce || a.Config.LearningAutoAllow || auth.Intent != "enforce_host_default_deny" || !protection.HostDefaultDenyReady {
			return errors.New("whole-server default deny is not explicitly opted in, reviewed or ready")
		}
	} else if !removal || auth.Intent != "remove_host_default_deny" {
		return errors.New("whole-server fallback removal requires its dedicated reviewed intent")
	}
	return nil
}

func managedRulesContain(rules []ManagedRule, candidate ManagedRule) bool {
	for _, rule := range rules {
		if rule.Zone == candidate.Zone && managedSemanticKey(rule.Rule) == managedSemanticKey(candidate.Rule) {
			return true
		}
	}
	return false
}

func (a *Agent) verifyHostDefaultDenyRemoved(ctx context.Context) error {
	snapshot := CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules(), a.Config.StateDir)
	if snapshot.Status != "ok" {
		return errors.New("whole-server cleanup absence could not be read back")
	}
	for _, rule := range snapshot.Rules {
		if rule.Kind == "rich_rule" && hostDefaultDenyFallback(ManagedRule{rule.Zone, rule.Value}) {
			return errors.New("owned whole-server fallback remains; cleanup is not committed")
		}
	}
	return nil
}

// Publish the new descriptor after a refused/raced push. A failed preflight
// must not leave the GUI stuck with a cached prior digest until discovery runs.
// This scan happens on failure, not on every heartbeat.
func (a *Agent) refreshHostDefaultDenyProtection(parent context.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if lease := managedLeaseFromContext(parent); lease != nil {
		ctx = withManagedLease(ctx, lease)
	}
	protection, _ := a.managedProtection(ctx)
	a.protection = &protection
}
