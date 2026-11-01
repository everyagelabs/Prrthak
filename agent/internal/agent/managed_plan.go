package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const maxManagedRules = 64
const managedCanonicalAllow = -31000
const managedCanonicalReject = -30999
const managedStageAllow = -31002
const managedStageReject = -31001

func canonicalSources(values []string, management bool) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		prefix, err := parsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, errors.New("managed sources must be numeric IPv4/IPv6 addresses or CIDRs")
		}
		prefix = prefix.Masked()
		if management && prefix.Bits() == 0 {
			return nil, errors.New("management_sources cannot contain a /0 network")
		}
		text := prefix.String()
		if !seen[text] {
			out = append(out, text)
			seen[text] = true
		}
	}
	sort.Strings(out)
	return out, nil
}
func compiledPolicyDigest(p *Policy) (string, error) {
	copyPolicy := *p
	copyPolicy.Digest = "canonical-hash-input"
	if err := ValidatePolicy(&copyPolicy); err != nil {
		return "", err
	}
	services := []map[string]any{}
	sorted := append([]Service{}, p.Services...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Protocol != sorted[j].Protocol {
			return sorted[i].Protocol < sorted[j].Protocol
		}
		return sorted[i].Port < sorted[j].Port
	})
	for _, svc := range sorted {
		mode := svc.Mode
		if mode == "" {
			mode = p.Mode
		}
		sources, err := canonicalSources(svc.Sources, false)
		if err != nil {
			return "", err
		}
		services = append(services, map[string]any{"port": svc.Port, "protocol": svc.Protocol, "mode": mode, "sources": sources})
	}
	value := map[string]any{"mode": p.Mode, "services": services}
	if p.HostDefaultDeny {
		value["host_default_deny"] = true
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return shaText(string(data)), nil
}
func enforcementBinding(p *Policy, protection string) string {
	return shaText("prthak-managed-v1\x00" + p.ServerID + "\x00" + fmt.Sprint(p.Version) + "\x00" + p.Digest + "\x00" + protection)
}
func managedRuleText(nonce string, priority int, family, source string, svc Service, action string) string {
	rule := fmt.Sprintf(`rule priority="%d" family="%s"`, priority, family)
	if source != "" {
		rule += fmt.Sprintf(` source address="%s"`, source)
	}
	return rule + fmt.Sprintf(` port port="%d" protocol="%s" log prefix="PRTM%s:" level="debug" limit value="1/m" %s`, svc.Port, svc.Protocol, nonce[:12], action)
}
func managedRules(p *Policy, protection Protection, nonce string, stage bool) ([]ManagedRule, error) {
	p = hostDefaultDenyRulePolicy(p, protection)
	allow, reject := managedCanonicalAllow, managedCanonicalReject
	if stage {
		allow, reject = managedStageAllow, managedStageReject
	}
	rules := []ManagedRule{}
	ssh := map[int]bool{}
	for _, port := range protection.SSHPorts {
		ssh[port] = true
	}
	for _, svc := range p.Services {
		mode := svc.Mode
		if mode == "" {
			mode = p.Mode
		}
		if mode != "enforce" {
			continue
		}
		sources := append([]string{}, svc.Sources...)
		if svc.Protocol == "tcp" && ssh[svc.Port] {
			if len(protection.ManagementSources) == 0 {
				return nil, errors.New("SSH enforcement requires nonempty approved management_sources")
			}
			sources = append(sources, protection.ManagementSources...)
		}
		sources, err := canonicalSources(sources, false)
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			prefix, _ := netip.ParsePrefix(source)
			family := "ipv6"
			if prefix.Addr().Is4() {
				family = "ipv4"
			}
			rules = append(rules, ManagedRule{protection.Zone, managedRuleText(nonce, allow, family, source, svc, "accept")})
		}
		if !p.HostDefaultDeny {
			for _, family := range []string{"ipv4", "ipv6"} {
				rules = append(rules, ManagedRule{protection.Zone, managedRuleText(nonce, reject, family, "", svc, "reject")})
			}
		}
	}
	if p.HostDefaultDeny {
		rules = append(rules, hostDefaultDenyControlRules(protection, nonce, stage)...)
	}
	if len(rules) > maxManagedRules {
		return nil, fmt.Errorf("managed bundle exceeds first-version limit of %d rich rules", maxManagedRules)
	}
	return rules, nil
}
func (a *Agent) managedProtection(ctx context.Context) (Protection, error) {
	controllerOrigin := a.Config.ControllerURL
	if a.Config.ControlURL != "" {
		controllerOrigin = a.Config.ControlURL
	}
	protection := Protection{ManagementSources: []string{}, SSHPorts: []int{}, ControllerURL: controllerOrigin, ManagementProbeURL: a.Config.ManagementProbeURL, Blockers: []string{}}
	add := func(err string) { protection.Blockers = append(protection.Blockers, err) }
	if err := policySigningReadiness(a.Config); err != nil {
		add("policy signing trust: " + err.Error())
	}
	var err error
	protection.ManagementSources, err = canonicalSources(a.Config.ManagementSources, true)
	if err != nil {
		protection.ManagementSources = []string{}
		add(err.Error())
	}
	if len(protection.ManagementSources) == 0 {
		add("configure restricted management_sources before managed enforcement")
	}
	protection.ManagementProbeURL = configuredManagedProbe(a.Config)
	if a.Simulate {
		add("simulation cannot enforce firewall policies")
	}
	zone, err := LearningZone(ctx, a.Config, a.Commands)
	if err != nil {
		add(err.Error())
	} else {
		protection.Zone = zone
	}
	// Unlike observation, managed access restrictions do not permit multiple active zones.
	if text, e := a.Commands.Run(ctx, "firewall-cmd", "--get-active-zones"); e != nil {
		add("active-zone discovery failed")
	} else {
		count := 0
		for _, line := range strings.Split(text, "\n") {
			if line != "" && line[0] != ' ' && line[0] != '\t' {
				count++
			}
		}
		if count != 1 {
			add("managed enforcement requires exactly one active zone")
		}
	}
	text, err := a.Commands.Run(ctx, "ss", "-H", "-lntup")
	if err != nil {
		add("actual SSH listener discovery failed")
	} else {
		listeners := ParseSockets(text)
		bindings := []SocketBinding{}
		if raw, e := a.Commands.Run(ctx, "systemctl", "list-sockets", "--all", "--no-legend", "--no-pager", "--plain"); e == nil {
			bindings = ParseSystemdSockets(raw)
		}
		listeners = EnrichListeners(listeners, readProcessCgroup, bindings)
		seen := map[int]bool{}
		for _, l := range listeners {
			if protectedSSHListener(l, a.Config) && !seen[l.Port] {
				protection.SSHPorts = append(protection.SSHPorts, l.Port)
				seen[l.Port] = true
			}
		}
		sort.Ints(protection.SSHPorts)
	}
	if len(protection.SSHPorts) == 0 {
		add("no verified SSH listener found; management health cannot be attested")
	}
	protection.Ready = len(protection.Blockers) == 0
	protection.Digest = protectionDigest(protection)
	a.enrichHostDefaultDenyProtection(ctx, &protection)
	return protection, nil
}
func (a *Agent) managedPreflight(ctx context.Context, protection Protection, wholeHost ...bool) error {
	if err := policySigningReadiness(a.Config); err != nil {
		return errors.New("policy signing trust: " + err.Error())
	}
	if !protection.Ready {
		return errors.New(strings.Join(protection.Blockers, "; "))
	}
	zone, topology, e := a.managedTopology(ctx)
	if e != nil {
		return e
	}
	if zone != protection.Zone {
		return errors.New("active management zone changed; refusing silent policy relocation")
	}
	if a.State.ManagedBundle != nil && a.State.ManagedBundle.TopologyDigest != "" && a.State.ManagedBundle.TopologyDigest != topology {
		return errors.New("committed zone/interface binding drift detected")
	}
	snapshot := CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules())
	if snapshot.Status != "ok" {
		return errors.New("managed enforcement requires complete fresh firewall inventory")
	}
	owned := map[string]bool{}
	if a.State.ManagedBundle != nil {
		for _, rule := range a.State.ManagedBundle.Rules {
			owned[rule.Zone+"\x00"+managedSemanticKey(rule.Rule)] = true
		}
	}
	for _, rule := range snapshot.Rules {
		if rule.Kind == "source" {
			return errors.New("source-bound zones require manual migration")
		}
		if rule.Kind == "direct" {
			return errors.New("direct firewall rules conflict with managed enforcement")
		}
		if rule.Zone != protection.Zone {
			continue
		}
		switch rule.Kind {
		case "source":
			return errors.New("source-bound zones are unsupported")
		case "target":
			if strings.EqualFold(rule.Value, "ACCEPT") && !(len(wholeHost) > 0 && wholeHost[0]) {
				return errors.New("zone target ACCEPT requires migration before enforcement")
			}
		case "rich_rule":
			if owned[rule.Zone+"\x00"+managedSemanticKey(rule.Value)] || a.ownsLearningAllowRule(rule.Zone, rule.Value) {
				continue
			}
			info, e := parseRich(rule.Value)
			if e != nil || info.Priority < 0 {
				return errors.New("unmanaged rich-rule priority/context conflicts with enforcement")
			}
		}
	}
	for _, scope := range []string{"runtime", "permanent"} {
		for _, query := range []string{"--get-all-passthroughs", "--get-all-chains"} {
			out, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--direct", query)...)
			if e != nil || strings.TrimSpace(out) != "" {
				return errors.New("direct passthrough/chain configuration requires manual review")
			}
		}
	}
	names, e := a.Commands.Run(ctx, "firewall-cmd", "--get-active-policies")
	if e != nil {
		if !unsupportedFirewallCommand(names) {
			return errors.New("active policy discovery failed")
		}
	} else {
		active, valid := activePolicyNames(names)
		if !valid {
			return errors.New("ambiguous active policy configuration")
		}
		for _, name := range active {
			for _, scope := range []string{"runtime", "permanent"} {
				details, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+name, "--list-all")...)
				if e != nil || !safeHostIPv6Policy(details) {
					return errors.New("active policy overlaps managed TCP/UDP enforcement")
				}
			}
		}
	}
	if text, _ := a.Commands.Run(ctx, "ufw", "status"); strings.Contains(strings.ToLower(text), "status: active") {
		return errors.New("UFW is active")
	}
	// Baseline owned rules must still exist in both scopes; never silently repair drift.
	if a.State.ManagedBundle != nil {
		for _, rule := range a.State.ManagedBundle.Rules {
			for _, scope := range []string{"runtime", "permanent"} {
				present, e := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
				if e != nil || !present {
					return errors.New("committed managed rule drift detected; refusing a new generation")
				}
			}
		}
	}
	return validateManagedCommittedSets(ctx, a.Commands, a.State.ManagedBundle)
}

func managedSemanticKey(rule string) string {
	return managedSetSemanticKey(rule)
}

func (a *Agent) managedProtectionFromReport(report Report) Protection {
	controllerOrigin := a.Config.ControllerURL
	if a.Config.ControlURL != "" {
		controllerOrigin = a.Config.ControlURL
	}
	protection := Protection{ManagementSources: []string{}, SSHPorts: []int{}, ControllerURL: controllerOrigin, ManagementProbeURL: configuredManagedProbe(a.Config), Zone: a.Config.Zone, Blockers: []string{}}
	if err := policySigningReadiness(a.Config); err != nil {
		protection.Blockers = append(protection.Blockers, "policy signing trust: "+err.Error())
	}
	sources, e := canonicalSources(a.Config.ManagementSources, true)
	if e != nil {
		protection.Blockers = append(protection.Blockers, e.Error())
	} else {
		protection.ManagementSources = sources
	}
	if len(protection.ManagementSources) == 0 {
		protection.Blockers = append(protection.Blockers, "configure restricted management_sources")
	}
	seen := map[int]bool{}
	for _, listener := range report.Listeners {
		if protectedSSHListener(listener, a.Config) && !seen[listener.Port] {
			protection.SSHPorts = append(protection.SSHPorts, listener.Port)
			seen[listener.Port] = true
		}
	}
	sort.Ints(protection.SSHPorts)
	if len(protection.SSHPorts) == 0 {
		protection.Blockers = append(protection.Blockers, "no verified actual SSH listener")
	}
	if protection.Zone == "" && report.FirewallSnapshot != nil {
		zones := map[string]bool{}
		for _, rule := range report.FirewallSnapshot.Rules {
			if rule.Scope == "runtime" && rule.Kind == "interface" {
				zones[rule.Zone] = true
			}
		}
		if len(zones) == 1 {
			for zone := range zones {
				protection.Zone = zone
			}
		}
	}
	if protection.Zone == "" {
		protection.Blockers = append(protection.Blockers, "exactly one active zone required")
	}
	if report.UFWActive {
		protection.Blockers = append(protection.Blockers, "UFW is active")
	}
	if report.FirewalldState != "running" {
		protection.Blockers = append(protection.Blockers, "firewalld is not running")
	}
	if a.Simulate {
		protection.ControllerURL = ""
		protection.ManagementProbeURL = ""
		protection.Blockers = append(protection.Blockers, "simulation cannot enforce")
	}
	protection.Ready = len(protection.Blockers) == 0
	protection.Digest = protectionDigest(protection)
	return protection
}

func (a *Agent) managedTopology(ctx context.Context) (string, string, error) {
	raw, e := a.Commands.Run(ctx, "firewall-cmd", "--get-active-zones")
	if e != nil {
		return "", "", errors.New("live active-zone discovery failed")
	}
	zones := []string{}
	interfaces := []string{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			if !firewallName.MatchString(fields[0]) {
				return "", "", errors.New("invalid active-zone output")
			}
			zones = append(zones, fields[0])
		} else if strings.HasPrefix(trimmed, "interfaces:") {
			interfaces = append(interfaces, strings.Fields(strings.TrimPrefix(trimmed, "interfaces:"))...)
		} else if strings.HasPrefix(trimmed, "sources:") && strings.TrimSpace(strings.TrimPrefix(trimmed, "sources:")) != "" {
			return "", "", errors.New("live source-zone bindings are unsupported")
		}
	}
	if len(zones) != 1 {
		return "", "", errors.New("live topology requires exactly one active zone")
	}
	if a.Config.Zone != "" && a.Config.Zone != zones[0] {
		return "", "", errors.New("configured zone is no longer the only active zone")
	}
	defaultZone, e := a.Commands.Run(ctx, "firewall-cmd", "--get-default-zone")
	if e != nil || !firewallName.MatchString(strings.TrimSpace(defaultZone)) {
		return "", "", errors.New("default zone discovery failed")
	}
	sort.Strings(interfaces)
	encoded, _ := json.Marshal(map[string]any{"zone": zones[0], "default_zone": strings.TrimSpace(defaultZone), "interfaces": interfaces})
	return zones[0], shaText(string(encoded)), nil
}
