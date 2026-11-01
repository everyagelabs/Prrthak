package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func eligibleLearningSource(text string) (netip.Addr, bool) {
	ip, e := netip.ParseAddr(text)
	if e != nil || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.String() == "255.255.255.255" || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip, true
}
func learningTuple(source, protocol string, port int) string {
	return fmt.Sprintf("%s|%s|%d", source, protocol, port)
}
func rememberLearningEvidence(state *State, session Session, flow Flow) {
	if session.PolicyAction != "auto_allow" {
		return
	}
	if _, ok := eligibleLearningSource(flow.SourceIP); !ok {
		return
	}
	if state.LearningEvidence == nil {
		state.LearningEvidence = map[string]map[string]LearningEvidence{}
	}
	// Evidence is private, bounded and session-specific; expired sessions never
	// authorize new grants. Keep only32 sessions to avoid unbounded disk growth.
	if state.LearningEvidence[session.ID] == nil {
		if len(state.LearningEvidence) >= 32 {
			oldestID := ""
			var oldest time.Time
			for id, items := range state.LearningEvidence {
				var last time.Time
				for _, item := range items {
					if item.LastSeen.After(last) {
						last = item.LastSeen
					}
				}
				if oldestID == "" || last.Before(oldest) {
					oldestID = id
					oldest = last
				}
			}
			delete(state.LearningEvidence, oldestID)
		}
		state.LearningEvidence[session.ID] = map[string]LearningEvidence{}
	}
	key := learningTuple(flow.SourceIP, flow.Protocol, flow.Port)
	prior, exists := state.LearningEvidence[session.ID][key]
	if !exists && len(state.LearningEvidence[session.ID]) >= maxLearningSourceEntries {
		return
	}
	if !exists {
		prior = LearningEvidence{flow.SourceIP, flow.Port, flow.Protocol, flow.FirstSeen, flow.LastSeen}
	} else {
		if flow.FirstSeen.Before(prior.FirstSeen) {
			prior.FirstSeen = flow.FirstSeen
		}
		if flow.LastSeen.After(prior.LastSeen) {
			prior.LastSeen = flow.LastSeen
		}
	}
	state.LearningEvidence[session.ID][key] = prior
}
func canonicalLearningServices(services []Service) ([]map[string]any, error) {
	if len(services) > 64 {
		return nil, errors.New("learning overlay exceeds64 service entries")
	}
	output := []map[string]any{}
	seen := map[string]bool{}
	count := 0
	rawCount := 0
	sorted := append([]Service{}, services...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Protocol != sorted[j].Protocol {
			return sorted[i].Protocol < sorted[j].Protocol
		}
		return sorted[i].Port < sorted[j].Port
	})
	for _, service := range sorted {
		if service.Port < 1 || service.Port > 65535 || (service.Protocol != "tcp" && service.Protocol != "udp") {
			return nil, errors.New("invalid learned service")
		}
		key := fmt.Sprintf("%s/%d", service.Protocol, service.Port)
		if seen[key] {
			return nil, errors.New("duplicate learned service")
		}
		seen[key] = true
		sources := []string{}
		sourceSeen := map[string]bool{}
		for _, value := range service.Sources {
			rawCount++
			if rawCount > maxLearningSourceEntries {
				return nil, errors.New("learning overlay exceeds10000 raw exact sources")
			}
			prefix, e := netip.ParsePrefix(value)
			if e != nil || prefix.Bits() != prefix.Addr().BitLen() {
				return nil, errors.New("learned sources must be exact /32 or /128 addresses")
			}
			ip, ok := eligibleLearningSource(prefix.Addr().String())
			if !ok {
				return nil, errors.New("learned source is not an eligible unicast address")
			}
			source := netip.PrefixFrom(ip, ip.BitLen()).String()
			if !sourceSeen[source] {
				sources = append(sources, source)
				sourceSeen[source] = true
				count++
			}
		}
		if len(sources) == 0 {
			return nil, errors.New("learned service must contain an explicit source")
		}
		sort.Strings(sources)
		output = append(output, map[string]any{"port": service.Port, "protocol": service.Protocol, "sources": sources})
	}
	if count > maxLearningSourceEntries {
		return nil, errors.New("learning overlay exceeds10000 exact sources")
	}
	return output, nil
}
func learningAllowDigest(p *LearningAllow) (string, error) {
	services, e := canonicalLearningServices(p.Services)
	if e != nil {
		return "", e
	}
	ids := append([]string{}, p.PolicyIDs...)
	sort.Strings(ids)
	for i, id := range ids {
		if !changeIDValid(id) || i > 0 && id == ids[i-1] {
			return "", errors.New("invalid learning policy IDs")
		}
	}
	body, _ := json.Marshal(map[string]any{"services": services, "policy_ids": ids})
	return shaText(string(body)), nil
}
func learningAllowBinding(p *LearningAllow) string {
	return shaText(strings.Join([]string{"prthak-learning-allow-v1", p.ServerID, fmt.Sprint(p.Generation), p.Digest, p.ProtectionDigest, p.TargetIPsDigest}, "\x00"))
}
func targetIPsDigest(ips []string) string {
	seen := map[string]bool{}
	values := []string{}
	for _, ip := range ips {
		if !seen[ip] {
			values = append(values, ip)
			seen[ip] = true
		}
	}
	sort.Strings(values)
	raw, _ := json.Marshal(values)
	return shaText(string(raw))
}
func learningServicesKey(services []Service) string {
	canonical, e := canonicalLearningServices(services)
	if e != nil {
		return "invalid"
	}
	raw, _ := json.Marshal(canonical)
	return string(raw)
}
func learningTuples(services []Service) map[string]Service {
	out := map[string]Service{}
	for _, service := range services {
		for _, source := range service.Sources {
			out[learningTuple(source, service.Protocol, service.Port)] = Service{Port: service.Port, Protocol: service.Protocol, Sources: []string{source}}
		}
	}
	return out
}
func authorityContains(authority LearningAuthority, tuple string) bool {
	_, ok := learningTuples(authority.Services)[tuple]
	return ok
}
func (a *Agent) validateLearningDelta(p *LearningAllow, now time.Time) error {
	old := map[string]Service{}
	var oldAuthorities []LearningAuthority
	if a.State.LearningAllowBundle != nil {
		old = learningTuples(a.State.LearningAllowBundle.Assignment.Services)
		oldAuthorities = a.State.LearningAllowBundle.Assignment.Authorities
	}
	next := learningTuples(p.Services)
	byPolicy := map[string]LearningAuthority{}
	if len(p.Authorities) > 128 || len(p.PolicyIDs) > 128 {
		return errors.New("learning overlay exceeds128 policy authorities")
	}
	authorityTuples := map[string]map[string]Service{}
	oldTuples := map[string]map[string]Service{}
	for _, authority := range oldAuthorities {
		oldTuples[authority.PolicyID] = learningTuples(authority.Services)
	}
	policyIDs := map[string]bool{}
	for _, id := range p.PolicyIDs {
		policyIDs[id] = true
	}
	for _, authority := range p.Authorities {
		if !changeIDValid(authority.PolicyID) || (authority.Kind != "auto" && authority.Kind != "reviewed") {
			return errors.New("invalid learning authority")
		}
		if _, exists := byPolicy[authority.PolicyID]; exists {
			return errors.New("duplicate learning authority")
		}
		byPolicy[authority.PolicyID] = authority
		authorityTuples[authority.PolicyID] = learningTuples(authority.Services)
	}
	for tuple, service := range next {
		if _, exists := old[tuple]; exists {
			continue
		}
		approved := false
		for _, authority := range p.Authorities {
			_, contains := authorityTuples[authority.PolicyID][tuple]
			if !policyIDs[authority.PolicyID] || !contains || !now.Before(authority.ExpiresAt) {
				continue
			}
			// Historical authorities remain as durable provenance. Only a
			// current authority actually granting this added tuple needs live
			// approval; another valid overlapping authority may still grant it.
			if validateEndpointApproval(a.Config, authority.ApprovalProof, p.ServerID, now, false, "learning") != nil {
				continue
			}
			if authority.Kind == "reviewed" {
				approved = true
				break
			}
			if _, held := a.State.LearningAllowFailedSessions[authority.SessionID]; held {
				continue
			}
			if a.State.Policy == nil {
				continue
			}
			for _, session := range ActiveSessions(a.State.Policy, now) {
				if session.ID != authority.SessionID || session.PolicyAction != "auto_allow" {
					continue
				}
				assigned := false
				for _, identifier := range session.ServerIDs {
					if identifier == p.ServerID {
						assigned = true
					}
				}
				if !assigned {
					continue
				}
				portMatches := false
				for _, port := range session.Ports {
					if port.Port == service.Port && port.Protocol == service.Protocol {
						portMatches = true
					}
				}
				authorityPort := false
				for _, port := range authority.Ports {
					if port.Port == service.Port && port.Protocol == service.Protocol {
						authorityPort = true
					}
				}
				if !portMatches || !authorityPort {
					continue
				}
				source, _ := netip.ParsePrefix(service.Sources[0])
				evidenceKey := learningTuple(source.Addr().String(), service.Protocol, service.Port)
				evidence, ok := a.State.LearningEvidence[session.ID][evidenceKey]
				if ok && !evidence.FirstSeen.Before(session.StartsAt) && evidence.LastSeen.Before(SessionCutoff(session)) {
					approved = true
				}
			}
		}
		if !approved {
			return errors.New("new learned tuple lacks active scoped authority and local ingress evidence")
		}
	}
	for tuple := range old {
		if _, exists := next[tuple]; exists {
			continue
		}
		owners := 0
		for _, authority := range oldAuthorities {
			if _, contains := oldTuples[authority.PolicyID][tuple]; !contains {
				continue
			}
			owners++
			reviewed, ok := byPolicy[authority.PolicyID]
			_, retained := authorityTuples[authority.PolicyID][tuple]
			if !ok || reviewed.Kind != "reviewed" || !now.Before(reviewed.ExpiresAt) || retained {
				return errors.New("learning source removal requires an exact reviewed policy update")
			}
			if err := validateEndpointApproval(a.Config, reviewed.ApprovalProof, p.ServerID, now, false, "learning"); err != nil {
				return err
			}
		}
		if owners == 0 {
			return errors.New("learning removal has no durable policy provenance")
		}
	}
	return nil
}
func learningAllowRule(nonce string, priority int, source string, service Service) string {
	prefix, _ := netip.ParsePrefix(source)
	family := "ipv6"
	if prefix.Addr().Is4() {
		family = "ipv4"
	}
	return fmt.Sprintf(`rule priority="%d" family="%s" source address="%s" port port="%d" protocol="%s" log prefix="PRTL%s:" level="debug" limit value="1/m" accept`, priority, family, source, service.Port, service.Protocol, nonce[:12])
}
func learningAllowRules(p *LearningAllow, zone, nonce string, stage bool) []ManagedRule {
	priority := learningAllowCanonicalPriority
	if stage {
		priority = learningAllowStagePriority
	}
	rules := []ManagedRule{}
	for _, service := range p.Services {
		for _, source := range service.Sources {
			rules = append(rules, ManagedRule{zone, learningAllowRule(nonce, priority, source, service)})
		}
	}
	return rules
}
func (a *Agent) learningRulePlan(p *LearningAllow, zone, nonce string, stage bool) ([]ManagedRule, []ManagedIPSet, error) {
	count := 0
	for _, service := range p.Services {
		count += len(service.Sources)
	}
	if count <= 64 {
		return learningAllowRules(p, zone, nonce, stage), nil, nil
	}
	bank := "la"
	if old := a.State.LearningAllowBundle; old != nil && len(old.IPSets) > 0 && strings.HasPrefix(old.IPSets[0].Name, "prthak_la") {
		bank = "lb"
	}
	rules, sets, e := sourceSetRules(&Policy{Mode: "enforce", Services: p.Services}, Protection{Zone: zone}, bank, nonce, stage, true)
	if e != nil {
		return nil, nil, e
	}
	oldPriority, priority := managedCanonicalAllow, learningAllowCanonicalPriority
	if stage {
		oldPriority, priority = managedStageAllow, learningAllowStagePriority
	}
	for i := range rules {
		rules[i].Rule = strings.Replace(rules[i].Rule, fmt.Sprintf(`priority="%d"`, oldPriority), fmt.Sprintf(`priority="%d"`, priority), 1)
		rules[i].Rule = strings.Replace(rules[i].Rule, "PRTM", "PRTL", 1)
	}
	return rules, sets, nil
}
func learningAllowOwned(rule string) bool {
	info, e := parseManagedRich(rule)
	return e == nil && (info.Priority == learningAllowCanonicalPriority || info.Priority == learningAllowStagePriority) && strings.HasPrefix(info.LogPrefix, "PRTL") && len(info.LogPrefix) == 17 && strings.HasSuffix(info.LogPrefix, ":") && (info.Source != "" || strings.HasPrefix(info.SourceIPSet, "prthak_l")) && info.Port != "" && (info.Transport == "tcp" || info.Transport == "udp") && info.Action == "accept" && info.LogLevel == "debug" && info.LogLimit == "1/m"
}
func (a *Agent) ownsLearningAllowRule(zone, rule string) bool {
	if a.State.LearningAllowBundle == nil || !learningAllowOwned(rule) {
		return false
	}
	key := managedSemanticKey(rule)
	for _, owned := range a.State.LearningAllowBundle.Rules {
		if owned.Zone == zone && managedSemanticKey(owned.Rule) == key {
			return true
		}
	}
	return false
}
func (a *Agent) learningAllowPreflight(ctx context.Context, p *LearningAllow, protection Protection) error {
	if e := a.managedPreflight(ctx, protection); e != nil {
		return e
	}
	for _, service := range p.Services {
		for _, port := range protection.SSHPorts {
			if service.Protocol == "tcp" && service.Port == port {
				return errors.New("learning auto-allow cannot grant access to protected SSH ports")
			}
		}
	}
	pseudo := &Policy{Mode: "enforce", Services: append([]Service{}, p.Services...)}
	if a.controllerIngressTargeted(pseudo) {
		return errors.New("learning auto-allow cannot target local controller ingress")
	}
	if a.State.LearningAllowBundle != nil {
		if e := validateManagedCommittedSets(ctx, a.Commands, learningBundleRecord(a.State.LearningAllowBundle)); e != nil {
			return e
		}
		_, topology, e := a.managedTopology(ctx)
		if e != nil {
			return e
		}
		if topology != a.State.LearningAllowBundle.TopologyDigest {
			return errors.New("learning overlay topology drift detected")
		}
		for _, rule := range a.State.LearningAllowBundle.Rules {
			for _, scope := range []string{"runtime", "permanent"} {
				present, e := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
				if e != nil || !present {
					return errors.New("committed learning overlay rule drift detected")
				}
			}
		}
	}
	return nil
}
