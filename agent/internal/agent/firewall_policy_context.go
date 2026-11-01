package agent

import (
	"strconv"
	"strings"
)

// Only the full normalized, non-TCP/UDP default host-IPv6 definition is exempt.
// A matching name, extra service/port/source, different target or extra rich rule
// never qualifies. The object remains view-only even when it is non-overlapping.
func safeHostIPv6Policy(text string) bool {
	fields := map[string]string{}
	rules := map[string]bool{}
	header := false
	inRich := false
	wanted := map[string]bool{"neighbour-advertisement": true, "neighbour-solicitation": true, "router-advertisement": true, "redirect": true}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !header {
			parts := strings.Fields(line)
			if len(parts) < 1 || !firewallName.MatchString(parts[0]) {
				return false
			}
			header = true
			continue
		}
		if inRich && strings.HasPrefix(line, "rule ") {
			tokens, e := richTokens(line)
			if e != nil || len(tokens) != 5 || tokens[0] != "rule" || tokens[1] != "family=ipv6" || tokens[2] != "icmp-type" || tokens[4] != "accept" {
				return false
			}
			name, ok := assignment(tokens[3], "name")
			if !ok || !wanted[name] || rules[name] {
				return false
			}
			rules[name] = true
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return false
		}
		key = strings.TrimSpace(key)
		if _, duplicate := fields[key]; duplicate {
			return false
		}
		fields[key] = strings.Join(strings.Fields(value), " ")
		inRich = key == "rich rules"
	}
	if !header || len(fields) != 12 || len(rules) != 4 {
		return false
	}
	priority, e := strconv.Atoi(fields["priority"])
	if e != nil || priority != -15000 {
		return false
	}
	if fields["target"] != "CONTINUE" || fields["ingress-zones"] != "ANY" || fields["egress-zones"] != "HOST" || fields["masquerade"] != "no" {
		return false
	}
	for _, field := range []string{"services", "ports", "protocols", "forward-ports", "source-ports", "icmp-blocks", "rich rules"} {
		value, present := fields[field]
		if !present || value != "" {
			return false
		}
	}
	return true
}
func activePolicyNames(text string) ([]string, bool) {
	names := []string{}
	for _, raw := range strings.Split(text, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) < 1 || !firewallName.MatchString(fields[0]) {
			return nil, false
		}
		names = append(names, fields[0])
	}
	return names, len(names) > 0 || strings.TrimSpace(text) == ""
}
