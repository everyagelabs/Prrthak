package agent

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Firewalld 0.9 generates per-family NAT tables alongside its inet filter
// table. Accept only inert generated dispatch, never any translation.
type legacyFirewalldNAT map[string]map[string]*nftTailscaleChain

// Older firewalld probes xtables features at startup. The nft frontends can
// materialize empty built-in hooks. Only these accept-only skeletons are inert.
type inertXTablesProbes map[string]map[string]bool

var xtablesProbePriorities = map[string]map[string]int{
	"ip/raw":        {"PREROUTING": -300, "OUTPUT": -300},
	"ip6/raw":       {"PREROUTING": -300, "OUTPUT": -300},
	"ip/security":   {"INPUT": 150, "FORWARD": 150, "OUTPUT": 150},
	"ip6/security":  {"INPUT": 150, "FORWARD": 150, "OUTPUT": 150},
	"bridge/filter": {"INPUT": -200, "FORWARD": -200, "OUTPUT": -200},
	"bridge/nat":    {"PREROUTING": -300, "OUTPUT": 100, "POSTROUTING": 300},
}

func (probes inertXTablesProbes) admit(kind string, item nftKernelItem, raw json.RawMessage) (recognized, valid bool) {
	table := item.Table
	if kind == "table" {
		table = item.Name
	}
	key := item.Family + "/" + table
	expected := xtablesProbePriorities[key]
	if expected == nil {
		return false, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return true, false
	}
	allowed := "family name handle"
	if kind == "chain" {
		allowed = "family table name handle type hook prio policy"
	}
	for field := range fields {
		if !strings.Contains(" "+allowed+" ", " "+field+" ") {
			return true, false
		}
	}
	chains := probes[key]
	switch kind {
	case "table":
		if chains != nil {
			return true, false
		}
		probes[key] = make(map[string]bool)
		return true, true
	case "chain":
		priority, ok := expected[item.Name]
		if chains == nil || chains[item.Name] || !ok || item.Prio == nil || *item.Prio != priority ||
			item.Type != "filter" || item.Hook != strings.ToLower(item.Name) || item.Policy != "accept" {
			return true, false
		}
		chains[item.Name] = true
		return true, true
	default:
		return true, false
	}
}

func (probes inertXTablesProbes) complete() bool {
	for key, chains := range probes {
		if len(chains) != len(xtablesProbePriorities[key]) {
			return false
		}
	}
	return true
}

func isLegacyFirewalldNAT(kind string, item nftKernelItem) bool {
	return (item.Family == "ip" || item.Family == "ip6") &&
		(kind == "table" && item.Name == "firewalld" || kind != "table" && item.Table == "firewalld")
}

func (tables legacyFirewalldNAT) add(kind string, item nftKernelItem) bool {
	chains := tables[item.Family]
	if kind == "table" {
		if chains != nil {
			return false
		}
		tables[item.Family] = make(map[string]*nftTailscaleChain)
		return true
	}
	if chains == nil {
		return false
	}
	switch kind {
	case "chain":
		if chains[item.Name] != nil || !validLegacyNATChain(item) {
			return false
		}
		chains[item.Name] = &nftTailscaleChain{Hook: item.Hook, Type: item.Type, Policy: item.Policy, Priority: item.Prio}
		return true
	case "rule":
		chain := chains[item.Chain]
		if chain == nil || len(chain.Rules) >= 256 || len(item.Expr) == 0 || len(item.Expr) > 5 {
			return false
		}
		rule := make([]json.RawMessage, 0, len(item.Expr))
		for _, expr := range item.Expr {
			var statement map[string]json.RawMessage
			if json.Unmarshal(expr, &statement) != nil || len(statement) != 1 {
				return false
			}
			if statement["counter"] == nil {
				canonical, _ := json.Marshal(statement)
				rule = append(rule, canonical)
			}
		}
		chain.Rules = append(chain.Rules, rule)
		return true
	case "set", "element":
		// Firewalld 0.9 mirrors sets across families. No admitted rule
		// references a named set, so membership cannot affect this proof.
		return true
	default:
		return false
	}
}

func legacyNATDirection(name string) string {
	for _, direction := range []string{"PRE", "POST"} {
		base := "nat_" + direction + "ROUTING"
		if name == base || strings.HasPrefix(name, base+"_") || strings.HasPrefix(name, "nat_"+direction+"_") {
			return direction
		}
	}
	return ""
}

func validLegacyNATChain(item nftKernelItem) bool {
	switch item.Name {
	case "nat_PREROUTING":
		return item.Hook == "prerouting" && item.Prio != nil && *item.Prio == -90 && item.Type == "nat" && item.Policy == "accept"
	case "nat_POSTROUTING":
		return item.Hook == "postrouting" && item.Prio != nil && *item.Prio == 110 && item.Type == "nat" && item.Policy == "accept"
	default:
		return len(item.Name) <= 128 && firewallName.MatchString(item.Name) && legacyNATDirection(item.Name) != "" &&
			item.Hook == "" && item.Prio == nil && item.Type == "" && item.Policy == ""
	}
}

func (tables legacyFirewalldNAT) proof() (json.RawMessage, bool) {
	for _, chains := range tables {
		for _, base := range []string{"nat_PREROUTING", "nat_POSTROUTING"} {
			chain := chains[base]
			if chain == nil {
				return nil, false
			}
			suffixes := []string{"_POLICIES_pre", "_ZONES", "_POLICIES_post"}
			if len(chain.Rules) == 4 {
				suffixes = []string{"_POLICIES_pre", "_ZONES_SOURCE", "_ZONES", "_POLICIES_post"}
			}
			if len(chain.Rules) != len(suffixes) {
				return nil, false
			}
			for i, suffix := range suffixes {
				target := base + suffix
				if chains[target] == nil || !equalNftRule(chain.Rules[i], fmt.Sprintf(`{"jump":{"target":%q}}`, target)) {
					return nil, false
				}
			}
		}
		// Every rule must consist solely of optional interface matches
		// followed by a same-direction jump/goto. Prove the resulting
		// graph is acyclic, including otherwise unreachable chains.
		visited := map[string]bool{}
		var inert func(string) bool
		inert = func(name string) bool {
			if complete, seen := visited[name]; seen {
				return complete
			}
			visited[name] = false
			for _, rule := range chains[name].Rules {
				target := legacyNATRuleTarget(rule)
				if chains[target] == nil || chains[target].Hook != "" || legacyNATDirection(target) != legacyNATDirection(name) || !inert(target) {
					return false
				}
			}
			visited[name] = true
			return true
		}
		for name := range chains {
			if !inert(name) {
				return nil, false
			}
		}
	}
	encoded, err := json.Marshal(tables)
	return encoded, err == nil
}

func legacyNATRuleTarget(rule []json.RawMessage) string {
	if len(rule) == 0 || len(rule) > 3 {
		return ""
	}
	for _, expr := range rule[:len(rule)-1] {
		if !legacyNATInterfaceMatch(expr) {
			return ""
		}
	}
	var verdict map[string]struct{ Target string }
	last := rule[len(rule)-1]
	if json.Unmarshal(last, &verdict) != nil || len(verdict) != 1 {
		return ""
	}
	for action, body := range verdict {
		if (action == "jump" || action == "goto") && equalNftRule([]json.RawMessage{last}, fmt.Sprintf(`{%q:{"target":%q}}`, action, body.Target)) {
			return body.Target
		}
	}
	return ""
}

func legacyNATInterfaceMatch(expr json.RawMessage) bool {
	var statement struct {
		Match struct {
			Left  struct{ Meta struct{ Key string } }
			Right json.RawMessage
		}
	}
	if json.Unmarshal(expr, &statement) != nil {
		return false
	}
	key := statement.Match.Left.Meta.Key
	right := statement.Match.Right
	if key != "iifname" && key != "oifname" {
		return false
	}
	var single string
	var set struct{ Set []string }
	valid := func(name string) bool { return name != "" && len(name) <= 16 }
	if json.Unmarshal(right, &single) == nil && valid(single) {
		right, _ = json.Marshal(single)
	} else if json.Unmarshal(right, &set) == nil && len(set.Set) > 0 && len(set.Set) <= 64 {
		for _, name := range set.Set {
			if !valid(name) {
				return false
			}
		}
		right, _ = json.Marshal(map[string][]string{"set": set.Set})
	} else {
		return false
	}
	return nftExpressionEqual(string(expr), fmt.Sprintf(`{"match":{"op":"==","left":{"meta":{"key":%q}},"right":%s}}`, key, right))
}
