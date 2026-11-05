package agent

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type nftTailscaleChain struct {
	Hook, Type, Policy string
	Priority           *int
	Rules              [][]json.RawMessage
}

// Per-family iptables-nft tables. Table names alone cannot prove that their
// hooks are safe. Only the verified chains and their reachable INPUT rules
// can coexist with the firewalld host-input proof.
type nftTailscaleContext map[string]map[string]*nftTailscaleChain

func (context nftTailscaleContext) add(kind string, item nftKernelItem, raw json.RawMessage) bool {
	if item.Family != "ip" && item.Family != "ip6" {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	allowedFields := map[string]string{
		"table": "family name handle",
		"chain": "family table name handle type hook prio policy",
		"rule":  "family table chain handle expr comment",
	}
	allowed, ok := allowedFields[kind]
	if !ok {
		return false
	}
	for field := range fields {
		if !slices.Contains(strings.Fields(allowed), field) {
			return false
		}
	}
	if kind == "table" {
		key := item.Family + "/" + item.Name
		if context[key] != nil || (item.Name != "filter" && item.Name != "nat" && item.Name != "mangle") {
			return false
		}
		context[key] = make(map[string]*nftTailscaleChain)
		return true
	}
	chains := context[item.Family+"/"+item.Table]
	if chains == nil {
		return false
	}
	if kind == "chain" {
		if chains[item.Name] != nil || !validTailscaleChain(item) {
			return false
		}
		chains[item.Name] = &nftTailscaleChain{Hook: item.Hook, Type: item.Type, Policy: item.Policy, Priority: item.Prio}
		return true
	}
	chain := chains[item.Chain]
	if chain == nil || len(item.Expr) == 0 || len(item.Expr) > 12 || len(chain.Rules) >= 16 {
		return false
	}
	var rule []json.RawMessage
	for _, expr := range item.Expr {
		var statement map[string]json.RawMessage
		if json.Unmarshal(expr, &statement) != nil || len(statement) != 1 {
			return false
		}
		if statement["counter"] != nil {
			continue
		}
		canonical, _ := json.Marshal(statement)
		rule = append(rule, canonical)
	}
	chain.Rules = append(chain.Rules, rule)
	return true
}

func validTailscaleChain(item nftKernelItem) bool {
	chain := item.Table + "/" + item.Name
	switch chain {
	case "filter/ts-input", "filter/ts-forward", "nat/ts-postrouting":
		return item.Hook == "" && item.Type == "" && item.Policy == "" && item.Prio == nil
	}
	if item.Hook != strings.ToLower(item.Name) || item.Prio == nil || item.Policy != "accept" {
		return false
	}
	switch chain {
	case "filter/INPUT", "filter/FORWARD", "filter/OUTPUT":
		// A separate priority-zero INPUT accept still traverses firewalld
		// INPUT at priority ten. An earlier drop never reaches its NFLOG.
		return item.Type == "filter" && *item.Prio == 0
	case "nat/PREROUTING", "nat/OUTPUT":
		return item.Type == "nat" && *item.Prio == -100
	case "nat/INPUT", "nat/POSTROUTING":
		return item.Type == "nat" && *item.Prio == 100
	case "mangle/PREROUTING", "mangle/INPUT", "mangle/FORWARD", "mangle/POSTROUTING":
		return item.Type == "filter" && *item.Prio == -150
	case "mangle/OUTPUT":
		return item.Type == "route" && *item.Prio == -150
	default:
		return false
	}
}

func (context nftTailscaleContext) proof() (json.RawMessage, bool) {
	for table, chains := range context {
		family, name, _ := strings.Cut(table, "/")
		if context[family+"/filter"] == nil {
			return nil, false
		}
		for chain, definition := range chains {
			rules := definition.Rules
			switch name + "/" + chain {
			case "filter/INPUT":
				if !onlyTailscaleJump(rules, "ts-input", chains) {
					return nil, false
				}
			case "filter/ts-input":
				if !validTailscaleInput(family, rules) {
					return nil, false
				}
			case "filter/FORWARD", "nat/POSTROUTING":
				target := "ts-" + strings.ToLower(chain)
				if len(rules) != 0 && !onlyTailscaleJump(rules, target, chains) {
					return nil, false
				}
			case "filter/ts-forward", "mangle/FORWARD":
				// The verified INPUT jump cannot reach these chains. Forwarded
				// packets are outside the host-input proof.
			case "nat/ts-postrouting":
				if len(rules) > 1 || len(rules) == 1 && !validTailscaleMasquerade(rules[0]) {
					return nil, false
				}
			default:
				// In particular, no active destination NAT, pre-routing
				// marks or additional rules in a competing input hook.
				if len(rules) != 0 {
					return nil, false
				}
			}
		}
		if name == "filter" && (chains["INPUT"] == nil || chains["ts-input"] == nil) {
			return nil, false
		}
	}
	encoded, err := json.Marshal(context)
	return encoded, err == nil
}

func onlyTailscaleJump(rules [][]json.RawMessage, target string, chains map[string]*nftTailscaleChain) bool {
	return chains[target] != nil && len(rules) == 1 && equalNftRule(rules[0], fmt.Sprintf(`{"jump":{"target":%q}}`, target))
}

func equalNftRule(rule []json.RawMessage, statements ...string) bool {
	if len(rule) != len(statements) {
		return false
	}
	for i, statement := range statements {
		if !nftExpressionEqual(string(rule[i]), statement) {
			return false
		}
	}
	return true
}

const tailscaleInterface = `{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}}`
const nonTailscaleInterface = `{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}}`
const acceptNft = `{"accept":null}`

func validTailscaleInput(family string, rules [][]json.RawMessage) bool {
	if len(rules) > 0 && tailscaleLoopbackRule(family, rules[0]) {
		rules = rules[1:]
	}
	if family == "ip" {
		if len(rules) < 2 || !tailscaleAntiSpoofRule(rules[0], "100.115.92.0", 23, "return") || !tailscaleAntiSpoofRule(rules[1], "100.64.0.0", 10, "drop") {
			return false
		}
		rules = rules[2:]
	}
	if len(rules) == 0 || !equalNftRule(rules[0], tailscaleInterface, acceptNft) {
		return false
	}
	return len(rules) == 1 || len(rules) == 2 && tailscaleUDPPortRule(rules[1])
}

func tailscaleAntiSpoofRule(rule []json.RawMessage, network string, bits int, verdict string) bool {
	source := fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":%q,"len":%d}}}}`, network, bits)
	end := fmt.Sprintf(`{%q:null}`, verdict)
	return equalNftRule(rule, source, nonTailscaleInterface, end) || equalNftRule(rule, nonTailscaleInterface, source, end)
}

func tailscaleLoopbackRule(family string, rule []json.RawMessage) bool {
	if len(rule) != 3 {
		return false
	}
	loopback := `{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}}`
	for _, source := range rule[:2] {
		var match struct {
			Match struct{ Right string } `json:"match"`
		}
		if json.Unmarshal(source, &match) != nil {
			continue
		}
		addr, err := netip.ParseAddr(match.Match.Right)
		if err != nil || family == "ip" && !netip.MustParsePrefix("100.64.0.0/10").Contains(addr) || family == "ip6" && !netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(addr) {
			continue
		}
		exact := fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":%q,"field":"saddr"}},"right":%q}}`, family, match.Match.Right)
		return equalNftRule(rule, loopback, exact, acceptNft) || equalNftRule(rule, exact, loopback, acceptNft)
	}
	return false
}

func tailscaleUDPPortRule(rule []json.RawMessage) bool {
	if len(rule) == 3 && nftExpressionEqual(string(rule[0]), `{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"udp"}}`) {
		rule = rule[1:]
	}
	if len(rule) != 2 {
		return false
	}
	var match struct {
		Match struct{ Right uint16 } `json:"match"`
	}
	if json.Unmarshal(rule[0], &match) != nil || match.Match.Right == 0 {
		return false
	}
	port := fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":%d}}`, match.Match.Right)
	return equalNftRule(rule, port, acceptNft)
}

func validTailscaleMasquerade(rule []json.RawMessage) bool {
	mark := `{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":262144}}`
	// iptables-nft may hide target arguments in JSON. This source-NAT
	// target is reachable only after routing and outside host INPUT.
	return equalNftRule(rule, mark, `{"xt":{"type":"target","name":"MASQUERADE"}}`) ||
		equalNftRule(rule, mark, `{"masquerade":null}`) || equalNftRule(rule, mark, `{"masquerade":{}}`)
}
