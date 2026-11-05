package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Inactive-firewall changes are supported only on an ordinary host with one
// understood firewall authority. A valid permanent file is not evidence that
// kernel forwarding/container/legacy rules are safe to change.
func activationInactiveContext(ctx context.Context, commands CommandRunner, root string, ufw bool, rules []FirewallActivationRule) (string, error) {
	return activationFirewallContext(ctx, commands, root, false, ufw, rules)
}

var errActivationForeignKernel = errors.New("foreign kernel firewall objects block activation; they are never flushed")

func activationFirewallContext(ctx context.Context, commands CommandRunner, root string, firewalldActive, ufw bool, rules []FirewallActivationRule) (string, error) {
	host, err := activationHostContext(ctx, commands, root)
	if err != nil {
		return "", err
	}
	// Legacy xtables hooks can coexist with nftables. Do not infer absence from
	// an empty nft ruleset or silently flush a second firewall authority.
	if err := checkNoLegacyNetfilterHooks(root); err != nil {
		return "", errors.New("legacy or unreadable iptables hooks require manual firewall migration")
	}
	raw, err := commands.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return "", errors.New("native kernel firewall inventory is required before activation")
	}
	if firewalldActive {
		raw, err = activationForeignNftObjects(raw)
		if err != nil {
			return "", err
		}
		commands = activationForeignNftRunner{commands}
	}
	kernel, err := activationInactiveKernel(raw, ufw, rules)
	if errors.Is(err, errActivationForeignKernel) && activationUsesNftables(root) {
		kernel, err = inactiveTailscaleKernelProof(ctx, commands, raw)
		if err != nil {
			return "", fmt.Errorf("%w: %v", errActivationForeignKernel, err)
		}
	}
	if err != nil {
		return "", err
	}
	return directApprovalDigest(map[string]any{"host": host, "kernel": kernel}), nil
}

type activationForeignNftRunner struct{ CommandRunner }

func (r activationForeignNftRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	raw, err := r.CommandRunner.Run(ctx, name, args...)
	if err == nil && name == "nft" && len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		return activationForeignNftObjects(raw)
	}
	return raw, err
}

func activationHostContext(ctx context.Context, commands CommandRunner, root string) (string, error) {
	namespace, err := networkNamespace(root)
	if err != nil {
		return "", err
	}
	topology, err := readNativeNetworkTopology(ctx, commands, true)
	if err != nil {
		return "", err
	}
	links, err := commands.Run(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return "", err
	}
	linkDigest, names, err := hostDefaultDenyLinkContext(links)
	if err != nil {
		return "", err
	}
	args := []string{"-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv4.conf.default.forwarding", "net.ipv6.conf.default.forwarding"}
	for _, name := range names {
		args = append(args, "net/ipv4/conf/"+name+"/forwarding", "net/ipv6/conf/"+name+"/forwarding")
	}
	text, err := commands.Run(ctx, "sysctl", args...)
	values := strings.Fields(text)
	if err != nil || len(values) != len(args)-1 {
		return "", errors.New("complete forwarding state is unavailable")
	}
	for _, value := range values {
		if value != "0" {
			return "", errors.New("router, default or per-interface forwarding blocks firewall activation")
		}
	}
	return directApprovalDigest(map[string]any{"namespace": namespace, "topology": topology, "links": linkDigest}), nil
}

func activationUsesNftables(root string) bool {
	raw, err := readPreparationSystemFile(root, "/etc/firewalld/firewalld.conf", 65536)
	if err != nil {
		return false
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(key) == "FirewallBackend" {
			if found || strings.TrimSpace(value) != "nftables" {
				return false
			}
			found = true
		}
	}
	return found
}

// Bind the reviewed foreign context across service start/stop without
// treating firewalld's own nftables table as a second firewall authority.
func activationForeignNftObjects(raw string) (string, error) {
	var doc struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if len(raw) > 8<<20 || json.Unmarshal([]byte(raw), &doc) != nil || doc.Objects == nil || len(doc.Objects) > 40000 {
		return "", errors.New("kernel firewall context is unavailable")
	}
	foreign := doc.Objects[:0]
	firewalld := false
	legacyNAT := make(legacyFirewalldNAT)
	probes := make(inertXTablesProbes)
	for _, object := range doc.Objects {
		if len(object) != 1 {
			return "", errors.New("ambiguous kernel firewall object")
		}
		for kind, body := range object {
			var item nftKernelItem
			if json.Unmarshal(body, &item) != nil {
				return "", errors.New("invalid kernel firewall object")
			}
			if known, inert := probes.admit(kind, item, body); known {
				if !inert {
					return "", errors.New("unexpected rule or chain in an xtables probe table")
				}
				continue
			}
			if isLegacyFirewalldNAT(kind, item) {
				if !legacyNAT.add(kind, item) {
					return "", errors.New("unexpected objects in firewalld family NAT tables")
				}
				continue
			}
			if item.Family != "inet" || kind == "table" && item.Name != "firewalld" || kind != "table" && item.Table != "firewalld" {
				foreign = append(foreign, object)
				continue
			}
			if kind == "table" {
				if firewalld {
					return "", errors.New("ambiguous native firewalld table")
				}
				firewalld = true
			}
		}
	}
	if !firewalld {
		return "", errors.New("the active firewalld table could not be verified")
	}
	if !probes.complete() {
		return "", errors.New("xtables probe table context is incomplete")
	}
	if len(legacyNAT) > 0 {
		if _, ok := legacyNAT.proof(); !ok {
			return "", errors.New("firewalld family NAT tables have active translation or unsupported dispatch")
		}
	}
	doc.Objects = foreign
	encoded, err := json.Marshal(doc)
	return string(encoded), err
}

func activationInactiveKernel(raw string, ufw bool, expected []FirewallActivationRule) (string, error) {
	if len(raw) > 8<<20 {
		return "", errors.New("kernel firewall context exceeds bound")
	}
	var doc struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || doc.Objects == nil || len(doc.Objects) > 40000 {
		return "", errors.New("kernel firewall context is unavailable")
	}
	canonical := []any{}
	observed := map[string][]string{}
	wanted := map[string][]string{}
	policies := map[string]map[string]string{}
	probes := make(inertXTablesProbes)
	for _, rule := range expected {
		key := rule.Family
		wanted[key] = append(wanted[key], activationNumericRuleKey(rule))
	}
	for _, object := range doc.Objects {
		if len(object) != 1 {
			return "", errors.New("ambiguous kernel firewall object")
		}
		for kind, body := range object {
			if kind == "metainfo" {
				continue
			}
			if !ufw {
				var item nftKernelItem
				if json.Unmarshal(body, &item) != nil {
					return "", errors.New("invalid kernel firewall object")
				}
				if known, inert := probes.admit(kind, item, body); known {
					if !inert {
						return "", errors.New("unexpected rule or chain in an xtables probe table")
					}
					continue
				}
				return "", errActivationForeignKernel
			}
			var item struct {
				Family string                       `json:"family"`
				Table  string                       `json:"table"`
				Name   string                       `json:"name"`
				Chain  string                       `json:"chain"`
				Hook   string                       `json:"hook"`
				Type   string                       `json:"type"`
				Policy string                       `json:"policy"`
				Prio   int                          `json:"prio"`
				Expr   []map[string]json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(body, &item) != nil || item.Family != "ip" && item.Family != "ip6" || kind == "table" && item.Name != "filter" || kind != "table" && item.Table != "filter" {
				return "", errors.New("foreign tables, NAT or bridge hooks block UFW cutover")
			}
			if kind == "table" {
				canonical = append(canonical, map[string]any{"kind": kind, "family": item.Family})
				continue
			}
			prefix := "ufw-"
			family := "ipv4"
			if item.Family == "ip6" {
				prefix = "ufw6-"
				family = "ipv6"
			}
			if kind == "chain" {
				if item.Hook != "" {
					expectedHook := map[string]string{"INPUT": "input", "OUTPUT": "output", "FORWARD": "forward"}[item.Name]
					expectedPolicy := "drop"
					if item.Name == "OUTPUT" {
						expectedPolicy = "accept"
					}
					if expectedHook == "" || item.Hook != expectedHook || item.Type != "filter" || item.Prio != 0 || item.Policy != expectedPolicy {
						return "", errors.New("UFW base chain policies/hooks differ from reviewed default deny/allow")
					}
					if policies[family] == nil {
						policies[family] = map[string]string{}
					}
					policies[family][item.Name] = item.Policy
				} else if !strings.HasPrefix(item.Name, prefix) {
					return "", errors.New("foreign kernel chain blocks UFW cutover")
				}
				canonical = append(canonical, map[string]any{"kind": kind, "family": family, "name": item.Name, "hook": item.Hook, "policy": item.Policy})
				continue
			}
			if kind != "rule" || len(item.Expr) > 20 {
				return "", errors.New("unmapped kernel objects block UFW cutover")
			}
			expr := []map[string]json.RawMessage{}
			for _, node := range item.Expr {
				if len(node) != 1 {
					return "", errors.New("ambiguous kernel expression")
				}
				if _, ok := node["counter"]; ok {
					continue
				}
				expr = append(expr, node)
			}
			if item.Chain == prefix+"user-input" {
				rule, err := activationKernelNumericRule(family, expr)
				if err != nil {
					return "", err
				}
				observed[family] = append(observed[family], activationNumericRuleKey(rule))
			} else {
				// Empty before/after hooks cannot conceal an active rule. Other generated
				// UFW chains are accepted only as an inert jump/return graph; logging,
				// tracking accept helpers and custom semantics need a separate adapter.
				if strings.Contains(item.Chain, "before-") || strings.Contains(item.Chain, "after-") {
					return "", errors.New("active kernel before/after rules differ from the empty reviewed UFW hooks")
				}
				builtin := item.Chain == "INPUT" || item.Chain == "OUTPUT" || item.Chain == "FORWARD"
				if !builtin && !strings.HasPrefix(item.Chain, prefix) {
					return "", errors.New("foreign rule chain blocks cutover")
				}
				if len(expr) != 1 {
					return "", errors.New("unmapped UFW generated rule blocks cutover")
				}
				valid := false
				for _, jump := range []string{"jump", "goto"} {
					if value, ok := expr[0][jump]; ok {
						var target struct {
							Target string `json:"target"`
						}
						if json.Unmarshal(value, &target) == nil && strings.HasPrefix(target.Target, prefix) {
							valid = true
						}
					}
				}
				if _, ok := expr[0]["return"]; ok && !builtin {
					valid = true
				}
				if !valid {
					return "", errors.New("unmapped generated UFW action blocks cutover")
				}
			}
			canonical = append(canonical, map[string]any{"kind": kind, "family": family, "chain": item.Chain, "expr": expr})
		}
	}
	if ufw {
		if len(policies) == 0 {
			return "", errors.New("active UFW kernel chains were not observed")
		}
		for _, base := range policies {
			if len(base) != 3 {
				return "", errors.New("complete UFW base policies are required")
			}
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			if strings.Join(observed[family], "|") != strings.Join(wanted[family], "|") {
				return "", errors.New("kernel UFW user rules differ from the exact persisted numeric rules")
			}
		}
	}
	// Rule order above is significant. Object counters and volatile handles are
	// excluded; topology/config generation is bound separately.
	if !probes.complete() {
		return "", errors.New("xtables probe table context is incomplete")
	}
	return directApprovalDigest(canonical), nil
}
func activationNumericRuleKey(rule FirewallActivationRule) string {
	return fmt.Sprintf("%s:%s:%d:%s:%s", rule.Family, rule.Source, rule.Port, rule.Protocol, rule.Action)
}
func activationKernelNumericRule(family string, expr []map[string]json.RawMessage) (FirewallActivationRule, error) {
	rule := FirewallActivationRule{Family: family, Priority: -29000}
	if family == "ipv4" {
		rule.Source = "0.0.0.0/0"
	} else {
		rule.Source = "::/0"
	}
	seen := map[string]bool{}
	for _, node := range expr {
		for kind, value := range node {
			if kind == "accept" || kind == "drop" || kind == "reject" {
				if rule.Action != "" {
					return rule, errors.New("duplicate UFW kernel verdict")
				}
				rule.Action = kind
				continue
			}
			if kind != "match" {
				return rule, errors.New("unmapped UFW kernel numeric expression")
			}
			var match struct {
				Op    string                     `json:"op"`
				Left  map[string]json.RawMessage `json:"left"`
				Right json.RawMessage            `json:"right"`
			}
			if json.Unmarshal(value, &match) != nil || match.Op != "==" || len(match.Left) != 1 {
				return rule, errors.New("unmapped UFW kernel comparison")
			}
			key := ""
			if payload, ok := match.Left["payload"]; ok {
				var p struct {
					Protocol string `json:"protocol"`
					Field    string `json:"field"`
				}
				if json.Unmarshal(payload, &p) != nil {
					return rule, errors.New("invalid kernel payload")
				}
				if p.Field == "saddr" && (family == "ipv4" && p.Protocol == "ip" || family == "ipv6" && p.Protocol == "ip6") {
					key = "source"
					var text string
					if json.Unmarshal(match.Right, &text) != nil {
						var prefix struct {
							Prefix struct {
								Addr string `json:"addr"`
								Len  int    `json:"len"`
							} `json:"prefix"`
						}
						if json.Unmarshal(match.Right, &prefix) != nil {
							return rule, errors.New("invalid kernel source prefix")
						}
						text = prefix.Prefix.Addr + "/" + strconv.Itoa(prefix.Prefix.Len)
					}
					network, err := parsePrefix(text)
					if err != nil {
						return rule, err
					}
					rule.Source = network.Masked().String()
				} else if p.Field == "dport" && (p.Protocol == "tcp" || p.Protocol == "udp") {
					key = "port"
					if rule.Protocol != "" && rule.Protocol != p.Protocol {
						return rule, errors.New("inconsistent kernel port protocol")
					}
					rule.Protocol = p.Protocol
					if json.Unmarshal(match.Right, &rule.Port) != nil {
						return rule, errors.New("non-numeric kernel port")
					}
				} else {
					return rule, errors.New("unmapped kernel payload match")
				}
			} else if meta, ok := match.Left["meta"]; ok {
				var m struct {
					Key string `json:"key"`
				}
				var proto string
				if json.Unmarshal(meta, &m) != nil || m.Key != "l4proto" || json.Unmarshal(match.Right, &proto) != nil || proto != "tcp" && proto != "udp" {
					return rule, errors.New("unmapped kernel protocol match")
				}
				key = "protocol"
				if rule.Protocol != "" && rule.Protocol != proto {
					return rule, errors.New("inconsistent kernel protocol")
				}
				rule.Protocol = proto
			} else {
				return rule, errors.New("unmapped kernel match selector")
			}
			if seen[key] {
				return rule, errors.New("duplicate kernel match")
			}
			seen[key] = true
		}
	}
	prefix, err := netip.ParsePrefix(rule.Source)
	if err != nil || prefix.Addr().Is4() != (family == "ipv4") {
		return rule, errors.New("kernel source family differs")
	}
	if err := validateActivationRule(rule); err != nil {
		return rule, err
	}
	return rule, nil
}

func activationNoInitHooks(root string) error {
	for _, name := range []string{"/etc/ufw/before.init", "/etc/ufw/after.init"} {
		if _, err := os.Lstat(root + name); os.IsNotExist(err) {
			continue
		}
		raw, err := readPreparationSystemFile(root, name, 65536)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				return errors.New("active UFW init hooks require a separate migration adapter")
			}
		}
	}
	return nil
}

func activationPreparationFiles() []string {
	names := append([]string{}, ufwPreparationFiles...)
	return append(names, "/etc/ufw/before.init", "/etc/ufw/after.init")
}
