package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
)

type nftKernelItem struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Name   string            `json:"name"`
	Chain  string            `json:"chain"`
	Hook   string            `json:"hook"`
	Policy string            `json:"policy"`
	Type   string            `json:"type"`
	Prio   *int              `json:"prio"`
	Expr   []json.RawMessage `json:"expr"`
}

func hostDefaultDenyLinkContext(raw string) (string, []string, error) {
	var links []struct {
		Name   string          `json:"ifname"`
		Type   string          `json:"link_type"`
		Master json.RawMessage `json:"master"`
		Flags  []string        `json:"flags"`
		Info   struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if len(raw) > 1024*1024 || json.Unmarshal([]byte(raw), &links) != nil || len(links) == 0 || len(links) > 256 {
		return "", nil, errors.New("interface inventory unavailable")
	}
	for _, link := range links {
		if !firewallName.MatchString(link.Name) || link.Info.Kind == "bridge" || link.Info.Kind == "vrf" || len(link.Master) > 0 && string(link.Master) != "0" && string(link.Master) != "null" && string(link.Master) != `""` {
			return "", nil, errors.New("bridge/VRF/master interface context requires manual migration")
		}
		sort.Strings(link.Flags)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
	encoded, _ := json.Marshal(links)
	names := []string{}
	for _, link := range links {
		names = append(names, link.Name)
	}
	return shaText(string(encoded)), names, nil
}

// Bound and inspect the live nftables structure, not only firewalld's cached
// zone text. No raw nft/iptables mutations are performed by this feature.
func hostDefaultDenyKernelContext(raw, zone string) (string, error) {
	return nftHostInputKernelProof(raw, zone, false, nil)
}

func liveHostDefaultDenyKernelContext(ctx context.Context, commands CommandRunner, raw, zone string) (string, error) {
	// Fixture runners supply synthetic rulesets from a different kernel. In
	// production nft and procfs must both describe the agent's namespace.
	switch commands.(type) {
	case ExecRunner, *ExecRunner:
		if err := checkNoLegacyNetfilterHooks(""); err != nil {
			return "", err
		}
		digest, err := stableNftHostInputKernelProof(ctx, commands, raw, zone, false)
		if err != nil {
			return "", err
		}
		if err := checkNoLegacyNetfilterHooks(""); err != nil {
			return "", err
		}
		return digest, nil
	default:
		return stableNftHostInputKernelProof(ctx, commands, raw, zone, false)
	}
}

func checkNoLegacyNetfilterHooks(root string) error {
	for _, path := range []string{"/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"} {
		raw, err := os.ReadFile(root + path)
		if os.IsNotExist(err) {
			continue // No legacy table registered for this family.
		}
		if err != nil || len(raw) > 4096 || strings.TrimSpace(string(raw)) != "" {
			return errors.New("legacy or unreadable iptables hooks prevent nftables host-input proof")
		}
	}
	return nil
}

func inactiveTailscaleKernelProof(ctx context.Context, commands CommandRunner, raw string) (string, error) {
	return stableNftHostInputKernelProof(ctx, commands, raw, "", true)
}

func stableNftHostInputKernelProof(ctx context.Context, commands CommandRunner, raw, zone string, tailscaleOnly bool) (string, error) {
	usedReadback := false
	read := func(family string, request tailscaleProofRequest) ([]string, bool) {
		usedReadback = true
		return readTailscaleXTables(ctx, commands, family, request)
	}
	digest, err := nftHostInputKernelProof(raw, zone, tailscaleOnly, read)
	if err != nil || !usedReadback {
		return digest, err
	}
	// Require the same structural proof and opaque-rule arguments on both
	// reads. Counters and rule handles are intentionally outside the proof.
	latest, err := commands.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return "", err
	}
	current, err := nftHostInputKernelProof(latest, zone, tailscaleOnly, read)
	if err != nil {
		return "", err
	}
	if current != digest {
		return "", errors.New("live nftables input context changed during native rule readback")
	}
	return digest, nil
}

func nftHostInputKernelProof(raw, zone string, tailscaleOnly bool, read tailscaleProofReader) (string, error) {
	bad := func() (string, error) { return "", errors.New("unsupported live nftables input context") }
	if len(raw) > 8*1024*1024 || !tailscaleOnly && !firewallName.MatchString(zone) {
		return bad()
	}
	var document struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(raw), &document) != nil || len(document.Objects) == 0 || len(document.Objects) > 40000 {
		return bad()
	}
	input, zonePre, established, loopback, dispatch := false, false, false, false, false
	base := map[string][]json.RawMessage{}
	compat := make(nftTailscaleContext)
	legacyNAT := make(legacyFirewalldNAT)
	probes := make(inertXTablesProbes)
	dispatchChains := map[string]bool{"filter_INPUT_POLICIES": true, "filter_INPUT_ZONES": true, "filter_INPUT_ZONES_SOURCE": true, "filter_INPUT_POLICIES_pre": true, "filter_INPUT_POLICIES_post": true}
	for _, object := range document.Objects {
		if len(object) != 1 {
			return bad()
		}
		for kind, body := range object {
			if kind == "metainfo" {
				continue
			}
			var item nftKernelItem
			if json.Unmarshal(body, &item) != nil {
				return bad()
			}
			if known, inert := probes.admit(kind, item, body); known {
				if !inert {
					return bad()
				}
				continue
			}
			if !tailscaleOnly && isLegacyFirewalldNAT(kind, item) {
				if !legacyNAT.add(kind, item) {
					return bad()
				}
				continue
			}
			if item.Family != "inet" || kind == "table" && item.Name != "firewalld" || kind != "table" && item.Table != "firewalld" {
				if !compat.add(kind, item, body) {
					return bad()
				}
				continue
			}
			if tailscaleOnly {
				return bad()
			}
			if kind == "chain" && item.Hook == "input" && item.Prio == nil {
				return bad()
			}
			if kind == "chain" {
				if item.Hook == "input" {
					if input || item.Name != "filter_INPUT" || *item.Prio != 10 || item.Type != "filter" || item.Policy != "accept" {
						return bad()
					}
					input = true
				}
				continue
			}
			if kind != "rule" {
				continue
			}
			expressions := []json.RawMessage{}
			for _, expression := range item.Expr {
				var node map[string]json.RawMessage
				if json.Unmarshal(expression, &node) != nil {
					return bad()
				}
				for _, forbidden := range []string{"dnat", "snat", "masquerade", "redirect", "tproxy", "flow", "fwd", "dup", "queue", "mangle"} {
					if _, found := node[forbidden]; found {
						return bad()
					}
				}
				if len(node) == 1 && node["counter"] != nil {
					continue
				}
				expressions = append(expressions, expression)
			}
			canonical, _ := json.Marshal(expressions)
			if item.Chain == "filter_INPUT" {
				base[item.Chain] = append(base[item.Chain], canonical)
				text := string(canonical)
				switch {
				case nftExpressionEqual(text, `[{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":{"set":["established","related"]}}},{"accept":null}]`):
					if dispatch {
						return bad()
					}
					established = true
				case nftExpressionEqual(text, `[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}]`):
					if dispatch {
						return bad()
					}
					loopback = true
				case nftExpressionEqual(text, `[{"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}},{"accept":null}]`),
					nftExpressionEqual(text, `[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"drop":null}]`):
					// DNAT itself is refused above/in both zone inventories.
				case nftJumpAllowed(expressions, dispatchChains):
					if !established || !loopback {
						return bad()
					}
					dispatch = true
				case len(expressions) == 1 && nftHasKey(expressions[0], "reject"):
					if !dispatch {
						return bad()
					}
				default:
					return bad()
				}
			} else if dispatchChains[item.Chain] {
				base[item.Chain] = append(base[item.Chain], canonical)
				last := expressions
				for len(last) > 0 && nftHasKey(last[0], "match") {
					var match struct {
						Match struct {
							Op   string `json:"op"`
							Left struct {
								Meta struct {
									Key string `json:"key"`
								} `json:"meta"`
							} `json:"left"`
							Right string `json:"right"`
						} `json:"match"`
					}
					if json.Unmarshal(last[0], &match) != nil || match.Match.Op != "==" || match.Match.Left.Meta.Key != "iifname" || match.Match.Right == "" {
						return bad()
					}
					last = last[1:]
				}
				allowed := map[string]bool{"filter_IN_" + zone: true, "filter_IN_policy_allow-host-ipv6": true}
				for name := range dispatchChains {
					allowed[name] = true
				}
				if !nftJumpAllowed(last, allowed) && !(len(last) == 1 && (nftHasKey(last[0], "reject") || nftHasKey(last[0], "drop") || nftHasKey(last[0], "return"))) {
					return bad()
				}
			} else if item.Chain == "filter_IN_"+zone {
				base[item.Chain] = append(base[item.Chain], canonical)
				if !zonePre {
					if !nftJumpAllowed(expressions, map[string]bool{"filter_IN_" + zone + "_pre": true}) {
						return bad()
					}
					zonePre = true
				}
			}
		}
	}
	if !probes.complete() || tailscaleOnly && len(compat) == 0 || !tailscaleOnly && (!input || !zonePre || !established || !loopback || !dispatch) {
		return bad()
	}
	if len(compat) > 0 {
		proof, ok := compat.proof(read)
		if !ok {
			return bad()
		}
		base["iptables-nft tailscale"] = []json.RawMessage{proof}
	}
	if len(legacyNAT) > 0 {
		proof, ok := legacyNAT.proof()
		if !ok {
			return bad()
		}
		base["firewalld family NAT dispatch"] = []json.RawMessage{proof}
	}
	encoded, _ := json.Marshal(base)
	return shaText(string(encoded)), nil
}

func nftHasKey(raw json.RawMessage, key string) bool {
	var node map[string]json.RawMessage
	return json.Unmarshal(raw, &node) == nil && len(node) == 1 && node[key] != nil
}
func nftExpressionEqual(actual, expected string) bool {
	var a, b any
	if json.Unmarshal([]byte(actual), &a) != nil || json.Unmarshal([]byte(expected), &b) != nil {
		return false
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func nftJumpAllowed(expressions []json.RawMessage, allowed map[string]bool) bool {
	if len(expressions) != 1 {
		return false
	}
	var node map[string]struct {
		Target string `json:"target"`
	}
	if json.Unmarshal(expressions[0], &node) != nil || len(node) != 1 {
		return false
	}
	for key, value := range node {
		if (key == "jump" || key == "goto") && allowed[value.Target] && !strings.Contains(value.Target, "\x00") {
			return true
		}
	}
	return false
}
