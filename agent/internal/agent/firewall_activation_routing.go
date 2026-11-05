package agent

import (
	"errors"
	"fmt"
	"net/netip"
)

// The ordinary routing selectors and the complete stock Tailscale profile
// are the only layouts activation accepts. This adapter is specific to
// service activation and does not authorize egress or whole-host isolation.
func activationRoutingRules(rules []any, family string) (bool, error) {
	unknown := errors.New("ambiguous routing selectors prevent firewall activation")
	seen := make(map[string]bool, len(rules))
	tailscaleCount := 0
	for _, value := range rules {
		row, ok := value.(map[string]any)
		if !ok || row["src"] != "all" {
			return false, unknown
		}
		priority := fmt.Sprint(row["priority"])
		if seen[priority] {
			return false, unknown
		}
		seen[priority] = true
		for key := range row {
			switch key {
			case "priority", "src", "table", "action", "fwmark", "fwmask":
			case "protocol":
				if row[key] != "kernel" || priority != "0" && priority != "32766" && priority != "32767" {
					return false, unknown
				}
			default:
				return false, unknown
			}
		}
		table := activationRoutingTable(row["table"])
		mark, mask, action := row["fwmark"], row["fwmask"], row["action"]
		switch priority {
		case "0", "32766", "32767":
			expected := map[string]string{"0": "local", "32766": "main", "32767": "default"}[priority]
			if table != expected || mark != nil || mask != nil || action != nil {
				return false, unknown
			}
		case "5210", "5230", "5250":
			if mark != "0x80000" || mask != "0xff0000" {
				return false, unknown
			}
			switch priority {
			case "5210":
				if table != "main" || action != nil {
					return false, unknown
				}
			case "5230":
				if table != "default" || action != nil {
					return false, unknown
				}
			case "5250":
				if table != "" || action != "unreachable" {
					return false, unknown
				}
			}
			tailscaleCount++
		case "5270":
			if table != "52" || mark != nil || mask != nil || action != nil {
				return false, unknown
			}
			tailscaleCount++
		default:
			return false, unknown
		}
	}
	if tailscaleCount == 0 {
		return false, nil
	}
	if tailscaleCount != 4 || !seen["0"] || !seen["32766"] || family == "-4" && !seen["32767"] {
		return false, errors.New("incomplete Tailscale routing rules prevent firewall activation")
	}
	return true, nil
}

func activationRoutingTable(value any) string {
	switch table := fmt.Sprint(value); table {
	case "<nil>", "":
		return ""
	case "255":
		return "local"
	case "254":
		return "main"
	case "253":
		return "default"
	default:
		return table
	}
}

func activationRouteSupported(row map[string]any, family string, tailscale bool) bool {
	table := activationRoutingTable(row["table"])
	switch table {
	case "", "local", "main", "default":
		if row["dev"] != "tailscale0" {
			return true
		}
		if !tailscale || table == "default" || row["protocol"] != "kernel" || row["gateway"] != nil || row["nexthops"] != nil || row["encap"] != nil {
			return false
		}
		if family == "-6" && (row["dst"] == "fe80::/64" || table == "local" && row["dst"] == "ff00::/8" && row["type"] == "multicast") {
			return true
		}
		return activationTailscalePeerRoute(row["dst"], family)
	case "52":
		if !tailscale || row["dev"] != "tailscale0" || row["type"] != nil && row["type"] != "unicast" {
			return false
		}
		for key := range row {
			switch key {
			case "dst", "dev", "table", "type", "scope", "metric", "protocol", "flags", "pref":
			default:
				return false
			}
		}
		return activationTailscalePeerRoute(row["dst"], family)
	default:
		return false
	}
}

func activationTailscalePeerRoute(value any, family string) bool {
	raw, ok := value.(string)
	if !ok {
		return false
	}
	route, err := netip.ParsePrefix(raw)
	if err != nil {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.Zone() != "" {
			return false
		}
		route = netip.PrefixFrom(address, address.BitLen())
	}
	tailnet := netip.MustParsePrefix("100.64.0.0/10")
	if family == "-6" {
		tailnet = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	}
	return route.Bits() >= tailnet.Bits() && tailnet.Contains(route.Masked().Addr())
}
