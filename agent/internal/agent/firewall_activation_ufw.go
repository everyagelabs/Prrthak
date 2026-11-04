package agent

// UFW conversion deliberately has a small, exact grammar. Unknown hooks,
// routes, application profiles, interfaces and NAT never become broad allows.
import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func activationUFWDefaults(raw string) (bool, error) {
	values := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || values[strings.TrimSpace(key)] != "" {
			return false, errors.New("ambiguous UFW defaults")
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	if values["DEFAULT_INPUT_POLICY"] != "DROP" || values["DEFAULT_OUTPUT_POLICY"] != "ACCEPT" || values["DEFAULT_FORWARD_POLICY"] != "DROP" || values["MANAGE_BUILTINS"] != "no" || values["IPV6"] != "yes" && values["IPV6"] != "no" {
		return false, errors.New("UFW conversion supports default-deny input, allow output, deny forwarding and unmanaged built-in chains only")
	}
	if values["IPT_MODULES"] != "" {
		return false, errors.New("UFW connection-tracking helper modules require manual migration review")
	}
	return values["IPV6"] == "yes", nil
}

// Empty filter hooks are supported. Any active before/after hook needs an
// explicit semantic adapter; even a familiar filename is not proof of stock
// behavior. In particular we do not silently discard stock mDNS/ICMP helpers.
func activationUFWEmptyHooks(raw string) error {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "*filter" || line == "COMMIT" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 3 && (strings.HasPrefix(fields[0], ":ufw-") || strings.HasPrefix(fields[0], ":ufw6-")) && fields[1] == "-" && fields[2] == "[0:0]" {
			continue
		}
		return errors.New("UFW before/after hooks contain unmapped rules; private export is retained and UFW is preserved")
	}
	return nil
}

func activationUFWRules(raw, family string) ([]FirewallActivationRule, error) {
	if len(raw) > 262144 || family != "ipv4" && family != "ipv6" {
		return nil, errors.New("UFW rule input exceeds its supported scope")
	}
	rules := []FirewallActivationRule{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 65536)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || line == "*filter" || line == "COMMIT" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 3 && (strings.HasPrefix(fields[0], ":ufw-") || strings.HasPrefix(fields[0], ":ufw6-")) && fields[1] == "-" && fields[2] == "[0:0]" {
			continue
		}
		if len(fields) < 8 || fields[0] != "-A" || (family == "ipv4" && fields[1] != "ufw-user-input") || (family == "ipv6" && fields[1] != "ufw6-user-input") {
			return nil, errors.New("UFW rules use an unsupported chain, routed rule or helper; no cutover is permitted")
		}
		values := map[string]string{}
		for index := 2; index < len(fields); index += 2 {
			if index+1 >= len(fields) {
				return nil, errors.New("incomplete UFW numeric rule")
			}
			key, value := fields[index], fields[index+1]
			if key == "-m" {
				if value != "tcp" && value != "udp" {
					return nil, errors.New("UFW match extensions are unsupported")
				}
				if values[key] != "" {
					return nil, errors.New("duplicate UFW match module")
				}
			} else if key != "-p" && key != "-s" && key != "--dport" && key != "-j" {
				return nil, errors.New("UFW destination, interface, limit, logging or NAT fields require manual migration")
			}
			if values[key] != "" {
				return nil, errors.New("duplicate UFW numeric rule field")
			}
			values[key] = value
		}
		protocol := values["-p"]
		if protocol != "tcp" && protocol != "udp" || values["-m"] != "" && values["-m"] != protocol {
			return nil, errors.New("UFW conversion supports exact TCP/UDP rules only")
		}
		port, err := strconv.Atoi(values["--dport"])
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != values["--dport"] {
			return nil, errors.New("UFW ranges and named service ports are unsupported")
		}
		source := values["-s"]
		if source == "" {
			if family == "ipv4" {
				source = "0.0.0.0/0"
			} else {
				source = "::/0"
			}
		}
		prefix, err := parsePrefix(source)
		if err != nil || (family == "ipv4") != prefix.Addr().Is4() {
			return nil, errors.New("UFW source family is unsupported")
		}
		action := map[string]string{"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject"}[values["-j"]]
		if action == "" {
			return nil, errors.New("UFW jump or verdict is unsupported")
		}
		rules = append(rules, FirewallActivationRule{Family: family, Source: prefix.Masked().String(), Port: port, Protocol: protocol, Action: action, Priority: -29000 + len(rules)})
		if len(rules) > 64 {
			return nil, errors.New("UFW conversion supports at most 64 exact rules per address family")
		}
	}
	if scanner.Err() != nil {
		return nil, errors.New("UFW rule line exceeds its safety bound")
	}
	return rules, nil
}

func validateActivationRule(rule FirewallActivationRule) error {
	if rule.Family != "ipv4" && rule.Family != "ipv6" || rule.Protocol != "tcp" && rule.Protocol != "udp" || rule.Port < 1 || rule.Port > 65535 || rule.Priority < -30000 || rule.Priority > -25000 || rule.Action != "accept" && rule.Action != "drop" && rule.Action != "reject" {
		return errors.New("invalid translated UFW rule")
	}
	prefix, err := netip.ParsePrefix(rule.Source)
	if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || (rule.Family == "ipv4") != prefix.Addr().Is4() || prefix.Masked().String() != rule.Source {
		return errors.New("invalid translated UFW native source")
	}
	return nil
}

func activationRuleText(rule FirewallActivationRule) (string, error) {
	if err := validateActivationRule(rule); err != nil {
		return "", err
	}
	return fmt.Sprintf(`rule priority="%d" family="%s" source address="%s" port port="%d" protocol="%s" %s`, rule.Priority, rule.Family, rule.Source, rule.Port, rule.Protocol, rule.Action), nil
}
