package agent

import (
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type richInfo struct {
	Family      string
	Priority    int
	Source      string
	SourceIPSet string
	Port        string
	Transport   string
	Service     string
	Protocol    string
	Action      string
	HasLog      bool
	LogPrefix   string
	LogLevel    string
	LogLimit    string
}

var firewallName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var probePrefix = regexp.MustCompile(`^PRTP[0-9a-f]{12}:$`)

func validProbeLogLimit(value string) bool {
	if !strings.HasSuffix(value, "/s") {
		return false
	}
	n, e := strconv.Atoi(strings.TrimSuffix(value, "/s"))
	return e == nil && n >= 1 && n <= 100
}

func richTokens(value string) ([]string, error) {
	if len(value) > 4096 {
		return nil, errors.New("rich rule too long")
	}
	tokens := []string{}
	var item strings.Builder
	quote := rune(0)
	escaped := false
	for _, r := range value {
		if unicode.IsControl(r) {
			return nil, errors.New("control character in rich rule")
		}
		if escaped {
			item.WriteRune(r)
			escaped = false
			continue
		}
		if quote != 0 {
			if r == '\\' {
				escaped = true
			} else if r == quote {
				quote = 0
			} else {
				item.WriteRune(r)
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if unicode.IsSpace(r) {
			if item.Len() > 0 {
				tokens = append(tokens, item.String())
				item.Reset()
			}
			continue
		}
		item.WriteRune(r)
	}
	if quote != 0 || escaped {
		return nil, errors.New("unterminated rich-rule quote")
	}
	if item.Len() > 0 {
		tokens = append(tokens, item.String())
	}
	if len(tokens) > 40 {
		return nil, errors.New("rich rule too complex")
	}
	return tokens, nil
}
func portRange(value string) (int, int, error) {
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return 0, 0, errors.New("invalid port range")
	}
	first, e := strconv.Atoi(parts[0])
	if e != nil || first < 1 || first > 65535 {
		return 0, 0, errors.New("invalid port")
	}
	last := first
	if len(parts) == 2 {
		last, e = strconv.Atoi(parts[1])
		if e != nil || last < first || last > 65535 {
			return 0, 0, errors.New("invalid port range")
		}
	}
	return first, last, nil
}
func validPortValue(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || (parts[1] != "tcp" && parts[1] != "udp") {
		return false
	}
	_, _, e := portRange(parts[0])
	return e == nil
}
func assignment(value, key string) (string, bool) {
	prefix := key + "="
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	return strings.TrimPrefix(value, prefix), true
}
func parseRich(value string) (richInfo, error) {
	info := richInfo{}
	tokens, e := richTokens(value)
	if e != nil {
		return info, e
	}
	if len(tokens) < 2 || tokens[0] != "rule" {
		return info, errors.New("not a rich rule")
	}
	seen := map[string]bool{}
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if value, ok := assignment(token, "family"); ok {
			if seen["family"] || value != "ipv4" && value != "ipv6" {
				return info, errors.New("invalid family")
			}
			seen["family"] = true
			info.Family = value
			continue
		}
		if value, ok := assignment(token, "priority"); ok {
			n, e := strconv.Atoi(value)
			if seen["priority"] || e != nil || n < -32768 || n > 32767 {
				return info, errors.New("invalid priority")
			}
			seen["priority"] = true
			info.Priority = n
			continue
		}
		switch token {
		case "source":
			if seen[token] || i+1 >= len(tokens) {
				return info, errors.New("invalid source")
			}
			seen[token] = true
			i++
			source, ok := assignment(tokens[i], "address")
			if !ok {
				return info, errors.New("only numeric address sources are supported")
			}
			prefix, e := parsePrefix(source)
			if e != nil {
				return info, e
			}
			info.Source = prefix.String()
		case "port":
			if seen["element"] || i+2 >= len(tokens) {
				return info, errors.New("invalid port element")
			}
			seen["element"] = true
			i++
			port, ok := assignment(tokens[i], "port")
			if !ok {
				return info, errors.New("invalid port element")
			}
			if _, _, e = portRange(port); e != nil {
				return info, e
			}
			i++
			proto, ok := assignment(tokens[i], "protocol")
			if !ok || proto != "tcp" && proto != "udp" {
				return info, errors.New("invalid port protocol")
			}
			info.Port = port
			info.Transport = proto
		case "service":
			if seen["element"] || i+1 >= len(tokens) {
				return info, errors.New("invalid service element")
			}
			seen["element"] = true
			i++
			name, ok := assignment(tokens[i], "name")
			if !ok || !firewallName.MatchString(name) {
				return info, errors.New("invalid service")
			}
			info.Service = name
		case "protocol":
			if seen["element"] || i+1 >= len(tokens) {
				return info, errors.New("invalid protocol element")
			}
			seen["element"] = true
			i++
			proto, ok := assignment(tokens[i], "value")
			if !ok || proto != "tcp" && proto != "udp" {
				return info, errors.New("unsupported protocol element")
			}
			info.Protocol = proto
		case "log":
			if info.HasLog {
				return info, errors.New("duplicate log")
			}
			info.HasLog = true
			for i+1 < len(tokens) {
				if v, ok := assignment(tokens[i+1], "prefix"); ok {
					if seen["prefix"] {
						return info, errors.New("duplicate prefix")
					}
					seen["prefix"] = true
					info.LogPrefix = v
					i++
					continue
				}
				if v, ok := assignment(tokens[i+1], "level"); ok {
					if seen["level"] {
						return info, errors.New("duplicate level")
					}
					seen["level"] = true
					info.LogLevel = v
					i++
					continue
				}
				break
			}
		case "limit":
			if !info.HasLog || info.LogLimit != "" || i+1 >= len(tokens) {
				return info, errors.New("unsupported limit")
			}
			i++
			limit, ok := assignment(tokens[i], "value")
			if !ok {
				return info, errors.New("invalid limit")
			}
			info.LogLimit = limit
		case "accept", "drop", "reject":
			if info.Action != "" || i != len(tokens)-1 {
				return info, errors.New("unsupported action options")
			}
			info.Action = token
		default:
			return info, errors.New("unsupported rich-rule construct")
		}
	}
	if info.Source != "" {
		prefix, _ := netip.ParsePrefix(info.Source)
		if info.Family == "" || prefix.Addr().Is4() != (info.Family == "ipv4") {
			return info, errors.New("source family mismatch")
		}
	}
	if info.Action == "" && !info.HasLog {
		return info, errors.New("rich rule has no action")
	}
	return info, nil
}
func richEditable(info richInfo) bool {
	return info.Priority == 0 && !info.HasLog && info.Protocol == "" && info.Action != "" && (info.Source != "" || info.Port != "" || info.Service != "")
}
func ownedObservation(value string, owned []OwnedRule) bool {
	candidate, e := parseRich(value)
	if e != nil || !candidate.HasLog || candidate.Action != "" {
		return false
	}
	for _, record := range owned {
		expected, e := parseRich(record.Rule)
		if e != nil || !reflect.DeepEqual(candidate, expected) {
			continue
		}
		if strings.HasPrefix(record.SessionID, "hit:") {
			if ownedHitObservation(value, record) {
				return true
			}
			continue
		}
		if record.SessionID == "probe" {
			if candidate.Priority == -32750 && (candidate.Family == "ipv4" || candidate.Family == "ipv6") && (candidate.Protocol == "tcp" || candidate.Protocol == "udp") && probePrefix.MatchString(candidate.LogPrefix) && candidate.LogLevel == "info" && validProbeLogLimit(candidate.LogLimit) && candidate.Port == "" && candidate.Service == "" && candidate.Source == "" {
				return true
			}
			continue
		}
		if candidate.Priority == -32760 && candidate.Port != "" && (candidate.Transport == "tcp" || candidate.Transport == "udp") && candidate.Source == "" && candidate.Service == "" && candidate.Protocol == "" && candidate.LogPrefix == RulePrefix(record.SessionID) && candidate.LogLevel == "info" && candidate.LogLimit == "20/s" {
			return true
		}
	}
	return false
}
