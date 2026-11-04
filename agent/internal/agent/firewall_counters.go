package agent

// Native counters describe packets/bytes at a kernel rule, not connections or
// logical policy totals. No rule, log statement, configuration or service is
// changed here. One logical firewalld service can compile to several rules.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const FirewallCountersCapability = "firewall_rule_counters_v1"
const maxFirewallCounterRules = 512
const maxFirewallCounterBytes = 256 * 1024
const maxFirewallCounterInput = 4 * 1024 * 1024

type FirewallCounterRule struct {
	ID            string  `json:"id"`
	InstanceID    string  `json:"instance_id"`
	Family        string  `json:"family"`
	Table         string  `json:"table"`
	TableHandle   string  `json:"table_handle"`
	Chain         string  `json:"chain"`
	Handle        string  `json:"handle"`
	Ordinal       int     `json:"ordinal"`
	Zone          string  `json:"zone"`
	Kind          string  `json:"kind"`
	Basis         string  `json:"basis"`
	Provenance    string  `json:"provenance"`
	Expression    string  `json:"expression"`
	Action        string  `json:"action"`
	CounterStatus string  `json:"counter_status"`
	Packets       *string `json:"packets"`
	Bytes         *string `json:"bytes"`
	Reason        string  `json:"reason"`
}
type FirewallCounterSnapshot struct {
	SchemaVersion int                   `json:"schema_version"`
	Backend       string                `json:"backend"`
	Status        string                `json:"status"`
	CollectedAt   time.Time             `json:"collected_at"`
	BootID        string                `json:"boot_id"`
	Rules         []FirewallCounterRule `json:"rules"`
	Reason        string                `json:"reason"`
	Truncated     bool                  `json:"truncated"`
}

var counterName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var counterBootID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var iptablesCountLine = regexp.MustCompile(`^\[([0-9]+):([0-9]+)\] (-A .+)$`)
var iptablesChainLine = regexp.MustCompile(`^:([A-Za-z0-9_.:-]+) ([A-Z-]+) \[([0-9]+):([0-9]+)\]$`)

func counterDecimal(value any) (string, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return "", false
	}
	text := number.String()
	n, err := strconv.ParseUint(text, 10, 64)
	return strconv.FormatUint(n, 10), err == nil && text == strconv.FormatUint(n, 10)
}
func counterString(text string) (string, bool) { return counterDecimal(json.Number(text)) }

// Decode JSON with duplicate/depth/node checks before trusting native output.
// In particular, numeric counters never pass through float64.
func counterJSON(text string) (map[string]any, error) {
	if len(text) > maxFirewallCounterInput {
		return nil, errors.New("native counter output exceeds safety limit")
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	nodes := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		nodes++
		if depth > 24 || nodes > 100000 {
			return nil, errors.New("native counter JSON exceeds complexity limit")
		}
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				result := map[string]any{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return nil, e
					}
					name, ok := key.(string)
					if !ok || len(name) > 128 {
						return nil, errors.New("invalid native JSON key")
					}
					if _, exists := result[name]; exists {
						return nil, errors.New("duplicate native JSON key")
					}
					value, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					result[name] = value
				}
				_, err = d.Token()
				return result, err
			case '[':
				result := []any{}
				for d.More() {
					value, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					result = append(result, value)
				}
				_, err = d.Token()
				return result, err
			default:
				return nil, errors.New("invalid native JSON delimiter")
			}
		}
		if value, ok := token.(string); ok && len(value) > 32768 {
			return nil, errors.New("native JSON string too large")
		}
		return token, nil
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing native JSON data")
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("native JSON object required")
	}
	return result, nil
}

func counterLocation(chain string, inventory *FirewallSnapshot) (string, string) {
	if strings.Contains(chain, "_direct") {
		return "", "direct"
	}
	if strings.Contains(chain, "policy_") {
		return "", "policy"
	}
	if inventory != nil {
		for _, row := range inventory.Rules {
			if row.Scope != "runtime" || row.Zone == "" {
				continue
			}
			for _, prefix := range []string{"filter_IN_", "filter_OUT_", "filter_FWDI_", "filter_FWDO_", "nat_PRE_", "nat_POST_", "nat_OUT_", "mangle_PRE_", "IN_", "OUT_", "FWDI_", "FWDO_", "PRE_", "POST_"} {
				base := prefix + row.Zone
				if chain == base || strings.HasPrefix(chain, base+"_") {
					return row.Zone, "zone"
				}
			}
		}
	}
	return "", "base"
}
func counterIdentity(rule *FirewallCounterRule, bootID string) {
	rule.ID = shaText(strings.Join([]string{rule.Family, rule.Table, rule.Chain, rule.Basis, rule.Expression, strconv.Itoa(rule.Ordinal)}, "\x00"))
	rule.InstanceID = shaText(strings.Join([]string{bootID, rule.Family, rule.Table, rule.TableHandle, rule.Chain, rule.Handle}, "\x00"))
}
func counterAction(expressions []any) string {
	for i := len(expressions) - 1; i >= 0; i-- {
		if item, ok := expressions[i].(map[string]any); ok {
			for _, name := range []string{"accept", "drop", "reject", "return", "jump", "goto", "dnat", "snat", "masquerade", "redirect"} {
				if _, exists := item[name]; exists {
					return name
				}
			}
		}
	}
	return "continue"
}

// ParseNFTFirewallCounters accepts only the requested firewalld table/family.
// Other tables and sets (including their potentially large address elements)
// are never exported. Counter position is retained in the normalized expression.
func ParseNFTFirewallCounters(text, family, bootID string, inventory *FirewallSnapshot) ([]FirewallCounterRule, error) {
	if family != "inet" && family != "ip" && family != "ip6" {
		return nil, errors.New("unsupported nft family")
	}
	document, err := counterJSON(text)
	if err != nil {
		return nil, err
	}
	objects, ok := document["nftables"].([]any)
	if !ok {
		return nil, errors.New("missing nftables objects")
	}
	tableHandle := ""
	tableSeen := false
	for _, object := range objects {
		item, ok := object.(map[string]any)
		if !ok {
			return nil, errors.New("invalid nft object")
		}
		if table, ok := item["table"].(map[string]any); ok && table["family"] == family && table["name"] == "firewalld" {
			if tableSeen {
				return nil, errors.New("duplicate nft firewalld table")
			}
			tableSeen = true
			tableHandle, _ = counterDecimal(table["handle"])
		}
	}
	if !tableSeen {
		return nil, errors.New("requested firewalld table not returned")
	}
	if tableHandle == "" || tableHandle == "0" {
		return nil, errors.New("native firewalld table generation handle is unavailable")
	}
	result := []FirewallCounterRule{}
	duplicates := map[string]int{}
	handles := map[string]bool{}
	for _, object := range objects {
		item := object.(map[string]any)
		if chain, ok := item["chain"].(map[string]any); ok && chain["family"] == family && chain["table"] == "firewalld" && chain["policy"] != nil {
			name, valid := chain["name"].(string)
			policy, known := chain["policy"].(string)
			handle, numbered := counterDecimal(chain["handle"])
			if !valid || !counterName.MatchString(name) || !known || (policy != "accept" && policy != "drop") || !numbered {
				return nil, errors.New("invalid nft base chain policy")
			}
			expression, _ := json.Marshal(map[string]string{"policy": policy})
			row := FirewallCounterRule{Family: family, Table: "firewalld", TableHandle: tableHandle, Chain: name, Handle: handle, Kind: "base", Basis: "chain_policy", Provenance: "firewalld_table", Expression: string(expression), Action: policy, CounterStatus: "unavailable", Reason: "An implicit nftables base-chain policy has no independent packet/byte counter. Explicit default accept/drop/reject rules are shown separately."}
			counterIdentity(&row, bootID)
			result = append(result, row)
			if len(result) > maxFirewallCounterRules {
				return result[:maxFirewallCounterRules], errors.New("firewalld rule counter inventory exceeds row limit")
			}
			continue
		}
		rule, ok := item["rule"].(map[string]any)
		if !ok {
			continue
		}
		if rule["family"] != family || rule["table"] != "firewalld" {
			continue
		}
		chain, ok := rule["chain"].(string)
		if !ok || !counterName.MatchString(chain) {
			return nil, errors.New("invalid nft chain")
		}
		handle, ok := counterDecimal(rule["handle"])
		if !ok || handle == "0" {
			return nil, errors.New("missing nft rule handle")
		}
		physical := chain + "\x00" + handle
		if handles[physical] {
			return nil, errors.New("duplicate nft rule handle")
		}
		handles[physical] = true
		expressions, ok := rule["expr"].([]any)
		if !ok || len(expressions) == 0 || len(expressions) > 64 {
			return nil, errors.New("invalid nft expression list")
		}
		normalized := []any{}
		count := 0
		var packets, bytes *string
		reason := "No native counter is present. NftablesCounters is off or unsupported by this firewalld version; Prṛthak does not alter or reload it."
		for _, expression := range expressions {
			part, ok := expression.(map[string]any)
			if !ok || len(part) != 1 {
				return nil, errors.New("invalid nft expression")
			}
			if counter, exists := part["counter"]; exists {
				count++
				normalized = append(normalized, map[string]any{"counter": "[packet/byte counter]"})
				values, inline := counter.(map[string]any)
				if inline {
					p, pok := counterDecimal(values["packets"])
					b, bok := counterDecimal(values["bytes"])
					if pok && bok && len(values) == 2 {
						packets = &p
						bytes = &b
						reason = ""
					} else {
						return nil, errors.New("invalid native packet/byte values")
					}
				} else {
					reason = "Named or unavailable counter cannot be attributed independently to this rule."
				}
				continue
			}
			normalized = append(normalized, part)
		}
		if count != 1 {
			packets = nil
			bytes = nil
			if count > 1 {
				reason = "Multiple counters in one rule cannot be represented as one per-rule count."
			}
		}
		if reason != "" {
			packets = nil
			bytes = nil
		}
		encoded, e := json.Marshal(normalized)
		if e != nil || len(encoded) > 1536 {
			return nil, errors.New("native rule expression exceeds safety limit")
		}
		zone, kind := counterLocation(chain, inventory)
		row := FirewallCounterRule{Family: family, Table: "firewalld", TableHandle: tableHandle, Chain: chain, Handle: handle, Zone: zone, Kind: kind, Basis: "kernel_rule", Provenance: "firewalld_table", Expression: string(encoded), Action: counterAction(expressions), CounterStatus: "unavailable", Packets: packets, Bytes: bytes, Reason: reason}
		if packets != nil {
			row.CounterStatus = "available"
		}
		key := chain + "\x00" + row.Expression
		row.Ordinal = duplicates[key]
		duplicates[key]++
		counterIdentity(&row, bootID)
		result = append(result, row)
		if len(result) > maxFirewallCounterRules {
			return result[:maxFirewallCounterRules], errors.New("firewalld rule counter inventory exceeds row limit")
		}
	}
	return result, nil
}

func iptablesOwnedChain(chain string, inventory *FirewallSnapshot) bool {
	for _, base := range []string{"INPUT_direct", "OUTPUT_direct", "FORWARD_direct", "INPUT_ZONES", "INPUT_ZONES_SOURCE", "OUTPUT_ZONES", "OUTPUT_ZONES_SOURCE", "FORWARD_IN_ZONES", "FORWARD_IN_ZONES_SOURCE", "FORWARD_OUT_ZONES", "FORWARD_OUT_ZONES_SOURCE"} {
		if chain == base {
			return true
		}
	}
	zone, kind := counterLocation(chain, inventory)
	return kind == "zone" && zone != ""
}
func iptablesBaseRule(chain string, tokens []string, inventory *FirewallSnapshot) bool {
	if chain != "INPUT" && chain != "FORWARD" && chain != "OUTPUT" {
		return false
	}
	joined := strings.Join(tokens, " ")
	for _, rule := range []string{"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", "-m conntrack --ctstate INVALID -j DROP", "-i lo -j ACCEPT", "-o lo -j ACCEPT", "-j REJECT --reject-with icmp-host-prohibited", "-j REJECT --reject-with icmp6-adm-prohibited"} {
		if joined == rule {
			return true
		}
	}
	return len(tokens) == 2 && (tokens[0] == "-j" || tokens[0] == "-g") && iptablesOwnedChain(tokens[1], inventory)
}

func ParseIPTablesFirewallCounters(text, family, bootID string, inventory *FirewallSnapshot) ([]FirewallCounterRule, error) {
	if family != "ipv4" && family != "ipv6" {
		return nil, errors.New("unsupported iptables family")
	}
	if len(text) > maxFirewallCounterInput {
		return nil, errors.New("native counter output exceeds safety limit")
	}
	result := []FirewallCounterRule{}
	duplicates := map[string]int{}
	positions := map[string]int{}
	chains := map[string]bool{}
	inFilter := false
	completed := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "*filter" {
			if inFilter || completed {
				return nil, errors.New("duplicate filter table")
			}
			inFilter = true
			continue
		}
		if line == "COMMIT" {
			if !inFilter {
				return nil, errors.New("unexpected iptables commit")
			}
			inFilter = false
			completed = true
			continue
		}
		if !inFilter {
			return nil, errors.New("unexpected iptables table output")
		}
		if len(line) > 4096 {
			return nil, errors.New("iptables counter line exceeds limit")
		}
		if m := iptablesChainLine.FindStringSubmatch(line); m != nil {
			if chains[m[1]] {
				return nil, errors.New("duplicate iptables chain")
			}
			chains[m[1]] = true
			if m[1] == "INPUT" || m[1] == "FORWARD" || m[1] == "OUTPUT" {
				p, pok := counterString(m[3])
				b, bok := counterString(m[4])
				policy := strings.ToLower(m[2])
				if !pok || !bok || (policy != "accept" && policy != "drop") {
					return nil, errors.New("invalid iptables builtin policy counters")
				}
				expression, _ := json.Marshal(map[string]string{"policy": policy})
				row := FirewallCounterRule{Family: family, Table: "filter", Chain: m[1], Handle: "0", Kind: "base", Basis: "chain_policy", Provenance: "firewalld_builtin_pattern", Expression: string(expression), Action: policy, CounterStatus: "available", Packets: &p, Bytes: &b}
				counterIdentity(&row, bootID)
				result = append(result, row)
			}
			continue
		}
		m := iptablesCountLine.FindStringSubmatch(line)
		if m == nil {
			return nil, errors.New("iptables rule counter missing or malformed")
		}
		p, pok := counterString(m[1])
		b, bok := counterString(m[2])
		if !pok || !bok {
			return nil, errors.New("invalid iptables packet/byte values")
		}
		tokens, e := richTokens(m[3])
		if e != nil || len(tokens) < 4 || tokens[0] != "-A" || !counterName.MatchString(tokens[1]) {
			return nil, errors.New("invalid iptables rule")
		}
		chain := tokens[1]
		if !chains[chain] {
			return nil, errors.New("iptables rule references an undeclared chain")
		}
		positions[chain]++
		owned := iptablesOwnedChain(chain, inventory)
		base := iptablesBaseRule(chain, tokens[2:], inventory)
		if !owned && !base {
			continue
		}
		encoded, e := json.Marshal(tokens[2:])
		if e != nil || len(encoded) > 1536 {
			return nil, errors.New("iptables expression exceeds limit")
		}
		zone, kind := counterLocation(chain, inventory)
		provenance := "firewalld_chain"
		if !owned {
			provenance = "firewalld_builtin_pattern"
		}
		action := "continue"
		for i := 2; i+1 < len(tokens); i++ {
			if tokens[i] == "-j" || tokens[i] == "-g" {
				target := strings.ToLower(tokens[i+1])
				switch target {
				case "accept", "drop", "reject", "return":
					action = target
				default:
					action = "jump"
				}
				break
			}
		}
		row := FirewallCounterRule{Family: family, Table: "filter", TableHandle: "", Chain: chain, Handle: strconv.Itoa(positions[chain]), Zone: zone, Kind: kind, Basis: "kernel_rule", Provenance: provenance, Expression: string(encoded), Action: action, CounterStatus: "available", Packets: &p, Bytes: &b}
		key := chain + "\x00" + row.Expression
		row.Ordinal = duplicates[key]
		duplicates[key]++
		counterIdentity(&row, bootID)
		result = append(result, row)
		if len(result) > maxFirewallCounterRules {
			return result[:maxFirewallCounterRules], errors.New("firewalld rule counter inventory exceeds row limit")
		}
	}
	if !completed || inFilter {
		return nil, errors.New("incomplete iptables filter snapshot")
	}
	return result, nil
}

func unavailableFirewallCounters(backend, reason string, now time.Time) *FirewallCounterSnapshot {
	return &FirewallCounterSnapshot{SchemaVersion: 1, Backend: backend, Status: "unavailable", CollectedAt: now.UTC(), Rules: []FirewallCounterRule{}, Reason: reason}
}

func CollectFirewallCounters(ctx context.Context, runner CommandRunner, backend, state string, inventory *FirewallSnapshot, now time.Time) *FirewallCounterSnapshot {
	bootID := ""
	if value, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil && counterBootID.MatchString(strings.TrimSpace(string(value))) {
		bootID = strings.TrimSpace(string(value))
	}
	return collectFirewallCounters(ctx, runner, backend, state, inventory, bootID, now)
}
func collectFirewallCounters(ctx context.Context, runner CommandRunner, backend, state string, inventory *FirewallSnapshot, bootID string, now time.Time) *FirewallCounterSnapshot {
	if backend != "nftables" && backend != "iptables" {
		return unavailableFirewallCounters("unknown", "The active firewall backend is not identified; no foreign firewall tables are inspected.", now)
	}
	if state != "running" {
		return unavailableFirewallCounters(backend, "Firewalld is not running; native rule counters are unavailable.", now)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	snapshot := unavailableFirewallCounters(backend, "", now)
	snapshot.BootID = bootID
	succeeded := 0
	failures := 0
	unavailableFamilies := []string{}
	budget := 0
	available := 0
	appendRows := func(rows []FirewallCounterRule) {
		for _, row := range rows {
			encoded, _ := json.Marshal(row)
			if len(snapshot.Rules) >= maxFirewallCounterRules || budget+len(encoded) > maxFirewallCounterBytes-4096 {
				snapshot.Truncated = true
				return
			}
			snapshot.Rules = append(snapshot.Rules, row)
			budget += len(encoded)
			if row.CounterStatus == "available" {
				available++
			}
		}
	}
	if backend == "nftables" {
		for _, family := range []string{"inet", "ip", "ip6"} {
			if ctx.Err() != nil {
				failures++
				unavailableFamilies = append(unavailableFamilies, family+" (sample deadline)")
				break
			}
			text, err := runner.Run(ctx, "nft", "-j", "-a", "list", "table", family, "firewalld")
			if err != nil {
				if !strings.Contains(strings.ToLower(text), "no such file or directory") {
					failures++
					unavailableFamilies = append(unavailableFamilies, family)
				}
				continue
			}
			rows, err := ParseNFTFirewallCounters(text, family, bootID, inventory)
			if err != nil {
				failures++
				unavailableFamilies = append(unavailableFamilies, family)
				if len(rows) > 0 {
					snapshot.Truncated = true
				}
			} else {
				succeeded++
			}
			appendRows(rows)
		}
	} else {
		for _, item := range [][2]string{{"iptables-save", "ipv4"}, {"ip6tables-save", "ipv6"}} {
			if ctx.Err() != nil {
				failures++
				unavailableFamilies = append(unavailableFamilies, item[1]+" (sample deadline)")
				break
			}
			text, err := runner.Run(ctx, item[0], "-c", "-t", "filter")
			if err != nil {
				failures++
				unavailableFamilies = append(unavailableFamilies, item[1])
				continue
			}
			rows, err := ParseIPTablesFirewallCounters(text, item[1], bootID, inventory)
			if err != nil {
				failures++
				unavailableFamilies = append(unavailableFamilies, item[1])
				if len(rows) > 0 {
					snapshot.Truncated = true
				}
			} else {
				succeeded++
			}
			appendRows(rows)
		}
	}
	sort.Slice(snapshot.Rules, func(i, j int) bool { return snapshot.Rules[i].ID < snapshot.Rules[j].ID })
	switch {
	case succeeded == 0 && len(snapshot.Rules) == 0:
		snapshot.Reason = "Native firewalld tables could not be read within the bounded sample. The required read-only tool, permissions or backend support is unavailable."
	case available == 0:
		if backend == "nftables" {
			snapshot.Reason = "Native counters are absent. Firewalld 2.0+ supports NftablesCounters, which defaults to no; older versions may not support it. No configuration or reload was performed."
		} else {
			snapshot.Reason = "No supported native firewalld filter counters were found in the reported address families."
		}
	case failures > 0 || snapshot.Truncated || available < len(snapshot.Rules):
		snapshot.Status = "partial"
		snapshot.Reason = "Only available native rule counters are shown; part of the table, address family or counter coverage is unavailable."
	default:
		snapshot.Status = "ok"
	}
	if snapshot.Truncated {
		snapshot.Status = "partial"
		snapshot.Reason = "Counter inventory reached its bounded report limit; additional rules are not included."
	}
	if len(unavailableFamilies) > 0 {
		snapshot.Reason += " Unavailable address families: " + strings.Join(unavailableFamilies, ", ") + "."
	}
	return snapshot
}
