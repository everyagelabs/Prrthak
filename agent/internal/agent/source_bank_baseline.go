package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func sourceBankDefinitions() []ManagedIPSet {
	sets := make([]ManagedIPSet, 0, sourceBankCount)
	for _, bank := range []string{"a", "b", "la", "lb"} {
		for _, family := range []struct{ name, digit string }{{"inet", "4"}, {"inet6", "6"}} {
			for slot := 0; slot < managedSetSlots; slot++ {
				sets = append(sets, ManagedIPSet{Name: fmt.Sprintf("prthak_%s%s_%02d", bank, family.digit, slot), Family: family.name, Entries: []string{}})
			}
		}
	}
	return sets
}

func sourceBankFamily(name string) (string, bool) {
	if !managedSetName.MatchString(name) {
		return "", false
	}
	slot, err := strconv.Atoi(name[len(name)-2:])
	if err != nil || slot >= managedSetSlots {
		return "", false
	}
	if strings.Contains(name, "4_") {
		return "inet", true
	}
	return "inet6", true
}

func sourceBankCanonicalZones(text string, owned, active, activeServices map[string]bool) (string, []string, []string, error) {
	zones, err := parseFirewallZones(text)
	if err != nil {
		return "", nil, nil, err
	}
	services, icmps := map[string]bool{}, map[string]bool{}
	for i := range zones {
		zone := &zones[i]
		zone.Active = false // Presentation-only marker, not policy content.
		for key, values := range zone.Fields {
			switch key {
			case "interfaces", "services", "ports", "protocols", "icmp-blocks", "source-ports", "ingress-priority", "egress-priority", "forward", "masquerade", "icmp-block-inversion":
			case "sources", "forward-ports":
				if len(values) != 0 {
					return "", nil, nil, errors.New("source-bound zones and port forwarding block source-bank activation")
				}
			default:
				return "", nil, nil, errors.New("unrecognized zone fields block source-bank activation")
			}
			if key == "masquerade" && active[zone.Name] && strings.Join(values, " ") != "no" {
				return "", nil, nil, errors.New("masquerading blocks source-bank activation")
			}
			if key == "services" {
				for _, name := range values {
					services[name] = true
					if active[zone.Name] {
						activeServices[name] = true
					}
				}
			}
			if key == "icmp-blocks" {
				for _, name := range values {
					icmps[name] = true
				}
			}
			sort.Strings(values)
			if key == "interfaces" {
				zone.Fields[key] = []string{}
			}
		}
		for n, rule := range zone.Rich {
			info, err := parseManagedRich(rule)
			known := owned[zone.Name+"\x00"+managedSemanticKey(rule)]
			if err != nil || ((managedOwned(rule) || learningAllowOwned(rule) || info.SourceIPSet != "" || strings.Contains(rule, "PRTM") || strings.Contains(rule, "PRTL")) && !known) || strings.Contains(rule, "PRTHAK") || strings.Contains(rule, "PRTP") {
				return "", nil, nil, errors.New("complex, observed or managed rich rules block source-bank activation")
			}
			if info.Service != "" {
				services[info.Service] = true
				if active[zone.Name] {
					activeServices[info.Service] = true
				}
			}
			tokens, _ := richTokens(rule)
			zone.Rich[n] = strings.Join(tokens, " ")
		}
		sort.Strings(zone.Rich)
	}
	for expected := range owned {
		found := false
		for _, zone := range zones {
			for _, rule := range zone.Rich {
				if zone.Name+"\x00"+managedSemanticKey(rule) == expected {
					found = true
				}
			}
		}
		if !found {
			return "", nil, nil, errors.New("committed owned rule is missing from the inspected scope")
		}
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	raw, _ := json.Marshal(zones)
	keys := func(values map[string]bool) []string {
		out := []string{}
		for name := range values {
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	return string(raw), keys(services), keys(icmps), nil
}

// firewalld documents that runtime zone bindings are restored across reload.
// Preserve those bindings separately instead of requiring NetworkManager's
// current interface assignment to have been copied into permanent XML.
func sourceBankZoneBindings(text string) (map[string]string, error) {
	zones, err := parseFirewallZones(text)
	if err != nil {
		return nil, err
	}
	bindings := map[string]string{}
	for _, zone := range zones {
		for _, name := range zone.Fields["interfaces"] {
			if !firewallName.MatchString(name) || len(name) > 64 || bindings[name] != "" || len(bindings) >= 1024 {
				return nil, errors.New("ambiguous or unsupported interface bindings")
			}
			bindings[name] = zone.Name
		}
	}
	return bindings, nil
}

func sameSourceBankContext(left, right sourceBankBaseline) bool {
	return left.ContextDigest == right.ContextDigest && reflect.DeepEqual(left.RuntimeBindings, right.RuntimeBindings) && reflect.DeepEqual(left.PermanentBindings, right.PermanentBindings)
}

func bankDefinition(ctx context.Context, runner CommandRunner, scope, name string) (sourceBankDefinition, error) {
	family, valid := sourceBankFamily(name)
	if !valid {
		return sourceBankDefinition{}, errors.New("noncanonical source bank")
	}
	text, err := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--info-ipset="+name)...)
	if err != nil || len(text) > 4<<20 {
		return sourceBankDefinition{}, errors.New("source-bank definition is unreadable")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		key, value, has := strings.Cut(strings.TrimSpace(line), ":")
		if !has {
			continue
		}
		key = strings.TrimSpace(key)
		if _, exists := fields[key]; exists {
			return sourceBankDefinition{}, errors.New("ambiguous source-bank definition")
		}
		fields[key] = strings.TrimSpace(value)
	}
	options := map[string]string{}
	for _, item := range strings.Fields(fields["options"]) {
		key, value, has := strings.Cut(item, "=")
		if !has || options[key] != "" {
			return sourceBankDefinition{}, errors.New("ambiguous source-bank options")
		}
		options[key] = value
	}
	if options["family"] == "" {
		options["family"] = "inet"
	}
	if fields["type"] != "hash:net" || options["family"] != family {
		return sourceBankDefinition{}, errors.New("existing source-bank family/type differs; no overwrite permitted")
	}
	for key, value := range options {
		switch key {
		case "family":
		case "hashsize", "maxelem":
			number, err := strconv.Atoi(value)
			if err != nil || number < 1024 || number > 1<<20 || key == "maxelem" && number < maxManagedSetEntries {
				return sourceBankDefinition{}, errors.New("existing source-bank capacity is unsupported")
			}
		default:
			return sourceBankDefinition{}, errors.New("existing source-bank options are unsupported")
		}
	}
	entryText, present := fields["entries"]
	if !present {
		return sourceBankDefinition{}, errors.New("source-bank entries missing from complete info response")
	}
	entries := []string{}
	seenEntries := map[string]bool{}
	for _, value := range strings.Fields(entryText) {
		prefix, err := parsePrefix(value)
		if err != nil {
			return sourceBankDefinition{}, errors.New("invalid source-bank entry")
		}
		entry := prefix.Masked().String()
		if !seenEntries[entry] {
			entries = append(entries, entry)
			seenEntries[entry] = true
		}
		if len(entries) > maxManagedSetEntries {
			return sourceBankDefinition{}, errors.New("source-bank entries exceed their bound")
		}
	}
	sort.Strings(entries)
	if !validManagedSet(ManagedIPSet{Name: name, Family: family, Entries: entries}) {
		return sourceBankDefinition{}, errors.New("unsupported source-bank membership")
	}
	return sourceBankDefinition{Family: family, Options: options, Entries: entries}, nil
}

func readBankSetNames(ctx context.Context, commands CommandRunner, scope string) ([]string, error) {
	text, err := commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-ipsets")...)
	if err != nil || len(text) > 32768 {
		return nil, errors.New("source-bank inventory unavailable")
	}
	names, seen := strings.Fields(text), map[string]bool{}
	if len(names) > sourceBankCount {
		return nil, errors.New("foreign or excessive ipsets block source-bank activation")
	}
	for _, name := range names {
		if _, valid := sourceBankFamily(name); !valid || seen[name] {
			return nil, errors.New("foreign or duplicate ipsets block source-bank activation")
		}
		seen[name] = true
	}
	sort.Strings(names)
	return names, nil
}

// Full parity is deliberately stricter than the normal small-policy adapter.
// A reload must not activate unrelated staged permanent changes or discard
// runtime-only access. Unsupported contexts are reported before any mutation.
func (a *Agent) sourceBankBaseline(ctx context.Context) (sourceBankBaseline, error) {
	return a.sourceBankBaselineState(ctx, false)
}

func (a *Agent) sourceBankBaselineState(ctx context.Context, allowInactive bool) (sourceBankBaseline, error) {
	result := sourceBankBaseline{Runtime: map[string]sourceBankDefinition{}, Permanent: map[string]sourceBankDefinition{}, RuntimeBindings: map[string]string{}, PermanentBindings: map[string]string{}}
	result.OwnedRules = append([]ManagedRule{}, a.sourceBankOwnedRulesOverride...)
	if a.sourceBankOwnedRulesOverride == nil {
		if a.State.ManagedBundle != nil {
			result.OwnedRules = append(result.OwnedRules, a.State.ManagedBundle.Rules...)
		}
		if a.State.LearningAllowBundle != nil {
			result.OwnedRules = append(result.OwnedRules, a.State.LearningAllowBundle.Rules...)
		}
	}
	sort.Slice(result.OwnedRules, func(i, j int) bool {
		return result.OwnedRules[i].Zone+result.OwnedRules[i].Rule < result.OwnedRules[j].Zone+result.OwnedRules[j].Rule
	})
	owned := map[string]bool{}
	for _, rule := range result.OwnedRules {
		if !firewallName.MatchString(rule.Zone) || !managedOwned(rule.Rule) {
			return result, errors.New("invalid recorded owned rule")
		}
		owned[rule.Zone+"\x00"+managedSemanticKey(rule.Rule)] = true
	}
	state, err := a.Commands.Run(ctx, "firewall-cmd", "--state")
	if err != nil || strings.TrimSpace(state) != "running" {
		return result, errors.New("firewalld is not running")
	}
	if text, _ := a.Commands.Run(ctx, "ufw", "status"); strings.Contains(strings.ToLower(text), "status: active") {
		return result, errors.New("UFW is active; source-bank activation refused")
	}
	contextValues := map[string]string{}
	for _, option := range []string{"--get-default-zone", "--get-log-denied"} {
		text, err := a.Commands.Run(ctx, "firewall-cmd", option)
		if err != nil || strings.TrimSpace(text) == "" || len(text) > 1024 {
			return result, errors.New("firewalld global state cannot be inspected")
		}
		contextValues[option] = strings.TrimSpace(text)
	}
	panicState, panicErr := a.Commands.Run(ctx, "firewall-cmd", "--query-panic")
	if strings.TrimSpace(panicState) != "no" || panicErr == nil { // no normally exits 1; tolerate successful fake/readers below.
		if strings.TrimSpace(panicState) != "no" {
			return result, errors.New("panic mode is active or unknown")
		}
	}
	var zoneCanonical string
	var requiredServices, requiredICMP []string
	activeZones := map[string]bool{contextValues["--get-default-zone"]: true}
	activeServices := map[string]bool{}
	for _, scope := range []string{"runtime", "permanent"} {
		text, err := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--list-all-zones")...)
		if err != nil || len(text) > 512<<10 {
			return result, errors.New("complete zone inventory unavailable")
		}
		if scope == "runtime" {
			zones, err := parseFirewallZones(text)
			if err != nil {
				return result, err
			}
			for _, zone := range zones {
				if zone.Active || len(zone.Fields["interfaces"]) > 0 || len(zone.Fields["sources"]) > 0 {
					activeZones[zone.Name] = true
				}
			}
		}
		canonical, services, icmp, err := sourceBankCanonicalZones(text, owned, activeZones, activeServices)
		if err != nil {
			return result, err
		}
		bindings, err := sourceBankZoneBindings(text)
		if err != nil {
			return result, err
		}
		if scope == "runtime" {
			result.RuntimeBindings = bindings
		} else {
			result.PermanentBindings = bindings
		}
		if scope == "runtime" {
			zoneCanonical = canonical
			requiredServices = services
			requiredICMP = icmp
		} else if canonical != zoneCanonical {
			return result, errors.New("runtime and permanent zones differ; review those differences in Firewall before activation")
		}
		for _, option := range []string{"--get-all-rules", "--get-all-passthroughs", "--get-all-chains"} {
			text, err := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--direct", option)...)
			if err != nil || strings.TrimSpace(text) != "" {
				return result, errors.New("direct rules, chains or passthroughs block source-bank activation")
			}
		}
		policyNames, err := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-policies")...)
		if err != nil && !unsupportedFirewallCommand(policyNames) {
			return result, errors.New("policy context unavailable")
		}
		policies := strings.Fields(policyNames)
		if err != nil {
			policies = nil
		}
		if len(policies) > 16 {
			return result, errors.New("excessive policy objects")
		}
		for _, name := range policies {
			if !firewallName.MatchString(name) {
				return result, errors.New("invalid policy name")
			}
			details, err := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+name, "--list-all")...)
			if name == egressPolicyName && err == nil && OwnedEgressPolicyContext(ctx, a.Commands, a.Config.StateDir) == nil {
				contextValues[scope+":policy:"+name] = shaText(details)
				continue
			}
			if err != nil || !safeHostIPv6Policy(details) {
				return result, errors.New("only the verified default host-IPv6 policy is supported during activation")
			}
			contextValues[scope+":policy:"+name] = "verified-default-host-ipv6"
		}
		names, err := readBankSetNames(ctx, a.Commands, scope)
		if err != nil {
			return result, err
		}
		for _, name := range names {
			if a.sourceBankSkipInventory {
				continue
			}
			definition, err := bankDefinition(ctx, a.Commands, scope, name)
			if err != nil {
				return result, err
			}
			if scope == "runtime" {
				result.Runtime[name] = definition
			} else {
				result.Permanent[name] = definition
			}
			if err := a.sourceBankProgress(ctx); err != nil {
				return result, err
			}
		}
	}
	for name, zone := range result.PermanentBindings {
		if result.RuntimeBindings[name] != zone {
			return result, errors.New("permanent interface bindings differ from runtime; reload could activate an unreviewed zone")
		}
	}
	for name, zone := range result.RuntimeBindings {
		if _, pinned := result.PermanentBindings[name]; !pinned && zone != contextValues["--get-default-zone"] {
			return result, errors.New("runtime-only interface binding requires the same protected default zone during reload")
		}
	}
	contextValues["zones"] = zoneCanonical
	for _, item := range []struct {
		kind  string
		names []string
	}{{"service", requiredServices}, {"icmptype", requiredICMP}} {
		if len(item.names) > 128 {
			return result, errors.New("too many referenced definitions")
		}
		for _, name := range item.names {
			if !firewallName.MatchString(name) {
				return result, errors.New("invalid referenced definition")
			}
			first := ""
			for _, scope := range []string{"runtime", "permanent"} {
				text, err := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--info-"+item.kind+"="+name)...)
				if err != nil || len(text) > 65536 {
					return result, errors.New("referenced service/ICMP definition unavailable")
				}
				text = strings.TrimSpace(text)
				if item.kind == "service" && activeServices[name] {
					for _, line := range strings.Split(text, "\n") {
						key, value, _ := strings.Cut(strings.TrimSpace(line), ":")
						if (key == "includes" || key == "helpers" || key == "modules") && strings.TrimSpace(value) != "" {
							return result, fmt.Errorf("active/default service %s uses includes, helpers or modules requiring unsupported dependency inspection before reload", name)
						}
					}
				}
				if scope == "runtime" {
					first = text
				} else if first != text {
					return result, errors.New("runtime and permanent referenced definitions differ")
				}
			}
			contextValues[item.kind+":"+name] = first
		}
	}
	totalEntries := 0
	for name, definition := range result.Runtime {
		totalEntries += len(definition.Entries)
		if other, exists := result.Permanent[name]; !exists || !reflect.DeepEqual(definition, other) {
			return result, errors.New("existing runtime source bank differs from permanent configuration")
		}
	}
	for name, definition := range result.Permanent {
		totalEntries += len(definition.Entries)
		if _, active := result.Runtime[name]; !active && (!allowInactive || len(definition.Entries) != 0) {
			return result, errors.New("existing runtime/permanent source-bank activation differs; reconcile staged definitions before maintenance")
		}
	}
	if totalEntries > 2*maxManagedTotalEntries {
		return result, errors.New("existing source-bank history exceeds the maintenance snapshot budget")
	}
	if !a.sourceBankSkipInventory {
		known := []ManagedIPSet{}
		if a.State.ManagedBundle != nil {
			known = append(known, a.State.ManagedBundle.IPSets...)
		}
		if a.State.LearningAllowBundle != nil {
			known = append(known, a.State.LearningAllowBundle.IPSets...)
		}
		for _, set := range known {
			want := append([]string{}, set.Entries...)
			sort.Strings(want)
			if !reflect.DeepEqual(result.Runtime[set.Name].Entries, want) || !reflect.DeepEqual(result.Permanent[set.Name].Entries, want) {
				return result, errors.New("committed source-bank membership drift blocks maintenance")
			}
		}
	}
	// Local config bytes also fence a pending change to global reload behavior.
	if a.sourceBankConfigDigest != nil {
		value, err := a.sourceBankConfigDigest()
		if err != nil {
			return result, err
		}
		contextValues["global-config"] = value
	} else {
		digest, err := firewallActivationGlobalConfigDigest(ctx, a.Config.StateDir, "", a.Commands)
		if err != nil {
			return result, err
		}
		contextValues["global-config"] = digest
	}
	for key, value := range contextValues {
		if strings.HasPrefix(key, "runtime:policy:") {
			if contextValues["permanent:policy:"+strings.TrimPrefix(key, "runtime:policy:")] != value {
				return result, errors.New("runtime and permanent policies differ")
			}
		}
		if strings.HasPrefix(key, "permanent:policy:") {
			if contextValues["runtime:policy:"+strings.TrimPrefix(key, "permanent:policy:")] != value {
				return result, errors.New("runtime and permanent policies differ")
			}
		}
	}
	raw, _ := json.Marshal(contextValues)
	result.ContextDigest = shaText(string(raw))
	copy := result
	copy.Digest = ""
	raw, _ = json.Marshal(copy)
	result.Digest = shaText(string(raw))
	return result, nil
}
