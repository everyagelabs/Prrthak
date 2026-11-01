package agent

// firewalld's public API creates ipsets in permanent configuration only. A
// reviewed maintenance bootstrap provisions two empty banks; policy updates
// change only entries and owned rich rules, never reload the firewall.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const managedSetSlots = 32
const maxManagedSetEntries = 10000
const maxManagedTotalEntries = 40000
const maxManagedSetRules = 128

var managedSetName = regexp.MustCompile(`^prthak_(?:[ab]|l[ab])[46]_[0-9]{2}$`)

type ManagedIPSet struct {
	Name    string   `json:"name"`
	Family  string   `json:"family"`
	Entries []string `json:"entries"`
}
type managedIPSetMutation struct {
	Scope  string       `json:"scope"`
	Set    ManagedIPSet `json:"set"`
	Before []string     `json:"before"`
}

func validManagedSet(set ManagedIPSet) bool {
	if !managedSetName.MatchString(set.Name) || len(set.Entries) > maxManagedSetEntries {
		return false
	}
	index, _ := strconv.Atoi(set.Name[len(set.Name)-2:])
	if index >= managedSetSlots {
		return false
	}
	if set.Family != "inet" && set.Family != "inet6" {
		return false
	}
	if strings.Contains(set.Name, "4_") != (set.Family == "inet") {
		return false
	}
	for _, entry := range set.Entries {
		prefix, e := netip.ParsePrefix(entry)
		if e != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix.Addr().Is4() != (set.Family == "inet") {
			return false
		}
	}
	return true
}

func managedSetRules(p *Policy, protection Protection, bank string, nonce string, stage bool) ([]ManagedRule, []ManagedIPSet, error) {
	return sourceSetRules(p, protection, bank, nonce, stage, false)
}
func sourceSetRules(p *Policy, protection Protection, bank string, nonce string, stage, additive bool) ([]ManagedRule, []ManagedIPSet, error) {
	if bank != "a" && bank != "b" && bank != "la" && bank != "lb" {
		return nil, nil, errors.New("invalid managed source-set bank")
	}
	allow, reject := managedCanonicalAllow, managedCanonicalReject
	if stage {
		allow, reject = managedStageAllow, managedStageReject
	}
	rules, sets := []ManagedRule{}, []ManagedIPSet{}
	known := map[string]string{}
	next := map[string]int{"inet": 0, "inet6": 0}
	total := 0
	services := append([]Service{}, p.Services...)
	sort.Slice(services, func(i, j int) bool {
		if services[i].Protocol != services[j].Protocol {
			return services[i].Protocol < services[j].Protocol
		}
		return services[i].Port < services[j].Port
	})
	ssh := map[int]bool{}
	for _, port := range protection.SSHPorts {
		ssh[port] = true
	}
	for _, svc := range services {
		mode := svc.Mode
		if mode == "" {
			mode = p.Mode
		}
		if mode != "enforce" {
			continue
		}
		sources := append([]string{}, svc.Sources...)
		if svc.Protocol == "tcp" && ssh[svc.Port] {
			if len(protection.ManagementSources) == 0 {
				return nil, nil, errors.New("SSH requires approved management sources")
			}
			sources = append(sources, protection.ManagementSources...)
		}
		canonical, e := canonicalSources(sources, false)
		if e != nil {
			return nil, nil, e
		}
		for _, family := range []string{"inet", "inet6"} {
			entries := []string{}
			all := false
			richFamily := "ipv4"
			digit := "4"
			if family == "inet6" {
				richFamily = "ipv6"
				digit = "6"
			}
			for _, entry := range canonical {
				prefix, _ := netip.ParsePrefix(entry)
				if prefix.Addr().Is4() != (family == "inet") {
					continue
				}
				if prefix.Bits() == 0 {
					all = true
				}
				entries = append(entries, entry)
			}
			if all {
				rules = append(rules, ManagedRule{protection.Zone, managedRuleText(nonce, allow, richFamily, "", svc, "accept")})
			} else if len(entries) > 0 {
				key := family + "\x00" + strings.Join(entries, "\n")
				name, ok := known[key]
				if !ok {
					if next[family] >= managedSetSlots || len(entries) > maxManagedSetEntries {
						return nil, nil, errors.New("managed source-set capacity exceeded")
					}
					name = fmt.Sprintf("prthak_%s%s_%02d", bank, digit, next[family])
					next[family]++
					known[key] = name
					sets = append(sets, ManagedIPSet{Name: name, Family: family, Entries: entries})
					total += len(entries)
				}
				rule := managedRuleText(nonce, allow, richFamily, "", svc, "accept")
				rule = strings.Replace(rule, " port port=", ` source ipset="`+name+`" port port=`, 1)
				rules = append(rules, ManagedRule{protection.Zone, rule})
			}
			if !additive {
				rules = append(rules, ManagedRule{protection.Zone, managedRuleText(nonce, reject, richFamily, "", svc, "reject")})
			}
		}
	}
	if len(rules) > maxManagedSetRules || total > maxManagedTotalEntries {
		return nil, nil, errors.New("managed set bundle exceeds bounded port/source capacity")
	}
	return rules, sets, nil
}

func (a *Agent) managedRulePlan(p *Policy, protection Protection, nonce string, stage bool) ([]ManagedRule, []ManagedIPSet, error) {
	rules, e := managedRules(p, protection, nonce, stage)
	if e == nil {
		return rules, nil, nil
	}
	bank := "a"
	if a.State.ManagedBundle != nil && len(a.State.ManagedBundle.IPSets) > 0 && strings.HasPrefix(a.State.ManagedBundle.IPSets[0].Name, "prthak_a") {
		bank = "b"
	}
	return managedSetRules(p, protection, bank, nonce, stage)
}

func parseManagedRich(value string) (richInfo, error) {
	info, e := parseRich(value)
	if e == nil {
		return info, nil
	}
	tokens, err := richTokens(value)
	if err != nil {
		return info, e
	}
	name := ""
	family := ""
	for _, token := range tokens {
		if v, ok := assignment(token, "family"); ok {
			family = v
		}
	}
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] == "source" {
			if v, ok := assignment(tokens[i+1], "ipset"); ok {
				if !managedSetName.MatchString(v) {
					return info, e
				}
				name = v
				source := "0.0.0.0/0"
				if family == "ipv6" {
					source = "::/0"
				}
				tokens[i+1] = "address=" + source
			}
		}
	}
	if name == "" {
		return info, e
	}
	info, e = parseRich(strings.Join(tokens, " "))
	if e != nil {
		return info, e
	}
	info.Source = ""
	info.SourceIPSet = name
	return info, nil
}

func readManagedIPSet(ctx context.Context, runner CommandRunner, scope string, set ManagedIPSet) ([]string, error) {
	if !validManagedSet(set) {
		return nil, errors.New("invalid owned source set")
	}
	text, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--info-ipset="+set.Name)...)
	if e != nil {
		return nil, errors.New("managed ipset bank is not active; run reviewed bank provisioning and maintenance activation first")
	}
	typeOK, familyOK := false, set.Family == "inet"
	options := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "type:") {
			typeOK = strings.TrimSpace(strings.TrimPrefix(line, "type:")) == "hash:net"
		}
		if strings.HasPrefix(line, "options:") {
			options = true
			for _, option := range strings.Fields(strings.TrimPrefix(line, "options:")) {
				parts := strings.SplitN(option, "=", 2)
				if len(parts) != 2 {
					return nil, errors.New("ambiguous managed ipset options")
				}
				switch parts[0] {
				case "family":
					familyOK = parts[1] == set.Family
				case "hashsize", "maxelem":
					number, err := strconv.Atoi(parts[1])
					if err != nil || number < 1024 {
						return nil, errors.New("unsafe managed ipset capacity")
					}
				default:
					return nil, errors.New("unexpected managed ipset option")
				}
			}
		}
	}
	if !typeOK || !familyOK || !options {
		return nil, errors.New("managed ipset type/family differs from reviewed pool")
	}
	raw, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--ipset="+set.Name, "--get-entries")...)
	if e != nil {
		return nil, e
	}
	entries, e := canonicalSources(strings.Fields(raw), false)
	if e != nil {
		return nil, e
	}
	probe := set
	probe.Entries = entries
	if !validManagedSet(probe) {
		return nil, errors.New("managed ipset contains unsupported or excessive entries")
	}
	return entries, nil
}

func sameManagedEntries(a, b []string) bool { return strings.Join(a, "\n") == strings.Join(b, "\n") }
func writeManagedSetEntries(ctx context.Context, runner CommandRunner, directory, scope string, set ManagedIPSet, entries []string) error {
	if !validManagedSet(set) {
		return errors.New("invalid owned source-set write")
	}
	check := set
	check.Entries = entries
	if !validManagedSet(check) {
		return errors.New("invalid owned source-set entries")
	}
	current, e := readManagedIPSet(ctx, runner, scope, set)
	if e != nil {
		return e
	}
	if sameManagedEntries(current, entries) {
		return nil
	}
	file, e := os.CreateTemp(directory, "ipset-entries-")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	defer file.Close()
	bulk := func(operation string, values []string) error {
		if len(values) == 0 {
			return nil
		}
		if e := file.Truncate(0); e != nil {
			return e
		}
		if _, e := file.Seek(0, 0); e != nil {
			return e
		}
		if _, e := file.WriteString(strings.Join(values, "\n") + "\n"); e != nil {
			return e
		}
		if e := file.Sync(); e != nil {
			return e
		}
		_, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--ipset="+set.Name, "--"+operation+"-entries-from-file="+file.Name())...)
		return e
	}
	if e = bulk("remove", current); e != nil {
		return e
	}
	if e = bulk("add", entries); e != nil {
		return e
	}
	after, e := readManagedIPSet(ctx, runner, scope, set)
	if e != nil || !sameManagedEntries(after, entries) {
		return errors.New("managed ipset exact bulk read-back failed")
	}
	return nil
}

func (a *Agent) managedSetPreflight(ctx context.Context, sets []ManagedIPSet) error {
	if len(sets) == 0 {
		return nil
	}
	targets := map[string]bool{}
	for _, set := range sets {
		targets[set.Name] = true
		for _, scope := range []string{"runtime", "permanent"} {
			if _, e := readManagedIPSet(ctx, a.Commands, scope, set); e != nil {
				return e
			}
		}
	}
	referenced := func(raw string) bool {
		for _, line := range strings.Split(raw, "\n") {
			tokens, _ := richTokens(line)
			for _, token := range tokens {
				if name, ok := assignment(token, "ipset"); ok && targets[name] {
					return true
				}
				if strings.HasPrefix(token, "ipset:") && targets[strings.TrimPrefix(token, "ipset:")] {
					return true
				}
			}
		}
		return false
	}
	// Never overwrite an allegedly unused bank that another rule references.
	for _, scope := range []string{"runtime", "permanent"} {
		zones, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-zones")...)
		if e != nil {
			return e
		}
		for _, zone := range strings.Fields(zones) {
			if !firewallName.MatchString(zone) {
				return errors.New("invalid zone during source-bank preflight")
			}
			raw, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--zone="+zone, "--list-rich-rules")...)
			if e != nil {
				return e
			}
			if referenced(raw) {
				return errors.New("inactive source bank is referenced by an existing rule; refusing to change its entries")
			}
			sources, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--zone="+zone, "--list-sources")...)
			if e != nil {
				return e
			}
			if referenced(sources) {
				return errors.New("inactive source bank is bound to a zone; refusing to change its entries")
			}
		}
		policies, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-policies")...)
		if e != nil {
			if unsupportedFirewallCommand(policies) {
				continue
			}
			return errors.New("policy source-bank references could not be inspected")
		}
		for _, policy := range strings.Fields(policies) {
			if !firewallName.MatchString(policy) {
				return errors.New("invalid policy name during source-bank preflight")
			}
			details, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+policy, "--list-all")...)
			if e != nil {
				return e
			}
			if referenced(details) {
				return errors.New("source bank is referenced by an existing policy object; refusing to change its entries")
			}
		}
	}
	return nil
}
func (a *Agent) managedSetMutation(ctx context.Context, path string, journal *managedJournal, scope string, set ManagedIPSet) error {
	if time.Until(journal.Deadline) < 10*time.Second {
		return errors.New("rollback deadline approaching; source-set mutation refused")
	}
	before, e := readManagedIPSet(ctx, a.Commands, scope, set)
	if e != nil {
		return e
	}
	if sameManagedEntries(before, set.Entries) {
		return nil
	}
	journal.SetMutations = append(journal.SetMutations, managedIPSetMutation{Scope: scope, Set: set, Before: before})
	if e = saveManagedJournal(path, journal); e != nil {
		return e
	}
	return writeManagedSetEntries(ctx, a.Commands, filepath.Dir(path), scope, set, set.Entries)
}

func validateManagedSetJournal(j *managedJournal) error {
	if len(j.SetMutations) > 128 {
		return errors.New("managed source-set journal exceeds limit")
	}
	for _, m := range j.SetMutations {
		before := m.Set
		before.Entries = m.Before
		if (m.Scope != "runtime" && m.Scope != "permanent") || !validManagedSet(m.Set) || !validManagedSet(before) {
			return errors.New("invalid owned source-set journal")
		}
	}
	return nil
}
func validateManagedCommittedSets(ctx context.Context, runner CommandRunner, bundle *ManagedBundle) error {
	if bundle == nil {
		return nil
	}
	for _, set := range bundle.IPSets {
		for _, scope := range []string{"runtime", "permanent"} {
			entries, e := readManagedIPSet(ctx, runner, scope, set)
			if e != nil || !sameManagedEntries(entries, set.Entries) {
				return errors.New("committed managed source-set drift detected")
			}
		}
	}
	return nil
}

// Kept separate from rich-rule parsing so imported arbitrary ipset rules remain
// unsupported rather than being interpreted as a broad address-less allowance.
func managedSetSemanticKey(rule string) string {
	info, e := parseManagedRich(rule)
	if e != nil {
		return rule
	}
	data, _ := json.Marshal(info)
	return string(data)
}
