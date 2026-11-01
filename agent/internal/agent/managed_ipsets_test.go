package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

type managedSetFake struct {
	*managedFake
	sets       map[string][]string
	bulk       int
	failBulk   int
	missing    bool
	sourceRefs string
	policyRefs string
}

func (f *managedSetFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	scope := "runtime"
	set := ""
	for _, arg := range args {
		if arg == "--list-sources" && f.sourceRefs != "" {
			return f.sourceRefs, nil
		}
		if arg == "--get-policies" && f.policyRefs != "" {
			return "inactive-policy", nil
		}
		if arg == "--list-all" && f.policyRefs != "" {
			return f.policyRefs, nil
		}
		if arg == "--permanent" {
			scope = "permanent"
		}
		if strings.HasPrefix(arg, "--ipset=") {
			set = strings.TrimPrefix(arg, "--ipset=")
		}
	}
	for _, arg := range args {
		if arg == "--get-zones" {
			return "public", nil
		}
		if arg == "--list-rich-rules" {
			values := []string{}
			for key, present := range f.rules {
				parts := strings.SplitN(key, "|", 3)
				if present && parts[0] == scope && parts[1] == "rich_rule" {
					values = append(values, parts[2])
				}
			}
			sort.Strings(values)
			return strings.Join(values, "\n"), nil
		}
		if strings.HasPrefix(arg, "--info-ipset=") {
			if f.missing {
				return "", errors.New("unknown set")
			}
			s := strings.TrimPrefix(arg, "--info-ipset=")
			family := "inet"
			if strings.Contains(s, "6_") {
				family = "inet6"
			}
			return s + "\n type: hash:net\n options: family=" + family + " hashsize=1024 maxelem=16384\n", nil
		}
		if arg == "--get-entries" {
			return strings.Join(f.sets[scope+"|"+set], "\n"), nil
		}
		for _, verb := range []string{"add", "remove"} {
			prefix := "--" + verb + "-entries-from-file="
			if strings.HasPrefix(arg, prefix) {
				raw, e := os.ReadFile(strings.TrimPrefix(arg, prefix))
				if e != nil {
					return "", e
				}
				f.bulk++
				values := strings.Fields(string(raw))
				key := scope + "|" + set
				existing := map[string]bool{}
				for _, entry := range f.sets[key] {
					existing[entry] = true
				}
				for index, entry := range values {
					if verb == "add" {
						existing[entry] = true
					} else {
						delete(existing, entry)
					}
					if f.failBulk == f.bulk && index >= len(values)/2 {
						break
					}
				}
				f.sets[key] = []string{}
				for entry := range existing {
					f.sets[key] = append(f.sets[key], entry)
				}
				sort.Strings(f.sets[key])
				if f.failBulk == f.bulk {
					return "", errors.New("partial bulk failure")
				}
				return "success", nil
			}
		}
	}
	return f.managedFake.Run(ctx, name, args...)
}
func largeSources(offset, count int) []string {
	values := []string{}
	for i := 0; i < count; i++ {
		value := i + offset
		values = append(values, fmt.Sprintf("10.%d.%d.%d/32", 1+value/65536, (value/256)%256, value%256))
	}
	sort.Strings(values)
	return values
}
func scaleManagedAgent(t *testing.T) (*Agent, *managedSetFake, Protection) {
	a, f, p := managedTestAgent(t)
	setFake := &managedSetFake{managedFake: f, sets: map[string][]string{}}
	a.Commands = setFake
	return a, setFake, p
}
func TestManagedIPSetsFiveThousandSourcesUseBoundedOwnedRules(t *testing.T) {
	a, f, protection := scaleManagedAgent(t)
	policy := managedTestPolicy(protection, 1, largeSources(0, 5000)...)
	if e := a.applyManaged(context.Background(), policy, protection); e != nil {
		t.Fatal(e)
	}
	if len(a.State.ManagedBundle.Rules) != 3 || len(a.State.ManagedBundle.IPSets) != 1 {
		t.Fatalf("unexpected compiled shape %+v", a.State.ManagedBundle)
	}
	set := a.State.ManagedBundle.IPSets[0]
	if !strings.HasPrefix(set.Name, "prthak_a4_") {
		t.Fatal("first bank mismatch")
	}
	for _, scope := range []string{"runtime", "permanent"} {
		if !sameManagedEntries(f.sets[scope+"|"+set.Name], largeSources(0, 5000)) {
			t.Fatal("source-set scope did not commit exactly")
		}
	}
	for _, rule := range a.State.ManagedBundle.Rules {
		if !managedOwned(rule.Rule) {
			t.Fatal("generated set rule not owned")
		}
		if strings.Contains(rule.Rule, "ipset=") {
			if _, e := parseRich(rule.Rule); e == nil {
				t.Fatal("general imported-rule parser incorrectly accepts managed-only ipsets")
			}
		}
	}
	second := managedTestPolicy(protection, 2, largeSources(6000, 5000)...)
	if e := a.applyManaged(context.Background(), second, protection); e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(a.State.ManagedBundle.IPSets[0].Name, "prthak_b4_") {
		t.Fatal("next generation did not use inactive bank")
	}
}
func TestManagedIPSetPartialBulkFailureRestoresPreviousRulesAndBothSetScopes(t *testing.T) {
	a, f, p := scaleManagedAgent(t)
	first := managedTestPolicy(p, 1, largeSources(0, 5000)...)
	if e := a.applyManaged(context.Background(), first, p); e != nil {
		t.Fatal(e)
	}
	before := append([]ManagedRule{}, a.State.ManagedBundle.Rules...)
	f.failBulk = f.bulk + 1
	second := managedTestPolicy(p, 2, largeSources(6000, 5000)...)
	if a.applyManaged(context.Background(), second, p) == nil {
		t.Fatal("partial source-set mutation accepted")
	}
	if a.State.AppliedVersion != 1 || a.State.ManagedEnforcement.Status != "rolled_back" {
		t.Fatalf("rollback state %+v", a.State.ManagedEnforcement)
	}
	for _, rule := range before {
		for _, scope := range []string{"runtime", "permanent"} {
			if !f.has(scope, "rich_rule", rule.Rule) {
				t.Fatal("old policy was not preserved")
			}
		}
	}
	if len(f.sets["runtime|prthak_b4_00"]) != 0 || len(f.sets["permanent|prthak_b4_00"]) != 0 {
		t.Fatal("partial inactive bank contents survived rollback")
	}
}
func TestManagedIPSetMissingBankAndForeignReferencesFailBeforeMutation(t *testing.T) {
	a, f, p := scaleManagedAgent(t)
	policy := managedTestPolicy(p, 1, largeSources(0, 5000)...)
	f.missing = true
	if a.applyManaged(context.Background(), policy, p) == nil || f.bulk != 0 || f.mutations != 0 {
		t.Fatal("missing maintenance prerequisite mutated firewall")
	}
	f.missing = false
	f.set("runtime", "rich_rule", `rule family="ipv4" source ipset="prthak_a4_00" port port="443" protocol="tcp" accept`, true)
	if a.applyManaged(context.Background(), policy, p) == nil || f.bulk != 0 {
		t.Fatal("referenced inactive bank was overwritten")
	}
}
func TestManagedIPSetWatchdogRestoresJournalAfterInterruptedBulkAndRules(t *testing.T) {
	a, f, p := scaleManagedAgent(t)
	nonce := strings.Repeat("b", 32)
	rules, sets, e := managedSetRules(managedTestPolicy(p, 1, largeSources(0, 5000)...), p, "a", nonce, true)
	if e != nil {
		t.Fatal(e)
	}
	set := sets[0]
	path := managedJournalPath(a.Config.StateDir, nonce)
	j := &managedJournal{Nonce: nonce, Phase: "staging", PID: os.Getpid(), Deadline: time.Now().Add(-time.Second), Next: ManagedBundle{Version: 1, Digest: "a", IPSets: sets}, SetMutations: []managedIPSetMutation{{Scope: "runtime", Set: set, Before: []string{}}}, Mutations: []managedMutation{{Scope: "runtime", Zone: p.Zone, Rule: rules[0].Rule, Before: false, After: true}}}
	if e = saveManagedJournal(path, j); e != nil {
		t.Fatal(e)
	}
	f.sets["runtime|"+set.Name] = set.Entries[:1000]
	f.set("runtime", "rich_rule", rules[0].Rule, true)
	loaded, e := readManagedJournal(path, nonce)
	if e != nil {
		t.Fatal(e)
	}
	if e = rollbackManaged(context.Background(), f, path, loaded); e != nil {
		t.Fatal(e)
	}
	if len(f.sets["runtime|"+set.Name]) != 0 || f.has("runtime", "rich_rule", rules[0].Rule) {
		t.Fatal("independent journal compensation incomplete")
	}
	if _, e = os.Stat(filepath.Join(filepath.Dir(filepath.Dir(path)), "committed.json")); e != nil {
		t.Fatal(e)
	}
}
func TestManagedIPSetFamiliesDeduplicateListsWithoutCrossPortMixing(t *testing.T) {
	_, _, p := scaleManagedAgent(t)
	policy := managedTestPolicy(p, 1, "10.1.0.0/16", "2001:db8:1::/64")
	policy.Services = append(policy.Services, Service{Port: 8443, Protocol: "tcp", Sources: []string{"10.1.0.0/16", "2001:db8:1::/64"}}, Service{Port: 5432, Protocol: "tcp", Sources: []string{"10.2.0.0/16"}})
	rules, sets, e := managedSetRules(policy, p, "a", strings.Repeat("a", 32), false)
	if e != nil {
		t.Fatal(e)
	}
	if len(sets) != 3 || len(rules) != 11 {
		t.Fatalf("unexpected deduplication: %d sets %d rules", len(sets), len(rules))
	}
	byName := map[string]ManagedIPSet{}
	for _, set := range sets {
		if !validManagedSet(set) {
			t.Fatal("families mixed")
		}
		byName[set.Name] = set
	}
	for _, rule := range rules {
		info, e := parseManagedRich(rule.Rule)
		if e != nil {
			t.Fatal(e)
		}
		if info.Port == "5432" && info.SourceIPSet != "" && !sameManagedEntries(byName[info.SourceIPSet].Entries, []string{"10.2.0.0/16"}) {
			t.Fatal("different source lists crossed service rows")
		}
	}
}
func TestManagedIPSetInactiveZoneBindingsAndPolicyReferencesCannotBeOverwritten(t *testing.T) {
	for _, kind := range []string{"zone-source", "inactive-policy"} {
		t.Run(kind, func(t *testing.T) {
			a, f, _ := scaleManagedAgent(t)
			if kind == "zone-source" {
				f.sourceRefs = "ipset:prthak_a4_00"
			} else {
				f.policyRefs = `rich rules:
    rule family="ipv4" source ipset="prthak_a4_00" accept`
			}
			set := ManagedIPSet{Name: "prthak_a4_00", Family: "inet", Entries: largeSources(0, 5000)}
			if e := a.managedSetPreflight(context.Background(), []ManagedIPSet{set}); e == nil || f.bulk != 0 {
				t.Fatal("externally referenced source bank was writable")
			}
		})
	}
}
