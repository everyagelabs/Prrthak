package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

type extendedApplyFake struct {
	*firewallFake
	targets              map[string]string
	calls                [][]string
	failTargetAfterWrite bool
}

func newExtendedApplyFake(t *testing.T) *extendedApplyFake {
	t.Helper()
	oldRange := readFirewallEphemeralRange
	readFirewallEphemeralRange = func() (int, int, error) { return 32768, 60999, nil }
	t.Cleanup(func() { readFirewallEphemeralRange = oldRange })
	return &extendedApplyFake{firewallFake: newFirewallFake(), targets: map[string]string{"runtime": "default", "permanent": "default"}}
}
func (f *extendedApplyFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name != "firewall-cmd" {
		return f.firewallFake.Run(ctx, name, args...)
	}
	f.calls = append(f.calls, append([]string{}, args...))
	scope, options := "runtime", []string{}
	for _, arg := range args {
		if arg == "--permanent" {
			scope = "permanent"
		} else {
			options = append(options, arg)
		}
	}
	for index, arg := range options {
		if arg == "--get-target" {
			return f.targets[scope], nil
		}
		if strings.HasPrefix(arg, "--set-target=") {
			f.targets[scope] = strings.TrimPrefix(arg, "--set-target=")
			if f.failTargetAfterWrite {
				return "", errors.New("owned fake uncertain result")
			}
			return "success", nil
		}
		if arg == "--get-all-rules" {
			values := []string{}
			for key, present := range f.rules {
				parts := strings.SplitN(key, "|", 3)
				if present && parts[0] == scope && parts[1] == "direct" {
					values = append(values, parts[2])
				}
			}
			sort.Strings(values)
			return strings.Join(values, "\n"), nil
		}
		if arg == "--query-rule" || arg == "--add-rule" || arg == "--remove-rule" {
			value := strings.Join(options[index+1:], " ")
			if arg == "--query-rule" {
				if f.has(scope, "direct", value) {
					return "yes", nil
				}
				return "no", errors.New("not enabled")
			}
			f.set(scope, "direct", value, arg == "--add-rule")
			return "success", nil
		}
		for _, verb := range []string{"query", "add", "remove"} {
			prefix := "--" + verb + "-forward-port="
			if strings.HasPrefix(arg, prefix) {
				value := strings.TrimPrefix(arg, prefix)
				if verb == "query" {
					if f.has(scope, "forward_port", value) {
						return "yes", nil
					}
					return "no", errors.New("not enabled")
				}
				f.set(scope, "forward_port", value, verb == "add")
				return "success", nil
			}
		}
		if arg == "--list-all-zones" {
			text, err := f.firewallFake.Run(ctx, name, args...)
			text = strings.Replace(text, "target: "+f.target, "target: "+f.targets[scope], 1)
			values := []string{}
			for key, present := range f.rules {
				parts := strings.SplitN(key, "|", 3)
				if present && parts[0] == scope && parts[1] == "forward_port" {
					values = append(values, parts[2])
				}
			}
			sort.Strings(values)
			return strings.Replace(text, "  rich rules:", "  forward-ports: "+strings.Join(values, " ")+"\n  rich rules:", 1), err
		}
	}
	return f.firewallFake.Run(ctx, name, args...)
}
func extendedApplyAgent(t *testing.T, f *extendedApplyFake) *Agent {
	t.Helper()
	a := firewallAgent(t, f.firewallFake)
	a.Commands = f
	return a
}
func extendedApplyPlan(f *extendedApplyFake, operations ...FirewallOperation) FirewallChange {
	return FirewallChange{ID: "typed-imported-change", PlanDigest: strings.Repeat("b", 64), ExpectedSnapshotDigest: CollectFirewallSnapshot(context.Background(), f, nil).Digest,
		ConfirmationCount: 2, ExpiresAt: time.Now().Add(time.Hour), Operations: operations}
}
func assertNoReload(t *testing.T, f *extendedApplyFake) {
	t.Helper()
	for _, args := range f.calls {
		for _, arg := range args {
			if arg == "--reload" || arg == "--complete-reload" || arg == "--runtime-to-permanent" {
				t.Fatalf("unexpected broad operation %v", args)
			}
		}
	}
}

func TestExtendedInventoryPromotesOnlyTypedSubsetAndKeepsBothScopes(t *testing.T) {
	f := newExtendedApplyFake(t)
	for _, scope := range []string{"runtime", "permanent"} {
		f.set(scope, "direct", "ipv4 filter INPUT 0 -p tcp --dport 8443 -j ACCEPT", true)
		f.set(scope, "forward_port", "port=8080:proto=tcp:toport=8181:toaddr=", true)
		f.set(scope, "port", "8080/tcp", true)
	}
	snapshot := CollectFirewallSnapshot(context.Background(), f, nil)
	if snapshot.Status != "ok" {
		t.Fatal(snapshot.Error)
	}
	counts := map[string]int{}
	for _, rule := range snapshot.Rules {
		if rule.Kind == "direct" || rule.Kind == "forward_port" || rule.Kind == "port" {
			if !rule.Editable {
				t.Fatalf("typed subset disabled %+v", rule)
			}
			counts[rule.Kind]++
		}
		if rule.Kind == "target" && rule.Editable != (rule.Scope == "permanent") {
			t.Fatalf("wrong target scope %+v", rule)
		}
	}
	if counts["direct"] != 2 || counts["forward_port"] != 2 || counts["port"] != 2 {
		t.Fatal(counts)
	}
	f.set("runtime", "direct", "ipv4 nat PREROUTING 0 -j DNAT --to-destination 10.0.0.1", true)
	blocked := CollectFirewallSnapshot(context.Background(), f, nil)
	for _, rule := range blocked.Rules {
		if rule.Editable {
			t.Fatalf("unsupported context promoted %+v", rule)
		}
	}
}
func TestExtendedTargetUsesSinglePermanentSetAndDurablePreviousValue(t *testing.T) {
	f := newExtendedApplyFake(t)
	a := extendedApplyAgent(t, f)
	plan := extendedApplyPlan(f, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "target", OldValue: "default", NewValue: "ACCEPT", Operation: "replace"})
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "applied" || f.targets["runtime"] != "default" || f.targets["permanent"] != "ACCEPT" {
		t.Fatalf("wrong target outcome %+v %+v", result, f.targets)
	}
	data, err := os.ReadFile(a.firewallJournalPath(plan.ID))
	if err != nil {
		t.Fatal(err)
	}
	var journal firewallJournal
	if err = json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	if len(journal.Mutations) != 1 || journal.Mutations[0].Operation != "set" || journal.Mutations[0].PreviousValue != "default" || !journal.Mutations[0].Completed {
		t.Fatalf("bad singleton journal %+v", journal)
	}
	assertNoReload(t, f)
}
func TestExtendedTargetFinalRevocationRestoresOnlyOwnedValue(t *testing.T) {
	for _, thirdParty := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "refuse-third-party"}[thirdParty], func(t *testing.T) {
			f := newExtendedApplyFake(t)
			a := extendedApplyAgent(t, f)
			calls := 0
			plan := extendedApplyPlan(f, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "target", OldValue: "default", NewValue: "ACCEPT", Operation: "replace"})
			a.checkFirewallAuthorization = func(context.Context, FirewallChange, string) error {
				calls++
				if calls == 3 {
					if thirdParty {
						f.targets["permanent"] = "DROP"
					}
					return errors.New("revoked")
				}
				return nil
			}
			result := a.applyFirewallChange(context.Background(), plan)
			want := "default"
			if thirdParty {
				want = "DROP"
			}
			if result.Status != "failed" || f.targets["permanent"] != want || calls != 3 {
				t.Fatalf("wrong rollback %+v targets=%v calls=%d", result, f.targets, calls)
			}
			assertNoReload(t, f)
		})
	}
}
func TestExtendedTargetUnacknowledgedSetRequiresBaselineReview(t *testing.T) {
	f := newExtendedApplyFake(t)
	f.failTargetAfterWrite = true
	a := extendedApplyAgent(t, f)
	plan := extendedApplyPlan(f, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "target", OldValue: "default", NewValue: "ACCEPT", Operation: "replace"})
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "failed" || !strings.Contains(result.Message, "manual review") || f.targets["permanent"] != "ACCEPT" {
		t.Fatalf("uncertain target falsely compensated %+v %v", result, f.targets)
	}
	assertNoReload(t, f)
}
func TestExtendedLocalRedirectAndDirectApplyExactRulesInBothScopes(t *testing.T) {
	for _, kind := range []string{"direct", "forward_port"} {
		t.Run(kind, func(t *testing.T) {
			f := newExtendedApplyFake(t)
			a := extendedApplyAgent(t, f)
			old, next, zone := "port=8080:proto=tcp:toport=8181:toaddr=", "port=8080:proto=tcp:toport=8282:toaddr=", "public"
			if kind == "direct" {
				old, next, zone = "ipv4 filter INPUT 0 -p tcp --dport 8443 -j ACCEPT", "ipv4 filter INPUT 0 -p tcp --dport 8444 -j ACCEPT", ""
			}
			ops := []FirewallOperation{}
			for _, scope := range []string{"runtime", "permanent"} {
				f.set(scope, kind, old, true)
				ops = append(ops, FirewallOperation{Scope: scope, Zone: zone, Kind: kind, OldValue: old, NewValue: next, Operation: "replace"})
			}
			result := a.applyFirewallChange(context.Background(), extendedApplyPlan(f, ops...))
			if result.Status != "applied" {
				t.Fatalf("typed apply failed %+v", result)
			}
			for _, scope := range []string{"runtime", "permanent"} {
				if f.has(scope, kind, old) || !f.has(scope, kind, next) {
					t.Fatalf("scope not exact %s %s", kind, scope)
				}
			}
			assertNoReload(t, f)
		})
	}
}
func TestExtendedOperationsForceIndependentSecondConfirmation(t *testing.T) {
	f := newExtendedApplyFake(t)
	a := extendedApplyAgent(t, f)
	plan := extendedApplyPlan(f, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "target", OldValue: "default", NewValue: "ACCEPT", Operation: "replace"})
	plan.RequiresDoubleConfirmation, plan.ConfirmationCount = false, 1
	if result := a.applyFirewallChange(context.Background(), plan); result.Status != "failed" || !strings.Contains(result.Message, "two confirmations") {
		t.Fatalf("confirmation flag bypass %+v", result)
	}
}
func TestExtendedManagementRejectsConfiguredActualSSHRedirectAndReturnPorts(t *testing.T) {
	cases := []struct{ name, kind, old, next string }{
		{"actual-ssh", "direct", "ipv4 filter INPUT 0 -p tcp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -p tcp --dport 2022 -j DROP"},
		{"configured-ssh-not-listening", "direct", "ipv4 filter INPUT 0 -p tcp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -p tcp --dport 2222 -j DROP"},
		{"tcp-return", "direct", "ipv4 filter INPUT 0 -p tcp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -p tcp --dport 33000 -j DROP"},
		{"udp-dns-return", "direct", "ipv4 filter INPUT 0 -p udp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -p udp --dport 33000 -j REJECT"},
		{"management-source", "direct", "ipv4 filter INPUT 0 -p tcp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -s 10.20.0.1/32 -p tcp --dport 6000 -j DROP"},
		{"redirect-to-ssh", "forward_port", "port=8080:proto=tcp:toport=8181:toaddr=", "port=8080:proto=tcp:toport=2222:toaddr="},
		{"redirect-from-ssh", "forward_port", "port=8080:proto=tcp:toport=8181:toaddr=", "port=2022:proto=tcp:toport=8181:toaddr="},
		{"redirect-to-return", "forward_port", "port=8080:proto=tcp:toport=8181:toaddr=", "port=8080:proto=tcp:toport=33000:toaddr="},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newExtendedApplyFake(t)
			a := extendedApplyAgent(t, f)
			a.Config.ProtectedSSHPorts = []int{2022, 2222}
			zone := "public"
			if test.kind == "direct" {
				zone = ""
			}
			f.set("runtime", test.kind, test.old, true)
			plan := extendedApplyPlan(f, FirewallOperation{Scope: "runtime", Zone: zone, Kind: test.kind, OldValue: test.old, NewValue: test.next, Operation: "replace"})
			if result := a.applyFirewallChange(context.Background(), plan); result.Status != "failed" {
				t.Fatalf("protected mutation applied %+v", result)
			}
			if !f.has("runtime", test.kind, test.old) || f.has("runtime", test.kind, test.next) {
				t.Fatal("guard changed rules")
			}
		})
	}
}
func TestExtendedControllerLocalityProtectsAllOriginsWithoutRemote443FalsePositive(t *testing.T) {
	oldLookup := firewallControllerIngressTargeted
	t.Cleanup(func() { firewallControllerIngressTargeted = oldLookup })
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "proven-remote", true: "local-or-unknown"}[local], func(t *testing.T) {
			f := newExtendedApplyFake(t)
			a := extendedApplyAgent(t, f)
			a.Config.ControllerURL = "https://controller.example:8787"
			a.Config.ControlURL = "https://control.example:9443"
			a.Config.DiscoveryURL = "https://discovery.example"
			seen := map[string]bool{}
			firewallControllerIngressTargeted = func(origin string, _ *Policy) bool { seen[origin] = true; return local }
			old, next := "ipv4 filter INPUT 0 -p tcp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -p tcp --dport 443 -j DROP"
			f.set("runtime", "direct", old, true)
			result := a.applyFirewallChange(context.Background(), extendedApplyPlan(f, FirewallOperation{Scope: "runtime", Kind: "direct", OldValue: old, NewValue: next, Operation: "replace"}))
			if local && result.Status != "failed" || !local && result.Status != "applied" {
				t.Fatalf("wrong locality guard %+v", result)
			}
			if !seen["https://discovery.example:443"] || len(seen) != 1 {
				t.Fatalf("lookup must only inspect intersected third origin %v", seen)
			}
		})
	}
	for _, port := range []string{"8787", "9443"} {
		t.Run(port, func(t *testing.T) {
			f := newExtendedApplyFake(t)
			a := extendedApplyAgent(t, f)
			a.Config.ControllerURL = "https://controller.example:8787"
			a.Config.ControlURL = "https://control.example:9443"
			firewallControllerIngressTargeted = func(string, *Policy) bool { return true }
			old, next := "ipv4 filter INPUT 0 -p tcp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -p tcp --dport "+port+" -j DROP"
			f.set("runtime", "direct", old, true)
			if result := a.applyFirewallChange(context.Background(), extendedApplyPlan(f, FirewallOperation{Scope: "runtime", Kind: "direct", OldValue: old, NewValue: next, Operation: "replace"})); result.Status != "failed" {
				t.Fatalf("origin guard missed %+v", result)
			}
		})
	}
}
func TestExtendedEphemeralReadFailureAndRestrictiveTargetFailClosed(t *testing.T) {
	f := newExtendedApplyFake(t)
	a := extendedApplyAgent(t, f)
	readFirewallEphemeralRange = func() (int, int, error) { return 0, 0, errors.New("missing") }
	old, next := "ipv4 filter INPUT 0 -p tcp --dport 6000 -j ACCEPT", "ipv4 filter INPUT 0 -p tcp --dport 6001 -j DROP"
	f.set("runtime", "direct", old, true)
	result := a.applyFirewallChange(context.Background(), extendedApplyPlan(f, FirewallOperation{Scope: "runtime", Kind: "direct", OldValue: old, NewValue: next, Operation: "replace"}))
	if result.Status != "failed" || !strings.Contains(result.Message, "ephemeral") {
		t.Fatalf("uncertain return path accepted %+v", result)
	}
	result = a.applyFirewallChange(context.Background(), extendedApplyPlan(f, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "target", OldValue: "default", NewValue: "DROP", Operation: "replace"}))
	if result.Status != "failed" || !strings.Contains(result.Message, "surviving SSH") {
		t.Fatalf("restrictive target lacked independent allowance %+v", result)
	}
}

func TestExtendedSSHProtectionUnionsTrustedObservedAndUnboundConfiguredPorts(t *testing.T) {
	ports, err := protectedFirewallSSHPorts([]Listener{{Port: 2022, Protocol: "tcp", ProtectedSSH: true}, {Port: 8080, Protocol: "tcp", Process: "sshd", Service: "SSH"}}, Config{ProtectedSSHPorts: []int{2222}})
	if err != nil {
		t.Fatal(err)
	}
	sort.Ints(ports)
	if len(ports) != 2 || ports[0] != 2022 || ports[1] != 2222 {
		t.Fatalf("trusted/configured union incorrect %v", ports)
	}
}

func TestExtendedDirectAliasesAreRejectedBeforeAnyMutation(t *testing.T) {
	old := "ipv4 filter INPUT 0 -p tcp --dport 8440:8441 -j ACCEPT"
	aliases := []string{strings.Replace(old, "8440:8441", "8440-8441", 1), strings.Replace(old, " -p", "  -p", 1), strings.Replace(old, "INPUT 0", "INPUT 00", 1), "ipv4 filter INPUT 0 -j ACCEPT --dport 8440:8441 -p tcp -m tcp"}
	for _, next := range aliases {
		t.Run(next, func(t *testing.T) {
			f := newExtendedApplyFake(t)
			a := extendedApplyAgent(t, f)
			f.set("runtime", "direct", old, true)
			result := a.applyFirewallChange(context.Background(), extendedApplyPlan(f, FirewallOperation{Scope: "runtime", Kind: "direct", OldValue: old, NewValue: next, Operation: "replace"}))
			if result.Status != "failed" || !f.has("runtime", "direct", old) {
				t.Fatalf("alias deleted the desired rule %+v", result)
			}
			for _, args := range f.calls {
				for _, arg := range args {
					if arg == "--add-rule" || arg == "--remove-rule" {
						t.Fatalf("alias reached mutation %v", args)
					}
				}
			}
		})
	}
}

func TestExtendedConflictingEqualPriorityDirectOrderingRemainsViewOnly(t *testing.T) {
	f := newExtendedApplyFake(t)
	f.set("runtime", "direct", "ipv4 filter INPUT 0 -p tcp --dport 8443 -j ACCEPT", true)
	f.set("runtime", "direct", "ipv4 filter INPUT 0 -s 192.0.2.0/24 -p tcp --dport 8443 -j DROP", true)
	for _, rule := range CollectFirewallSnapshot(context.Background(), f, nil).Rules {
		if rule.Editable {
			t.Fatalf("ambiguous insertion order promoted %+v", rule)
		}
	}
	f = newExtendedApplyFake(t)
	a := extendedApplyAgent(t, f)
	old := "ipv4 filter INPUT 0 -p tcp --dport 8444 -j ACCEPT"
	f.set("runtime", "direct", old, true)
	f.set("runtime", "direct", "ipv4 filter INPUT 0 -s 192.0.2.0/24 -p tcp --dport 8443 -j DROP", true)
	result := a.applyFirewallChange(context.Background(), extendedApplyPlan(f, FirewallOperation{Scope: "runtime", Kind: "direct", OldValue: old, NewValue: strings.Replace(old, "8444", "8443", 1), Operation: "replace"}))
	if result.Status != "failed" || !strings.Contains(result.Message, "equal priority") {
		t.Fatalf("new insertion ambiguity allowed %+v", result)
	}
}

func TestExtendedRestrictiveTargetRejectsLocalControllerAndPermitsProvenRemote(t *testing.T) {
	oldLookup := firewallControllerIngressTargeted
	t.Cleanup(func() { firewallControllerIngressTargeted = oldLookup })
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "proven-remote", true: "local-or-unresolved"}[local], func(t *testing.T) {
			f := newExtendedApplyFake(t)
			a := extendedApplyAgent(t, f)
			a.Config.DiscoveryURL = "https://discovery.example:9443"
			f.set("permanent", "service", "ssh", true)
			firewallControllerIngressTargeted = func(string, *Policy) bool { return local }
			result := a.applyFirewallChange(context.Background(), extendedApplyPlan(f, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "target", OldValue: "default", NewValue: "DROP", Operation: "replace"}))
			if local && result.Status != "failed" || !local && result.Status != "applied" {
				t.Fatalf("target topology check incorrect %+v", result)
			}
		})
	}
}
