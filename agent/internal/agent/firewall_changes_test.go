package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

type firewallFake struct {
	rules            map[string]bool
	target           string
	writes           []string
	failRemove       string
	failPermanent    bool
	beforeWrite      func()
	direct           string
	policyDefinition string
}

func newFirewallFake() *firewallFake {
	return &firewallFake{rules: map[string]bool{}, target: "default"}
}
func (f *firewallFake) set(scope, kind, value string, present bool) {
	f.rules[scope+"|"+kind+"|"+value] = present
}
func (f *firewallFake) has(scope, kind, value string) bool { return f.rules[scope+"|"+kind+"|"+value] }
func (f *firewallFake) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "ss" {
		return `tcp LISTEN 0 128 0.0.0.0:2022 0.0.0.0:* users:(("sshd",pid=9999999,fd=3))`, nil
	}
	if name == "ufw" {
		return "Status: inactive", nil
	}
	if name == "systemctl" {
		return "", nil
	}
	if name != "firewall-cmd" {
		return "", fmt.Errorf("unexpected command %s", name)
	}
	scope := "runtime"
	options := []string{}
	for _, arg := range args {
		if arg == "--permanent" {
			scope = "permanent"
		} else {
			options = append(options, arg)
		}
	}
	for _, option := range options {
		switch option {
		case "--state":
			return "running", nil
		case "--get-default-zone":
			return "public", nil
		case "--get-policies", "--get-active-policies":
			if f.policyDefinition != "" {
				return "custom-policy", nil
			}
			return "", nil
		case "--list-all":
			return f.policyDefinition, nil
		case "--get-all-rules":
			return f.direct, nil
		case "--list-all-zones":
			if scope == "permanent" && f.failPermanent {
				return "", errors.New("permanent read unavailable")
			}
			services, ports, rich := []string{}, []string{}, []string{}
			for key, present := range f.rules {
				parts := strings.SplitN(key, "|", 3)
				if !present || parts[0] != scope {
					continue
				}
				switch parts[1] {
				case "service":
					services = append(services, parts[2])
				case "port":
					ports = append(ports, parts[2])
				case "rich_rule":
					rich = append(rich, parts[2])
				}
			}
			sort.Strings(services)
			sort.Strings(ports)
			sort.Strings(rich)
			text := "public"
			if scope == "runtime" {
				text += " (active)"
			}
			text += "\n  target: " + f.target + "\n  interfaces: eth0\n  sources:\n  services: " + strings.Join(services, " ") + "\n  ports: " + strings.Join(ports, " ") + "\n  protocols:\n  forward: no\n  masquerade: no\n  rich rules:\n"
			for _, rule := range rich {
				text += "    " + rule + "\n"
			}
			return text, nil
		}
		if strings.HasPrefix(option, "--info-service=") {
			service := strings.TrimPrefix(option, "--info-service=")
			port := map[string]string{"ssh": "2022/tcp", "http": "80/tcp", "https": "443/tcp"}[service]
			if port == "" {
				return "", errors.New("unknown service")
			}
			return service + "\n  ports: " + port + "\n  protocols:\n  source-ports:\n  destination:\n  includes:\n", nil
		}
		for _, verb := range []string{"query", "add", "remove"} {
			for _, kind := range []string{"service", "port", "rich-rule"} {
				prefix := "--" + verb + "-" + kind + "="
				if !strings.HasPrefix(option, prefix) {
					continue
				}
				value := strings.TrimPrefix(option, prefix)
				keyKind := strings.ReplaceAll(kind, "-", "_")
				if verb == "query" {
					if f.has(scope, keyKind, value) {
						return "yes", nil
					}
					return "no", errors.New("not enabled")
				}
				if f.beforeWrite != nil {
					f.beforeWrite()
				}
				f.writes = append(f.writes, scope+":"+verb+":"+keyKind+":"+value)
				if verb == "remove" && value == f.failRemove {
					return "", errors.New("injected removal failure")
				}
				f.set(scope, keyKind, value, verb == "add")
				return "success", nil
			}
		}
	}
	return "", nil
}
func firewallAgent(t *testing.T, f *firewallFake) *Agent {
	t.Helper()
	return &Agent{Config: Config{StateDir: t.TempDir(), AllowFirewallChanges: true, ManagementSources: []string{"10.20.0.0/24"}, ProtectedSSHPorts: []int{2022}}, Commands: f, State: State{Coverage: map[string]*Coverage{}}, checkFirewallAuthorization: func(context.Context, FirewallChange, string) error { return nil }}
}
func firewallPlan(f *firewallFake, operations ...FirewallOperation) FirewallChange {
	return FirewallChange{ID: "approved-change-1", PlanDigest: strings.Repeat("a", 64), ExpectedSnapshotDigest: CollectFirewallSnapshot(context.Background(), f, nil).Digest, ConfirmationCount: 2, ExpiresAt: time.Now().Add(time.Hour), Operations: operations}
}
func TestFirewallInventoryHashScopesAndRealServicePorts(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	f.set("permanent", "port", "8080/tcp", true)
	f.set("runtime", "service", "ssh", true)
	snapshot := CollectFirewallSnapshot(context.Background(), f, nil)
	if snapshot.Status != "ok" {
		t.Fatal(snapshot.Error)
	}
	var ports []FirewallRule
	resolved := false
	for _, rule := range snapshot.Rules {
		if rule.Kind == "port" {
			ports = append(ports, rule)
		}
		if rule.Kind == "service" && rule.Value == "ssh" && len(rule.Ports) == 1 && rule.Ports[0].Port == "2022" {
			resolved = true
		}
	}
	if len(ports) != 2 || ports[0].Fingerprint == ports[1].Fingerprint || ports[0].LogicalKey != ports[1].LogicalKey || !resolved {
		t.Fatalf("scope/service metadata wrong %+v", snapshot)
	}
	expected := sha256.Sum256([]byte("runtime\x00public\x00port\x008080/tcp"))
	if FirewallFingerprint("runtime", "public", "port", "8080/tcp") != hex.EncodeToString(expected[:]) {
		t.Fatal("fingerprint NUL contract mismatch")
	}
}
func TestFirewallSnapshotExcludesOnlyOwnedLogInstrumentation(t *testing.T) {
	f := newFirewallFake()
	base := CollectFirewallSnapshot(context.Background(), f, nil)
	now := time.Now()
	session := sessionAt(now)
	learning := ObservationRule(session, Port{80, "tcp"})
	probe := `rule priority="-32750" family="ipv4" protocol value="tcp" log prefix="PRTP012345abcdef:" level="info" limit value="5/s"`
	f.set("runtime", "rich_rule", learning, true)
	f.set("runtime", "rich_rule", probe, true)
	owned := []OwnedRule{{SessionID: session.ID, Zone: "public", Rule: learning}, {SessionID: "probe", Zone: "public", Rule: probe}}
	current := CollectFirewallSnapshot(context.Background(), f, owned)
	if current.Digest != base.Digest {
		t.Fatal("owned temporary logs invalidated approved snapshot")
	}
	f.set("runtime", "rich_rule", learning+" accept", true)
	changed := CollectFirewallSnapshot(context.Background(), f, owned)
	if changed.Digest == base.Digest {
		t.Fatal("owned-looking access rule was hidden")
	}
}
func TestFirewallPartialInventoryRetainsPreviousAndBoundsReport(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	old := CollectFirewallSnapshot(context.Background(), f, nil)
	f.failPermanent = true
	next := retainFirewallSnapshot(old, CollectFirewallSnapshot(context.Background(), f, nil))
	if next.Status != "partial" || next.Digest != old.Digest {
		t.Fatal("failed read discarded previous inventory")
	}
	for _, r := range next.Rules {
		if r.Editable {
			t.Fatal("incomplete retained inventory is writable")
		}
	}
	f.failPermanent = false
	for port := 10000; port < 12500; port++ {
		f.set("runtime", "port", fmt.Sprintf("%d/tcp", port), true)
	}
	bounded := CollectFirewallSnapshot(context.Background(), f, nil)
	data, _ := json.Marshal(bounded)
	if bounded.Status != "partial" || len(data) > maxFirewallSnapshotBytes || len(bounded.Rules) > maxFirewallRules {
		t.Fatalf("unbounded snapshot rules=%d bytes=%d", len(bounded.Rules), len(data))
	}
}
func TestApprovedFirewallReplaceBacksUpAndAddsBeforeRemoveBothScopes(t *testing.T) {
	f := newFirewallFake()
	for _, scope := range []string{"runtime", "permanent"} {
		f.set(scope, "port", "8080/tcp", true)
	}
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", NewValue: "8081/tcp", Operation: "replace"}, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "port", OldValue: "8080/tcp", NewValue: "8081/tcp", Operation: "replace"})
	f.beforeWrite = func() {
		info, e := os.Stat(a.firewallJournalPath(plan.ID))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("mutation occurred without private pre-change backup")
		}
	}
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "applied" {
		t.Fatalf("apply failed %+v", result)
	}
	expected := []string{"runtime:add:port:8081/tcp", "runtime:remove:port:8080/tcp", "permanent:add:port:8081/tcp", "permanent:remove:port:8080/tcp"}
	if strings.Join(f.writes, "|") != strings.Join(expected, "|") {
		t.Fatalf("unsafe order %v", f.writes)
	}
	for _, scope := range []string{"runtime", "permanent"} {
		if f.has(scope, "port", "8080/tcp") || !f.has(scope, "port", "8081/tcp") {
			t.Fatal("runtime/permanent exact change missing")
		}
	}
}
func TestApprovedFirewallFailureRollsBackExactCompletedMutations(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	f.failRemove = "8080/tcp"
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", NewValue: "8081/tcp", Operation: "replace"})
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "failed" || !f.has("runtime", "port", "8080/tcp") || f.has("runtime", "port", "8081/tcp") {
		t.Fatalf("rollback failed %+v writes=%v", result, f.writes)
	}
	if len(f.writes) != 3 || f.writes[2] != "runtime:remove:port:8081/tcp" {
		t.Fatal("rollback touched rules outside its completed add")
	}
}
func TestApprovedFirewallRefusesDriftAndMissingOptIn(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", Operation: "remove"})
	a.Config.AllowFirewallChanges = false
	if result := a.applyFirewallChange(context.Background(), plan); result.Status != "preview" {
		t.Fatal("missing opt-in did not preview")
	}
	a.Config.AllowFirewallChanges = true
	f.set("runtime", "port", "9000/tcp", true)
	if result := a.applyFirewallChange(context.Background(), plan); result.Status != "conflict" {
		t.Fatalf("drift not refused %+v", result)
	}
	if len(f.writes) > 0 {
		t.Fatal("preview/conflict changed firewall")
	}
}
func TestApprovedDenyRemovalIndependentlyRequiresTwoConfirmations(t *testing.T) {
	f := newFirewallFake()
	rule := `rule port port="8080" protocol="tcp" drop`
	f.set("runtime", "rich_rule", rule, true)
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "rich_rule", OldValue: rule, Operation: "remove"})
	for _, count := range []int{0, 1} {
		plan.ConfirmationCount = count
		result := a.applyFirewallChange(context.Background(), plan)
		if result.Status != "failed" {
			t.Fatalf("deny removal with%d confirmations accepted %+v", count, result)
		}
	}
	if len(f.writes) > 0 {
		t.Fatal("unconfirmed deny removal wrote rules")
	}
	plan.ConfirmationCount = 2
	if result := a.applyFirewallChange(context.Background(), plan); result.Status != "applied" {
		t.Fatalf("confirmed deny removal failed %+v", result)
	}
}
func TestApprovedChangeProtectsActualSSH2022AndIndependentManagementAllow(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "2022/tcp", true)
	a := firewallAgent(t, f)
	op := FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "2022/tcp", Operation: "remove"}
	plan := firewallPlan(f, op)
	if result := a.applyFirewallChange(context.Background(), plan); result.Status != "failed" || !strings.Contains(result.Message, "management") {
		t.Fatalf("SSH2022 lockout accepted %+v", result)
	}
	independent := `rule family="ipv4" source address="10.20.0.0/24" port port="2022" protocol="tcp" accept`
	f.set("runtime", "rich_rule", independent, true)
	plan = firewallPlan(f, op)
	if result := a.applyFirewallChange(context.Background(), plan); result.Status != "applied" {
		t.Fatalf("proven surviving management allowance refused %+v", result)
	}
}
func TestApprovedBroadDenyCannotReplaceUnrelatedAllowAndBlockSSH(t *testing.T) {
	f := newFirewallFake()
	old := `rule port port="8080" protocol="tcp" accept`
	f.set("runtime", "rich_rule", old, true)
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "rich_rule", OldValue: old, NewValue: `rule port port="2022" protocol="tcp" reject`, Operation: "replace"})
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "failed" || !strings.Contains(result.Message, "SSH") {
		t.Fatalf("broad SSH deny accepted %+v", result)
	}
	if len(f.writes) != 0 {
		t.Fatal("management-deny refusal occurred after mutation")
	}
}
func TestApprovedChangesReplayCommittedOutcomeWithoutReapplying(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", Operation: "remove"})
	if e := a.processApprovedChanges(context.Background(), []FirewallChange{plan}); e != nil {
		t.Fatal(e)
	}
	count := len(f.writes)
	if e := a.processApprovedChanges(context.Background(), []FirewallChange{plan}); e != nil {
		t.Fatal(e)
	}
	a.State.FirewallChangeResults = nil
	if e := a.processApprovedChanges(context.Background(), []FirewallChange{plan}); e != nil {
		t.Fatal(e)
	}
	if len(f.writes) != count || len(a.State.FirewallChangeResults) != 1 || a.State.FirewallChangeResults[0].Status != "applied" {
		t.Fatal("persisted outcome was not idempotent")
	}
}
func TestViewOnlyDirectAndAcceptTargetCannotBeEdited(t *testing.T) {
	for _, contextName := range []string{"direct", "target"} {
		f := newFirewallFake()
		f.set("runtime", "port", "8080/tcp", true)
		if contextName == "direct" {
			f.direct = "ipv4 filter INPUT 0 -j ACCEPT"
		} else {
			f.target = "ACCEPT"
		}
		snapshot := CollectFirewallSnapshot(context.Background(), f, nil)
		for _, rule := range snapshot.Rules {
			if rule.Kind == "port" && rule.Editable {
				t.Fatal("ambiguous context remained editable")
			}
		}
	}
}

func TestOwnedProbeExclusionAcceptsConfiguredRateOnlyWithExactSavedRule(t *testing.T) {
	rule := `rule priority="-32750" family="ipv4" protocol value="tcp" log prefix="PRTP012345abcdef:" level="info" limit value="10/s"`
	recorded := []OwnedRule{{SessionID: "probe", Zone: "public", Rule: rule}}
	canonical := `rule family="ipv4" priority="-32750" protocol value="tcp" log prefix="PRTP012345abcdef:" level="info" limit value="10/s"`
	if !ownedObservation(canonical, recorded) {
		t.Fatal("configured10/s owned probe changed snapshot")
	}
	if ownedObservation(strings.Replace(canonical, "10/s", "20/s", 1), recorded) {
		t.Fatal("unrecorded probe rate was hidden")
	}
	if ownedObservation(strings.Replace(canonical, "10/s", "101/s", 1), []OwnedRule{{SessionID: "probe", Rule: strings.Replace(rule, "10/s", "101/s", 1)}}) {
		t.Fatal("out-of-range probe rate was hidden")
	}
}

const defaultHostIPv6Policy = `allow-host-ipv6 (active)
  priority: -15000
  target: CONTINUE
  ingress-zones: ANY
  egress-zones: HOST
  services:
  ports:
  protocols:
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
    rule family="ipv6" icmp-type name="neighbour-advertisement" accept
    rule family="ipv6" icmp-type name="neighbour-solicitation" accept
    rule family="ipv6" icmp-type name="router-advertisement" accept
    rule family="ipv6" icmp-type name="redirect" accept
`

const defaultHostIPv6PolicyWithMLD = defaultHostIPv6Policy + `    rule family="ipv6" icmp-type name="mld-listener-done" accept
    rule family="ipv6" icmp-type name="mld-listener-query" accept
    rule family="ipv6" icmp-type name="mld-listener-report" accept
    rule family="ipv6" icmp-type name="mld2-listener-report" accept
`

func TestDefaultHostIPv6PolicyRecognizedByFullDefinitionOnly(t *testing.T) {
	if !safeHostIPv6Policy(defaultHostIPv6Policy) {
		t.Fatal("actual default IPv6 policy not recognized")
	}
	if !safeHostIPv6Policy(defaultHostIPv6PolicyWithMLD) {
		t.Error("stock RHEL 9 IPv6 policy with MLD rules not recognized")
	}
	if !safeHostIPv6Policy(strings.Replace(defaultHostIPv6Policy, "allow-host-ipv6", "another-policy", 1)) {
		t.Fatal("safe classification incorrectly depended on name")
	}
	for _, mutated := range []string{strings.Replace(defaultHostIPv6Policy, "  services:", "  services: ssh", 1), strings.Replace(defaultHostIPv6Policy, "  ports:", "  ports: 2022/tcp", 1), strings.Replace(defaultHostIPv6Policy, "target: CONTINUE", "target: ACCEPT", 1), strings.Replace(defaultHostIPv6Policy, "priority: -15000", "priority: -100", 1), defaultHostIPv6Policy + "    rule port port=\"2022\" protocol=\"tcp\" accept\n", defaultHostIPv6Policy + "  sources: 0.0.0.0/0\n"} {
		if safeHostIPv6Policy(mutated) {
			t.Fatal("broadened or unknown policy definition was trusted")
		}
	}
}

func TestDefaultHostIPv6PolicyAcceptsOnlyExplicitEnabledSetting(t *testing.T) {
	for _, base := range []string{defaultHostIPv6Policy, defaultHostIPv6PolicyWithMLD} {
		enabled := strings.Replace(base, "  target: CONTINUE\n", "  target: CONTINUE\n  disable: no\n", 1)
		if !safeHostIPv6Policy(enabled) {
			t.Fatal("stock firewalld 2.4 disable:no setting rejected")
		}
		for _, changed := range []string{
			strings.Replace(enabled, "disable: no", "disable: yes", 1),
			strings.Replace(enabled, "disable: no", "disable: unknown", 1),
			strings.Replace(enabled, "disable: no", "unknown: no", 1),
			strings.Replace(enabled, "disable: no", "disable: no\n  disable: no", 1),
			strings.Replace(enabled, "  services:", "  services: ssh", 1),
		} {
			if safeHostIPv6Policy(changed) {
				t.Fatal("unknown, disabled, duplicate or overlapping stock policy accepted")
			}
		}
	}
}

func TestDefaultHostIPv6PolicyRejectsModifiedMLDDefinitions(t *testing.T) {
	const lastRule = `    rule family="ipv6" icmp-type name="mld2-listener-report" accept` + "\n"
	for name, policy := range map[string]string{
		"incomplete MLD group": strings.TrimSuffix(defaultHostIPv6PolicyWithMLD, lastRule),
		"duplicate MLD rule":   defaultHostIPv6PolicyWithMLD + lastRule,
		"missing base rule":    strings.Replace(defaultHostIPv6PolicyWithMLD, `    rule family="ipv6" icmp-type name="redirect" accept`+"\n", "", 1),
		"unknown ICMP type":    strings.Replace(defaultHostIPv6PolicyWithMLD, "mld2-listener-report", "echo-request", 1),
		"different action":     strings.Replace(defaultHostIPv6PolicyWithMLD, `name="mld2-listener-report" accept`, `name="mld2-listener-report" drop`, 1),
		"different family":     strings.Replace(defaultHostIPv6PolicyWithMLD, `family="ipv6" icmp-type name="mld2-listener-report"`, `family="ipv4" icmp-type name="mld2-listener-report"`, 1),
		"TCP port":             strings.Replace(defaultHostIPv6PolicyWithMLD, "  ports:", "  ports: 443/tcp", 1),
		"extra rich rule":      defaultHostIPv6PolicyWithMLD + `    rule family="ipv6" port port="53" protocol="udp" accept` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if safeHostIPv6Policy(policy) {
				t.Fatal("modified IPv6 policy was classified as non-overlapping")
			}
		})
	}
}

func TestHarmlessIPv6ControlPolicyDoesNotBlockTCPPortEdit(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	f.policyDefinition = defaultHostIPv6Policy
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", NewValue: "8081/tcp", Operation: "replace"})
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "applied" {
		t.Fatalf("known nonoverlapping IPv6 control policy blocked exactTCPchange %+v", result)
	}
	f = newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	f.policyDefinition = strings.Replace(defaultHostIPv6Policy, "  ports:", "  ports: 8080/tcp", 1)
	a = firewallAgent(t, f)
	plan = firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", Operation: "remove"})
	result = a.applyFirewallChange(context.Background(), plan)
	if result.Status != "failed" || len(f.writes) > 0 {
		t.Fatal("TCP-overlapping policy context allowed mutation")
	}
}

func TestOwnedObservationExclusionIsRuntimeAndZoneScoped(t *testing.T) {
	f := newFirewallFake()
	session := sessionAt(time.Now())
	rule := ObservationRule(session, Port{80, "tcp"})
	owned := []OwnedRule{{SessionID: session.ID, Zone: "public", Rule: rule}}
	f.set("runtime", "rich_rule", rule, true)
	runtimeOnly := CollectFirewallSnapshot(context.Background(), f, owned)
	f.set("permanent", "rich_rule", rule, true)
	permanent := CollectFirewallSnapshot(context.Background(), f, owned)
	if permanent.Digest == runtimeOnly.Digest {
		t.Fatal("permanent rule was hidden as temporary runtime instrumentation")
	}
	f.set("permanent", "rich_rule", rule, false)
	wrongZone := CollectFirewallSnapshot(context.Background(), f, []OwnedRule{{SessionID: session.ID, Zone: "internal", Rule: rule}})
	if wrongZone.Digest == runtimeOnly.Digest {
		t.Fatal("different-zone rule was treated as locally owned")
	}
}
