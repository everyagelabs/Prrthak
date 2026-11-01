package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func hostDenyKernelFixture() string {
	return `{"nftables":[{"table":{"family":"inet","name":"firewalld"}},
{"chain":{"family":"inet","table":"firewalld","name":"filter_INPUT","type":"filter","hook":"input","prio":10,"policy":"accept"}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_INPUT","expr":[{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":{"set":["established","related"]}}},{"accept":null}]}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_INPUT","expr":[{"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}},{"accept":null}]}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_INPUT","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}]}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_INPUT","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"drop":null}]}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_INPUT","expr":[{"jump":{"target":"filter_INPUT_POLICIES"}}]}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_INPUT","expr":[{"reject":{"type":"icmpx","expr":"admin-prohibited"}}]}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_INPUT_POLICIES","expr":[{"jump":{"target":"filter_IN_public"}}]}},
{"rule":{"family":"inet","table":"firewalld","chain":"filter_IN_public","expr":[{"jump":{"target":"filter_IN_public_pre"}}]}}]}`
}

type hostDenyFake struct {
	CommandRunner
	nft                 string
	forwarding          string
	interfaceForwarding bool
}

func (f *hostDenyFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "nft" {
		return f.nft, nil
	}
	if name == "sysctl" {
		if strings.Join(strings.Fields(f.forwarding), " ") == "0 0" {
			if f.interfaceForwarding {
				return strings.Repeat("0\n", len(args)-2) + "1\n", nil
			}
			return strings.Repeat("0\n", len(args)-1), nil
		}
		return f.forwarding, nil
	}
	if name == "ip" {
		return `[{"ifname":"lo","link_type":"loopback","flags":["UP"]},{"ifname":"eth0","link_type":"ether","flags":["UP"]}]`, nil
	}
	return f.CommandRunner.Run(ctx, name, args...)
}

func hostDenyTestAgent(t *testing.T) (*Agent, *managedFake, *hostDenyFake, Protection) {
	t.Helper()
	a, f, _ := managedTestAgent(t)
	a.Config.AllowHostDefaultDeny = true
	a.Config.ControllerURL = "https://192.0.2.200:8787"
	h := &hostDenyFake{CommandRunner: f, nft: hostDenyKernelFixture(), forwarding: "0\n0\n"}
	a.Commands = h
	protection, err := a.managedProtection(context.Background())
	if err != nil || !protection.HostDefaultDenyReady {
		t.Fatalf("whole-host readiness: %+v %v", protection, err)
	}
	return a, f, h, protection
}

func hostDenyPolicy(a *Agent, protection Protection, version int, enabled bool, sources ...string) *Policy {
	p := managedTestPolicy(protection, version, sources...)
	p.HostDefaultDeny = enabled
	p.Digest, _ = compiledPolicyDigest(p)
	auth := p.Enforcement
	auth.ApprovedDigest, auth.BindingDigest = p.Digest, enforcementBinding(p, protection.Digest)
	auth.HostDefaultDenyAck, auth.HostDefaultDenyRevision = true, version
	auth.HostDefaultDenyConfigurationDigest = configurationState(a.Config).Digest
	auth.ConfirmationCount = 1
	action := "enable"
	auth.Intent = "enforce_host_default_deny"
	if !enabled {
		action, auth.Intent = "disable", "remove_host_default_deny"
	}
	proof := singleAdminProofFixture()
	proof.Scope["kind"] = json.RawMessage(`"host_default_deny"`)
	proof.Scope["action"], _ = json.Marshal(action)
	proof.Scope["server_ids"], _ = json.Marshal([]string{p.ServerID})
	auth.ApprovalProof = sealDirectApproval(proof)
	return p
}

func TestHostDefaultDenyDigestOptInAndControls(t *testing.T) {
	a, _, _, protection := hostDenyTestAgent(t)
	p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32", "2001:db8::1/128")
	without := *p
	without.HostDefaultDeny = false
	ordinary, _ := compiledPolicyDigest(&without)
	if ordinary == p.Digest {
		t.Fatal("whole-host flag is not bound into compiled digest")
	}
	for _, stage := range []bool{false, true} {
		rules, err := managedRules(p, protection, strings.Repeat("a", 32), stage)
		if err != nil {
			t.Fatal(err)
		}
		fallbacks, controls, ssh := 0, 0, false
		for index, rule := range rules {
			if !managedOwned(rule.Rule) {
				t.Fatalf("unowned generated rule: %s", rule.Rule)
			}
			info, err := parseManagedRich(rule.Rule)
			if err != nil {
				t.Fatal(err)
			}
			if hostDefaultDenyFallback(rule) {
				fallbacks++
				if index < len(rules)-2 {
					t.Fatal("global reject precedes a required allow")
				}
				want := managedCanonicalReject
				if stage {
					want = managedStageReject
				}
				if info.Priority != want {
					t.Fatal("global reject wrong priority")
				}
			} else if info.Protocol == "icmp" || info.Protocol == "ipv6-icmp" || info.Transport == "udp" && (info.Port == "68" || info.Port == "546") {
				controls++
			}
			if info.Port == "2022" && info.Source == "10.20.0.0/24" && info.Action == "accept" {
				ssh = true
			}
		}
		if fallbacks != 2 || controls != 4 || !ssh {
			t.Fatalf("missing essential controls: %+v", rules)
		}
	}
	raw, _ := json.Marshal(Config{})
	settings, _ := json.Marshal(EndpointConfigurationSettings{})
	if strings.Contains(string(raw), "allow_host_default_deny") || strings.Contains(string(settings), "allow_host_default_deny") {
		t.Fatal("false changed legacy configuration wire/digest")
	}
	legacy := protection
	legacy.HostDefaultDenyContextDigest, legacy.HostDefaultDenyControlProfile = "", ""
	if protectionDigest(legacy) == protection.Digest {
		t.Fatal("context/profile not bound into protection digest")
	}
}

func TestHostDefaultDenyRejectsUnsafeOwnershipAndKeepsImportedGrammar(t *testing.T) {
	rules := hostDefaultDenyControlRules(Protection{Zone: "public"}, strings.Repeat("a", 32), false)
	for _, rule := range rules {
		if !managedOwned(rule.Rule) {
			t.Fatal(rule.Rule)
		}
		for _, mutate := range []func(string) string{
			func(s string) string { return strings.Replace(s, "PRTMaaaaaaaaaaaa:", "PRTMxxxxxxxxxxxx:", 1) },
			func(s string) string { return strings.Replace(s, `level="debug"`, `level="info"`, 1) },
			func(s string) string { return strings.Replace(s, `priority="-31000"`, `priority="-32000"`, 1) },
		} {
			changed := mutate(rule.Rule)
			if changed != rule.Rule && managedOwned(changed) {
				t.Fatalf("overbroad ownership: %s", changed)
			}
		}
		if strings.Contains(rule.Rule, "protocol value=") {
			if _, err := parseRich(rule.Rule); err == nil {
				t.Fatal("managed ICMP widened imported edit grammar")
			}
		}
	}
	if managedOwned(`rule priority="-31000" family="ipv4" log prefix="PRTMaaaaaaaaaaaa:" level="debug" limit value="1/m" accept`) {
		t.Fatal("global accept is not an owned managed construct")
	}
}

func TestHostDefaultDenyKernelProofRejectsBypasses(t *testing.T) {
	base := hostDenyKernelFixture()
	if digest, err := hostDefaultDenyKernelContext(base, "public"); err != nil || !validDigest(digest) {
		t.Fatalf("fixture: %s %v", digest, err)
	}
	cases := map[string]string{
		"unconditional base accept": strings.Replace(base, `{"reject":{"type":"icmpx","expr":"admin-prohibited"}}`, `{"accept":null}`, 1),
		"lost stateful protection":  strings.Replace(base, `"established"`, `"new"`, 1),
		"lost loopback":             strings.Replace(base, `"right":"lo"`, `"right":"eth0"`, 1),
		"late zone pre":             strings.Replace(base, `"filter_IN_public_pre"`, `"filter_IN_public_allow"`, 1),
		"dispatch to bypass":        strings.Replace(base, `"target":"filter_IN_public"`, `"target":"filter_IN_public_allow"`, 1),
		"foreign table":             strings.Replace(base, `"name":"firewalld"`, `"name":"docker"`, 1),
		"DNAT":                      strings.Replace(base, `{"reject":{"type":"icmpx","expr":"admin-prohibited"}}`, `{"dnat":{"addr":"127.0.0.1"}}`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := hostDefaultDenyKernelContext(raw, "public"); err == nil {
				t.Fatal("unsafe context accepted")
			}
		})
	}
}

func TestHostDefaultDenyAcknowledgementAndScopeCannotBeInferred(t *testing.T) {
	for _, item := range []string{"optin", "generic", "ack", "configuration", "revision", "intent", "action", "context"} {
		t.Run(item, func(t *testing.T) {
			a, f, _, protection := hostDenyTestAgent(t)
			p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32")
			switch item {
			case "optin":
				a.Config.AllowHostDefaultDeny = false
			case "generic":
				proof := singleAdminProofFixture()
				proof.Scope["kind"] = json.RawMessage(`"managed_rollout"`)
				proof.Scope["server_ids"], _ = json.Marshal([]string{p.ServerID})
				p.Enforcement.ApprovalProof = sealDirectApproval(proof)
			case "ack":
				p.Enforcement.HostDefaultDenyAck = false
			case "configuration":
				p.Enforcement.HostDefaultDenyConfigurationDigest = strings.Repeat("0", 64)
			case "revision":
				p.Enforcement.HostDefaultDenyRevision = 0
			case "intent":
				p.Enforcement.Intent = "enforce_managed_rules"
			case "action":
				var proof endpointApprovalProof
				json.Unmarshal(p.Enforcement.ApprovalProof, &proof)
				proof.Scope["action"] = json.RawMessage(`"disable"`)
				p.Enforcement.ApprovalProof = sealDirectApproval(proof)
			case "context":
				protection.HostDefaultDenyContextDigest = strings.Repeat("0", 64)
			}
			if err := a.applyManaged(context.Background(), p, protection); err == nil || f.mutations != 0 || a.State.ManagedBundle != nil {
				t.Fatalf("unreviewed authority wrote: err=%v mutations=%d", err, f.mutations)
			}
		})
	}
}

func TestHostDefaultDenyCommitContextStabilityAndGlobalOnlyRemoval(t *testing.T) {
	a, f, _, protection := hostDenyTestAgent(t)
	f.target = "ACCEPT" // A pre-zone reject must override a legacy open zone.
	protection, _ = a.managedProtection(context.Background())
	p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32")
	if err := a.applyManaged(context.Background(), p, protection); err != nil {
		t.Fatal(err)
	}
	old := a.State.ManagedBundle
	if old == nil || !old.HostDefaultDeny {
		t.Fatal("not committed")
	}
	for _, rule := range old.Rules {
		for _, scope := range []string{"runtime", "permanent"} {
			if !f.has(scope, "rich_rule", rule.Rule) {
				t.Fatal("not present in both scopes")
			}
		}
	}
	a.enrichManagedStatus()
	if !a.State.ManagedEnforcement.HostDefaultDenyActive {
		t.Fatal("receipt did not attest committed fallback")
	}
	fresh, _ := a.managedProtection(context.Background())
	if fresh.Digest != protection.Digest || !fresh.HostDefaultDenyReady {
		t.Fatalf("own rules invalidate review context: %+v", fresh)
	}
	a.Config.AllowHostDefaultDeny, a.Config.Enforce = false, false
	fresh, _ = a.managedProtection(context.Background())
	remove := hostDenyPolicy(a, fresh, 2, false, "10.30.0.1/32")
	start := len(f.writes)
	if err := a.applyManaged(context.Background(), remove, fresh); err != nil {
		t.Fatal(err)
	}
	for _, write := range f.writes[start:] {
		if !strings.Contains(write, ":remove:rich_rule:") || strings.Contains(write, " port ") || strings.Contains(write, " protocol ") {
			t.Fatalf("removal mutated a grant/control: %s", write)
		}
	}
	if len(f.writes[start:]) != 4 {
		t.Fatalf("expected only two-family/two-scope fallback removals: %v", f.writes[start:])
	}
	for _, rule := range old.Rules {
		for _, scope := range []string{"runtime", "permanent"} {
			if f.has(scope, "rich_rule", rule.Rule) == hostDefaultDenyFallback(rule) {
				t.Fatal("removal did not preserve exact remaining rules")
			}
		}
	}
	a.enrichManagedStatus()
	if a.State.ManagedEnforcement.HostDefaultDenyActive || a.State.ManagedBundle.HostDefaultDeny {
		t.Fatal("removal receipt still active")
	}
	if a.State.ManagedEnforcement.ManagedRulesPresent == nil || !*a.State.ManagedEnforcement.ManagedRulesPresent {
		t.Fatal("retained SSH/control grants were reported absent")
	}
}

func TestHostDefaultDenyFailureRestoresExactPriorGeneration(t *testing.T) {
	for _, failAt := range []int{1, 5, 10, 17, 25} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			a, f, _, protection := hostDenyTestAgent(t)
			p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32")
			if err := a.applyManaged(context.Background(), p, protection); err != nil {
				t.Fatal(err)
			}
			prior := a.State.ManagedBundle
			f.failAt = f.mutations + failAt
			next := hostDenyPolicy(a, protection, 2, true, "10.40.0.1/32")
			if err := a.applyManaged(context.Background(), next, protection); err == nil {
				t.Fatal("injected fault did not fail")
			}
			if a.State.ManagedBundle.Generation != prior.Generation || !a.State.ManagedBundle.HostDefaultDeny {
				t.Fatal("failed candidate replaced committed state")
			}
			for _, rule := range prior.Rules {
				for _, scope := range []string{"runtime", "permanent"} {
					if !f.has(scope, "rich_rule", rule.Rule) {
						t.Fatal("rollback lost previous rule")
					}
				}
			}
			for key, present := range f.rules {
				if present && strings.Contains(key, "rich_rule") {
					found := false
					for _, rule := range prior.Rules {
						if strings.HasSuffix(key, "|"+rule.Rule) {
							found = true
						}
					}
					if !found {
						t.Fatalf("candidate residue: %s", key)
					}
				}
			}
		})
	}
}

func TestHostDefaultDenyGuardsOverlaysAndForwarding(t *testing.T) {
	a, f, h, protection := hostDenyTestAgent(t)
	p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32")
	a.State.Policy = p
	if result := a.applyFirewallChange(context.Background(), firewallPlan(f.firewallFake)); !strings.Contains(result.Message, "whole-server") {
		t.Fatalf("imported mutation admitted: %+v", result)
	}
	if err := a.processLearningAllow(context.Background(), &LearningAllow{Generation: 1, Services: p.Services}); err != nil || a.State.LearningAllowOutcome.Status != "blocked" || f.mutations != 0 {
		t.Fatal("additive learning was admitted")
	}
	h.forwarding = "1\n0\n"
	fresh, _ := a.managedProtection(context.Background())
	if fresh.HostDefaultDenyReady {
		t.Fatal("router context ready")
	}
	if err := a.applyManaged(context.Background(), p, protection); err == nil || f.mutations != 0 {
		t.Fatal("stale safe context authorized changed forwarding")
	}
	h.forwarding = "0\n0\n"
	h.interfaceForwarding = true
	fresh, _ = a.managedProtection(context.Background())
	if fresh.HostDefaultDenyReady {
		t.Fatal("per-interface forwarding bypassed zero global forwarding")
	}
}

func TestHostDefaultDenySourceBankPlanStillProtectsSSHAndGlobalOrder(t *testing.T) {
	a, f, protection := scaleManagedAgent(t)
	a.Config.AllowHostDefaultDeny = true
	a.Config.ControllerURL = "https://192.0.2.200:8787"
	h := &hostDenyFake{CommandRunner: f, nft: hostDenyKernelFixture(), forwarding: "0\n0"}
	a.Commands = h
	protection, _ = a.managedProtection(context.Background())
	p := hostDenyPolicy(a, protection, 1, true, largeSources(0, 5000)...)
	if err := a.applyManaged(context.Background(), p, protection); err != nil {
		t.Fatal(err)
	}
	if len(a.State.ManagedBundle.IPSets) != 2 || len(a.State.ManagedBundle.Rules) > 12 {
		t.Fatal("unbounded source-bank shape")
	}
	for _, rule := range a.State.ManagedBundle.Rules {
		if !managedOwned(rule.Rule) {
			t.Fatal(rule.Rule)
		}
	}
	prior := a.State.ManagedBundle
	bulk := f.bulk
	remove := hostDenyPolicy(a, protection, 2, false, largeSources(0, 5000)...)
	if err := a.applyManaged(context.Background(), remove, protection); err != nil {
		t.Fatal("source-bank cleanup:", err)
	}
	if f.bulk != bulk || len(a.State.ManagedBundle.IPSets) != len(prior.IPSets) || a.State.ManagedBundle.HostDefaultDeny {
		t.Fatal("source-bank cleanup rewrote a retained active bank")
	}
}

func TestHostDefaultDenyObserveSessionsDoNotGrantOrInvalidateContext(t *testing.T) {
	a, _, _, protection := hostDenyTestAgent(t)
	a.State.Policy = &Policy{LearningSessions: []Session{{ID: "observe-session-123", PolicyAction: "observe", Status: "active", StartsAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}}}
	fresh, _ := a.managedProtection(context.Background())
	if !fresh.HostDefaultDenyReady || fresh.Digest != protection.Digest {
		t.Fatalf("non-mutating observation changed context: %+v", fresh)
	}
	a.State.Policy.LearningSessions[0].PolicyAction = "auto_allow"
	fresh, _ = a.managedProtection(context.Background())
	if fresh.HostDefaultDenyReady {
		t.Fatal("automatic access-changing session did not block feature")
	}
}

func TestHostDefaultDenyCancellationBeforeFirstApplyVerifiesEmptyMonitor(t *testing.T) {
	for _, orphan := range []bool{false, true} {
		t.Run(fmt.Sprint(orphan), func(t *testing.T) {
			a, f, _, protection := hostDenyTestAgent(t)
			p := hostDenyPolicy(a, protection, 2, false)
			p.Mode, p.Services = "monitor", []Service{}
			p.Digest, _ = compiledPolicyDigest(p)
			p.Enforcement.ApprovedDigest = p.Digest
			p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
			if orphan {
				rule := hostDefaultDenyControlRules(protection, strings.Repeat("a", 32), false)[4]
				f.set("runtime", "rich_rule", rule.Rule, true)
			}
			err := a.applyManaged(context.Background(), p, protection)
			if orphan {
				if err == nil || a.State.ManagedBundle != nil || len(f.writes) != 0 {
					t.Fatal("unowned fallback was silently cleared/acknowledged")
				}
				return
			}
			if err != nil || a.State.ManagedBundle == nil || a.State.ManagedBundle.HostDefaultDeny || len(a.State.ManagedBundle.Rules) != 0 || len(f.writes) != 0 {
				t.Fatalf("unapplied cancellation did not commit verified absence: %v %+v", err, a.State.ManagedBundle)
			}
			a.enrichManagedStatus()
			if a.State.ManagedEnforcement.Status != "enforced" || a.State.ManagedEnforcement.ApprovalID != p.Enforcement.ApprovalID || a.State.ManagedEnforcement.HostDefaultDenyActive {
				t.Fatal("cleanup receipt did not bind its verified cancellation")
			}
			if a.State.ManagedEnforcement.ManagedRulesPresent == nil || *a.State.ManagedEnforcement.ManagedRulesPresent {
				t.Fatal("empty verified cancellation reported retained rules")
			}
		})
	}
}

func TestHostDefaultDenyEmptyAppliedBundleCanBeRemovedByMonitor(t *testing.T) {
	a, _, _, protection := hostDenyTestAgent(t)
	p := hostDenyPolicy(a, protection, 1, true)
	p.Services = []Service{}
	p.Digest, _ = compiledPolicyDigest(p)
	p.Enforcement.ApprovedDigest = p.Digest
	p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
	if err := a.applyManaged(context.Background(), p, protection); err != nil {
		t.Fatal(err)
	}
	a.Config.AllowHostDefaultDeny = false
	protection, _ = a.managedProtection(context.Background())
	remove := hostDenyPolicy(a, protection, 2, false)
	remove.Mode, remove.Services = "monitor", []Service{}
	remove.Digest, _ = compiledPolicyDigest(remove)
	remove.Enforcement.ApprovedDigest = remove.Digest
	remove.Enforcement.BindingDigest = enforcementBinding(remove, protection.Digest)
	if err := a.applyManaged(context.Background(), remove, protection); err != nil {
		t.Fatal(err)
	}
	if a.State.ManagedBundle.HostDefaultDeny {
		t.Fatal("empty applied bundle remains blocked")
	}
	// An ordinary cleanup may share the disabled monitor bundle's version/hash;
	// it still must remove retained controls rather than hit the no-change path.
	cleanup := *remove
	auth := *remove.Enforcement
	cleanup.Enforcement = &auth
	auth.HostDefaultDenyAck, auth.HostDefaultDenyRevision, auth.HostDefaultDenyConfigurationDigest = false, 0, ""
	auth.Intent, auth.ApprovalID = "remove_managed_rules", "ordinary-reviewed-cleanup"
	proof := singleAdminProofFixture()
	proof.Scope["kind"] = json.RawMessage(`"managed_rollout"`)
	proof.Scope["server_ids"], _ = json.Marshal([]string{cleanup.ServerID})
	auth.ApprovalProof = sealDirectApproval(proof)
	a.protection = &protection
	a.State.Policy = &cleanup
	if err := a.processManaged(context.Background(), &cleanup); err != nil {
		t.Fatal("ordinary retained-control cleanup:", err)
	}
	if len(a.State.ManagedBundle.Rules) != 0 || len(a.State.ManagedBundle.IPSets) != 0 {
		t.Fatal("ordinary cleanup was treated as unchanged")
	}
	if err := a.recoverManaged(context.Background()); err != nil {
		t.Fatal("same-version cleanup recovery:", err)
	}
	a.enrichManagedStatus()
	if len(a.State.ManagedBundle.Rules) != 0 || a.State.ManagedEnforcement.ManagedRulesPresent == nil || *a.State.ManagedEnforcement.ManagedRulesPresent || a.State.ManagedEnforcement.ApprovalID != auth.ApprovalID {
		t.Fatal("recovery resurrected the pre-cleanup generation")
	}
}

func TestHostDefaultDenyStagingContextDriftRollsBack(t *testing.T) {
	a, f, _, protection := hostDenyTestAgent(t)
	p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32")
	injected := false
	f.beforeWrite = func() {
		if !injected {
			injected = true
			f.set("runtime", "rich_rule", `rule priority="-32000" family="ipv4" source address="10.99.0.0/24" accept`, true)
		}
	}
	if err := a.applyManaged(context.Background(), p, protection); err == nil || a.State.ManagedBundle != nil {
		t.Fatal("mid-stage context drift committed")
	}
	for key, present := range f.rules {
		if present && strings.Contains(key, "PRTM") {
			t.Fatal("staging rollback left owned restrictions")
		}
	}
	if a.protection == nil || a.protection.HostDefaultDenyReady {
		t.Fatal("refused push left stale ready context in the immediate report cache")
	}
}

func TestHostDefaultDenyFreshWitnessRetainsDedicatedAuthority(t *testing.T) {
	a, _, _, protection := hostDenyTestAgent(t)
	p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32")
	a.Client = &Client{}
	fixtureAuthenticatedClient(a, p.ServerID)
	a.inventory = &Report{IPs: []string{"10.30.0.10"}}
	now := time.Now().UTC()
	body := map[string]any{"nonce": "fresh-nonce", "server_id": p.ServerID, "version": p.Version, "digest": p.Digest, "protection_digest": protection.Digest, "binding_digest": p.Enforcement.BindingDigest, "checked_at": now, "controller_ok": true, "status": "healthy", "host_default_deny_ack": true, "host_default_deny_revision": p.Enforcement.HostDefaultDenyRevision, "host_default_deny_configuration_digest": p.Enforcement.HostDefaultDenyConfigurationDigest, "intent": p.Enforcement.Intent, "approval_proof": p.Enforcement.ApprovalProof, "ssh_checks": []map[string]any{{"target_ip": "10.30.0.10", "source_ip": "10.20.0.1", "port": 2022, "ssh_banner_verified": true}}}
	raw, _ := json.Marshal(body)
	var witness managedWitness
	json.Unmarshal(raw, &witness)
	if err := a.validateManagedWitness(witness, p, protection, "fresh-nonce", now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*managedWitness){func(w *managedWitness) { w.HostDefaultDenyAck = false }, func(w *managedWitness) { w.HostDefaultDenyRevision++ }, func(w *managedWitness) { w.HostDefaultDenyConfigurationDigest = strings.Repeat("0", 64) }, func(w *managedWitness) { w.Intent = "enforce_managed_rules" }, func(w *managedWitness) { w.ApprovalProof = nil }, func(w *managedWitness) { w.Nonce = "replayed" }} {
		copy := witness
		mutate(&copy)
		if err := a.validateManagedWitness(copy, p, protection, "fresh-nonce", now); err == nil {
			t.Fatal("fresh host authority binding was dropped")
		}
	}
}

func TestHostDefaultDenySignedAssignmentBindsFlagAndAcknowledgement(t *testing.T) {
	a, _, _, protection := hostDenyTestAgent(t)
	p := hostDenyPolicy(a, protection, 1, true, "10.30.0.1/32")
	config, signed := signPolicyForTest(t, p, time.Now())
	if err := ValidatePolicySignature(config, signed); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"flag", "ack", "revision", "config", "profile"} {
		raw, _ := json.Marshal(signed)
		var candidate Policy
		json.Unmarshal(raw, &candidate)
		switch change {
		case "flag":
			candidate.HostDefaultDeny = false
		case "ack":
			candidate.Enforcement.HostDefaultDenyAck = false
		case "revision":
			candidate.Enforcement.HostDefaultDenyRevision++
		case "config":
			candidate.Enforcement.HostDefaultDenyConfigurationDigest = strings.Repeat("0", 64)
		case "profile":
			candidate.Enforcement.ProtectionDigest = strings.Repeat("0", 64)
		}
		if err := ValidatePolicySignature(config, &candidate); err == nil {
			t.Fatalf("signed %s mutation accepted", change)
		}
	}
}
