package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

type gatewayPolicyFixture struct {
	Name      string `json:"name"`
	Runtime   string `json:"runtime"`
	Permanent string `json:"permanent"`
}

type gatewayCaptureRunner struct {
	CommandRunner
	t                     *testing.T
	names                 map[string][]string
	definitions           map[string]string
	definitionReads       map[string]int
	namesReads            map[string]int
	activeReads           int
	nftReads              int
	changeDefinition      string
	changeControl         string
	changeValidControl    string
	changeInventory       bool
	changeActive          bool
	changeKernel          bool
	activateDuringKernel  bool
	inventoryDuringKernel bool
	active                string
}

func (r *gatewayCaptureRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "nft" && strings.Join(args, " ") == "-j list ruleset" {
		r.nftReads++
		raw, err := r.CommandRunner.Run(ctx, name, args...)
		if r.activateDuringKernel && r.nftReads > 1 {
			r.active += "\ngateway-lan-to-world\n  ingress-zones: internal\n  egress-zones: public\n"
		}
		if r.inventoryDuringKernel && r.nftReads > 1 {
			r.names["permanent"] = append(r.names["permanent"], "custom-late-policy")
		}
		if r.changeKernel && r.nftReads > 1 {
			changed := strings.Replace(raw, `"hook":"input","prio":10`, `"hook":"input","prio":9`, 1)
			if changed == raw {
				r.t.Fatal("kernel mutation did not change fixture")
			}
			return changed, err
		}
		return raw, err
	}
	if name != "firewall-cmd" {
		return r.CommandRunner.Run(ctx, name, args...)
	}
	scope, policy := "runtime", ""
	for _, arg := range args {
		if arg == "--permanent" {
			scope = "permanent"
		}
		if strings.HasPrefix(arg, "--policy=") {
			policy = strings.TrimPrefix(arg, "--policy=")
		}
		if strings.HasPrefix(arg, "--add-") || strings.HasPrefix(arg, "--remove-") || arg == "--reload" {
			r.t.Fatal("read-only NFLOG planner attempted mutation", args)
		}
	}
	for _, arg := range args {
		switch arg {
		case "--get-policies":
			r.namesReads[scope]++
			value := strings.Join(r.names[scope], " ")
			if r.changeInventory && r.namesReads[scope] >= 3 {
				value += " custom-new-policy"
			}
			return value, nil
		case "--get-active-policies":
			r.activeReads++
			value := r.active
			if r.changeActive && r.activeReads >= 3 {
				value += "\ngateway-lan-to-world\n  ingress-zones: internal\n  egress-zones: public\n"
			}
			return value, nil
		case "--list-all":
			if policy != "" {
				key := scope + "/" + policy
				r.definitionReads[key]++
				value, present := r.definitions[key]
				if !present {
					return "", fmt.Errorf("missing policy fixture %s", key)
				}
				if r.changeDefinition == key && r.definitionReads[key] >= 2 {
					value = strings.Replace(value, "disable: yes", "disable: no", 1)
				}
				if r.changeControl == key && r.definitionReads[key] >= 2 {
					value += "    rule family=ipv4 port port=19180 protocol=tcp accept\n"
				}
				if r.changeValidControl == key && r.definitionReads[key] >= 2 {
					// Both stock ICMPv6 layouts are recognized, but changing
					// between them during one proof is still content drift.
					kept := []string{}
					for _, line := range strings.Split(value, "\n") {
						if !strings.Contains(line, "mld") {
							kept = append(kept, line)
						}
					}
					value = strings.Join(kept, "\n")
					if !safeHostIPv6Policy(value) {
						r.t.Fatal("changed control-layout fixture must remain independently recognized")
					}
				}
				return value, nil
			}
		}
	}
	return r.CommandRunner.Run(ctx, name, args...)
}

func gatewayCaptureFixture(t *testing.T) (*Agent, *managedFake, *gatewayCaptureRunner, []capturePortScope, time.Time) {
	t.Helper()
	// Policy fixtures are derived from exact upstream v2.4.3 XML/rendering,
	// not claimed as saved RHEL policy readback or native NFLOG wire evidence.
	raw, err := os.ReadFile("testdata/firewalld-2.4.3-upstream-disabled-gateways.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Policies []gatewayPolicyFixture `json:"policies"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	a, fake, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "198.51.100.0/24")
	p.Services = []Service{{Port: 19180, Protocol: "tcp", Mode: "enforce", Sources: []string{"198.51.100.0/24"}}, {Port: 19181, Protocol: "udp", Mode: "enforce", Sources: []string{"198.51.100.0/24"}}}
	p.Digest, _ = compiledPolicyDigest(p)
	p.Enforcement.ApprovedDigest, p.Enforcement.BindingDigest = p.Digest, enforcementBinding(p, protection.Digest)
	if err := a.applyManaged(context.Background(), p, protection); err != nil {
		t.Fatal(err)
	}
	kernel, err := os.ReadFile("testdata/rhel10-firewalld-2.4-tailscale-native.json")
	if err != nil {
		t.Fatal(err)
	}
	runner := &gatewayCaptureRunner{CommandRunner: &hostDenyFake{CommandRunner: fake, nft: string(kernel)}, t: t, names: map[string][]string{}, definitions: map[string]string{}, definitionReads: map[string]int{}, namesReads: map[string]int{}, active: "allow-host-ipv6\n  ingress-zones: ANY\n  egress-zones: HOST\n"}
	for _, scope := range []string{"runtime", "permanent"} {
		runner.names[scope] = []string{"allow-host-ipv6"}
		runner.definitions[scope+"/allow-host-ipv6"] = strings.Replace(defaultHostIPv6PolicyWithMLD, "  priority:", "  disable: no\n  priority:", 1)
		for _, policy := range fixture.Policies {
			runner.names[scope] = append(runner.names[scope], policy.Name)
			if scope == "runtime" {
				runner.definitions[scope+"/"+policy.Name] = policy.Runtime
			} else {
				runner.definitions[scope+"/"+policy.Name] = policy.Permanent
			}
		}
		sort.Strings(runner.names[scope])
	}
	a.Commands = runner
	now := time.Now().UTC()
	scopes := []capturePortScope{}
	for _, port := range []Port{{19180, "tcp"}, {19181, "udp"}} {
		scopes = append(scopes, capturePortScope{Port: port, Kind: captureDenied, StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)})
	}
	return a, fake, runner, scopes, now
}

func TestCaptureDisabledUpstreamGatewaysPreserveStrictDualTransportPlan(t *testing.T) {
	a, fake, runner, scopes, now := gatewayCaptureFixture(t)
	mutations := fake.mutations
	rules, gaps, err := a.plannedCaptureSidecars(context.Background(), scopes, now)
	if err != nil || len(rules) < 2 || len(gaps) == 0 || fake.mutations != mutations {
		t.Fatal("disabled stock inventory blocked read-only exact deny planning", rules, gaps, err)
	}
	families := 2
	if raw, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil && strings.TrimSpace(string(raw)) == "1" {
		families = 1
	}
	if len(rules) != families*2 {
		t.Fatal("TCP/UDP family coverage was not explicit", rules)
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Priority != managedCaptureReject || !validCaptureSidecar(rule) {
			t.Fatal("sidecar lost exact owned terminal-verdict priority", rule)
		}
		seen[rule.Family+"/"+rule.Port.Protocol] = true
	}
	if !seen["ipv4/tcp"] || !seen["ipv4/udp"] || families == 2 && (!seen["ipv6/tcp"] || !seen["ipv6/udp"]) {
		t.Fatal("required protocol/family plan missing", seen)
	}
	if runner.activeReads != 3 || runner.nftReads != 2 || runner.namesReads["runtime"] != 3 || runner.namesReads["permanent"] != 3 {
		t.Fatal("ordering proof did not perform bounded stable readbacks", runner)
	}
	if len(runner.definitionReads) != 12 {
		t.Fatal("complete six-object inventory in both scopes was not read", runner.definitionReads)
	}
	for key, count := range runner.definitionReads {
		if count != 2 {
			t.Fatal("every accepted policy definition must be revalidated", key, count)
		}
	}
}

func TestCaptureSavedRHEL10GatewayMetadataMatchesExactUpstreamDefinitions(t *testing.T) {
	raw, err := os.ReadFile("testdata/rhel10-firewalld-2.4.3-disabled-gateway-readback.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Commands []struct {
			Argv   []string `json:"argv"`
			Scope  string   `json:"scope"`
			Policy string   `json:"policy"`
			Exit   int      `json:"exit"`
			Stdout string   `json:"stdout"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	a, fake, runner, scopes, now := gatewayCaptureFixture(t)
	classified := 0
	if len(fixture.Commands) != 16 {
		t.Fatal("saved version, inventories, activity and both-scope metadata are incomplete", len(fixture.Commands))
	}
	for _, command := range fixture.Commands {
		if command.Exit != 0 {
			t.Fatal("saved metadata command did not succeed", command.Argv)
		}
		if len(command.Argv) == 2 && command.Argv[1] == "--get-active-policies" {
			runner.active = command.Stdout
		}
		if len(command.Argv) == 2 && command.Argv[1] == "--version" && strings.TrimSpace(command.Stdout) != "2.4.3" {
			t.Fatal("saved policy metadata is from a different firewalld version")
		}
		if command.Scope != "" && len(command.Argv) > 0 && command.Argv[len(command.Argv)-1] == "--get-policies" {
			runner.names[command.Scope] = strings.Fields(command.Stdout)
		}
		if command.Policy != "" {
			runner.definitions[command.Scope+"/"+command.Policy] = command.Stdout
			if command.Policy != "allow-host-ipv6" {
				if !captureStockGatewayDefinition(command.Policy, command.Stdout, command.Scope) {
					t.Fatal("actual disabled template differs from pinned upstream semantic classifier", command.Scope, command.Policy)
				}
				classified++
			}
		}
	}
	if classified != 10 {
		t.Fatal("both scopes of all five gateway templates were not represented", classified)
	}
	mutations := fake.mutations
	if rows, _, err := a.plannedCaptureSidecars(context.Background(), scopes, now); err != nil || len(rows) < 2 || fake.mutations != mutations {
		t.Fatal("actual metadata blocked the strict read-only planner fixture", rows, err)
	}
}

func TestCaptureGatewayProofRejectsModifiedOrAmbiguousPolicies(t *testing.T) {
	for name, change := range map[string]func(*gatewayCaptureRunner){
		"runtime enabled": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "disable: yes", "disable: no", 1)
		},
		"permanent enabled": func(r *gatewayCaptureRunner) {
			key := "permanent/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "disable: yes", "disable: no", 1)
		},
		"active runtime header": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "(disabled)", "(active, disabled)", 1)
		},
		"missing disabled header": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], " (disabled)", "", 1)
		},
		"modified target": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "target: ACCEPT", "target: CONTINUE", 1)
		},
		"modified priority": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "priority: 1000", "priority: -1000", 1)
		},
		"widened ingress": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "ingress-zones: internal home trusted", "ingress-zones: ANY", 1)
		},
		"duplicate zones": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "egress-zones: external public", "egress-zones: external public public", 1)
		},
		"additional port": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "  ports:", "  ports: 8443/tcp", 1)
		},
		"extra service": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "services: ftp tftp", "services: ftp tftp http", 1)
		},
		"NAT enabled": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "masquerade: no", "masquerade: yes", 1)
		},
		"unknown field": func(r *gatewayCaptureRunner) {
			r.definitions["runtime/gateway-lan-to-world"] += "  custom-field: yes\n"
		},
		"duplicate disable": func(r *gatewayCaptureRunner) { r.definitions["runtime/gateway-lan-to-world"] += "  disable: yes\n" },
		"missing field": func(r *gatewayCaptureRunner) {
			key := "runtime/gateway-lan-to-world"
			r.definitions[key] = strings.Replace(r.definitions[key], "  protocols:\n", "", 1)
		},
		"active gateway": func(r *gatewayCaptureRunner) {
			r.active += "gateway-lan-to-world\n  ingress-zones: internal\n  egress-zones: public\n"
		},
		"ambiguous active bindings":  func(r *gatewayCaptureRunner) { r.active += "  ingress-zones: ANY\n" },
		"unknown active binding":     func(r *gatewayCaptureRunner) { r.active += "  other-state: no\n" },
		"incomplete active bindings": func(r *gatewayCaptureRunner) { r.active = "allow-host-ipv6\n  ingress-zones: ANY\n" },
		"unknown active policy": func(r *gatewayCaptureRunner) {
			r.active += "custom-active\n  ingress-zones: ANY\n  egress-zones: HOST\n"
		},
		"changed active zones": func(r *gatewayCaptureRunner) {
			r.active = strings.Replace(r.active, "ingress-zones: ANY", "ingress-zones: internal", 1)
		},
		"custom permanent-only policy": func(r *gatewayCaptureRunner) {
			r.names["permanent"] = append(r.names["permanent"], "custom-policy")
			r.definitions["permanent/custom-policy"] = r.definitions["permanent/gateway-lan-to-world"]
		},
		"custom runtime policy": func(r *gatewayCaptureRunner) {
			for _, scope := range []string{"runtime", "permanent"} {
				r.names[scope] = append(r.names[scope], "custom-gateway")
				r.definitions[scope+"/custom-gateway"] = strings.Replace(r.definitions[scope+"/gateway-lan-to-world"], "gateway-lan-to-world", "custom-gateway", 1)
			}
		},
		"extra IPv6 control graph": func(r *gatewayCaptureRunner) {
			for _, scope := range []string{"runtime", "permanent"} {
				r.names[scope] = append(r.names[scope], "second-ipv6-control")
				r.definitions[scope+"/second-ipv6-control"] = strings.Replace(r.definitions[scope+"/allow-host-ipv6"], "allow-host-ipv6", "second-ipv6-control", 1)
			}
		},
		"inventory changes":             func(r *gatewayCaptureRunner) { r.changeInventory = true },
		"runtime changes":               func(r *gatewayCaptureRunner) { r.changeDefinition = "runtime/gateway-lan-to-world" },
		"permanent changes":             func(r *gatewayCaptureRunner) { r.changeDefinition = "permanent/gateway-lan-to-world" },
		"runtime control changes":       func(r *gatewayCaptureRunner) { r.changeControl = "runtime/allow-host-ipv6" },
		"permanent control changes":     func(r *gatewayCaptureRunner) { r.changeControl = "permanent/allow-host-ipv6" },
		"valid control layout changes":  func(r *gatewayCaptureRunner) { r.changeValidControl = "runtime/allow-host-ipv6" },
		"active context changes":        func(r *gatewayCaptureRunner) { r.changeActive = true },
		"live hook changes":             func(r *gatewayCaptureRunner) { r.changeKernel = true },
		"activation during kernel read": func(r *gatewayCaptureRunner) { r.activateDuringKernel = true },
		"inventory during kernel read":  func(r *gatewayCaptureRunner) { r.inventoryDuringKernel = true },
	} {
		t.Run(name, func(t *testing.T) {
			a, fake, runner, scopes, now := gatewayCaptureFixture(t)
			change(runner)
			mutations := fake.mutations
			if _, _, err := a.plannedCaptureSidecars(context.Background(), scopes, now); err == nil || fake.mutations != mutations {
				t.Fatal("unproved policy context admitted or access changed", err)
			}
		})
	}
}

func TestCaptureGatewayProofStillRequiresExactOwnedTerminalReject(t *testing.T) {
	a, fake, _, scopes, now := gatewayCaptureFixture(t)
	for _, rule := range a.State.ManagedBundle.Rules {
		info, err := parseManagedRich(rule.Rule)
		if err == nil && info.Action == "reject" {
			fake.set("runtime", "rich_rule", rule.Rule, false)
		}
	}
	if _, _, err := a.plannedCaptureSidecars(context.Background(), scopes, now); err == nil || !strings.Contains(err.Error(), "terminal managed reject") {
		t.Fatal("stock disabled policies bypassed actual terminal verdict readback", err)
	}
}
