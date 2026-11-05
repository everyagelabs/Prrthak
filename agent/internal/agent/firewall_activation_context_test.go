package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirewallActivationUFWConversionExactOrderFamiliesAndUnsupportedContexts(t *testing.T) {
	raw := "*filter\n:ufw-user-input - [0:0]\n-A ufw-user-input -p tcp -s 10.20.0.0/24 --dport 8443 -j ACCEPT\n-A ufw-user-input -p udp --dport 53 -j DROP\nCOMMIT\n"
	rules, err := activationUFWRules(raw, "ipv4")
	if err != nil || len(rules) != 2 || rules[0].Priority >= rules[1].Priority || rules[1].Source != "0.0.0.0/0" {
		t.Fatal(rules, err)
	}
	v6, err := activationUFWRules("*filter\n:ufw6-user-input - [0:0]\n-A ufw6-user-input -p tcp -s 2001:db8::/64 --dport 443 -j REJECT\nCOMMIT\n", "ipv6")
	if err != nil || len(v6) != 1 || v6[0].Family != "ipv6" {
		t.Fatal(v6, err)
	}
	for _, line := range []string{"-A ufw-user-input -p tcp --dport 80:90 -j ACCEPT", "-A ufw-user-input -p tcp --dport 80 -i eth0 -j ACCEPT", "-A ufw-user-forward -p tcp --dport 80 -j ACCEPT", "-A ufw-user-input -p tcp -m limit --dport 80 -j ACCEPT", "-A ufw-user-input -p tcp -d 10.0.0.1 --dport 80 -j ACCEPT", "-A ufw-user-input -p tcp --dport 80 -j LOG"} {
		if _, err := activationUFWRules(line, "ipv4"); err == nil {
			t.Fatal("unmapped rule admitted", line)
		}
	}
	if activationUFWEmptyHooks("*filter\n:ufw-before-input - [0:0]\n-A ufw-before-input -p icmp -j ACCEPT\nCOMMIT\n") == nil {
		t.Fatal("active stock hook silently dropped")
	}
	if err := activationUFWEmptyHooks("*filter\n:ufw6-before-input - [0:0]\nCOMMIT\n"); err != nil {
		t.Fatal("empty numeric-family hook rejected", err)
	}
	defaults := "IPV6=yes\nDEFAULT_INPUT_POLICY=DROP\nDEFAULT_OUTPUT_POLICY=ACCEPT\nDEFAULT_FORWARD_POLICY=DROP\nMANAGE_BUILTINS=no\nIPT_MODULES=\"\"\n"
	if v6, err := activationUFWDefaults(defaults); err != nil || !v6 {
		t.Fatal(v6, err)
	}
	if _, err := activationUFWDefaults(strings.Replace(defaults, "DEFAULT_FORWARD_POLICY=DROP", "DEFAULT_FORWARD_POLICY=ACCEPT", 1)); err == nil {
		t.Fatal("router defaults admitted")
	}
}
func activationKernelFixture() map[string]any {
	objects := []any{map[string]any{"table": map[string]any{"family": "ip", "name": "filter"}}}
	for _, name := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		policy := "drop"
		if name == "OUTPUT" {
			policy = "accept"
		}
		objects = append(objects, map[string]any{"chain": map[string]any{"family": "ip", "table": "filter", "name": name, "type": "filter", "hook": strings.ToLower(name), "prio": 0, "policy": policy}})
	}
	objects = append(objects, map[string]any{"chain": map[string]any{"family": "ip", "table": "filter", "name": "ufw-user-input"}}, map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "INPUT", "expr": []any{map[string]any{"counter": map[string]any{"packets": 123, "bytes": 456}}, map[string]any{"jump": map[string]any{"target": "ufw-user-input"}}}}}, map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "ufw-user-input", "expr": []any{map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": "tcp"}}, map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "saddr"}}, "right": map[string]any{"prefix": map[string]any{"addr": "10.20.0.0", "len": 24}}}}, map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}, "right": 8443}}, map[string]any{"accept": nil}}}})
	return map[string]any{"nftables": objects}
}
func TestFirewallActivationKernelRequiresExclusiveExactUFWOrNoForeignAuthority(t *testing.T) {
	doc := activationKernelFixture()
	raw, _ := json.Marshal(doc)
	rules := []FirewallActivationRule{{"ipv4", "10.20.0.0/24", 8443, "tcp", "accept", -29000}}
	digest, err := activationInactiveKernel(string(raw), true, rules)
	if err != nil || !validDigest(digest) {
		t.Fatal(digest, err)
	}
	if _, err := activationInactiveKernel(string(raw), false, nil); err == nil {
		t.Fatal("foreign active firewall was ignored")
	}
	changed := append([]FirewallActivationRule{}, rules...)
	changed[0].Port = 443
	if _, err := activationInactiveKernel(string(raw), true, changed); err == nil {
		t.Fatal("kernel/persisted UFW mismatch was ignored")
	}
	doc["nftables"] = append(doc["nftables"].([]any), map[string]any{"table": map[string]any{"family": "ip", "name": "nat"}})
	raw, _ = json.Marshal(doc)
	if _, err := activationInactiveKernel(string(raw), true, rules); err == nil {
		t.Fatal("NAT admitted")
	}
	if _, err := activationInactiveKernel(`{"nftables":[]}`, false, nil); err != nil {
		t.Fatal("empty host blocked", err)
	}
	if _, err := activationInactiveKernel(`{"nftables":[]}`, true, nil); err == nil {
		t.Fatal("missing active UFW kernels admitted")
	}
}
func TestFirewallActivationFilesPreserveModeAndRefuseForeignAndSymlinkedBytes(t *testing.T) {
	a, f, baseline, _ := activationFixture(t, "enable_native_counters")
	name := "/etc/firewalld/firewalld.conf"
	before, _ := os.ReadFile(f.root + name)
	after, err := activationCounterConfig(before)
	if err != nil {
		t.Fatal(err)
	}
	change := firewallActivationFile{Before: before, After: after, Mode: 0640}
	if err := writeActivationFile(f.root, name, change, true); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(f.root + name)
	if info.Mode().Perm() != 0640 {
		t.Fatal("mode changed")
	}
	if err := writeActivationFile(f.root, name, change, false); err != nil {
		t.Fatal(err)
	}
	if err := activationFilesMatch(f.root, baseline.Files, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.root+name, []byte("unrelated=value\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if writeActivationFile(f.root, name, change, false) == nil {
		t.Fatal("foreign bytes overwritten")
	}
	if err := os.Remove(f.root + name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(a.Config.StateDir, "private"), f.root+name); err != nil {
		t.Fatal(err)
	}
	if _, err := activationConfigFiles(f.root); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, bad := range []string{"FirewallBackend=nftables\n", "NftablesCounters=no\nNftablesCounters=yes\n", "NftablesCounters=maybe\n"} {
		if _, err := activationCounterConfig([]byte(bad)); err == nil {
			t.Fatal("ambiguous counter option accepted", bad)
		}
	}
}
func TestFirewallActivationPreparedJournalCannotBecomeGenericOrEditAnotherFile(t *testing.T) {
	a, _, baseline, p := activationFixture(t, "migrate_ufw")
	request := activationPolicy(t, a, "migrate_ufw", baseline, p).FirewallActivation
	j := &managedJournal{Nonce: strings.Repeat("a", 32), Phase: "prepared", PID: os.Getpid(), FirewallActivation: &firewallActivationJournal{Assignment: *request, Baseline: baseline, ChangedFiles: map[string]firewallActivationFile{}, Report: activationReceipt(request)}}
	if err := a.prepareActivationFiles(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if err := validateFirewallActivationJournal(j); err != nil {
		t.Fatal(err)
	}
	j.Next.Generation = "foreign"
	if validateFirewallActivationJournal(j) == nil {
		t.Fatal("mixed generic journal admitted")
	}
	j.Next.Generation = ""
	j.FirewallActivation.ChangedFiles["/etc/ssh/sshd_config"] = firewallActivationFile{After: []byte("unsafe"), Mode: 0600}
	if validateFirewallActivationJournal(j) == nil {
		t.Fatal("unrelated rollback target admitted")
	}
}

type activationContextRunner struct {
	forward bool
	bridge  bool
}

func (f activationContextRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "ip" {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "link show") {
			if f.bridge {
				return `[{"ifname":"br0","link_type":"ether","linkinfo":{"info_kind":"bridge"}}]`, nil
			}
			return `[{"ifname":"eth0","link_type":"ether","flags":["UP"]}]`, nil
		}
		return `[]`, nil
	}
	if name == "sysctl" {
		values := []string{}
		for range args[1:] {
			values = append(values, "0")
		}
		if f.forward {
			values[len(values)-1] = "1"
		}
		return strings.Join(values, "\n"), nil
	}
	if name == "nft" {
		return `{"nftables":[]}`, nil
	}
	return "", errors.New("unexpected read-only native command")
}
func TestFirewallActivationNativeHostPreflightRejectsForwardingBridgeNamespaceAndLegacyHooks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeActivationNetworkFixture(t, root)
	if digest, err := activationInactiveContext(context.Background(), activationContextRunner{}, root, false, nil); err != nil || !validDigest(digest) {
		t.Fatal("ordinary empty host context rejected", digest, err)
	}
	for _, runner := range []activationContextRunner{{forward: true}, {bridge: true}} {
		if _, err := activationInactiveContext(context.Background(), runner, root, false, nil); err == nil {
			t.Fatal("unsafe host context accepted", runner)
		}
	}
	if err := os.WriteFile(root+"/proc/net/ip_tables_names", []byte("filter\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := activationInactiveContext(context.Background(), activationContextRunner{}, root, false, nil); err == nil {
		t.Fatal("legacy firewall ignored")
	}
	_ = os.Remove(root + "/proc/net/ip_tables_names")
	if err := os.MkdirAll(root+"/proc/2/ns", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[456]", root+"/proc/2/ns/net"); err != nil {
		t.Fatal(err)
	}
	if _, err := activationInactiveContext(context.Background(), activationContextRunner{}, root, false, nil); err == nil {
		t.Fatal("foreign namespace ignored")
	}
}

func writeActivationNetworkFixture(t *testing.T, root string) {
	t.Helper()
	for _, dir := range []string{"/proc/self/ns", "/proc/1/ns", "/proc/sys/net/ipv4", "/proc/sys/net/ipv6/conf/all", "/proc/net"} {
		if err := os.MkdirAll(root+dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		if err := os.Symlink("net:[123]", root+name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(root+name, []byte("0\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

type activationTailscaleRoutingRunner struct {
	CommandRunner
	rules4, rules6, routes4, routes6, links string
}

func (r activationTailscaleRoutingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	switch name + " " + strings.Join(args, " ") {
	case "ip -4 -j rule show":
		return r.rules4, nil
	case "ip -6 -j rule show":
		return r.rules6, nil
	case "ip -4 -j route show table all":
		return r.routes4, nil
	case "ip -6 -j route show table all":
		return r.routes6, nil
	case "ip -j -d link show", "ip -j link show":
		return r.links, nil
	}
	return r.CommandRunner.Run(ctx, name, args...)
}

func activationTailscaleRoutingFixture(runner CommandRunner) activationTailscaleRoutingRunner {
	const rules = `[{"priority":0,"src":"all","table":"local"},{"priority":5210,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","table":"main"},{"priority":5230,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","table":"default"},{"priority":5250,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","action":"unreachable"},{"priority":5270,"src":"all","table":"52"},{"priority":32766,"src":"all","table":"main"}`
	return activationTailscaleRoutingRunner{
		CommandRunner: runner,
		rules4:        rules + `,{"priority":32767,"src":"all","table":"default"}]`, rules6: rules + "]",
		routes4: `[{"dst":"100.66.222.20","dev":"tailscale0","table":"52","scope":"link","flags":[]},{"type":"local","dst":"100.66.222.30","dev":"tailscale0","table":"local","protocol":"kernel","scope":"host","prefsrc":"100.66.222.30","flags":[]}]`,
		routes6: `[{"dst":"fd7a:115c:a1e0::20","dev":"tailscale0","table":"52","metric":1024,"flags":[],"pref":"medium"},{"dst":"fd7a:115c:a1e0::30","dev":"tailscale0","protocol":"kernel","metric":256,"flags":[],"pref":"medium"},{"type":"multicast","dst":"ff00::/8","dev":"tailscale0","table":"local","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}]`,
		links:   `[{"ifname":"eth0","link_type":"ether","flags":["UP"]},{"ifname":"tailscale0","link_type":"none","flags":["UP"],"linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}}}]`,
	}
}

func TestFirewallActivationAcceptsKernelTailscaleIPv6LinkLocalHostRoute(t *testing.T) {
	const linkLocal = `{"type":"local","dst":"fe80::1234:5678","dev":"tailscale0","table":"local","protocol":"kernel","metric":0,"flags":[],"pref":"medium"}`
	ctx := context.Background()
	runner := activationTailscaleRoutingFixture(activationContextRunner{})
	runner.routes6 = strings.TrimSuffix(runner.routes6, "]") + "," + linkLocal + "]"
	if _, err := readNativeNetworkTopology(ctx, runner, true); err != nil {
		t.Fatal("the kernel's Tailscale link-local host route was rejected", err)
	}
	for _, tc := range []struct {
		name, from, to string
	}{
		{"foreign address", `"fe80::1234:5678"`, `"2001:db8::1234"`},
		{"subnet route", `"fe80::1234:5678"`, `"fe80::/96"`},
		{"zoned address", `"fe80::1234:5678"`, `"fe80::1234:5678%tailscale0"`},
		{"policy table", `"table":"local"`, `"table":"52"`},
		{"wrong route type", `"type":"local"`, `"type":"unicast"`},
		{"wrong protocol", `"protocol":"kernel"`, `"protocol":"static"`},
		{"unknown flag", `"flags":[]`, `"flags":["onlink"]`},
		{"gateway", `"metric":0`, `"metric":0,"gateway":"fe80::1"`},
		{"nexthop object", `"metric":0`, `"metric":0,"nhid":15`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := runner
			changed.routes6 = strings.Replace(runner.routes6, linkLocal, strings.Replace(linkLocal, tc.from, tc.to, 1), 1)
			if _, err := readNativeNetworkTopology(ctx, changed, true); err == nil {
				t.Fatal("unrecognized Tailscale link-local host route admitted")
			}
		})
	}
}

func TestFirewallActivationRequiresExactTailscaleRoutingAndTunnel(t *testing.T) {
	ctx := context.Background()
	runner := activationTailscaleRoutingFixture(activationContextRunner{})
	if _, err := readNativeNetworkTopology(ctx, runner, true); err != nil {
		t.Fatal("reviewed Tailscale host routes rejected", err)
	}
	if _, err := nativeNetworkTopology(ctx, runner); err == nil {
		t.Fatal("activation adapter must not authorize egress or quarantine")
	}
	for name, mutate := range map[string]func(*activationTailscaleRoutingRunner){
		"wrong mask": func(r *activationTailscaleRoutingRunner) {
			r.rules4 = strings.Replace(r.rules4, "0xff0000", "0xffffffff", 1)
		},
		"unexpected selector": func(r *activationTailscaleRoutingRunner) {
			r.rules4 = strings.Replace(r.rules4, `"priority":5270`, `"priority":5270,"iif":"eth0"`, 1)
		},
		"changed action": func(r *activationTailscaleRoutingRunner) {
			r.rules4 = strings.Replace(r.rules4, "unreachable", "blackhole", 1)
		},
		"missing rule": func(r *activationTailscaleRoutingRunner) {
			r.rules4 = strings.Replace(r.rules4, `{"priority":5270,"src":"all","table":"52"},`, "", 1)
		},
		"missing family":    func(r *activationTailscaleRoutingRunner) { r.rules6, r.routes6 = "[]", "[]" },
		"wrong tunnel name": func(r *activationTailscaleRoutingRunner) { r.links = strings.Replace(r.links, "tailscale0", "tun0", 1) },
		"wrong tunnel type": func(r *activationTailscaleRoutingRunner) {
			r.links = strings.Replace(r.links, `"type":"tun"`, `"type":"tap"`, 1)
		},
		"wrong tunnel interface": func(r *activationTailscaleRoutingRunner) {
			r.routes4 = strings.Replace(r.routes4, "tailscale0", "eth0", 1)
		},
		"subnet route": func(r *activationTailscaleRoutingRunner) {
			r.routes4 = strings.Replace(r.routes4, "100.66.222.20", "10.0.0.0/24", 1)
		},
		"exit-node route": func(r *activationTailscaleRoutingRunner) {
			r.routes4 = strings.Replace(r.routes4, "100.66.222.20", "default", 1)
		},
		"unknown table": func(r *activationTailscaleRoutingRunner) {
			r.routes4 = strings.Replace(r.routes4, `"table":"52"`, `"table":"53"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := runner
			mutate(&changed)
			if _, err := readNativeNetworkTopology(ctx, changed, true); err == nil {
				t.Fatal("ambiguous activation route or tunnel admitted")
			}
		})
	}
}

func TestFirewallActivationKeepsForeignKernelContextAcrossStartAndStop(t *testing.T) {
	ctx := context.Background()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeActivationNetworkFixture(t, root)
	if err := os.MkdirAll(root+"/etc/firewalld", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/etc/firewalld/firewalld.conf", []byte("FirewallBackend=nftables\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, legacyJSON := range []bool{false, true} {
		active := tailscaleConnmarkFixture(t, legacyJSON, false)
		inactive, err := activationForeignNftObjects(active)
		if err != nil {
			t.Fatal(err)
		}
		kernel := connmarkKernelCommands{
			CommandRunner: activationContextRunner{},
			raw:           inactive, version: "(nf_tables)",
			mangle:     "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n" + tailscaleConnmarkRestore + "\n" + tailscaleConnmarkSave,
			udp:        "-N ts-input\n-A ts-input -i tailscale0 -j ACCEPT\n-A ts-input -p udp -m udp --dport 41641 -j ACCEPT\n",
			masquerade: tailscaleMasqueradeReadback,
		}
		runner := activationTailscaleRoutingFixture(kernel)
		before, err := activationInactiveContext(ctx, runner, root, false, nil)
		if err != nil || !validDigest(before) {
			t.Fatal("Tailscale inactive baseline rejected", before, err)
		}
		kernel.raw = active
		runner.CommandRunner = kernel
		started, err := activationFirewallContext(ctx, runner, root, true, false, nil)
		if err != nil || started != before {
			t.Fatal("starting firewalld changed the verified foreign baseline", before, started, err)
		}
		kernel.raw = strings.TrimSuffix(inactive, "]}") + `,{"table":{"family":"inet","name":"foreign"}}]}`
		runner.CommandRunner = kernel
		if _, err := activationInactiveContext(ctx, runner, root, false, nil); err == nil {
			t.Fatal("foreign nftables hook/table admitted")
		}
	}
}

type activationTailscaleServiceRunner struct {
	*activationFake
	topology                   activationTailscaleRoutingRunner
	activeRules, inactiveRules string
}

func (r *activationTailscaleServiceRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	switch name {
	case "nft":
		if r.active {
			return r.activeRules, nil
		}
		return r.inactiveRules, nil
	case "ip", "sysctl":
		return r.topology.Run(ctx, name, args...)
	default:
		return r.activationFake.Run(ctx, name, args...)
	}
}

func TestFirewallActivationRestoresServiceWhenForeignKernelContextDrifts(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{"activate_existing", "deactivate_existing"} {
		t.Run(operation, func(t *testing.T) {
			a, service, baseline, protection := activationFixture(t, operation)
			writeActivationNetworkFixture(t, service.root)
			active := tailscaleKernelFixture()
			inactive, err := activationForeignNftObjects(active)
			if err != nil {
				t.Fatal(err)
			}
			runner := &activationTailscaleServiceRunner{
				activationFake: service, topology: activationTailscaleRoutingFixture(activationContextRunner{}),
				activeRules: active, inactiveRules: inactive,
			}
			a.Commands = runner
			wasActive := service.active
			baseline.NativeTopology, err = activationHostContext(ctx, runner, service.root)
			if err != nil {
				t.Fatal(err)
			}
			baseline.NativeContext, err = activationFirewallContext(ctx, runner, service.root, wasActive, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			baseline.Digest = activationDigest(baseline)
			a.firewallActivation.Baseline = func() (firewallActivationBaseline, Protection, error) {
				return baseline, protection, nil
			}
			if wasActive {
				runner.inactiveRules = strings.ReplaceAll(inactive, "41641", "51641")
			} else {
				runner.activeRules = strings.ReplaceAll(active, "41641", "51641")
			}
			_, err = a.processFirewallActivation(ctx, activationPolicy(t, a, operation, baseline, protection))
			receipt := ReadFirewallActivationStatus(a.Config.StateDir)
			if err == nil || !strings.Contains(err.Error(), "foreign kernel firewall context changed") || receipt == nil ||
				receipt.Status != "rolled_back" || service.active != wasActive || service.enabled != wasActive {
				t.Fatal("foreign context change did not restore the original service", err, receipt)
			}
			if got, err := activationFirewallContext(ctx, runner, service.root, wasActive, false, nil); err != nil || got != baseline.NativeContext {
				t.Fatal("original foreign kernel state did not verify after rollback", got, err)
			}
		})
	}
}
