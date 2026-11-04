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
	for _, dir := range []string{"/proc/self/ns", "/proc/1/ns", "/proc/sys/net/ipv4", "/proc/sys/net/ipv6/conf/all", "/proc/net"} {
		if err := os.MkdirAll(root+dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		if err := os.Symlink("net:[fixture-host]", root+name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(root+name, []byte("0\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
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
	if err := os.Symlink("net:[foreign]", root+"/proc/2/ns/net"); err != nil {
		t.Fatal(err)
	}
	if _, err := activationInactiveContext(context.Background(), activationContextRunner{}, root, false, nil); err == nil {
		t.Fatal("foreign namespace ignored")
	}
}
