package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRHEL10SavedNativeTailscaleKernelProof(t *testing.T) {
	// RHEL 10.2/firewalld 2.4.3/Tailscale 1.104.5 native nft readback.
	// Retaining the full ruleset checks firewalld dispatch as well as the
	// independent IPv4/IPv6 native mark and interface representations.
	raw, err := os.ReadFile("testdata/rhel10-firewalld-2.4-tailscale-native.json")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	read := func(string, tailscaleProofRequest) ([]string, bool) {
		called = true
		return nil, false
	}
	if digest, err := nftHostInputKernelProof(string(raw), "public", false, read); err != nil || !validDigest(digest) {
		t.Fatalf("exact observed native context rejected: %q %v", digest, err)
	}
	if called {
		t.Fatal("fully exposed native expressions required unavailable xtables readback")
	}
	for name, pair := range map[string][2]string{
		"changed native mask":          {`{"ct":{"key":"mark"}},16711680`, `{"ct":{"key":"mark"}},16711681`},
		"changed inbound states":       {`"right":["established","related"]`, `"right":["new","related"]`},
		"changed outbound state":       {`"right":"new"`, `"right":"established"`},
		"broader Tailscale interface":  {`"right":"tailscale0*"`, `"right":"tailscale*"`},
		"broader loopback interface":   {`"right":"lo*"`, `"right":"*"`},
		"wrong native output priority": {`"type":"filter","hook":"output","prio":-150`, `"type":"filter","hook":"output","prio":-149`},
	} {
		t.Run(name, func(t *testing.T) {
			changed := strings.ReplaceAll(string(raw), pair[0], pair[1])
			if changed == string(raw) {
				t.Fatal("mutation did not change fixture")
			}
			if _, err := nftHostInputKernelProof(changed, "public", false, read); err == nil {
				t.Fatal("modified native Tailscale context accepted")
			}
		})
	}
	var document struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document.Objects = append(document.Objects, map[string]json.RawMessage{"rule": json.RawMessage(`{"family":"ip","table":"mangle","chain":"PREROUTING","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}`)})
	changed, _ := json.Marshal(document)
	if _, err := nftHostInputKernelProof(string(changed), "public", false, read); err == nil {
		t.Fatal("extra native mark rule accepted")
	}
}

type connmarkKernelCommands struct {
	CommandRunner
	raw, version, mangle, udp, masquerade string
}

func (f connmarkKernelCommands) Run(ctx context.Context, name string, args ...string) (string, error) {
	switch name + " " + strings.Join(args, " ") {
	case "nft -j list ruleset":
		return f.raw, nil
	case "iptables --version", "ip6tables --version":
		return name + " v1.8.5 " + f.version, nil
	case "iptables -t mangle -S", "ip6tables -t mangle -S":
		return f.mangle, nil
	case "iptables -t filter -S ts-input", "ip6tables -t filter -S ts-input":
		return f.udp, nil
	case "iptables -t nat -S ts-postrouting", "ip6tables -t nat -S ts-postrouting":
		return f.masquerade, nil
	default:
		if f.CommandRunner != nil {
			return f.CommandRunner.Run(ctx, name, args...)
		}
		return "", fmt.Errorf("unexpected command: %s %v", name, args)
	}
}

func TestTailscaleConnmarkKernelRequiresStableNftReadback(t *testing.T) {
	ctx := context.Background()
	for _, legacyJSON := range []bool{false, true} {
		raw := tailscaleConnmarkFixture(t, legacyJSON, false)
		f := connmarkKernelCommands{
			raw:        raw,
			version:    "(nf_tables)",
			mangle:     "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n" + tailscaleConnmarkRestore + "\n" + tailscaleConnmarkSave,
			udp:        "-N ts-input\n-A ts-input -i tailscale0 -j ACCEPT\n-A ts-input -p udp -m udp --dport 41641 -j ACCEPT\n",
			masquerade: tailscaleMasqueradeReadback,
		}
		if _, err := hostDefaultDenyKernelContext(raw, "public"); err == nil {
			t.Fatal("opaque CONNMARK rules were accepted without independent readback")
		}
		digest, err := liveHostDefaultDenyKernelContext(ctx, f, raw, "public")
		if err != nil || !validDigest(digest) {
			t.Fatalf("expected verified newer Tailscale layout with legacy JSON %t: %q, %v", legacyJSON, digest, err)
		}
		inactive := tailscaleConnmarkFixture(t, legacyJSON, true)
		inactiveRunner := f
		inactiveRunner.raw = inactive
		if digest, err := inactiveTailscaleKernelProof(ctx, inactiveRunner, inactive); err != nil || !validDigest(digest) {
			t.Fatalf("expected Tailscale-only proof with firewalld inactive: %q, %v", digest, err)
		}
		if _, err := inactiveTailscaleKernelProof(ctx, f, raw); err == nil {
			t.Fatal("inactive proof accepted a firewalld table")
		}
		if _, err := liveHostDefaultDenyKernelContext(ctx, inactiveRunner, inactive, "public"); err == nil {
			t.Fatal("live proof accepted a missing firewalld table")
		}
		for name, edit := range map[string]func(*connmarkKernelCommands){
			"legacy backend": func(r *connmarkKernelCommands) { r.version = "(legacy)" },
			"non-Tailscale mark mask": func(r *connmarkKernelCommands) {
				r.mangle = strings.ReplaceAll(r.mangle, "0xff0000", "0xffff0000")
			},
			"unqualified restore": func(r *connmarkKernelCommands) {
				r.mangle = strings.ReplaceAll(r.mangle, " -m connmark ! --mark 0x0/0xff0000", "")
			},
			"extra mark rule": func(r *connmarkKernelCommands) {
				r.mangle += "\n-A INPUT -j MARK --set-xmark 0x1/0xffffffff"
			},
			"kernel snapshot changed": func(r *connmarkKernelCommands) {
				r.raw = strings.Replace(r.raw, `"name":"OUTPUT","policy":"accept","prio":-150`, `"name":"OUTPUT","policy":"drop","prio":-150`, 1)
			},
		} {
			t.Run(fmt.Sprintf("%s legacyJSON=%t", name, legacyJSON), func(t *testing.T) {
				changed := f
				edit(&changed)
				if changed == f {
					t.Fatal("test did not change input")
				}
				if _, err := liveHostDefaultDenyKernelContext(ctx, changed, raw, "public"); err == nil {
					t.Fatal("accepted unproven kernel/readback context")
				}
			})
		}
		if legacyJSON {
			changed := f
			changed.udp = strings.Replace(f.udp, "41641", "51641", 1)
			if next, err := liveHostDefaultDenyKernelContext(ctx, changed, raw, "public"); err != nil || next == digest {
				t.Fatalf("legacy opaque UDP port did not bind into the proof: %q, %v", next, err)
			}
			for _, bad := range []string{
				"",
				tailscaleMasqueradeReadback + " --to-ports 15000",
				strings.Replace(tailscaleMasqueradeReadback, "0x40000/0xff0000", "0x50000/0xff0000", 1),
			} {
				changed := f
				changed.masquerade = bad
				if _, err := liveHostDefaultDenyKernelContext(ctx, changed, raw, "public"); err == nil {
					t.Fatal("opaque source NAT accepted with unavailable or altered readback")
				}
			}
		}
	}
}

func tailscaleConnmarkFixture(t *testing.T, legacyJSON, inactive bool) string {
	t.Helper()
	var doc struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(tailscaleKernelFixture()), &doc); err != nil {
		t.Fatal(err)
	}
	var objects, moved []map[string]json.RawMessage
	const udpPort = `{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":41641}}`
	const mark = `{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":262144}}`
	for _, object := range doc.Objects {
		for kind, raw := range object {
			body := string(raw)
			if inactive && strings.Contains(body, `"family":"inet"`) {
				continue
			}
			if legacyJSON {
				body = strings.ReplaceAll(body, udpPort, nftUDPProtocol+","+nftXTMatch("udp"))
				body = strings.ReplaceAll(body, mark, nftXTMatch("mark"))
				object[kind] = json.RawMessage(body)
			}
			if kind == "rule" && strings.Contains(body, `"family":"ip","table":"filter","chain":"ts-input"`) && (strings.Contains(body, `{"return":null}`) || strings.Contains(body, `{"drop":null}`)) {
				moved = append(moved, object)
			} else {
				objects = append(objects, object)
			}
		}
	}
	// Tailscale now appends the two IPv4 anti-spoof rules after its tunnel
	// and UDP accepts. The existing isolated fixture records the older order.
	doc.Objects = append(objects, moved...)
	for _, family := range []string{"ip", "ip6"} {
		const target = `{"xt":{"type":"target","name":"CONNMARK"}}`
		outMatch := `{"match":{"op":"!=","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":0}}`
		if legacyJSON {
			outMatch = nftXTMatch("mark")
		}
		for _, chain := range []struct{ name, hook, kind, match string }{
			{"PREROUTING", "prerouting", "filter", nftXTMatch("connmark")},
			{"OUTPUT", "output", "route", outMatch},
		} {
			definition := fmt.Sprintf(`{"family":%q,"table":"mangle","name":%q,"policy":"accept","prio":-150,"hook":%q,"type":%q}`, family, chain.name, chain.hook, chain.kind)
			rule := fmt.Sprintf(`{"family":%q,"table":"mangle","chain":%q,"expr":[%s,%s,%s]}`, family, chain.name, nftXTMatch("conntrack"), chain.match, target)
			doc.Objects = append(doc.Objects, map[string]json.RawMessage{"chain": json.RawMessage(definition)}, map[string]json.RawMessage{"rule": json.RawMessage(rule)})
		}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestHostDefaultDenyTailscaleKernelProof(t *testing.T) {
	raw := tailscaleKernelFixture()
	baseline, err := hostDefaultDenyKernelContext(raw, "public")
	if err != nil || !validDigest(baseline) {
		t.Fatalf("stock Tailscale host-input context: %q, %v", baseline, err)
	}

	counters := strings.ReplaceAll(raw, `"packets":0,"bytes":0`, `"packets":21,"bytes":1728`)
	counters = strings.ReplaceAll(counters, `"handle":2`, `"handle":17`)
	if counters == raw {
		t.Fatal("fixture has no kernel counters or handles to change")
	}
	if digest, err := hostDefaultDenyKernelContext(counters, "public"); err != nil || digest != baseline {
		t.Fatalf("kernel counter and handle churn changed proof: %q, %v", digest, err)
	}

	changedPort := strings.ReplaceAll(raw, `"right":41641`, `"right":51641`)
	if changedPort == raw {
		t.Fatal("fixture has no Tailscale transport port to change")
	}
	if digest, err := hostDefaultDenyKernelContext(changedPort, "public"); err != nil || !validDigest(digest) || digest == baseline {
		t.Fatalf("valid transport port change did not change proof: %q, %v", digest, err)
	}
}

func TestHostDefaultDenyTailscaleKernelProofRefusesUnprovenRules(t *testing.T) {
	stock := tailscaleKernelFixture()
	const input = `"name":"INPUT","handle":3,"type":"filter","hook":"input","prio":0,"policy":"accept"`
	const mangle = `{"table":{"family":"ip6","name":"mangle","handle":6}}`
	const udp = `{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":41641}}`
	tests := []struct {
		name string
		from string
		to   string
	}{
		{"unrelated input base chain", input, input + `}},
{"chain":{"family":"ip","table":"filter","name":"ts-alternate-input","type":"filter","hook":"input","prio":10,"policy":"accept"`},
		{"unrelated jump in known input chain", `{"jump":{"target":"ts-input"}}`, `{"jump":{"target":"ts-other"}}`},
		{"input priority", input, strings.Replace(input, `"prio":0`, `"prio":10`, 1)},
		{"input policy", input, strings.Replace(input, `"policy":"accept"`, `"policy":"drop"`, 1)},
		{"missing input priority", input, strings.Replace(input, `,"prio":0`, "", 1)},
		{"prerouting DNAT", mangle, mangle + `,
{"chain":{"family":"ip","table":"nat","name":"PREROUTING","type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
{"rule":{"family":"ip","table":"nat","chain":"PREROUTING","expr":[{"dnat":{"addr":"127.0.0.1"}}]}}`},
		{"foreign postrouting target", `{"xt":{"type":"target","name":"MASQUERADE"}}`, `{"xt":{"type":"target","name":"SNAT"}}`},
		{"unrecognized ts-input predicate", udp, `{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":41641}}`},
		{"malformed ts-input predicate", udp, `{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":65536}}`},
		{"opaque ts-input target", udp, `{"xt":{"type":"target","name":"MARK"}}`},
		{"active foreign prerouting mangle", mangle, mangle + `,
{"chain":{"family":"ip6","table":"mangle","name":"PREROUTING","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"family":"ip6","table":"mangle","chain":"PREROUTING","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := strings.Replace(stock, test.from, test.to, 1)
			if candidate == stock {
				t.Fatal("mutation did not match fixture")
			}
			if !json.Valid([]byte(candidate)) {
				t.Fatal("test must retain valid JSON")
			}
			if _, err := hostDefaultDenyKernelContext(candidate, "public"); err == nil {
				t.Fatal("unproven Tailscale context was accepted")
			}
		})
	}
}

func TestTrafficCapturePlansDenySidecarsWithStockTailscale(t *testing.T) {
	ctx := context.Background()
	a, firewall, protection := managedTestAgent(t)
	if err := a.applyManaged(ctx, managedTestPolicy(protection, 1, "198.51.100.0/24"), protection); err != nil {
		t.Fatal(err)
	}
	a.Commands = &hostDenyFake{CommandRunner: firewall, nft: tailscaleKernelFixture(), forwarding: "0 0"}
	port := Port{18080, "tcp"}
	now := time.Now().UTC()
	scopes := []capturePortScope{{Port: port, Kind: captureDenied, StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}}
	mutations := firewall.mutations
	rules, gaps, err := a.plannedCaptureSidecars(ctx, scopes, now)
	if err != nil || len(rules) == 0 || len(gaps) == 0 || firewall.mutations != mutations {
		t.Fatalf("expected a read-only NFLOG plan with a coverage gap: %+v, %v, %v", rules, gaps, err)
	}
	for _, rule := range rules {
		if rule.Port != port || rule.Priority != managedCaptureReject || !validCaptureSidecar(rule) {
			t.Fatalf("unexpected sidecar before the owned terminal reject: %+v", rule)
		}
	}
}

// Stock Tailscale rules captured in an isolated Linux namespace via
// iptables-nft 1.8.10 and nft 1.0.9. Tailnet addresses are fixture-only.
func tailscaleKernelFixture() string {
	return strings.TrimSuffix(hostDenyKernelFixture(), "]}") + `,
{"table":{"family":"ip","name":"filter","handle":1}},
{"chain":{"family":"ip","table":"filter","name":"ts-input","handle":1}},
{"chain":{"family":"ip","table":"filter","name":"ts-forward","handle":2}},
{"chain":{"family":"ip","table":"filter","name":"INPUT","handle":3,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
{"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":5,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"rule":{"family":"ip","table":"filter","chain":"ts-input","handle":10,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"100.64.11.22"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-input","handle":7,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"100.115.92.0","len":23}}}},{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"return":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-input","handle":8,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"100.64.0.0","len":10}}}},{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"drop":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-input","handle":9,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-input","handle":11,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":41641}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-forward","handle":12,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"xt":{"type":"target","name":"MARK"}}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-forward","handle":13,"expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":262144}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-forward","handle":14,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"100.64.0.0","len":10}}}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"drop":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"ts-forward","handle":15,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":4,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ts-input"}}]}},
{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":6,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ts-forward"}}]}},
{"table":{"family":"ip","name":"nat","handle":2}},
{"chain":{"family":"ip","table":"nat","name":"ts-postrouting","handle":1}},
{"chain":{"family":"ip","table":"nat","name":"POSTROUTING","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
{"rule":{"family":"ip","table":"nat","chain":"ts-postrouting","handle":4,"expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":262144}},{"counter":{"packets":0,"bytes":0}},{"xt":{"type":"target","name":"MASQUERADE"}}]}},
{"rule":{"family":"ip","table":"nat","chain":"POSTROUTING","handle":3,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ts-postrouting"}}]}},
{"table":{"family":"ip","name":"mangle","handle":3}},
{"table":{"family":"ip6","name":"filter","handle":4}},
{"chain":{"family":"ip6","table":"filter","name":"ts-input","handle":1}},
{"chain":{"family":"ip6","table":"filter","name":"ts-forward","handle":2}},
{"chain":{"family":"ip6","table":"filter","name":"INPUT","handle":3,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
{"chain":{"family":"ip6","table":"filter","name":"FORWARD","handle":5,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"rule":{"family":"ip6","table":"filter","chain":"ts-input","handle":8,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"fd7a:115c:a1e0::1122"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip6","table":"filter","chain":"ts-input","handle":7,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip6","table":"filter","chain":"ts-input","handle":9,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":41641}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip6","table":"filter","chain":"ts-forward","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"xt":{"type":"target","name":"MARK"}}]}},
{"rule":{"family":"ip6","table":"filter","chain":"ts-forward","handle":11,"expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":262144}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip6","table":"filter","chain":"ts-forward","handle":12,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"tailscale0"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}},
{"rule":{"family":"ip6","table":"filter","chain":"INPUT","handle":4,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ts-input"}}]}},
{"rule":{"family":"ip6","table":"filter","chain":"FORWARD","handle":6,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ts-forward"}}]}},
{"table":{"family":"ip6","name":"nat","handle":5}},
{"chain":{"family":"ip6","table":"nat","name":"ts-postrouting","handle":1}},
{"chain":{"family":"ip6","table":"nat","name":"POSTROUTING","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
{"rule":{"family":"ip6","table":"nat","chain":"ts-postrouting","handle":4,"expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":262144}},{"counter":{"packets":0,"bytes":0}},{"xt":{"type":"target","name":"MASQUERADE"}}]}},
{"rule":{"family":"ip6","table":"nat","chain":"POSTROUTING","handle":3,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ts-postrouting"}}]}},
{"table":{"family":"ip6","name":"mangle","handle":6}}]}`
}
