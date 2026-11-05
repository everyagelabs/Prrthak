package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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
