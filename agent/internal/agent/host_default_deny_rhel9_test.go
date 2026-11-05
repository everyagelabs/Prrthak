package agent

import (
	"fmt"
	"strings"
	"testing"
)

const rhel9PolicyPre = "filter_INPUT_POLICIES_pre"
const rhel9IPv6Policy = "filter_IN_policy_allow-host-ipv6"
const rhel9Zone = "filter_IN_public"

func rhel9FirewallChain(name string) string {
	return fmt.Sprintf(`{"chain":{"family":"inet","table":"firewalld","name":%q}}`, name)
}

func rhel9FirewallRule(chain, expressions string) string {
	return fmt.Sprintf(`{"rule":{"family":"inet","table":"firewalld","chain":%q,"expr":[%s]}}`, chain, expressions)
}

func rhel9FirewallJump(chain, target string) string {
	return rhel9FirewallRule(chain, fmt.Sprintf(`{"jump":{"target":%q}}`, target))
}

func rhel9ICMPv6PolicyRule(message string) string {
	return rhel9FirewallRule(rhel9IPv6Policy+"_allow", fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":%q}},{"accept":null}`, message))
}

// The EL9 kernel uses zone-local policy dispatch before its own _pre chain.
// Model only the relevant active INPUT graph, with fixture-only interface names.
func rhel9ZoneOrderFixture(mld bool) string {
	objects := []string{
		`{"table":{"family":"inet","name":"firewalld","flags":["owner","persist"]}}`,
		`{"chain":{"family":"inet","table":"firewalld","name":"filter_INPUT","type":"filter","hook":"input","prio":10,"policy":"accept"}}`,
	}
	for _, name := range []string{rhel9PolicyPre, "filter_INPUT_ZONES", "filter_INPUT_POLICIES_post", rhel9Zone, rhel9IPv6Policy} {
		objects = append(objects, rhel9FirewallChain(name))
	}
	suffixes := []string{"_pre", "_log", "_deny", "_allow", "_post"}
	for _, suffix := range suffixes {
		objects = append(objects, rhel9FirewallChain(rhel9Zone+suffix), rhel9FirewallChain(rhel9IPv6Policy+suffix))
	}
	objects = append(objects,
		rhel9FirewallRule("filter_INPUT", `{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":{"set":["established","related"]}}},{"accept":null}`),
		rhel9FirewallRule("filter_INPUT", `{"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}},{"accept":null}`),
		rhel9FirewallRule("filter_INPUT", `{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}`),
		rhel9FirewallRule("filter_INPUT", `{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"drop":null}`),
		rhel9FirewallJump("filter_INPUT", "filter_INPUT_ZONES"),
		rhel9FirewallRule("filter_INPUT", `{"reject":{"type":"icmpx","expr":"admin-prohibited"}}`),
		rhel9FirewallRule("filter_INPUT_ZONES", `{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"goto":{"target":"filter_IN_public"}}`),
		rhel9FirewallRule("filter_INPUT_ZONES", `{"goto":{"target":"filter_IN_public"}}`),
		rhel9FirewallJump(rhel9PolicyPre, rhel9IPv6Policy),
		rhel9FirewallJump(rhel9Zone, rhel9PolicyPre),
	)
	for _, suffix := range suffixes {
		objects = append(objects, rhel9FirewallJump(rhel9Zone, rhel9Zone+suffix))
	}
	objects = append(objects,
		rhel9FirewallJump(rhel9Zone, "filter_INPUT_POLICIES_post"),
		rhel9FirewallRule(rhel9Zone, `{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":{"set":["icmp","ipv6-icmp"]}}},{"accept":null}`),
		rhel9FirewallRule(rhel9Zone, `{"reject":{"type":"icmpx","expr":"admin-prohibited"}}`),
	)
	for _, suffix := range suffixes {
		objects = append(objects, rhel9FirewallJump(rhel9IPv6Policy, rhel9IPv6Policy+suffix))
	}
	messages := []string{"nd-neighbor-advert", "nd-neighbor-solicit", "nd-router-advert", "nd-redirect"}
	if mld {
		messages = append(messages, "mld-listener-done", "mld-listener-query", "mld-listener-report", "mld2-listener-report")
	}
	for _, message := range messages {
		objects = append(objects, rhel9ICMPv6PolicyRule(message))
	}
	return `{"nftables":[` + strings.Join(objects, ",") + `]}`
}

func TestHostDefaultDenyAcceptsStockRHEL9ZonePolicyOrdering(t *testing.T) {
	for _, tc := range []struct {
		name string
		mld  bool
	}{
		{name: "base IPv6 policy"},
		{name: "MLD backport", mld: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if digest, err := hostDefaultDenyKernelContext(rhel9ZoneOrderFixture(tc.mld), "public"); err != nil || digest == "" {
				t.Fatalf("stock EL9 INPUT ordering rejected: digest=%q err=%v", digest, err)
			}
		})
	}
}

func TestHostDefaultDenyRejectsUnsafeRHEL9PrePolicy(t *testing.T) {
	fixture := rhel9ZoneOrderFixture(true)
	pre := rhel9FirewallJump(rhel9PolicyPre, rhel9IPv6Policy)
	zonePolicy := rhel9FirewallJump(rhel9Zone, rhel9PolicyPre)
	zonePre := rhel9FirewallJump(rhel9Zone, rhel9Zone+"_pre")
	policyAllow := rhel9FirewallJump(rhel9IPv6Policy, rhel9IPv6Policy+"_allow")
	tcpAccept := `{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"accept":null}`
	mld := rhel9ICMPv6PolicyRule("mld-listener-query")
	for _, tc := range []struct {
		name, original, replacement string
	}{
		{name: "early TCP accept in policy pre", original: pre, replacement: rhel9FirewallRule(rhel9IPv6Policy+"_pre", tcpAccept) + "," + pre},
		{name: "early TCP accept in policy allow", original: mld, replacement: rhel9FirewallRule(rhel9IPv6Policy+"_allow", tcpAccept)},
		{name: "missing policy dispatch", original: pre + ","},
		{name: "extra policy dispatch", original: pre, replacement: pre + "," + rhel9FirewallJump(rhel9PolicyPre, "filter_INPUT_ZONES")},
		{name: "duplicate policy dispatch", original: pre, replacement: pre + "," + pre},
		{name: "missing child chain", original: rhel9FirewallChain(rhel9IPv6Policy+"_allow") + ","},
		{name: "missing child dispatch", original: policyAllow + ","},
		{name: "unrecognized ICMPv6 type", original: mld, replacement: rhel9ICMPv6PolicyRule("echo-request")},
		{name: "partial MLD backport", original: mld + ","},
		{name: "duplicate ICMPv6 type", original: mld, replacement: rhel9ICMPv6PolicyRule("mld-listener-done")},
		{name: "missing zone pre", original: zonePre + ","},
		{name: "nonreturning zone policy dispatch", original: zonePolicy, replacement: strings.Replace(zonePolicy, `"jump"`, `"goto"`, 1)},
		{name: "nonreturning zone pre dispatch", original: zonePre, replacement: strings.Replace(zonePre, `"jump"`, `"goto"`, 1)},
		{name: "duplicate zone policy dispatch", original: zonePolicy, replacement: zonePolicy + "," + zonePolicy},
		{name: "misordered zone policy dispatch", original: zonePolicy + "," + zonePre, replacement: zonePre + "," + zonePolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(fixture, tc.original, tc.replacement, 1)
			if raw == fixture {
				t.Fatal("fixture mutation did not apply")
			}
			if digest, err := hostDefaultDenyKernelContext(raw, "public"); err == nil || digest != "" {
				t.Fatalf("unproven EL9 INPUT path accepted: digest=%q err=%v", digest, err)
			}
		})
	}
}
