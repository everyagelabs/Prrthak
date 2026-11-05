package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func rhel10LoopbackNamespaceRunner(t *testing.T) *namespaceTestRunner {
	t.Helper()
	raw, err := os.ReadFile("testdata/rhel10-private-loopback-namespace.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Addresses json.RawMessage `json:"addresses"`
		Routes4   json.RawMessage `json:"routes4"`
		Routes6   json.RawMessage `json:"routes6"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	runner := newNamespaceTestRunner(t)
	runner.addresses, runner.routes4, runner.routes6 = string(fixture.Addresses), string(fixture.Routes4), string(fixture.Routes6)
	return runner
}

func TestRHEL10SavedLoopbackNamespaceMetadata(t *testing.T) {
	root, runner := namespaceTestRoot(t, 2), rhel10LoopbackNamespaceRunner(t)
	first, err := networkNamespace(context.Background(), runner, root)
	if err != nil || !validDigest(first) || runner.calls != 12 {
		t.Fatal("saved kernel loopback metadata was rejected", first, err, runner.calls)
	}
	if digest, err := activationInactiveContext(context.Background(), activationNamespaceTestRunner{runner}, root, false, nil); err != nil || !validDigest(digest) {
		t.Fatal("saved metadata blocked an otherwise valid firewall activation assessment", err)
	}
	// The optional Boolean flag does not add a destination or route, but its
	// state remains part of the signed review's native context.
	runner.addresses = strings.ReplaceAll(runner.addresses, `"noprefixroute":true`, `"noprefixroute":false`)
	second, err := networkNamespace(context.Background(), runner, root)
	if err != nil || first == second {
		t.Fatal("valid metadata change failed to invalidate the previous review digest", err)
	}
}

func TestRHEL10LoopbackMetadataRequiresExactTypesAndTopology(t *testing.T) {
	for name, change := range map[string]func(*namespaceTestRunner){
		"promiscuous mode": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"promiscuity":0`, `"promiscuity":1`)
		},
		"all multicast mode": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"allmulti":0`, `"allmulti":1`)
		},
		"non numeric mode": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"promiscuity":0`, `"promiscuity":false`)
		},
		"string telemetry": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"min_mtu":0`, `"min_mtu":"0"`)
		},
		"negative telemetry": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"num_tx_queues":1`, `"num_tx_queues":-1`)
		},
		"zero queues": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"num_rx_queues":1`, `"num_rx_queues":0`)
		},
		"overflow telemetry": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"gso_max_size":65536`, `"gso_max_size":4294967296`)
		},
		"fraction telemetry": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"tso_max_size":524280`, `"tso_max_size":1.5`)
		},
		"unknown link data": func(r *namespaceTestRunner) {
			r.addresses = strings.Replace(r.addresses, `"ifindex":1`, `"ifindex":1,"xdp":{"attached":"driver"}`, 1)
		},
		"duplicate telemetry": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"allmulti":0`, `"allmulti":0,"allmulti":0`)
		},
		"non Boolean flag": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"noprefixroute":true`, `"noprefixroute":"true"`)
		},
		"null flag": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"noprefixroute":true`, `"noprefixroute":null`)
		},
		"IPv4 flag outside observed layout": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"family":"inet",`, `"family":"inet","noprefixroute":true,`)
		},
		"nonloopback IPv6 address": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"local":"::1"`, `"local":"2001:db8::1"`)
		},
		"IPv6 default route":          func(r *namespaceTestRunner) { r.routes6 = strings.ReplaceAll(r.routes6, `"dst":"::1"`, `"dst":"::/0"`) },
		"nonloopback route interface": func(r *namespaceTestRunner) { r.routes6 = strings.ReplaceAll(r.routes6, `"dev":"lo"`, `"dev":"eth0"`) },
		"global IPv4 route": func(r *namespaceTestRunner) {
			r.routes4 = strings.Replace(r.routes4, `"scope":"host"`, `"scope":"global"`, 1)
		},
		"global unicast route": func(r *namespaceTestRunner) {
			r.routes6 = strings.ReplaceAll(r.routes6, `"type":"local"`, `"type":"unicast"`)
		},
		"global route missing local type": func(r *namespaceTestRunner) { r.routes6 = strings.ReplaceAll(r.routes6, `"type":"local",`, ``) },
		"global main table route": func(r *namespaceTestRunner) {
			r.routes6 = strings.ReplaceAll(r.routes6, `"table":"local"`, `"table":"main"`)
		},
		"global route missing local table": func(r *namespaceTestRunner) { r.routes6 = strings.ReplaceAll(r.routes6, `"table":"local",`, ``) },
		"gateway route": func(r *namespaceTestRunner) {
			r.routes6 = strings.ReplaceAll(r.routes6, `"dev":"lo"`, `"dev":"lo","gateway":"::1"`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := rhel10LoopbackNamespaceRunner(t)
			before := runner.addresses + runner.routes4 + runner.routes6
			change(runner)
			if before == runner.addresses+runner.routes4+runner.routes6 {
				t.Fatal("mutation did not change saved fixture")
			}
			if _, err := networkNamespace(context.Background(), runner, namespaceTestRoot(t, 1)); err == nil {
				t.Fatal("unreviewed or widened loopback layout was admitted")
			}
		})
	}
}

func TestRHEL10MetadataStillParticipatesInWholeInventorySweeps(t *testing.T) {
	root, runner := namespaceTestRoot(t, 2), rhel10LoopbackNamespaceRunner(t)
	runner.addressesByPin = map[string]string{}
	runner.afterCall = func(n int) {
		if n == 4 {
			runner.addressesByPin[runner.pinPaths[0]] = strings.ReplaceAll(runner.addresses, `"noprefixroute":true`, `"noprefixroute":false`)
		}
	}
	if _, err := networkNamespace(context.Background(), runner, root); err == nil || !strings.Contains(err.Error(), "topology changed between inventory sweeps") {
		t.Fatal("saved metadata bypassed the cross-namespace race check", err)
	}
}
