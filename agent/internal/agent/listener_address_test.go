package agent

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSocketsNormalizesUbuntu26IPv4InterfaceSuffixes(t *testing.T) {
	for _, test := range []struct{ address, iface string }{
		{"127.0.0.53", "lo"}, {"172.31.2.254", "enX0"}, {"100.66.222.40", "tailscale0"},
		{"172.31.2.254", "veth@peer"}, {"172.31.2.254", "edge+app"}, {"172.31.2.254", "veth[0]"}, {"172.31.2.254", "veth%peer"},
	} {
		t.Run(test.iface, func(t *testing.T) {
			row := fmt.Sprintf("tcp LISTEN 0 128 %s%%%s:8443 0.0.0.0:* users:((\"nginx\",pid=9999999,fd=3))", test.address, test.iface)
			listeners := ParseSockets(row)
			if len(listeners) != 1 || listeners[0].Address != test.address || listeners[0].Service != "Nginx" {
				t.Fatalf("IPv4 scope annotation was not normalized: %+v", listeners)
			}
			if listenerBindingKey("tcp", 8443, test.address+"%"+test.iface) != listenerBindingKey("tcp", 8443, test.address) {
				t.Fatal("IPv4 interface annotation cannot reconcile with native binding")
			}
		})
	}
}

func TestListenerAddressNormalizationKeepsIPv6ScopeAndRejectsMalformedRows(t *testing.T) {
	rows := ParseSockets("udp UNCONN 0 0 [fe80::1234%eth0]:546 [::]:*\n" +
		"udp UNCONN 0 0 [fe80::1234]%eth1:546 [::]:*\n" +
		"tcp LISTEN 0 128 [fd7a:115c:a1e0::1]%tailscale0:8443 [::]:*")
	if len(rows) != 3 || rows[0].Address != "fe80::1234%eth0" || rows[1].Address != "fe80::1234%eth1" || rows[2].Address != "fd7a:115c:a1e0::1%tailscale0" {
		t.Fatalf("IPv6 binding scope was changed or collapsed: %+v", rows)
	}
	for _, zone := range []string{"veth@peer", "edge+app", "UPLINK!", "网卡0", "veth[0]", "veth]0", "veth]%peer"} {
		address, ok := normalizeListenerAddress("[fe80::1234%" + zone + "]")
		if !ok || address != "fe80::1234%"+zone {
			t.Fatalf("valid IPv6 interface name was changed or rejected: %q %v", address, ok)
		}
		outside, outsideOK := normalizeListenerAddress("[fe80::1234]%" + zone)
		if !outsideOK || outside != address {
			t.Fatalf("outside-bracket scope was changed or rejected: %q %v", outside, outsideOK)
		}
	}
	for _, address := range []string{"127.0.0.1%", "127.0.0.1%/lo", "127.0.0.1%..", "127.0.0.1%interface-name-is-too-long", "999.0.0.1%lo", "hostname%lo", "[127.0.0.1]%lo", "[::1]garbage", "[fe80::1%eth0]%eth1", "fe80::1%", "[fe80::1%/eth0]"} {
		t.Run(address, func(t *testing.T) {
			line := "tcp LISTEN 0 128 " + address + ":8443 0.0.0.0:*"
			if len(ParseSockets(line)) != 0 {
				t.Fatal("malformed listener address was accepted")
			}
			runner := &fakeRunner{fn: func(string, []string) (string, error) { return line, nil }}
			if _, err := DiscoverListeners(context.Background(), runner); err == nil {
				t.Fatal("malformed address became a successful listener scan")
			}
		})
	}
	if listenerBindingKey("tcp", 8443, "172.31.2.254%enX0") == listenerBindingKey("tcp", 8443, "172.31.2.255") {
		t.Fatal("actual IPv4 address changes were collapsed")
	}
	if listenerBindingKey("udp", 546, "fe80::1234%eth0") == listenerBindingKey("udp", 546, "fe80::5678%eth0") {
		t.Fatal("actual IPv6 address changes were collapsed")
	}
	// Native fingerprints retain interface identity independently from the
	// address reconciliation key used for a verified ss refresh.
	before, _ := newListenerSnapshot([]string{"17/546/fe80::1234/2/99"}, nil)
	after, _ := newListenerSnapshot([]string{"17/546/fe80::1234/3/99"}, nil)
	if before.fingerprint == after.fingerprint {
		t.Fatal("IPv6 interface change disappeared from native identity")
	}
}

func TestListenerAddressNormalizationPreservesScopedWildcard(t *testing.T) {
	rows := "tcp LISTEN 0 128 *%tailscale0:8443 *:*\n" +
		"udp UNCONN 0 0 [::]%enX0:5353 [::]:*"
	runner := &fakeRunner{fn: func(name string, _ []string) (string, error) {
		if name == "ss" {
			return rows, nil
		}
		return "", nil
	}}
	listeners, err := DiscoverListeners(context.Background(), runner)
	if err != nil || len(listeners) != 2 {
		t.Fatalf("scoped wildcards rejected: %v %+v", err, listeners)
	}
	if listeners[0].Address != "::%enX0" || listeners[1].Address != "::%tailscale0" {
		t.Fatalf("reported wildcard interface identities changed: %+v", listeners)
	}
	if listenerBindingKey("tcp", 8443, "*%tailscale0") != listenerBindingKey("tcp", 8443, "::") {
		t.Fatal("scoped ss wildcard does not match its kernel address")
	}
	for _, address := range []string{"*%", "[*]%eth0"} {
		if _, ok := normalizeListenerAddress(address); ok {
			t.Fatalf("malformed wildcard accepted: %q", address)
		}
	}
}

func TestFastDiscoveryAcceptsStableIPv4ScopedSSRowsAndStillDetectsActualChanges(t *testing.T) {
	a, fixture, now := newFastDiscoveryFixture(t)
	fixture.rows = "tcp LISTEN 0 128 127.0.0.53%lo:5353 0.0.0.0:*\n" +
		"tcp LISTEN 0 128 172.31.2.254%enX0:8443 0.0.0.0:*\n" +
		"tcp LISTEN 0 128 100.66.222.40%tailscale0:2022 0.0.0.0:*"
	canonical := strings.NewReplacer("%lo", "", "%enX0", "", "%tailscale0", "").Replace(fixture.rows)
	fingerprint := "native-plain-ipv4"
	a.listenerSnapshot = func(context.Context) (listenerSnapshot, error) {
		return listenerSnapshot{fingerprint: fingerprint, ports: listenerPortSet(ParseSockets(canonical)), bindings: listenerBindingSet(ParseSockets(canonical))}, nil
	}
	if !a.fastDiscoveryTick(context.Background(), now.Add(5*time.Second)) || a.inventory.DiscoveryError != "" || len(a.inventory.Listeners) != 3 {
		t.Fatalf("stable Ubuntu IPv4 rows were rejected against native snapshot: %+v", a.inventory)
	}
	if a.fastDiscoveryTick(context.Background(), now.Add(10*time.Second)) || fixture.ssCalls != 1 {
		t.Fatal("unchanged bindings repeatedly rescanned ss")
	}
	fixture.rows = strings.Replace(fixture.rows, "172.31.2.254", "172.31.2.253", 1)
	canonical = strings.Replace(canonical, "172.31.2.254", "172.31.2.253", 1)
	fingerprint = "native-real-address-change"
	if !a.fastDiscoveryTick(context.Background(), now.Add(15*time.Second)) || a.inventory.DiscoveryError != "" {
		t.Fatal("real stable listener address change was not published")
	}
	found := false
	for _, listener := range a.inventory.Listeners {
		found = found || listener.Address == "172.31.2.253"
	}
	if !found {
		t.Fatal("published inventory retained the old actual binding")
	}
	previous := append([]Listener(nil), a.inventory.Listeners...)
	fixture.rows = strings.Replace(fixture.rows, "172.31.2.253", "172.31.2.252", 1)
	fingerprint = "native-ss-mismatch"
	if !a.fastDiscoveryTick(context.Background(), now.Add(20*time.Second)) || !strings.Contains(a.inventory.DiscoveryError, "listener bindings changed") || !reflect.DeepEqual(a.inventory.Listeners, previous) {
		t.Fatal("normalizing annotations concealed a real binding mismatch")
	}
}
