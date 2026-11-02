//go:build linux

package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRealTrafficCapturePrivateKernelIPv4IPv6(t *testing.T) {
	if os.Getenv("PRTHAK_TRAFFIC_CAPTURE_PRIVATE_KERNEL") != "1" {
		t.Skip("explicit disposable NET_ADMIN/NET_RAW private-network container only")
	}
	if _, err := os.Stat("/run/prthak-private-netns"); err != nil {
		t.Fatal("missing isolated namespace marker")
	}
	ctx := context.Background()
	verifyPolicy := os.Getenv("PRTHAK_POLICY_VERIFICATION_PRIVATE_KERNEL") == "1"
	commands := ExecRunner{}
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := commands.Run(ctx, name, args...); err != nil {
			t.Fatalf("%s %v %s %v", name, args, out, err)
		}
	}
	run("ip", "link", "add", "hd-host", "type", "veth", "peer", "name", "hd-peer")
	defer commands.Run(ctx, "ip", "link", "delete", "hd-host")
	for _, device := range []string{"hd-host", "hd-peer"} {
		run("ip", "link", "set", device, "up")
	}
	run("ip", "addr", "add", "10.253.0.1/24", "dev", "hd-host")
	v6 := os.Getenv("PRTHAK_HOST_DEFAULT_DENY_IPV6_DISABLED") != "1"
	if v6 {
		run("ip", "-6", "addr", "add", "fd00:253::1/64", "dev", "hd-host", "nodad")
	}
	mac, err := os.ReadFile("/sys/class/net/hd-peer/address")
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"2", "3"} {
		run("ip", "neigh", "replace", "10.253.0."+suffix, "lladdr", strings.TrimSpace(string(mac)), "dev", "hd-host", "nud", "permanent")
		if v6 {
			run("ip", "-6", "neigh", "replace", "fd00:253::"+suffix, "lladdr", strings.TrimSpace(string(mac)), "dev", "hd-host", "nud", "permanent")
		}
	}
	run("firewall-cmd", "--zone=public", "--add-interface=hd-host")
	ports := []Port{{18443, "tcp"}, {18444, "udp"}}
	for _, family := range []string{"4", "6"} {
		if family == "6" && !v6 {
			continue
		}
		host := "0.0.0.0"
		if family == "6" {
			host = "::"
		}
		listener, err := net.Listen("tcp"+family, net.JoinHostPort(host, "18443"))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_, _ = conn.Write([]byte("SSH-2.0-PrthakCaptureFixture\r\n"))
				if verifyPolicy {
					time.Sleep(500 * time.Millisecond) // Keep the test connection established for exact GET.
				}
				_ = conn.Close()
			}
		}()
		udp, err := net.ListenPacket("udp"+family, net.JoinHostPort(host, "18444"))
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		go func() {
			buffer := make([]byte, 512)
			for {
				count, peer, err := udp.ReadFrom(buffer)
				if err != nil {
					return
				}
				_, _ = udp.WriteTo(buffer[:count], peer)
			}
		}()
	}
	nonce := strings.Repeat("c", 32)
	bundle := &ManagedBundle{Generation: nonce}
	for _, family := range []string{"ipv4", "ipv6"} {
		if family == "ipv6" && !v6 {
			continue
		}
		source := "10.253.0.2/32"
		if family == "ipv6" {
			source = "fd00:253::2/128"
		}
		for _, port := range ports {
			svc := Service{Port: port.Port, Protocol: port.Protocol}
			for _, entry := range []struct {
				priority       int
				source, action string
			}{{managedCanonicalAllow, source, "accept"}, {managedCanonicalReject, "", "reject"}} {
				rule := ManagedRule{Zone: "public", Rule: managedRuleText(nonce, entry.priority, family, entry.source, svc, entry.action)}
				run("firewall-cmd", "--zone=public", "--add-rich-rule="+rule.Rule)
				bundle.Rules = append(bundle.Rules, rule)
			}
		}
	}
	now := time.Now().UTC()
	scopes := []capturePortScope{}
	for _, kind := range []string{captureAccepted, captureDenied} {
		for _, port := range ports {
			scopes = append(scopes, capturePortScope{Port: port, Kind: kind, StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(100 * time.Second)})
		}
	}
	capture := newNativeCapture()
	defer capture.Close()
	if err := capture.Configure(scopes); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Config: Config{StateDir: t.TempDir(), Zone: "public"}, State: State{ManagedBundle: bundle}, Commands: commands, trafficCapture: capture}
	if verifyPolicy {
		// Native provenance + verification classifier test only. Durable signed
		// arm/readback/management-health behavior has separate adversarial tests.
		// The harness may enable timestamps only in this disposable netns.
		if !a.verificationTimestampAvailable() {
			t.Fatal("isolated verification fixture requires per-netns conntrack timestamp capability; the agent must not enable it")
		}
		ips := []string{"10.253.0.1"}
		allowedSources := []string{"10.253.0.2/32"}
		if v6 {
			ips = append(ips, "fd00:253::1")
			allowedSources = append(allowedSources, "fd00:253::2/128")
		}
		protection := &Protection{Digest: shaText("explicit-private-verification-protection")}
		policy := &Policy{ServerID: "private-native-verification", Version: 1, Mode: "enforce"}
		for _, port := range ports {
			policy.Services = append(policy.Services, Service{Port: port.Port, Protocol: port.Protocol, Mode: "enforce", Sources: allowedSources})
		}
		policy.Digest, _ = compiledPolicyDigest(policy)
		assignment := PolicyVerificationAssignment{SchemaVersion: 1, ID: "private-native-verification", ServerID: policy.ServerID, Version: 1, Digest: policy.Digest, ProtectionDigest: protection.Digest, TargetIPsDigest: targetIPsDigest(ips), Ports: ports, StartsAt: now, ExpiresAt: now.Add(10 * time.Minute), WindowSeconds: 600}
		policy.PolicyVerification = &assignment
		bundle.Version, bundle.Digest, bundle.ProtectionDigest = 1, policy.Digest, protection.Digest
		rows, sources := verificationCases(policy, *protection, ports, ips)
		receipt := verificationReceipt(assignment, now)
		receipt.State, receipt.ArmedAt, receipt.AppliedGeneration, receipt.Ports = "observing", &now, bundle.Generation, rows
		a.State.PolicyVerification = &policyVerificationState{Assignment: assignment, Report: receipt, ArmEpoch: shaText("private-native-arm-epoch"), Deadline: time.Now().Add(10 * time.Minute), Matchers: verificationBuildMatchers(sources), Confirmed: true}
		a.State.Policy, a.State.ManagedEnforcement = policy, &ManagedEnforcement{Status: "enforced"}
		a.inventory, a.protection = &Report{IPs: ips}, protection
		scopes = a.policyVerificationScopes(now)
		if err := capture.Configure(scopes); err != nil {
			t.Fatal("real verification birth-provenance scope", err)
		}
	}
	if err := a.reconcileCaptureSidecars(ctx, scopes, now); err != nil {
		t.Fatal("real NFLOG instrumentation", err)
	}
	defer func() {
		lock, err := managedLock(a.Config.StateDir, true)
		if err == nil {
			_ = clearTrafficCaptureSidecars(withManagedLease(ctx, lock), a.Config.StateDir, commands)
			unlockManaged(lock)
		}
	}()
	// Let the baseline table dump finish before creating the measured flows.
	time.Sleep(300 * time.Millisecond)
	packetProbe := hostDenyPacketProbe
	if verifyPolicy {
		// The ordinary firewall fixture resets immediately. This provenance
		// fixture intentionally keeps its own test flow established for the
		// read-only GET, without weakening production lifecycle validation.
		packetProbe = strings.ReplaceAll(packetProbe, "allowed=True;send(4,serverseq+1);break", "allowed=True;time.sleep(.25);send(4,serverseq+1);break")
	}
	for _, suffix := range []string{"2", "3"} {
		for _, family := range []string{"4", "6"} {
			if family == "6" && !v6 {
				continue
			}
			source, target := "10.253.0."+suffix, "10.253.0.1"
			if family == "6" {
				source, target = "fd00:253::"+suffix, "fd00:253::1"
			}
			for _, port := range ports {
				kind := "ssh"
				if port.Protocol == "udp" {
					kind = "udp"
				}
				out, err := exec.CommandContext(ctx, "python3", "-c", packetProbe, family, source, target, fmt.Sprint(port.Port), kind).CombinedOutput()
				if err != nil || (strings.TrimSpace(string(out)) == "ALLOW") != (suffix == "2") {
					t.Fatalf("probe source=%s family=%s %s error=%v", source, family, out, err)
				}
			}
		}
	}
	var events []capturedFlow
	var coverage TrafficCaptureCoverage
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		flows, cov := capture.Drain()
		events = append(events, flows...)
		coverage = cov
		expected := 4
		if v6 {
			expected = 8
		}
		if len(events) >= expected {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, event := range events {
		if !validTypedCapture(event.Flow, event.EventID) {
			t.Fatalf("invalid real capture %+v", event)
		}
		if ids[event.EventID] {
			t.Fatal("native event duplicate")
		}
		if event.ReceivedAt.IsZero() || event.CaptureEpoch == "" || event.DestinationIP == "" {
			t.Fatal("real capture lost native observer provenance", event)
		}
		if event.CaptureKind == captureDenied && event.RulePrefix == "" {
			t.Fatal("real NFLOG observation lost its exact rule prefix")
		}
		if verifyPolicy && event.CaptureKind == captureAccepted && !event.ConnectionStartedAt.After(now) {
			t.Fatal("real connection lacks a strictly post-arm kernel lifecycle start", event)
		}
		ids[event.EventID] = true
		wantedSource := ".2"
		if event.CaptureKind == captureDenied {
			wantedSource = ".3"
		}
		if strings.Contains(event.SourceIP, ":") {
			wantedSource = strings.Replace(wantedSource, ".", "::", 1)
		}
		if !strings.HasSuffix(event.SourceIP, wantedSource) {
			t.Fatalf("wrong source/verdict classification %+v", event)
		}
		seen[event.CaptureKind+"/"+event.AddressFamily+"/"+event.Protocol] = true
	}
	if verifyPolicy {
		if !a.observePolicyVerification(events) {
			t.Fatal("real native observations failed to qualify for exact version verification")
		}
		a.updatePolicyVerification(time.Now().UTC(), nil)
		if a.State.PolicyVerification.Report.State != "verified" {
			t.Fatal("both real per-port allow/deny samples were not independently verified", a.State.PolicyVerification.Report)
		}
		t.Log("PASS real conntrack birth metadata, scoped PRTV NFLOG prefixes and independent per-port policy witness classification")
	}
	for _, kind := range []string{captureAccepted, captureDenied} {
		for _, family := range []string{"ipv4", "ipv6"} {
			if family == "ipv6" && !v6 {
				continue
			}
			for _, protocol := range []string{"tcp", "udp"} {
				if !seen[kind+"/"+family+"/"+protocol] {
					t.Fatalf("missing real%s/%s/%s events=%+v coverage=%+v", kind, family, protocol, events, coverage)
				}
			}
		}
	}
	// Rebinding the same exclusive group resets the kernel's local sequence.
	// Its new socket epoch must keep a subsequent packet's identity distinct.
	state, err := readCaptureSidecars(a.Config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []string{}
	for _, rule := range state.Rules {
		prefixes = append(prefixes, rule.Prefix)
	}
	logger := capture.(interface{ SetDeniedPrefixes(uint16, []string) error })
	if err = logger.SetDeniedPrefixes(captureGroup(a.Config.StateDir), nil); err != nil {
		t.Fatal(err)
	}
	if err = logger.SetDeniedPrefixes(captureGroup(a.Config.StateDir), prefixes); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, "python3", "-c", hostDenyPacketProbe, "4", "10.253.0.3", "10.253.0.1", "18443", "ssh").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "DENY" {
		t.Fatalf("rebindprobe %s %v", out, err)
	}
	newPacket := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		flows, _ := capture.Drain()
		for _, flow := range flows {
			if flow.CaptureKind == captureDenied {
				if ids[flow.EventID] {
					t.Fatal("NFLOG rebind reused an old packet identity")
				}
				newPacket = true
			}
		}
		if newPacket {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !newPacket {
		t.Fatal("no denied packet after safe group rebind")
	}
	t.Logf("PASS real conntrack establishedTCP/confirmedUDP plus exact NFLOG denies, dual-stack=%v, events=%d coverage=%+v", v6, len(events), coverage)
}

func TestTrafficCaptureNativeScopeQueueAndUnknownLoss(t *testing.T) {
	m := newNativeCapture().(*netfilterCapture)
	m.ctStatus = CaptureBackendReport{Backend: "conntrack", Status: "off"}
	m.logStatus = CaptureBackendReport{Backend: "nflog", Status: "active"}
	now := time.Now().UTC()
	m.local = map[netip.Addr]bool{netip.MustParseAddr("10.241.0.1"): true}
	m.scopes = []capturePortScope{{Port: Port{8443, "tcp"}, Kind: captureDenied, StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}}
	flow := capturedFlow{Flow: Flow{EventID: strings.Repeat("a", 64), SourceIP: "10.241.0.2", Port: 8443, Protocol: "tcp", Verdict: "denied", CaptureKind: captureDenied, CaptureBackend: "nflog", CountUnit: "packets", AddressFamily: "ipv4", Count: 1, FirstSeen: now, LastSeen: now}, DestinationIP: "10.241.0.1"}
	wrong := flow
	wrong.Port = 22
	m.publish(wrong)
	if len(m.queue) != 0 {
		t.Fatal("unselected port captured")
	}
	for index := 0; index < captureQueueLimit+2; index++ {
		m.publish(flow)
	}
	_, coverage := m.Drain()
	if m.lost["nflog"] != 2 || m.lost["conntrack"] != 0 {
		t.Fatal("queue loss attributed to wrong backend", coverage)
	}
	m.addGap("NFLOG sequence gap fixture", true)
	_, coverage = m.Drain()
	for _, backend := range coverage.Backends {
		if backend.Backend == "nflog" && backend.LostEvents != nil {
			t.Fatal("unknown loss rewritten as zero")
		}
	}
	m.scopes[0].Deadline = time.Now().Add(-time.Second)
	m.publish(flow)
	if len(m.queue) != 0 {
		t.Fatal("wall clock allowed expired monotonic scope")
	}
}

func TestTrafficCaptureScopeConfigurationFailureClosesPreviousScope(t *testing.T) {
	m := newNativeCapture().(*netfilterCapture)
	m.scopes = []capturePortScope{{Port: Port{8443, "tcp"}, Kind: captureAccepted, StartsAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Minute)}}
	if err := m.Configure(make([]capturePortScope, 2049)); err == nil {
		t.Fatal("oversized scope accepted")
	}
	if len(m.scopes) != 0 || m.ct != nil || m.log != nil {
		t.Fatal("refused scope retained a previous native capture scope")
	}
	_, coverage := m.Drain()
	for _, backend := range coverage.Backends {
		if backend.Status == "active" {
			t.Fatal("scope failure still claims active capture")
		}
	}
}
