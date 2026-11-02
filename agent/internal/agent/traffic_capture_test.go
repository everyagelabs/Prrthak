package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrafficCaptureLifecycleMetadataDoesNotRecountNotificationsAndDumps(t *testing.T) {
	record, _ := decodeConntrackRecord(captureTestConntrack(false, 6, 3, 10), false)
	cache, dedup := conntrackLifecycles{limit: 2}, conntrackDedup{limit: 8}
	now := time.Now().UTC()
	record.started = 100
	baseline, birth, ok := cache.normalize(record)
	if !ok || birth != 100 {
		t.Fatal("baseline birth lost")
	}
	if count, _ := dedup.observe(baseline, true, now); count {
		t.Fatal("baseline fabricated an event")
	}
	record.started = 0
	update, birth, ok := cache.normalize(record)
	if !ok || birth != 100 || update.identity() != baseline.identity() {
		t.Fatal("timestamp-less UPDATE lost baseline identity")
	}
	if count, _ := dedup.observe(update, false, now); count {
		t.Fatal("old baseline was recounted")
	}
	record.id++
	first, _, ok := cache.normalize(record)
	if !ok {
		t.Fatal("new lifecycle refused")
	}
	if count, _ := dedup.observe(first, false, now); !count {
		t.Fatal("new notification absent")
	}
	record.started = 200
	enriched, birth, ok := cache.normalize(record)
	if !ok || birth != 200 || enriched.identity() != first.identity() {
		t.Fatal("late metadata changed event identity")
	}
	if count, _ := dedup.observe(enriched, false, now); count {
		t.Fatal("late GET/dump enrichment was double-counted")
	}
	record.started = 300
	reused, birth, ok := cache.normalize(record)
	if !ok || birth != 300 || reused.identity() == enriched.identity() {
		t.Fatal("authoritative newer lifecycle reuse was lost")
	}
	if count, _ := dedup.observe(reused, false, now); !count {
		t.Fatal("newer kernel lifecycle not counted")
	}
	record.started = 200
	if _, _, ok := cache.normalize(record); ok {
		t.Fatal("old lifecycle rebound to the reused ID")
	}
	record.id++
	if _, _, ok := cache.normalize(record); ok || len(cache.entries) != 2 {
		t.Fatal("metadata cache exceeded its hard bound")
	}
}

func TestTrafficCaptureVerificationOnlyEnrichmentNeverBecomesLearningEvidence(t *testing.T) {
	now := time.Now().UTC()
	session := Session{ID: "no-proof-to-learning", StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), Ports: []Port{{8443, "tcp"}}, ObservationKinds: []string{captureAccepted}}
	a := &Agent{Config: Config{StateDir: t.TempDir(), MaxSpoolBatches: 8}, State: State{Policy: &Policy{LearningSessions: []Session{session}}}}
	flow := capturedFlow{Flow: Flow{EventID: strings.Repeat("a", 64), SourceIP: "198.51.100.8", Port: 8443, Protocol: "tcp", CaptureKind: captureAccepted, CaptureBackend: "conntrack", CountUnit: "connections", AddressFamily: "ipv4", Verdict: "allowed", Count: 1, FirstSeen: now, LastSeen: now}, DestinationIP: "192.0.2.10", VerificationOnly: true}
	if err := a.storeCapturedFlows([]capturedFlow{flow}); err != nil {
		t.Fatal(err)
	}
	if len(a.State.Coverage) != 0 || len(a.State.LearningEvidence) != 0 {
		t.Fatal("read-only proof enrichment acquired learning authority")
	}
	files, err := filepath.Glob(filepath.Join(a.Config.StateDir, "spool", "*.json"))
	if err != nil || len(files) != 0 {
		t.Fatal("proof enrichment was recounted as normal traffic", files, err)
	}
}

func TestTrafficCaptureUnestablishedBirthCannotBorrowAnAcceptedNotification(t *testing.T) {
	record, _ := decodeConntrackRecord(captureTestConntrack(false, 6, 1, 10), false)
	record.started = 100
	cache := conntrackLifecycles{limit: 8}
	cache.normalize(record)
	key := conntrackBaseIdentity(record)
	if cache.entries[key].acceptedBirth {
		t.Fatal("SYN birth was treated as an accepted connection")
	}
	record.started, record.tcpState = 0, 3
	cache.normalize(record)
	if cache.entries[key].acceptedBirth {
		t.Fatal("undated event borrowed another lifecycle's birth")
	}
	record.started = 100
	cache.normalize(record)
	if !cache.entries[key].acceptedBirth {
		t.Fatal("authoritative accepted snapshot did not bind its own birth")
	}
	record.started, record.tcpState = 200, 1
	cache.normalize(record)
	if cache.entries[key].acceptedBirth {
		t.Fatal("ID reuse attached a prior accepted state to new unestablished birth")
	}
}

func captureTestNLA(kind uint16, data []byte) []byte {
	raw := make([]byte, (len(data)+7)&^3)
	binary.NativeEndian.PutUint16(raw, uint16(len(data)+4))
	binary.NativeEndian.PutUint16(raw[2:], kind)
	copy(raw[4:], data)
	return raw
}
func captureTestBE32(value uint32) []byte {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, value)
	return raw
}
func captureTestTuple(source, destination string, proto byte, sport, dport uint16) []byte {
	src, dst := netip.MustParseAddr(source), netip.MustParseAddr(destination)
	srcKey, dstKey := uint16(1), uint16(2)
	if src.Is6() {
		srcKey, dstKey = 3, 4
	}
	ips := append(captureTestNLA(srcKey, src.AsSlice()), captureTestNLA(dstKey, dst.AsSlice())...)
	ports := []byte{byte(sport >> 8), byte(sport)}
	protocol := append(captureTestNLA(1, []byte{proto}), captureTestNLA(2, ports)...)
	ports = []byte{byte(dport >> 8), byte(dport)}
	protocol = append(protocol, captureTestNLA(3, ports)...)
	return append(captureTestNLA(1, ips), captureTestNLA(2, protocol)...)
}
func captureTestConntrack(v6 bool, proto, state byte, status uint32) []byte {
	family, source, target := byte(2), "10.241.0.2", "10.241.0.1"
	if v6 {
		family, source, target = 10, "2001:db8:241::2", "2001:db8:241::1"
	}
	raw := []byte{family, 0, 0, 0}
	raw = append(raw, captureTestNLA(1, captureTestTuple(source, target, proto, 42000, 8443))...)
	raw = append(raw, captureTestNLA(2, captureTestTuple(target, source, proto, 8443, 42000))...)
	raw = append(raw, captureTestNLA(3, captureTestBE32(status))...)
	raw = append(raw, captureTestNLA(12, captureTestBE32(12345))...)
	if proto == 6 {
		raw = append(raw, captureTestNLA(4, captureTestNLA(1, captureTestNLA(1, []byte{state})))...)
	}
	return raw
}
func TestTrafficCaptureConntrackDualFamilyAndTransportSemantics(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, test := range []struct {
			name         string
			proto, state byte
			status       uint32
			accepted     bool
		}{{"tcp-syn", 6, 1, 8, false}, {"tcp-established", 6, 3, 10, true}, {"tcp-one-way-pickup", 6, 3, 8, false}, {"tcp-unconfirmed", 6, 3, 0, false}, {"udp-confirmed", 17, 0, 8, true}, {"udp-unconfirmed", 17, 0, 0, false}} {
			t.Run(test.name+map[bool]string{false: "-ipv4", true: "-ipv6"}[v6], func(t *testing.T) {
				record, err := decodeConntrackRecord(captureTestConntrack(v6, test.proto, test.state, test.status), false)
				if err != nil || record.accepted() != test.accepted || record.reply.sourcePort != 8443 {
					t.Fatalf("record=%+v error=%v", record, err)
				}
			})
		}
	}
	valid := captureTestConntrack(false, 6, 3, 8)
	for cut := 0; cut < len(valid); cut++ {
		_, err := decodeConntrackRecord(valid[:cut], false)
		if err == nil && cut < len(valid)-8 {
			t.Fatalf("accepted malformed/truncated conntrack at%d", cut)
		}
	}
	duplicate := append(append([]byte{}, valid...), captureTestNLA(12, captureTestBE32(999))...)
	if _, err := decodeConntrackRecord(duplicate, false); err == nil {
		t.Fatal("duplicate conntrack ID accepted")
	}
}
func TestTrafficCaptureConntrackDedupResyncReuseAndOutOfOrder(t *testing.T) {
	record, err := decodeConntrackRecord(captureTestConntrack(true, 6, 3, 10), false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	dedup := conntrackDedup{limit: 8}
	if count, _ := dedup.observe(record, false, now); !count {
		t.Fatal("new established flow absent")
	}
	id := conntrackFlowID("boot-one", record)
	for tick := 1; tick <= 120; tick++ {
		if count, _ := dedup.observe(record, false, now.Add(time.Duration(tick)*time.Minute)); count {
			t.Fatal("long-lived flow recounted by periodic dump")
		}
		if conntrackFlowID("boot-one", record) != id {
			t.Fatal("flow identity changed")
		}
	}
	reused := record
	reused.id++
	if count, _ := dedup.observe(reused, false, now); !count || conntrackFlowID("boot-one", reused) == id {
		t.Fatal("same tuple new kernel ID lost")
	}
	reused = record
	reused.started = 99
	if count, _ := dedup.observe(reused, false, now); !count || conntrackFlowID("boot-one", reused) == id {
		t.Fatal("start timestamp did not disambiguate reused ID")
	}
	retired := record
	retired.id += 2
	retired.deleted = true
	if count, _ := dedup.observe(retired, false, now); count {
		t.Fatal("DESTROY fabricated a successful connection")
	}
	retired.deleted = false
	if count, _ := dedup.observe(retired, false, now); count {
		t.Fatal("out-of-order UPDATE recounted retired connection")
	}
	baseline := record
	baseline.id += 3
	if count, _ := dedup.observe(baseline, true, now); count {
		t.Fatal("preexisting dump counted as new")
	}
	if count, _ := dedup.observe(baseline, false, now); count {
		t.Fatal("preexisting flow later UPDATE counted")
	}
	if conntrackFlowID("boot-two", record) == id {
		t.Fatal("boot reuse shares identity")
	}
	small := conntrackDedup{limit: 1}
	_, _ = small.observe(record, false, now)
	if count, limited := small.observe(reused, false, now); count || !limited {
		t.Fatal("identity bound did not fail explicitly")
	}
}
func captureTestNFLog(v6, extension bool) []byte {
	family := byte(2)
	packet := make([]byte, 24)
	packet[0] = 0x45
	packet[9] = 6
	copy(packet[12:16], netip.MustParseAddr("10.241.0.2").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("10.241.0.1").AsSlice())
	offset := 20
	if v6 {
		family = 10
		packet = make([]byte, 44)
		packet[0] = 0x60
		packet[6] = 6
		copy(packet[8:24], netip.MustParseAddr("2001:db8::2").AsSlice())
		copy(packet[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
		offset = 40
		if extension {
			packet = append(packet, make([]byte, 8)...)
			packet[6] = 60
			packet[40] = 6
			packet[41] = 0
			offset = 48
		}
	}
	packet[offset+2], packet[offset+3] = 0x20, 0xfb
	raw := []byte{family, 0, 0, 1}
	raw = append(raw, captureTestNLA(1, []byte{0x08, 0x00, 1, 0})...)
	raw = append(raw, captureTestNLA(4, captureTestBE32(3))...)
	raw = append(raw, captureTestNLA(9, packet)...)
	raw = append(raw, captureTestNLA(10, []byte("PRTN0123456789abcdef:\x00"))...)
	raw = append(raw, captureTestNLA(12, captureTestBE32(7))...)
	return raw
}
func TestTrafficCaptureNFLogDualFamilyExtensionsAndStrictLocalHook(t *testing.T) {
	for _, test := range []struct{ v6, extension bool }{{false, false}, {true, false}, {true, true}} {
		raw := captureTestNFLog(test.v6, test.extension)
		record, err := decodeNFLogRecord(raw)
		if err != nil || record.port != 8443 || record.sequence != 7 || record.source.Is6() != test.v6 {
			t.Fatalf("record%+v err%v", record, err)
		}
		minimum := bytes.Index(raw, []byte("PRTN0123456789abcdef:")) + len("PRTN0123456789abcdef:") + 1
		for cut := 0; cut < minimum; cut++ {
			if _, err := decodeNFLogRecord(raw[:cut]); err == nil {
				t.Fatalf("accepted truncated NFLOG at%d", cut)
			}
		}
		bad := append([]byte{}, raw...)
		bad[10] = 0 // PACKET_HDR hook at nfgen4+nla4+offset2
		if _, err := decodeNFLogRecord(bad); err == nil {
			t.Fatal("pre-routing log was treated as locally denied")
		}
		if test.extension {
			bad := append([]byte{}, raw...)
			attrs, _ := captureAttributes(bad[4:])
			attrs[9][41] = 20
			if _, err := decodeNFLogRecord(bad); err == nil {
				t.Fatal("truncated IPv6 extension accepted")
			}
		}
	}
}
func TestTrafficCaptureTypedScopeSpoolAndAutoLearningEvidence(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	session := Session{ID: "typed-learning-one", PolicyAction: "auto_allow", ObservationKinds: []string{captureDenied}, StartsAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Status: "active", Ports: []Port{{8443, "tcp"}}}
	a := &Agent{Config: Config{StateDir: dir, MaxSpoolBatches: 5}, State: State{Policy: &Policy{LearningSessions: []Session{session}}, Coverage: map[string]*Coverage{session.ID: {SessionID: session.ID}}}}
	flow := Flow{EventID: strings.Repeat("a", 64), SourceIP: "2001:db8::2", Port: 8443, Protocol: "tcp", Verdict: "denied", Count: 1, FirstSeen: now, LastSeen: now, CaptureKind: captureDenied, CaptureBackend: "nflog", CountUnit: "packets", AddressFamily: "ipv6"}
	accepted := flow
	accepted.CaptureKind = captureAccepted
	accepted.CaptureBackend = "conntrack"
	accepted.CountUnit = "connections"
	accepted.Verdict = "allowed"
	wrongPort := flow
	wrongPort.Port = 22
	if err := a.storeCapturedFlows([]capturedFlow{{Flow: flow}, {Flow: accepted}, {Flow: wrongPort}}); err != nil {
		t.Fatal(err)
	}
	files, err := spoolFiles(filepath.Join(dir, "spool"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	raw, _ := os.ReadFile(files[0])
	var batch Batch
	if json.Unmarshal(raw, &batch) != nil || len(batch.Events) != 1 || batch.Events[0].CaptureKind != captureDenied || !validTypedCapture(batch.Events[0], batch.Events[0].EventID) {
		t.Fatalf("bad typed batch %s", raw)
	}
	if len(a.State.LearningEvidence[session.ID]) != 1 {
		t.Fatal("denied first hit lost explicit any-hit auto-learning intent")
	}
	if _, ok := ParseKernelLog("PRT old log", now, session); ok {
		t.Fatal("typed scope silently fell back to kernel journal")
	}
	for _, kinds := range [][]string{{}, {"anything"}, {captureDenied, captureDenied}} {
		if validateObservationKinds(kinds) == nil {
			t.Fatal("unsafe kinds accepted", kinds)
		}
	}
}
func TestTrafficCaptureSidecarsAreLogOnlyPrivateAndCleanupVerified(t *testing.T) {
	dir := t.TempDir()
	rule := captureSidecar{Zone: "public", Family: "ipv6", Port: Port{8443, "tcp"}, Group: 49001, Prefix: "PRTN0123456789abcdef:", Priority: managedCaptureReject, ExpiresAt: time.Now().Add(time.Minute)}
	if !validCaptureSidecar(rule) || strings.Contains(rule.text(), " reject") || strings.Contains(rule.text(), " accept") || strings.Contains(rule.text(), " drop") {
		t.Fatal("capture rule can change an access verdict")
	}
	if err := atomicJSON(captureSidecarPath(dir), captureSidecarState{Version: 1, Rules: []captureSidecar{rule}}); err != nil {
		t.Fatal(err)
	}
	fake := newFirewallFake()
	fake.set("runtime", "rich_rule", rule.text(), true)
	if err := clearTrafficCaptureSidecars(context.Background(), dir, fake); err == nil {
		t.Fatal("cleanup ran without mutation lease")
	}
	lock, err := managedLock(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lock)
	if err = clearTrafficCaptureSidecars(withManagedLease(context.Background(), lock), dir, fake); err != nil {
		t.Fatal(err)
	}
	state, err := readCaptureSidecars(dir)
	if err != nil || len(state.Rules) != 0 || fake.has("runtime", "rich_rule", rule.text()) {
		t.Fatal("cleanup notdurable/verified", state, err)
	}
}

type trafficCaptureFixture struct {
	flows  []capturedFlow
	closed bool
}

func (f *trafficCaptureFixture) Configure([]capturePortScope) error { return nil }
func (f *trafficCaptureFixture) Close() error                       { f.closed = true; return nil }
func (f *trafficCaptureFixture) Drain() ([]capturedFlow, TrafficCaptureCoverage) {
	flows := f.flows
	f.flows = nil
	zero := 0
	return flows, TrafficCaptureCoverage{Backends: []CaptureBackendReport{{Backend: "conntrack", Status: "active", IPv4: true, IPv6: true, LostEvents: &zero}}}
}
func TestTrafficCaptureTypedMonitorStaysNativeAndReceiptsDoNotFlap(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	fake := newFirewallFake()
	m, err := NewHitMonitor(dir, "public", 5, fake, false)
	if err != nil {
		t.Fatal(err)
	}
	item := HitMonitorAssignment{ID: "typed-monitor", ServerID: "endpoint-one", ObservationKinds: []string{captureAccepted}, StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), Ports: []Port{{8443, "tcp"}}}
	if err = m.SetAssignments(item.ServerID, []HitMonitorAssignment{item}, now); err != nil {
		t.Fatal(err)
	}
	flow := Flow{EventID: strings.Repeat("c", 64), CaptureKind: captureAccepted, CaptureBackend: "conntrack", CountUnit: "connections", AddressFamily: "ipv6", SourceIP: "2001:db8::2", Port: 8443, Protocol: "tcp", Verdict: "allowed", Count: 1, FirstSeen: now, LastSeen: now}
	native := &trafficCaptureFixture{flows: []capturedFlow{{Flow: flow}}}
	a := &Agent{Config: Config{StateDir: dir, MaxSpoolBatches: 5}, State: State{Coverage: map[string]*Coverage{}}, Commands: fake, hitMonitor: m, trafficCapture: native}
	if err = m.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err = a.tickTrafficCapture(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err = m.Tick(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	statuses := m.Statuses()
	if len(statuses) != 1 || statuses[0].Status != "observing" || len(statuses[0].Backends) != 1 || statuses[0].Backends[0].Backend != "conntrack" {
		t.Fatalf("native status incorrectly requires LOG rules: %+v", statuses)
	}
	files, err := spoolFiles(filepath.Join(m.dir, "spool"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	raw, _ := os.ReadFile(files[0])
	var batch HitBatch
	if json.Unmarshal(raw, &batch) != nil || validateHitBatch(batch) != nil || len(batch.Events) != 1 || batch.Events[0].CaptureKind != captureAccepted {
		t.Fatalf("typed hitspool %s", raw)
	}
	if len(fake.writes) != 0 || len(m.state.Rules) != 0 {
		t.Fatal("native accepted-only monitor installed legacy LOG rules")
	}
}
func TestTrafficCaptureStopDrainsOnlyPreStopTypedEvidence(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	stop := now.Add(-time.Second)
	session := Session{ID: "typed-stopped-learning", ObservationKinds: []string{captureAccepted}, Ports: []Port{{8443, "tcp"}}, StartsAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), StoppedAt: &stop, Status: "stopped"}
	a := &Agent{Config: Config{StateDir: dir, MaxSpoolBatches: 5}, State: State{Policy: &Policy{LearningTombstones: []Session{session}}, Coverage: map[string]*Coverage{}}}
	flow := Flow{EventID: strings.Repeat("d", 64), CaptureKind: captureAccepted, CaptureBackend: "conntrack", CountUnit: "connections", AddressFamily: "ipv4", SourceIP: "10.241.0.2", Port: 8443, Protocol: "tcp", Verdict: "allowed", Count: 1, FirstSeen: stop.Add(-time.Millisecond), LastSeen: stop.Add(-time.Millisecond)}
	after := flow
	after.EventID = strings.Repeat("e", 64)
	after.FirstSeen = now
	after.LastSeen = now
	if err := a.storeCapturedFlows([]capturedFlow{{Flow: flow}, {Flow: after}}); err != nil {
		t.Fatal(err)
	}
	files, err := spoolFiles(filepath.Join(dir, "spool"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	raw, _ := os.ReadFile(files[0])
	var batch Batch
	if json.Unmarshal(raw, &batch) != nil || len(batch.Events) != 1 || !batch.Events[0].FirstSeen.Before(stop) {
		t.Fatalf("stop cutoff/tail changed %s", raw)
	}
}

func TestTrafficCaptureSimulationAdvertisesWireOnlyWithUnsupportedBackends(t *testing.T) {
	a := &Agent{Config: Config{DiscoveryIntervalSeconds: 900}, Simulate: true, SimulateHostname: "simulated-capture-contract"}
	report := a.inventoryReport(context.Background(), time.Now().UTC())
	found := false
	for _, capability := range report.Capabilities {
		if capability == TrafficCaptureCapability {
			found = true
		}
	}
	if !found || report.TrafficCapture == nil || len(report.TrafficCapture.Backends) != 2 {
		t.Fatalf("simulator lacks typeddiscovery protocol %+v", report)
	}
	for _, backend := range report.TrafficCapture.Backends {
		if backend.Status != "unsupported" || backend.IPv4 || backend.IPv6 {
			t.Fatal("simulation claims nativecapture", backend)
		}
	}
	if report.ApplyStatus == "enforced" || a.trafficCapture != nil {
		t.Fatal("simulation fabricated a nativecollector or enforcement authority")
	}
}
