package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func minuteSamplingTestFlow(source string, port int, protocol, kind string, at time.Time) capturedFlow {
	flow := Flow{EventID: shaText(source + at.Format(time.RFC3339Nano) + kind), SourceIP: source, Port: port, Protocol: protocol, Count: 1, FirstSeen: at, LastSeen: at,
		CaptureKind: kind, CaptureBackend: "conntrack", CountUnit: "connections", AddressFamily: "ipv4", Verdict: "allowed"}
	if kind == captureDenied {
		flow.CaptureBackend, flow.CountUnit, flow.Verdict = "nflog", "packets", "denied"
	}
	return capturedFlow{Flow: flow}
}

func minuteSamplingTestBatches(t *testing.T, dir string) map[string][]Flow {
	t.Helper()
	files, err := spoolFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	bySession := map[string][]Flow{}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var batch Batch
		if err = json.Unmarshal(raw, &batch); err != nil {
			t.Fatal(err)
		}
		bySession[batch.SessionID] = append(bySession[batch.SessionID], batch.Events...)
	}
	return bySession
}

func TestTrafficMinuteSamplingRetainsOneObservationPerRelationshipAndLeavesHitsIntact(t *testing.T) {
	minute := time.Now().UTC().Truncate(time.Minute)
	sampled := Session{ID: "sampled-traffic", Purpose: "traffic", PolicyAction: "observe", TrafficCollectionMode: "sampled", StartsAt: minute.Add(-time.Minute), ExpiresAt: minute.Add(3 * time.Minute),
		Ports: []Port{{443, "tcp"}, {443, "udp"}, {8443, "tcp"}}, ObservationKinds: []string{captureAccepted, captureDenied}}
	hits := sampled
	hits.ID, hits.TrafficCollectionMode = "explicit-hits", "hits"
	legacy := sampled
	legacy.ID, legacy.TrafficCollectionMode = "legacy-traffic", ""
	policy := sampled
	policy.ID, policy.Purpose, policy.PolicyAction, policy.TrafficCollectionMode = "policy-traffic", "policy", "auto_allow", ""
	a := &Agent{Config: Config{StateDir: t.TempDir(), MaxSpoolBatches: 20}, State: State{Policy: &Policy{LearningSessions: []Session{sampled, hits, legacy, policy}}}}
	spool := filepath.Join(a.Config.StateDir, "spool")
	first := minuteSamplingTestFlow("192.0.2.9", 443, "tcp", captureAccepted, minute.Add(time.Second))
	duplicate := minuteSamplingTestFlow("192.0.2.9", 443, "tcp", captureDenied, minute.Add(2*time.Second))
	if err := a.storeCapturedFlows([]capturedFlow{first, duplicate}); err != nil {
		t.Fatal(err)
	}
	otherIP := minuteSamplingTestFlow("192.0.2.10", 443, "tcp", captureAccepted, minute.Add(3*time.Second))
	otherPort := minuteSamplingTestFlow("192.0.2.9", 8443, "tcp", captureAccepted, minute.Add(3*time.Second))
	otherProtocol := minuteSamplingTestFlow("192.0.2.9", 443, "udp", captureAccepted, minute.Add(3*time.Second))
	nextMinute := minuteSamplingTestFlow("192.0.2.9", 443, "tcp", captureAccepted, minute.Add(time.Minute))
	if err := a.storeCapturedFlows([]capturedFlow{duplicate, otherIP, otherPort, otherProtocol, nextMinute, duplicate}); err != nil {
		t.Fatal(err)
	}
	observations := minuteSamplingTestBatches(t, spool)
	if got := len(observations[sampled.ID]); got != 5 {
		t.Fatalf("sampled mode kept %d observations, want five distinct minute slots", got)
	}
	for _, session := range []Session{hits, legacy, policy} {
		if len(observations[session.ID]) != 8 {
			t.Fatalf("unrelated mode dropped events for %s: %+v", session.ID, observations[session.ID])
		}
	}
	for _, flow := range observations[sampled.ID] {
		if !validTypedCapture(flow, flow.EventID) || flow.EventID != trafficSampleID(sampled.ID, flow) {
			t.Fatalf("sample lost native wire evidence or stable ID: %+v", flow)
		}
	}
	if a.State.Coverage[sampled.ID] != nil && a.State.Coverage[sampled.ID].DroppedEvents != 0 {
		t.Fatal("intentional sampling was misreported as loss")
	}
}

func TestTrafficMinuteSamplerBoundAndStableRestartIdentity(t *testing.T) {
	minute := time.Now().UTC().Truncate(time.Minute)
	first := minuteSamplingTestFlow("192.0.2.9", 443, "tcp", captureAccepted, minute).Flow
	other := minuteSamplingTestFlow("192.0.2.9", 443, "tcp", captureDenied, minute.Add(time.Second)).Flow
	var before, after trafficMinuteSampler
	id, err := before.reserve("sampled-session", first)
	if err != nil || id == "" {
		t.Fatalf("first sample: %q %v", id, err)
	}
	if again, err := after.reserve("sampled-session", other); err != nil || again != id {
		t.Fatalf("restart sample identity changed: %q %v", again, err)
	}
	for i := 1; i < maxTrafficMinuteSamples; i++ {
		before.current.ids[strconv.Itoa(i)] = struct{}{}
	}
	if duplicate, err := before.reserve("sampled-session", other); err != nil || duplicate != "" {
		t.Fatalf("duplicate counted as overflow: %q %v", duplicate, err)
	}
	other.Port = 8443
	if _, err := before.reserve("sampled-session", other); !errors.Is(err, errTrafficMinuteSampleLimit) {
		t.Fatalf("unbounded minute cache: %v", err)
	}
	other.FirstSeen = other.FirstSeen.Add(2 * time.Minute)
	if fresh, err := before.reserve("sampled-session", other); err != nil || fresh == "" {
		t.Fatalf("minute cache did not recover: %q %v", fresh, err)
	}
	if _, err := before.reserve("sampled-session", first); !errors.Is(err, errTrafficMinuteSampleLimit) {
		t.Fatalf("aged slot could be uploaded again: %v", err)
	}
}

func TestTrafficMinuteSamplingSessionValidation(t *testing.T) {
	start := time.Now()
	session := Session{ID: "sampling-guard", Purpose: "traffic", PolicyAction: "observe", TrafficCollectionMode: "sampled", StartsAt: start, ExpiresAt: start.Add(time.Hour), Ports: []Port{{443, "tcp"}}, ObservationKinds: []string{captureAccepted}}
	policy := &Policy{Digest: "digest", Mode: "monitor", LearningTombstones: []Session{session}}
	if err := ValidatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Session{
		{Purpose: "policy", TrafficCollectionMode: "sampled", PolicyAction: "observe"},
		{Purpose: "traffic", TrafficCollectionMode: "unknown", PolicyAction: "observe"},
		{Purpose: "traffic", TrafficCollectionMode: "sampled", PolicyAction: "auto_allow"},
	} {
		bad := session
		bad.Purpose, bad.TrafficCollectionMode, bad.PolicyAction = invalid.Purpose, invalid.TrafficCollectionMode, invalid.PolicyAction
		policy.LearningTombstones[0] = bad
		if err := ValidatePolicy(policy); err == nil {
			t.Fatalf("invalid session admitted: %+v", bad)
		}
	}
}

func TestTrafficMinuteSamplingModeIsBoundByAssignmentSignature(t *testing.T) {
	start := time.Now()
	session := Session{ID: "sampling-signed", Purpose: "traffic", PolicyAction: "observe", TrafficCollectionMode: "sampled", StartsAt: start, ExpiresAt: start.Add(time.Hour), Ports: []Port{{443, "tcp"}}, ObservationKinds: []string{captureAccepted}}
	c, signed := signPolicyForTest(t, &Policy{Digest: "digest", Mode: "monitor", LearningSessions: []Session{session}}, start)
	if err := validatePolicySignatureAt(c, signed, start); err != nil {
		t.Fatal(err)
	}
	signed.LearningSessions[0].TrafficCollectionMode = ""
	if err := validatePolicySignatureAt(c, signed, start); err == nil {
		t.Fatal("unsigned removal of minute sampling was accepted")
	}
}

func TestTrafficMinuteSamplingDoesNotAffectOverlappingContinuousMonitor(t *testing.T) {
	stateDir := t.TempDir()
	start := time.Now().UTC().Truncate(time.Minute)
	firewall := newFirewallFake()
	monitor, err := NewHitMonitor(stateDir, "public", 5, firewall, false)
	if err != nil {
		t.Fatal(err)
	}
	assignment := HitMonitorAssignment{ID: "coincident-monitor", ServerID: "endpoint-one", StartsAt: start, ExpiresAt: start.Add(time.Minute), Ports: []Port{{443, "tcp"}}, ObservationKinds: []string{captureAccepted}}
	if err := monitor.SetAssignments(assignment.ServerID, []HitMonitorAssignment{assignment}, start); err != nil {
		t.Fatal(err)
	}
	if err := monitor.Tick(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	sampled := Session{ID: "sampled-traffic", Purpose: "traffic", PolicyAction: "observe", TrafficCollectionMode: "sampled", StartsAt: start, ExpiresAt: start.Add(time.Minute), Ports: assignment.Ports, ObservationKinds: assignment.ObservationKinds}
	a := &Agent{Config: Config{StateDir: stateDir, MaxSpoolBatches: 5}, State: State{Policy: &Policy{LearningSessions: []Session{sampled}}}, hitMonitor: monitor}
	observed := []capturedFlow{
		minuteSamplingTestFlow("192.0.2.9", 443, "tcp", captureAccepted, start.Add(time.Second)),
		minuteSamplingTestFlow("192.0.2.9", 443, "tcp", captureAccepted, start.Add(2*time.Second)),
	}
	if err := a.storeCapturedFlows(observed); err != nil {
		t.Fatal(err)
	}
	files, err := spoolFiles(filepath.Join(monitor.dir, "spool"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one continuous monitor batch: %v %v", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var batch HitBatch
	if err := json.Unmarshal(raw, &batch); err != nil || len(batch.Events) != 2 || validateHitBatch(batch) != nil {
		t.Fatalf("sampled discovery altered the continuous-monitor hit batch: %v %s", err, raw)
	}
	if observations := minuteSamplingTestBatches(t, filepath.Join(stateDir, "spool")); len(observations[sampled.ID]) != 1 {
		t.Fatalf("expected a single discovery sample: %+v", observations)
	}
}
