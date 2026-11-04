package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real Python Store/Entra-fixture/preview/discovery/ingest/signature vectors.
// This verifies wire/proof/IPv6/count semantics, not kernel collection or a DC.
func TestTrafficCapturePythonSignedInterop(t *testing.T) {
	raw, err := os.ReadFile("../../../controller/tests/fixtures/traffic-capture-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SchemaVersion int `json:"schema_version"`
		Cases         []struct {
			Name           string                 `json:"name"`
			Legacy         bool                   `json:"legacy"`
			At             int64                  `json:"at"`
			Trust          policyTrust            `json:"trust"`
			Policy         json.RawMessage        `json:"policy"`
			EndpointIPs    []string               `json:"endpoint_ips"`
			Protection     Protection             `json:"protection"`
			Certificate    string                 `json:"certificate_pem"`
			EndpointCA     string                 `json:"endpoint_ca_pem"`
			NativeEvents   []Flow                 `json:"native_events"`
			LearningEvents []Flow                 `json:"learning_events"`
			MonitorEvents  []HitEvent             `json:"monitor_events"`
			Coverage       TrafficCaptureCoverage `json:"coverage"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil || vector.SchemaVersion != 1 || len(vector.Cases) != 4 {
		t.Fatal("invalid real backend capture vector", err)
	}
	for _, item := range vector.Cases {
		t.Run(item.Name, func(t *testing.T) {
			at := time.Unix(item.At, 0).UTC()
			c := defaultConfig()
			c.Enforce, c.LearningAutoAllow = true, true
			c.PolicySigningTrustFile = ""
			c.PolicySigningDeploymentID, c.PolicySigningKeys = item.Trust.DeploymentID, item.Trust.Keys
			c.StateDir = t.TempDir()
			var policy Policy
			if json.Unmarshal(item.Policy, &policy) != nil {
				t.Fatal("invalid delivered policy")
			}
			if err := validatePolicySignatureAt(c, &policy, at); err != nil {
				t.Fatal("Python signature did not bind capture fields", err)
			}
			if err := ValidatePolicy(&policy); err != nil {
				t.Fatal("Python capture scope is not a valid native assignment", err)
			}
			block, _ := pem.Decode([]byte(item.Certificate))
			if block == nil {
				t.Fatal("missing public endpoint identity")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(item.EndpointCA)) {
				t.Fatal("missing fixture endpoint issuer")
			}
			if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatal(err)
			}
			a := &Agent{Config: c, State: State{Policy: &policy}, Client: &Client{}, inventory: &Report{IPs: item.EndpointIPs}}
			a.Client.identity = &atomic.Pointer[tls.Certificate]{}
			a.Client.identity.Store(&tls.Certificate{Leaf: leaf})
			if err := a.validateAssignmentIdentity(&policy); err != nil {
				t.Fatal("signed capture authority is not endpoint-bound", err)
			}
			wrong := policy
			wrong.ServerID = "other-endpoint"
			if a.validateAssignmentIdentity(&wrong) == nil {
				t.Fatal("capture authority changed endpoint")
			}
			if len(policy.LearningSessions) != 1 || len(policy.HitMonitors) != 1 {
				t.Fatal("real backend omitted selected session or monitor")
			}
			session, monitor := policy.LearningSessions[0], policy.HitMonitors[0]
			if err := validateHitAssignment(monitor, policy.ServerID, at, true); err != nil {
				t.Fatal("real bucketed monitor lease rejected", err)
			}
			if item.Legacy {
				if session.ObservationKinds != nil || monitor.ObservationKinds != nil {
					t.Fatal("historical omitted kinds were upgraded")
				}
				for _, flow := range item.LearningEvents {
					if flow.CaptureKind != "" || flow.CountUnit != "" || flow.Count != 7 || validTypedCapture(flow, flow.EventID) {
						t.Fatal("legacy verdict strings became typed connection/packet evidence")
					}
				}
				return
			}
			if captureKindsKey(session.ObservationKinds) != captureKindsKey(monitor.ObservationKinds) {
				t.Fatal("learning and monitor selected kind schemas differ")
			}
			if policy.LearningAllow == nil || !policy.LearningAllow.Authorized || len(policy.LearningAllow.Authorities) != 1 {
				t.Fatal("current Admin automatic-learning authority was not delivered")
			}
			authority := policy.LearningAllow.Authorities[0]
			if captureKindsKey(authority.ObservationKinds) != captureKindsKey(session.ObservationKinds) {
				t.Fatal("automatic authority lost capture selection")
			}
			if err := validateEndpointApproval(c, authority.ApprovalProof, policy.ServerID, at, false, "learning"); err != nil {
				t.Fatal("Python current Admin proof", err)
			}
			for _, event := range item.LearningEvents {
				if !validTypedCapture(event, event.EventID) {
					t.Fatal("actual Python-admitted typed evidence rejected by native shape", event)
				}
				rememberLearningEvidence(&a.State, session, event)
			}
			if err := a.validateLearningAssignment(policy.LearningAllow, item.Protection); err != nil {
				t.Fatal("IPv4/IPv6 source/endpoint/config digest parity", err)
			}
			if err := a.validateLearningDelta(policy.LearningAllow, at); err != nil {
				t.Fatal("actual Python source grants do not match local ingress evidence", err)
			}
			bad := *policy.LearningAllow
			bad.Authorities = append([]LearningAuthority{}, bad.Authorities...)
			bad.Authorities[0].ObservationKinds = []string{"invalid_kind"}
			if a.validateLearningDelta(&bad, at) == nil {
				t.Fatal("changed authority capture kinds reused original local evidence")
			}
			for _, field := range []string{"session", "monitor", "authority"} {
				var changed Policy
				json.Unmarshal(item.Policy, &changed)
				switch field {
				case "session":
					changed.LearningSessions[0].ObservationKinds = []string{"invalid_kind"}
				case "monitor":
					changed.HitMonitors[0].ObservationKinds = []string{"invalid_kind"}
				case "authority":
					changed.LearningAllow.Authorities[0].ObservationKinds = []string{"invalid_kind"}
				}
				if validatePolicySignatureAt(c, &changed, at) == nil {
					t.Fatal("capture field escaped signed payload binding", field)
				}
			}
			if len(item.Coverage.Backends) != 2 || item.Coverage.Backends[0].LostEvents != nil || item.Coverage.Backends[1].Status != "unsupported" {
				t.Fatal("unknown losses or unsupported capture were converted into success")
			}
			m, err := NewHitMonitor(c.StateDir, "public", 16, &journalBudgetNoCommands{}, false)
			if err != nil {
				t.Fatal(err)
			}
			m.state.Grants = []hitGrant{{Assignment: monitor, CaptureFrom: monitor.StartsAt, CaptureUntil: monitor.ExpiresAt}}
			a.hitMonitor = m
			flows := []capturedFlow{}
			for _, flow := range item.NativeEvents {
				if !validTypedCapture(flow, flow.EventID) || !captureKindSelected(session.ObservationKinds, flow.CaptureKind) {
					t.Fatal("native vector scope or typed shape changed")
				}
				flows = append(flows, capturedFlow{Flow: flow, DestinationIP: item.EndpointIPs[0]})
			}
			if err := a.storeCapturedFlows(flows); err != nil {
				t.Fatal(err)
			}
			paths, err := spoolFiles(filepath.Join(c.StateDir, "spool"))
			if err != nil || len(paths) != 1 {
				t.Fatal("typed learning did not create one bounded batch", err)
			}
			var learningBatch Batch
			encoded, _ := os.ReadFile(paths[0])
			if json.Unmarshal(encoded, &learningBatch) != nil || !reflect.DeepEqual(learningBatch.Events, item.LearningEvents) {
				t.Fatal("native learning spool differs from actual Python-admitted evidence")
			}
			paths, err = spoolFiles(filepath.Join(m.dir, "spool"))
			if err != nil || len(paths) != 1 {
				t.Fatal("typed monitor did not create one bounded batch", err)
			}
			var hitBatch HitBatch
			encoded, _ = os.ReadFile(paths[0])
			if json.Unmarshal(encoded, &hitBatch) != nil || validateHitBatch(hitBatch) != nil || !reflect.DeepEqual(hitBatch.Events, item.MonitorEvents) {
				t.Fatal("native monitor spool differs from actual Python-admitted evidence")
			}
			for _, flow := range learningBatch.Events {
				if flow.AddressFamily == "ipv6" && !strings.Contains(flow.SourceIP, ":") {
					t.Fatal("IPv6 event changed address family during spooling")
				}
			}
			// The collector may replay a persisted boundary after a crash. Its
			// exact stable event/batch IDs must reuse the same two spool files.
			if err := a.storeCapturedFlows(flows); err != nil {
				t.Fatal(err)
			}
			files, _ := spoolFiles(filepath.Join(c.StateDir, "spool"))
			if len(files) != 1 {
				t.Fatal("exact learning replay created a second batch")
			}
			files, _ = spoolFiles(filepath.Join(m.dir, "spool"))
			if len(files) != 1 {
				t.Fatal("exact monitor replay created a second batch")
			}
		})
	}
}

func TestTrafficMinuteSamplingPythonSignedInterop(t *testing.T) {
	raw, err := os.ReadFile("../../../controller/tests/fixtures/traffic-minute-sampling-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		At           int64       `json:"at"`
		Trust        policyTrust `json:"trust"`
		Policy       Policy      `json:"policy"`
		NativeEvents []Flow      `json:"native_events"`
		Receipts     []struct {
			DuplicateEvents int `json:"duplicate_events"`
		} `json:"receipts"`
		FlowRows []Flow `json:"flow_rows"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.NativeEvents) != 3 || len(fixture.Receipts) != 4 || len(fixture.FlowRows) != 1 ||
		fixture.Receipts[1].DuplicateEvents != 1 || fixture.Receipts[3].DuplicateEvents != 2 ||
		fixture.FlowRows[0].CountUnit != "sample_minutes" || fixture.FlowRows[0].Count != 2 {
		t.Fatalf("Python did not retain two unique minutes across retries: %+v", fixture.FlowRows)
	}
	c := Config{Enforce: true, StateDir: t.TempDir(), MaxSpoolBatches: 5,
		PolicySigningDeploymentID: fixture.Trust.DeploymentID, PolicySigningKeys: fixture.Trust.Keys}
	if err := validatePolicySignatureAt(c, &fixture.Policy, time.Unix(fixture.At, 0)); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicy(&fixture.Policy); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Policy.LearningSessions) != 1 || fixture.Policy.LearningSessions[0].TrafficCollectionMode != "sampled" {
		t.Fatal("signed Python assignment lost its sampled mode")
	}
	session := fixture.Policy.LearningSessions[0]
	flows := make([]capturedFlow, 0, len(fixture.NativeEvents))
	for _, event := range fixture.NativeEvents {
		flows = append(flows, capturedFlow{Flow: event})
	}
	for i := 0; i < 2; i++ {
		// A restart loses the in-memory cache, but exact replay preserves IDs
		// and reuses the private spool batch instead of appending another batch.
		a := &Agent{Config: c, State: State{Policy: &fixture.Policy}}
		if err := a.storeCapturedFlows(flows); err != nil {
			t.Fatal(err)
		}
	}
	spooled := minuteSamplingTestBatches(t, filepath.Join(c.StateDir, "spool"))[session.ID]
	if len(spooled) != 2 || spooled[0].EventID != trafficSampleID(session.ID, fixture.NativeEvents[0]) ||
		spooled[1].EventID != trafficSampleID(session.ID, fixture.NativeEvents[2]) ||
		!validTypedCapture(spooled[0], spooled[0].EventID) || !validTypedCapture(spooled[1], spooled[1].EventID) {
		t.Fatalf("agent did not preserve typed evidence and stable identity for each sampled minute: %+v", spooled)
	}
}

func TestTrafficCaptureTypedKindsRemainDifferentCountUnits(t *testing.T) {
	kinds := []string{captureAccepted, captureDenied}
	sort.Strings(kinds)
	if captureKindsKey(kinds) != "accepted_connection,denied_packet" {
		t.Fatal("capture kind canonicalization changed")
	}
	at := time.Now().UTC()
	accepted := Flow{SourceIP: "2001:db8::44", AddressFamily: "ipv6", CaptureKind: captureAccepted,
		CaptureBackend: "conntrack", CountUnit: "connections", Verdict: "allowed", Count: 1, FirstSeen: at, LastSeen: at}
	if !validTypedCapture(accepted, strings.Repeat("a", 64)) {
		t.Fatal("standard IPv6 connection event rejected")
	}
	for _, mutation := range []string{"packets", "ipv4", "mapped", "scoped", "count"} {
		flow := accepted
		switch mutation {
		case "packets":
			flow.CountUnit = "packets"
		case "ipv4":
			flow.AddressFamily = "ipv4"
		case "mapped":
			flow.SourceIP = "::ffff:192.0.2.1"
		case "scoped":
			flow.SourceIP = "fe80::1%eth0"
		case "count":
			flow.Count = 2
		}
		if validTypedCapture(flow, strings.Repeat("a", 64)) {
			t.Fatal("typed evidence silently changed unit/family/meaning", mutation)
		}
	}
}

func TestTrafficCaptureConntrackDedupDoesNotRecountQuietLifecycle(t *testing.T) {
	started := time.Unix(1800000000, 0).UTC()
	a := conntrackRecord{id: 1, status: 8, started: 100,
		original: conntrackTuple{source: netip.MustParseAddr("2001:db8:20::44"),
			destination: netip.MustParseAddr("2001:db8:10::1"), sourcePort: 40123, destinationPort: 443, protocol: 17}}
	b := a
	b.id = 2
	dedup := conntrackDedup{limit: 1}
	if count, _ := dedup.observe(a, false, started); !count {
		t.Fatal("first accepted IPv6 lifecycle was not observed")
	}
	// A is quiet but has no DESTROY: it is still the same accepted lifecycle.
	// Saturation may cause a coverage gap for B, but must not recount A later.
	_, _ = dedup.observe(b, false, started.Add(16*time.Minute))
	if count, _ := dedup.observe(a, false, started.Add(32*time.Minute)); count {
		t.Fatal("quiet lifecycle was recounted with the same event_id and a different timestamp; backend would refuse the identity conflict")
	}
}
