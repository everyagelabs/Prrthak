package agent

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func verificationFixture(t *testing.T) (*Agent, *managedFake, *Policy) {
	t.Helper()
	a, commands, protection := managedTestAgent(t)
	a.Client = &Client{}
	fixtureAuthenticatedClient(a, "host-a")
	a.policyVerificationTimestampAvailable = func() bool { return true }
	p := managedTestPolicy(protection, 1, "198.51.100.0/24")
	p.ServerID = "host-a"
	p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
	if err := a.applyManaged(context.Background(), p, protection); err != nil {
		t.Fatal(err)
	}
	protection = a.sourceBankProtection(context.Background())
	if !protection.Ready {
		t.Fatal(protection.Blockers)
	}
	a.protection = &protection
	if protection.Digest != p.Enforcement.ProtectionDigest {
		t.Fatal("fixture protection changed", protection)
	}
	now := time.Now().UTC()
	p.PolicyVerification = &PolicyVerificationAssignment{SchemaVersion: 1, ID: "verification-test-one", DeploymentID: "33333333-3333-4333-8333-333333333333", ServerID: p.ServerID, Version: p.Version, Digest: p.Digest, ApprovalID: p.Enforcement.ApprovalID, ProtectionDigest: protection.Digest, TargetIPsDigest: targetIPsDigest(a.inventory.IPs), StartsAt: now, ExpiresAt: now.Add(10 * time.Minute), WindowSeconds: 600, Ports: []Port{{18080, "tcp"}}}
	_, p = signPolicyForTest(t, p, now)
	a.State.Policy = p
	a.confirmed = true
	return a, commands, p
}

func verificationEvent(t *testing.T, a *Agent, allowed bool) capturedFlow {
	t.Helper()
	v := a.State.PolicyVerification
	if v == nil || v.Report.ArmedAt == nil {
		t.Fatal("fixture verification was not armed")
	}
	when := v.Report.ArmedAt.Add(time.Second)
	target := ""
	for _, value := range a.inventory.IPs {
		if address, err := netip.ParseAddr(value); err == nil && address.Is4() && !address.IsLoopback() {
			target = value
			break
		}
	}
	if target == "" {
		t.Skip("fixture needs one non-loopback native IPv4 address")
	}
	flow := capturedFlow{Flow: Flow{EventID: strings.Repeat("a", 64), SourceIP: "203.0.113.9", Port: 18080, Protocol: "tcp", Verdict: "denied", CaptureKind: captureDenied, CaptureBackend: "nflog", CountUnit: "packets", AddressFamily: "ipv4", Count: 1, FirstSeen: when, LastSeen: when}, DestinationIP: target, ReceivedAt: when, CaptureEpoch: "native-test-reader", RulePrefix: a.policyVerificationPrefix(Port{18080, "tcp"}, "ipv4")}
	if allowed {
		flow.SourceIP, flow.Verdict, flow.CaptureKind, flow.CaptureBackend, flow.CountUnit = "198.51.100.9", "allowed", captureAccepted, "conntrack", "connections"
		flow.ConnectionStartedAt = when.Add(-time.Millisecond)
		flow.RulePrefix = ""
	} else {
		flow.EventID = strings.Repeat("b", 64)
	}
	a.clock = func() time.Time { return when.Add(time.Millisecond) }
	return flow
}

func TestPolicyVerificationArmsOnlyAfterAppliedReadbackAndNeverMutatesPolicy(t *testing.T) {
	a, commands, p := verificationFixture(t)
	beforeRules := commands.mutations
	beforeBundle, _ := json.Marshal(a.State.ManagedBundle)
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	v := a.State.PolicyVerification
	if v == nil || !v.Confirmed || v.Report.State != "observing" || v.Report.AppliedGeneration != a.State.ManagedBundle.Generation || v.Report.CommittedAt == nil || len(a.policyVerificationScopes(a.currentTime())) != 2 {
		t.Fatal("incorrect armed receipt", v)
	}
	afterBundle, _ := json.Marshal(a.State.ManagedBundle)
	if commands.mutations != beforeRules || string(beforeBundle) != string(afterBundle) || len(a.State.Rules) != 0 || len(a.State.Policy.LearningSessions) != 0 {
		t.Fatal("verification changed access policy or started learning")
	}
}

func TestPolicyVerificationRequiresIndependentAllowAndDenyWitnesses(t *testing.T) {
	a, _, p := verificationFixture(t)
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	allow := verificationEvent(t, a, true)
	if !a.observePolicyVerification([]capturedFlow{allow}) || a.State.PolicyVerification.Report.Ports[0].Deny.Status != "awaiting" {
		t.Fatal("one accepted connection falsely verified deny")
	}
	a.updatePolicyVerification(a.currentTime(), nil)
	if a.State.PolicyVerification.Report.State != "observing" {
		t.Fatal("partially witnessed port marked fully verified")
	}
	deny := verificationEvent(t, a, false)
	if !a.observePolicyVerification([]capturedFlow{deny}) {
		t.Fatal("matching fresh terminal-deny witness ignored")
	}
	a.updatePolicyVerification(a.currentTime(), nil)
	if a.State.PolicyVerification.Report.State != "verified" || len(a.policyVerificationScopes(a.currentTime())) != 0 {
		t.Fatal("complete samples failed to stop observation")
	}
}

func TestPolicyVerificationRejectsOldLifecyclePrefixWrongSourceAndSelfTraffic(t *testing.T) {
	for _, name := range []string{"old-lifecycle", "no-birth", "pre-arm-receipt", "foreign-destination", "self-source", "old-deny-prefix", "allowed-source-denied", "unapproved-source-allowed"} {
		t.Run(name, func(t *testing.T) {
			a, _, p := verificationFixture(t)
			if err := a.preparePolicyVerification(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			allow := name != "old-deny-prefix" && name != "allowed-source-denied"
			flow := verificationEvent(t, a, allow)
			switch name {
			case "old-lifecycle":
				flow.ConnectionStartedAt = a.State.PolicyVerification.Report.ArmedAt.Add(-time.Second)
			case "no-birth":
				flow.ConnectionStartedAt = time.Time{}
			case "pre-arm-receipt":
				flow.ReceivedAt = a.State.PolicyVerification.Report.ArmedAt.Add(-time.Second)
			case "foreign-destination":
				flow.DestinationIP = "192.0.2.254"
			case "self-source":
				flow.SourceIP = flow.DestinationIP
			case "old-deny-prefix":
				flow.RulePrefix = "PRTN" + strings.Repeat("a", 16) + ":"
			case "allowed-source-denied":
				flow.SourceIP = "198.51.100.9"
			case "unapproved-source-allowed":
				flow.SourceIP = "203.0.113.9"
			}
			if a.observePolicyVerification([]capturedFlow{flow}) {
				t.Fatal("nonmatching/pre-arm traffic falsely verified a case")
			}
		})
	}
}

func TestPolicyVerificationMissingKernelBirthCapabilityIsUnavailableWithoutSysctlWrites(t *testing.T) {
	a, commands, p := verificationFixture(t)
	a.policyVerificationTimestampAvailable = func() bool { return false }
	before := commands.mutations
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	row := a.State.PolicyVerification.Report.Ports[0]
	if row.Allow.Status != "unavailable" || !strings.Contains(row.Allow.Reason, "net.netfilter.nf_conntrack_timestamp=1") || row.Deny.Status != "awaiting" || commands.mutations != before {
		t.Fatal("missing metadata fabricated proof or changed policy", row)
	}
	if scopes := a.policyVerificationScopes(a.currentTime()); len(scopes) != 1 || scopes[0].Kind != captureDenied {
		t.Fatal("missing allow capability suppressed the independent deny observer", scopes)
	}
	deny := verificationEvent(t, a, false)
	if !a.observePolicyVerification([]capturedFlow{deny}) {
		t.Fatal("valid terminal deny witness ignored with conntrack timestamps disabled")
	}
	a.updatePolicyVerification(a.currentTime(), nil)
	report := a.State.PolicyVerification.Report
	if report.State != "unavailable" || report.Ports[0].Allow.Status != "unavailable" || report.Ports[0].Deny.Status != "verified" {
		t.Fatal("independent deny witness incorrectly proved the whole rollout", report)
	}
}

func TestPolicyVerificationIdleExpiryAndProcessRestartDoNotChangeAppliedPolicy(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle-expiry", true: "restart"}[restart], func(t *testing.T) {
			a, commands, p := verificationFixture(t)
			if err := a.preparePolicyVerification(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			before := commands.mutations
			if restart {
				a.State.PolicyVerification.Confirmed = false
				if err := a.preparePolicyVerification(context.Background(), p); err != nil {
					t.Fatal(err)
				}
				if a.State.PolicyVerification.Report.State != "superseded" {
					t.Fatal("restart silently reused a prior observation epoch")
				}
			} else {
				a.updatePolicyVerification(p.PolicyVerification.ExpiresAt, nil)
				if a.State.PolicyVerification.Report.State != "expired" || a.State.PolicyVerification.Report.Ports[0].Allow.Status != "unverified" {
					t.Fatal("idle service fabricated success or remained active")
				}
			}
			if commands.mutations != before || a.State.AppliedVersion != 1 || len(a.policyVerificationScopes(a.currentTime())) != 0 {
				t.Fatal("diagnostic termination changed policy or retained instrumentation scope")
			}
		})
	}
}

func TestPolicyVerificationShutdownFencesPreviousEvidenceBeforeAnyNextReceipt(t *testing.T) {
	a, commands, p := verificationFixture(t)
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	before := commands.mutations
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	report := a.inventoryReport(context.Background(), a.currentTime())
	if report.PolicyVerification == nil || report.PolicyVerification.State != "superseded" || a.State.PolicyVerification.Confirmed || commands.mutations != before {
		t.Fatal("stopped/restarted observer could publish prior proof as current", report.PolicyVerification)
	}
}

func TestPolicyVerificationSSHManagementExceptionsAndFamilyUnionApplicability(t *testing.T) {
	p := &Policy{Mode: "enforce", Services: []Service{{Port: 22, Protocol: "tcp", Sources: []string{}}, {Port: 443, Protocol: "tcp", Sources: []string{"0.0.0.0/1", "128.0.0.0/1"}}}}
	protection := Protection{SSHPorts: []int{22}, ManagementSources: []string{"10.20.0.0/24"}}
	rows, sources := verificationCases(p, protection, []Port{{22, "tcp"}, {443, "tcp"}}, []string{"192.0.2.1"})
	if rows[0].Allow.Status != "not_applicable" || rows[0].Deny.Status != "awaiting" || rows[1].Allow.Status != "awaiting" || rows[1].Deny.Status != "not_applicable" {
		t.Fatal("incorrect effective source complement/family coverage", rows)
	}
	if !verificationSourceMatches(sources["tcp/22"], netip.MustParseAddr("10.20.0.5")) || verificationSourceMatches(sources["business/tcp/22"], netip.MustParseAddr("10.20.0.5")) {
		t.Fatal("SSH management exception became a business allow witness")
	}
}

func TestPolicyVerificationMonitorSourcesNeverExpandEnforcedCases(t *testing.T) {
	p := &Policy{Mode: "enforce", Services: []Service{{Port: 443, Protocol: "tcp", Mode: "enforce", Sources: []string{"10.0.0.0/8"}}, {Port: 443, Protocol: "tcp", Mode: "monitor", Sources: []string{"0.0.0.0/0"}}}}
	rows, sources := verificationCases(p, Protection{}, []Port{{443, "tcp"}}, []string{"192.0.2.10"})
	if rows[0].Deny.Status != "awaiting" || !reflect.DeepEqual(sources["business/tcp/443"], []string{"10.0.0.0/8"}) || verificationSourceMatches(sources["tcp/443"], netip.MustParseAddr("203.0.113.9")) {
		t.Fatal("monitor-only sources were treated as approved enforcement", rows, sources)
	}
}

func TestPolicyVerificationNormalCompletedLeaseWithdrawalKeepsHistoricalSuccess(t *testing.T) {
	a, _, p := verificationFixture(t)
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	a.observePolicyVerification([]capturedFlow{verificationEvent(t, a, true), verificationEvent(t, a, false)})
	a.updatePolicyVerification(a.currentTime(), nil)
	if a.State.PolicyVerification.Report.State != "verified" {
		t.Fatal("fixture was not complete")
	}
	sequence := a.State.PolicyVerification.Report.Sequence
	p.PolicyVerification = nil
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if a.State.PolicyVerification.Report.State != "verified" || a.State.PolicyVerification.Report.Sequence != sequence || len(a.policyVerificationScopes(a.currentTime())) != 0 {
		t.Fatal("normal completion withdrawal erased success or retained capture authority")
	}
}

func TestPolicyVerificationMonotonicDeadlineStopsCaptureDespiteBackwardWallClock(t *testing.T) {
	a, commands, p := verificationFixture(t)
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	a.State.PolicyVerification.Deadline = time.Now().Add(-time.Millisecond)
	wall := p.PolicyVerification.StartsAt.Add(-time.Hour)
	a.clock = func() time.Time { return wall }
	before := commands.mutations
	if len(a.policyVerificationScopes(wall)) != 0 || a.policyVerificationPrefix(Port{18080, "tcp"}, "ipv4") != "" {
		t.Fatal("backward clock extended a native or NFLOG renewal scope")
	}
	if !a.updatePolicyVerification(wall, nil) || a.State.PolicyVerification.Report.State != "expired" || commands.mutations != before {
		t.Fatal("hard diagnostic deadline did not expire independently of wall clock")
	}
}

func TestPolicyVerificationPythonSignedLeaseInterop(t *testing.T) {
	path := os.Getenv("PRTHAK_POLICY_VERIFICATION_PYTHON_FIXTURE")
	if path == "" {
		t.Skip("explicit temporary controller-generated public-trust fixture only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Policy            *Policy                      `json:"policy"`
		Assignment        PolicyVerificationAssignment `json:"assignment"`
		IPs               []string                     `json:"ips"`
		Protection        Protection                   `json:"protection"`
		Trust             policyTrust                  `json:"trust"`
		TrustDeploymentID string                       `json:"trust_deployment_id"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || fixture.Policy == nil || fixture.Policy.PolicyVerification == nil {
		t.Fatal("invalid public cross-language fixture", err)
	}
	a := &Agent{Config: Config{PolicySigningKeys: fixture.Trust.Keys, PolicySigningDeploymentID: fixture.TrustDeploymentID}, Client: &Client{}, inventory: &Report{IPs: fixture.IPs}}
	fixtureAuthenticatedClient(a, fixture.Policy.ServerID)
	if fixture.Assignment.DeploymentID == fixture.TrustDeploymentID {
		t.Fatal("fixture must distinguish rollout identity from controller signing identity")
	}
	if err := a.validatePolicyVerification(fixture.Policy, fixture.Policy.PolicyVerification, time.Now().UTC()); err != nil {
		t.Fatal("actual Python-signed lease was rejected by Go", err)
	}
	if err := validateEnforcement(fixture.Policy, fixture.Protection, time.Now().UTC()); err != nil {
		t.Fatal("actual Python-compiled approval or source binding differs from Go", err)
	}
	t.Log("Python Ed25519 envelope, bulk-run ID, exact lease and enforcement/protection binding accepted by Go")
}

func TestPolicyVerificationExactKnownOwnedRuleDuplicateIsReadOnly(t *testing.T) {
	a, commands, _ := verificationFixture(t)
	rule := a.State.ManagedBundle.Rules[0]
	before := commands.mutations
	journal := &managedJournal{Deadline: time.Now().Add(time.Minute)}
	if err := a.managedMutation(context.Background(), "unused-because-no-write", journal, "runtime", rule, true); err != nil || commands.mutations != before || !reflect.DeepEqual(journal.Mutations, []managedMutation(nil)) {
		t.Fatal("already present exact known owned rule was not bypassed", err)
	}
}

func TestPolicyVerificationAlreadyInstalledNewApprovalHasFreshReadbackWithoutNewCommit(t *testing.T) {
	a, commands, p := verificationFixture(t)
	oldCommit, oldApproval := a.State.ManagedBundle.CommittedAt, a.State.ManagedBundle.ApprovalID
	p.Enforcement.ApprovalID = "approval-new-readback"
	p.PolicyVerification.ApprovalID = p.Enforcement.ApprovalID
	_, p = signPolicyForTest(t, p, time.Now().UTC())
	a.State.Policy = p
	before := commands.mutations
	if err := a.applyManaged(context.Background(), p, *a.protection); err != nil {
		t.Fatal(err)
	}
	if !a.State.ManagedEnforcement.AlreadyPresent || a.State.ManagedEnforcement.ApprovalID != p.Enforcement.ApprovalID || a.State.ManagedBundle.ApprovalID != oldApproval || !a.State.ManagedBundle.CommittedAt.Equal(*oldCommit) || commands.mutations != before {
		t.Fatal("same exact owned policy was rewritten or its original commit was invented", a.State.ManagedEnforcement)
	}
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	receipt := a.State.PolicyVerification.Report
	if !a.State.ManagedEnforcement.AlreadyPresent || a.State.ManagedEnforcement.UpdatedAt.Before(p.PolicyVerification.StartsAt) || receipt.ArmedAt.Before(a.State.ManagedEnforcement.UpdatedAt) || !receipt.CommittedAt.Equal(*oldCommit) || commands.mutations != before {
		t.Fatal("verification lost fresh readback authority/timing or original commit", receipt)
	}
}

func TestPolicyVerificationReadbackAnchorSurvivesLaterSameGenerationPoll(t *testing.T) {
	a, commands, p := verificationFixture(t)
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	anchor := a.State.ManagedEnforcement.VerificationReadbackAt
	if anchor == nil || a.State.ManagedEnforcement.VerificationID != p.PolicyVerification.ID || anchor.After(*a.State.PolicyVerification.Report.ArmedAt) {
		t.Fatal("fresh lease-specific readback anchor missing")
	}
	before := commands.mutations
	if err := a.applyManaged(context.Background(), p, *a.protection); err != nil {
		t.Fatal(err)
	}
	a.enrichManagedStatus()
	if a.State.ManagedEnforcement.VerificationReadbackAt == nil || !a.State.ManagedEnforcement.VerificationReadbackAt.Equal(*anchor) || a.State.ManagedEnforcement.VerificationID != p.PolicyVerification.ID || commands.mutations != before {
		t.Fatal("ordinary same-generation readback lost the immutable lease anchor", a.State.ManagedEnforcement)
	}
}

func TestPolicyVerificationSSHProtectedTrafficCannotVerifyBusinessAllowOrDeny(t *testing.T) {
	a, _, p := verificationFixture(t)
	protection := *a.protection
	p.Version = 2
	p.Services = []Service{{Port: 2022, Protocol: "tcp", Mode: "enforce", Sources: []string{"198.51.100.0/24"}}}
	p.Digest, _ = compiledPolicyDigest(p)
	p.Enforcement.ApprovalID = "approval-ssh-verify"
	p.Enforcement.ApprovedVersion, p.Enforcement.ApprovedDigest = p.Version, p.Digest
	p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
	if err := a.applyManaged(context.Background(), p, protection); err != nil {
		t.Fatal(err)
	}
	p.PolicyVerification.Version, p.PolicyVerification.Digest, p.PolicyVerification.ApprovalID, p.PolicyVerification.Ports = p.Version, p.Digest, p.Enforcement.ApprovalID, []Port{{2022, "tcp"}}
	_, p = signPolicyForTest(t, p, time.Now().UTC())
	a.State.Policy = p
	if err := a.preparePolicyVerification(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	for _, allowed := range []bool{false, true} {
		flow := verificationEvent(t, a, allowed)
		flow.Port, flow.SourceIP = 2022, "10.20.0.55"
		flow.RulePrefix = a.policyVerificationPrefix(Port{2022, "tcp"}, "ipv4")
		if a.observePolicyVerification([]capturedFlow{flow}) {
			t.Fatal("protected SSH health traffic falsely verified business policy", allowed)
		}
	}
}

func TestPolicyVerificationRejectsUnsignedWrongEndpointOrUnboundedLeaseBeforeArming(t *testing.T) {
	for _, kind := range []string{"unsigned", "wrong-server", "wrong-deployment", "changed-targets", "unbounded", "duplicate-ports"} {
		t.Run(kind, func(t *testing.T) {
			a, commands, p := verificationFixture(t)
			switch kind {
			case "unsigned":
				p.Signature = nil
			case "wrong-server":
				p.PolicyVerification.ServerID = "other-endpoint"
			case "wrong-deployment":
				p.PolicyVerification.DeploymentID = ""
			case "changed-targets":
				p.PolicyVerification.TargetIPsDigest = strings.Repeat("b", 64)
			case "unbounded":
				p.PolicyVerification.ExpiresAt = p.PolicyVerification.StartsAt.Add(time.Hour)
			case "duplicate-ports":
				p.PolicyVerification.Ports = append(p.PolicyVerification.Ports, p.PolicyVerification.Ports[0])
			}
			if kind != "unsigned" {
				_, p = signPolicyForTest(t, p, time.Now().UTC())
			}
			before := commands.mutations
			if err := a.preparePolicyVerification(context.Background(), p); err == nil || a.State.PolicyVerification != nil || commands.mutations != before {
				t.Fatal("invalid diagnostic lease gained observer authority", err)
			}
		})
	}
}

func TestPolicyVerificationCrossLanguageReceiptGolden(t *testing.T) {
	base := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	ips := []string{"192.0.2.10", "2001:db8::10"}
	protection := Protection{Ready: true, Zone: "public", ManagementSources: []string{"203.0.113.8/32"}, SSHPorts: []int{22}, ControllerURL: "https://controller.example.internal:8788", ManagementProbeURL: "https://controller.example.internal:8788/api/v1/agent/enforcement/check", Blockers: []string{}}
	protection.Digest = protectionDigest(protection)
	policy := &Policy{ServerID: "golden-endpoint", Version: 42, Mode: "enforce", Services: []Service{{Port: 8443, Protocol: "tcp", Mode: "enforce", Sources: []string{"198.51.100.0/24"}}}}
	policy.Digest, _ = compiledPolicyDigest(policy)
	approvalID := "22222222-2222-4222-8222-222222222222"
	policy.Enforcement = &EnforcementAuthorization{Authorized: true, ApprovalID: approvalID, ApprovedDigest: policy.Digest, ApprovedVersion: policy.Version, ProtectionDigest: protection.Digest, ConfirmationCount: 2, ExpiresAt: base.Add(15 * time.Minute)}
	policy.Enforcement.BindingDigest = enforcementBinding(policy, protection.Digest)
	assignment := PolicyVerificationAssignment{SchemaVersion: 1, ID: "11111111-1111-4111-8111-111111111111", DeploymentID: "33333333-3333-4333-8333-333333333333", ServerID: policy.ServerID, Version: policy.Version, Digest: policy.Digest, ApprovalID: approvalID, ProtectionDigest: protection.Digest, TargetIPsDigest: targetIPsDigest(ips), Ports: []Port{{8443, "tcp"}}, StartsAt: base, ExpiresAt: base.Add(10 * time.Minute), WindowSeconds: 600}
	policy.PolicyVerification = &assignment
	_, policy = signPolicyForTest(t, policy, base)
	generation := strings.Repeat("a", 32)
	epoch := shaText("public-policy-verification-arm-fixture-v1")
	armed, committed, born := base.Add(2*time.Second), base.Add(-time.Minute), base.Add(2500*time.Millisecond)
	received, observed := base.Add(3001*time.Millisecond), base.Add(3*time.Second)
	allowed := &PolicyVerificationEvidence{EventID: shaText("public-allowed-event-v1"), SourceIP: "198.51.100.9", DestinationIP: ips[0], Port: 8443, Protocol: "tcp", AddressFamily: "ipv4", CaptureKind: captureAccepted, CaptureBackend: "conntrack", CountUnit: "connections", ExpectedAction: "allowed", ObservedAt: observed, ReceivedAt: received, CaptureEpoch: epoch, ConnectionStartedAt: &born}
	denied := &PolicyVerificationEvidence{EventID: shaText("public-denied-event-v1"), SourceIP: "203.0.113.9", DestinationIP: ips[0], Port: 8443, Protocol: "tcp", AddressFamily: "ipv4", CaptureKind: captureDenied, CaptureBackend: "nflog", CountUnit: "packets", ExpectedAction: "denied", ObservedAt: observed, ReceivedAt: received, CaptureEpoch: epoch, RulePrefix: verificationDeniedPrefix(assignment.ID, generation, epoch, "tcp", 8443, "ipv4")}
	receipt := verificationReceipt(assignment, base.Add(4*time.Second))
	receipt.State, receipt.Sequence, receipt.ArmedAt, receipt.CommittedAt, receipt.AppliedGeneration = "verified", 3, &armed, &committed, generation
	receipt.Ports = []PolicyVerificationPort{{Port: 8443, Protocol: "tcp", Allow: PolicyVerificationCase{Status: "verified", Reason: "One matching native post-arm sample.", Evidence: allowed}, Deny: PolicyVerificationCase{Status: "verified", Reason: "One matching native post-arm sample.", Evidence: denied}}}
	readbackAt := base.Add(time.Second)
	managed := ManagedEnforcement{VerificationID: assignment.ID, VerificationReadbackAt: &readbackAt, AlreadyPresent: true, Status: "enforced", Version: 42, Digest: policy.Digest, ApprovalID: approvalID, LastGoodVersion: 42, LastGoodDigest: policy.Digest, Generation: generation, CommittedAt: &committed, UpdatedAt: base.Add(time.Second)}
	raw, err := json.Marshal(receipt)
	if err != nil || !strings.Contains(string(raw), `"connection_started_at"`) || !strings.Contains(string(raw), `"rule_prefix":"PRTV`) {
		t.Fatal("golden receipt lost typed native provenance", err)
	}
	if output := os.Getenv("PRTHAK_POLICY_VERIFICATION_GOLDEN"); output != "" {
		if err := atomicJSON(output, map[string]any{"policy": policy, "protection": protection, "ips": ips, "managed_enforcement": managed, "receipt": receipt}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPolicyVerificationSourceMatchersShareEquivalentListsAndHandleCIDRBoundaries(t *testing.T) {
	sources := []string{"10.0.0.0/9", "10.128.0.0/9", "192.0.2.0/24", "2001:db8::/64"}
	matchers := verificationBuildMatchers(map[string][]string{"one": sources, "two": sources})
	if matchers["one"] != matchers["two"] || len(matchers["one"].ranges) != 3 {
		t.Fatal("equivalent lists did not share merged bounded ranges")
	}
	for _, value := range []string{"10.0.0.0", "10.255.255.255", "192.0.2.255", "2001:db8::1"} {
		if !matchers["one"].contains(netip.MustParseAddr(value)) {
			t.Fatal("approved boundary missed", value)
		}
	}
	for _, value := range []string{"9.255.255.255", "11.0.0.0", "192.0.3.0", "2001:db9::1"} {
		if matchers["one"].contains(netip.MustParseAddr(value)) {
			t.Fatal("source complement was incorrectly allowed", value)
		}
	}
}
