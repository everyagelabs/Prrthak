package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func networkTestProof(kind, id, digest string) json.RawMessage {
	proof := singleAdminProofFixture()
	proof.PlanID = id
	proof.PlanDigest = digest
	proof.Scope["kind"], _ = json.Marshal(kind)
	return sealDirectApproval(proof)
}
func networkTestEgress(now time.Time) *EgressAssignment {
	r := &EgressAssignment{SchemaVersion: 1, ID: "outbound-test", Generation: 1, Operation: "apply", ProtectionDigest: strings.Repeat("b", 64), ContextDigest: strings.Repeat("c", 64), IssuedAt: now, ApprovalExpiresAt: now.Add(15 * time.Minute), DowntimeAck: true, DefaultDeny: false, Services: []EgressService{{Port: 443, Protocol: "tcp", Destinations: []string{"192.0.2.0/24", "2001:db8:1::/64"}}}}
	r.PlanDigest = descriptorDigest(r)
	r.ApprovalProof = networkTestProof("egress_policy", r.ID, r.PlanDigest)
	return r
}
func networkTestQuarantine(now time.Time) *QuarantineAssignment {
	r := &QuarantineAssignment{SchemaVersion: 1, ID: "isolation-test", Generation: 1, Operation: "enable", ProtectionDigest: strings.Repeat("b", 64), ContextDigest: strings.Repeat("c", 64), IssuedAt: now, ApprovalExpiresAt: now.Add(15 * time.Minute), DowntimeAck: true, ExpiresAt: now.Add(time.Hour)}
	r.PlanDigest = descriptorDigest(r)
	r.ApprovalProof = networkTestProof("emergency_quarantine", r.ID, r.PlanDigest)
	return r
}
func networkTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{StateDir: t.TempDir(), Enforce: true, AllowFirewallChanges: true, AllowHostDefaultDeny: true, ControllerURL: "https://controller.example.test:8787", ManagementSources: []string{"10.90.0.0/24"}, ProtectedSSHPorts: []int{22}}
}

func TestNetworkControlPythonDescriptorAndSingleAdminProofInterop(t *testing.T) {
	raw, err := os.ReadFile("../../../controller/tests/fixtures/network-control-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ServerID   string                `json:"server_id"`
		IssuedAt   time.Time             `json:"issued_at"`
		Egress     *EgressAssignment     `json:"egress_bundle"`
		Quarantine *QuarantineAssignment `json:"quarantine"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	c := networkTestConfig(t)
	now := fixture.IssuedAt.Add(time.Second)
	if err := validateEgressAssignment(c, fixture.ServerID, fixture.Egress, now); err != nil {
		t.Fatal("Python outbound descriptor/proof", err)
	}
	if err := validateQuarantineAssignment(c, fixture.ServerID, fixture.Quarantine, now); err != nil {
		t.Fatal("Python quarantine descriptor/proof", err)
	}
	for _, change := range []func(*Config){func(c *Config) { c.Enforce = false }, func(c *Config) { c.AllowFirewallChanges = false }, func(c *Config) { c.AllowHostDefaultDeny = false }} {
		copy := c
		change(&copy)
		if validateEgressAssignment(copy, fixture.ServerID, fixture.Egress, now) == nil || validateQuarantineAssignment(copy, fixture.ServerID, fixture.Quarantine, now) == nil {
			t.Fatal("one local opt-in elevated another")
		}
	}
	if validateQuarantineAssignment(c, "foreign-server", fixture.Quarantine, now) == nil {
		t.Fatal("foreign endpoint accepted")
	}
}

func TestNetworkControlAssessmentRemainsReadOnlyAndMutationsBindTypedDescriptors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := networkTestConfig(t)
	request := networkTestEgress(now)
	request.Operation = "assess"
	request.DowntimeAck = false
	request.PlanDigest = descriptorDigest(request)
	request.ApprovalProof = networkTestProof("egress_policy", request.ID, request.PlanDigest)
	c.Enforce = false
	c.AllowFirewallChanges = false
	c.AllowHostDefaultDeny = false
	if err := validateEgressAssignment(c, "host-a", request, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*EgressAssignment){func(r *EgressAssignment) { r.Services[0].Destinations = []string{"192.0.2.4/24"} }, func(r *EgressAssignment) { r.Services[0].Port = 0 }, func(r *EgressAssignment) { r.Services[0].Protocol = "icmp" }, func(r *EgressAssignment) { r.Services[0].Destinations = []string{"::ffff:192.0.2.0/120"} }, func(r *EgressAssignment) { r.Services = make([]EgressService, 65) }} {
		r := networkTestEgress(now)
		change(r)
		r.PlanDigest = descriptorDigest(r)
		r.ApprovalProof = networkTestProof("egress_policy", r.ID, r.PlanDigest)
		if validateEgressAssignment(networkTestConfig(t), "host-a", r, now.Add(time.Second)) == nil {
			t.Fatal("unsafe outbound descriptor accepted")
		}
	}
	q := networkTestQuarantine(now)
	q.ExpiresAt = now.Add(time.Hour + time.Second)
	q.PlanDigest = descriptorDigest(q)
	q.ApprovalProof = networkTestProof("emergency_quarantine", q.ID, q.PlanDigest)
	if validateQuarantineAssignment(networkTestConfig(t), "host-a", q, now.Add(time.Second)) == nil {
		t.Fatal("unbounded quarantine accepted")
	}
}

func TestNetworkControlProofKindsCannotBorrowBulkOrInboundAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := networkTestConfig(t)
	r := networkTestEgress(now)
	proof := singleAdminProofFixture()
	proof.PlanID = r.ID
	proof.PlanDigest = r.PlanDigest
	proof.Scope["kind"] = json.RawMessage(`"egress_policy"`)
	proof.Scope["server_ids"] = json.RawMessage(`["host-a","host-b"]`)
	r.ApprovalProof = sealDirectApproval(proof)
	if validateEgressAssignment(c, "host-a", r, now.Add(time.Second)) == nil {
		t.Fatal("network authority accepted multiple future-capable endpoints")
	}
	delete(proof.Scope, "server_ids")
	proof.Scope["target_count"] = json.RawMessage(`1`)
	proof.Scope["target_digest"] = json.RawMessage(`"` + strings.Repeat("a", 64) + `"`)
	r.ApprovalProof = sealDirectApproval(proof)
	if validateEgressAssignment(c, "host-a", r, now.Add(time.Second)) == nil {
		t.Fatal("network authority accepted an opaque aggregate scope")
	}
	r.ApprovalProof = networkTestProof("managed_policy", r.ID, r.PlanDigest)
	if validateEgressAssignment(c, "host-a", r, now.Add(time.Second)) == nil {
		t.Fatal("inbound approval authorized outbound writes")
	}
}

func TestOutboundRulesProtectControlDNSAndSSHWithoutChangingUnselectedPorts(t *testing.T) {
	now := time.Now().UTC()
	r := networkTestEgress(now)
	protected := []ProtectedEgress{{Destination: "10.10.0.10/32", Port: 8787, Protocol: "tcp", Kind: "controller"}, {Destination: "10.10.0.53/32", Port: 53, Protocol: "udp", Kind: "dns"}}
	rules, err := egressRichRules(r, protected, []string{"10.90.0.0/24"}, []int{22, 2022})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, `source-port port="2022"`) || !strings.Contains(joined, `port port="8787"`) || !strings.Contains(joined, `port port="53"`) {
		t.Fatal("protected management routes missing")
	}
	for _, rule := range rules {
		if strings.HasSuffix(rule, " reject") && !strings.Contains(rule, `port port="443"`) {
			t.Fatal("default-false outbound plan blocked unrelated ports")
		}
	}
	r.Services = append(r.Services, r.Services[0])
	duplicate, _ := egressRichRules(r, protected, []string{"10.90.0.0/24"}, []int{22, 2022})
	if strings.Join(rules, "\n") != strings.Join(duplicate, "\n") {
		t.Fatal("duplicate rule wasn't bypassed")
	}
	r.DefaultDeny = true
	all, _ := egressRichRules(r, protected, []string{"10.90.0.0/24"}, []int{22})
	if !strings.Contains(strings.Join(all, "\n"), `priority="32760" reject`) {
		t.Fatal("explicit whole-output deny missing")
	}
}

func networkTestPlan(now time.Time) quarantinePlan {
	return quarantinePlan{Nonce: strings.Repeat("a", 32), ExpiresAt: now.Add(time.Hour), LeaseSeconds: 3600, Protected: []ProtectedEgress{{Destination: "10.10.0.10/32", Port: 8787, Protocol: "tcp", Kind: "controller"}, {Destination: "2001:db8::10/128", Port: 8787, Protocol: "tcp", Kind: "controller"}, {Destination: "10.10.0.53/32", Port: 53, Protocol: "udp", Kind: "dns"}}, ManagementSources: []string{"10.90.0.0/24", "2001:db8:90::/64"}, SSHPorts: []int{22, 2022}}
}

func TestQuarantineTypedEarlyHooksCoverExistingIPv4IPv6AndIndependentSecondsLease(t *testing.T) {
	now := time.Now().UTC()
	plan := networkTestPlan(now)
	objects, err := quarantineNFTObjects(plan, 900*time.Second+950*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	chains := 0
	sets := 0
	for _, object := range objects {
		if row, ok := object["chain"].(map[string]any); ok {
			chains++
			if row["prio"] != -301 {
				t.Fatal("quarantine did not precede established connection accepts")
			}
		}
		if row, ok := object["set"].(map[string]any); ok {
			sets++
			if row["timeout"] != int64(900) {
				t.Fatal("nft JSON timeouts must be seconds and must round down")
			}
		}
	}
	if chains != 3 || sets != 2 {
		t.Fatal("host input/output/forward or IPv4/IPv6 coverage omitted")
	}
	raw, err := quarantineNFTBatch(objects, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, danger := range []string{"established", "conntrack", "flush", "restart", "--reload"} {
		if strings.Contains(string(raw), danger) {
			t.Fatal("quarantine included bypass, connection flush or service restart")
		}
	}
	if !strings.Contains(string(raw), `"create"`) {
		t.Fatal("nonexclusive owned table creation")
	}
	if _, err := quarantineNFTBatch(nil, "untrusted"); err == nil {
		t.Fatal("unbound table deletion accepted")
	}
	if _, err := quarantineNFTObjects(plan, time.Hour+time.Second); err == nil {
		t.Fatal("kernel lease exceeded one hour")
	}
}

type networkFirewallFake struct {
	rules       map[string]map[string]bool
	marker      egressTemplate
	objects     []map[string]any
	handle      int
	created     time.Time
	calls       []string
	writes      int
	rejectWrite int
	rejectDry   bool
	foreign     bool
}

func newNetworkFirewallFake() *networkFirewallFake {
	return &networkFirewallFake{rules: map[string]map[string]bool{"runtime": {}, "permanent": {}}, marker: canonicalEgressTemplate(strings.Repeat("e", 32)), handle: 10}
}
func (f *networkFirewallFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == "firewall-cmd" {
		scope := "runtime"
		if len(args) > 0 && args[0] == "--permanent" {
			scope = "permanent"
			args = args[1:]
		}
		if len(args) != 2 || args[0] != "--policy="+egressPolicyName {
			return "", errors.New("unexpected firewall command")
		}
		switch args[1] {
		case "--get-short":
			return f.marker.Short, nil
		case "--get-description":
			return f.marker.Description, nil
		case "--list-all":
			text := egressPolicyName + " (active)\n  priority: -30000\n  target: CONTINUE\n  ingress-zones: HOST\n  egress-zones: ANY\n  services:\n  ports:\n  protocols:\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
			for _, rule := range networkStringSet(mapKeys(f.rules[scope])) {
				text += "    " + rule + "\n"
			}
			return text, nil
		}
		for _, operation := range []string{"--query-rich-rule=", "--add-rich-rule=", "--remove-rich-rule="} {
			if strings.HasPrefix(args[1], operation) {
				rule := strings.TrimPrefix(args[1], operation)
				if operation == "--query-rich-rule=" {
					if f.rules[scope][rule] {
						return "yes", nil
					}
					return "no", errors.New("absent")
				}
				f.writes++
				if f.rejectWrite == f.writes {
					return "", errors.New("injected mutation failure")
				}
				if operation == "--add-rich-rule=" {
					f.rules[scope][rule] = true
				} else {
					delete(f.rules[scope], rule)
				}
				return "success", nil
			}
		}
		return "", errors.New("unexpected policy operation")
	}
	if name == "nft" && strings.Join(args, " ") == "-j -a list table inet "+quarantineTableName {
		if len(f.objects) == 0 {
			return "Error: No such file or directory", errors.New("absent")
		}
		objects, _ := normalizeQuarantineObjects(f.objects)
		for _, object := range objects {
			if table, ok := object["table"].(map[string]any); ok {
				table["handle"] = json.Number(strconv.Itoa(f.handle))
				if f.foreign {
					table["comment"] = "foreign owner"
				}
			}
			if set, ok := object["set"].(map[string]any); ok {
				seconds, _ := counterDecimal(set["timeout"])
				n, _ := strconv.Atoi(seconds)
				remaining := n - int(time.Since(f.created).Seconds())
				if remaining <= 0 {
					set["elem"] = []any{}
				} else {
					for _, item := range set["elem"].([]any) {
						item.(map[string]any)["elem"].(map[string]any)["expires"] = remaining
					}
				}
			}
		}
		raw, _ := json.Marshal(map[string]any{"nftables": objects})
		return string(raw), nil
	}
	if name == "nft" {
		check := len(args) > 0 && args[0] == "-c"
		if check {
			args = args[1:]
			if f.rejectDry {
				return "", errors.New("unsupported kernel feature")
			}
		}
		if len(args) != 3 || args[0] != "-j" || args[1] != "-f" {
			return "", errors.New("unexpected native writer")
		}
		raw, err := os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
		document, err := counterJSON(string(raw))
		if err != nil {
			return "", err
		}
		candidate := append([]map[string]any{}, f.objects...)
		for _, value := range document["nftables"].([]any) {
			command := value.(map[string]any)
			for verb, item := range command {
				object := item.(map[string]any)
				switch verb {
				case "delete":
					table := object["table"].(map[string]any)
					handle, _ := counterDecimal(table["handle"])
					if table["family"] != "inet" || handle != strconv.Itoa(f.handle) || len(candidate) == 0 {
						return "", errors.New("wrong table handle")
					}
					candidate = nil
				case "create":
					if len(candidate) != 0 {
						return "", errors.New("exclusive table collision")
					}
					candidate = append(candidate, object)
				case "add":
					candidate = append(candidate, object)
				default:
					return "", errors.New("arbitrary nft command rejected")
				}
			}
		}
		if !check {
			f.writes++
			if f.rejectWrite == f.writes {
				return "", errors.New("injected nft transaction failure")
			}
			f.objects = candidate
			f.handle++
			f.created = time.Now()
		}
		return "", nil
	}
	return "", errors.New("unexpected native test command")
}
func mapKeys(values map[string]bool) []string {
	result := []string{}
	for key := range values {
		result = append(result, key)
	}
	return result
}

func networkEngineFixture(t *testing.T) (*networkControlEngine, *networkFirewallFake, *int) {
	t.Helper()
	c := networkTestConfig(t)
	fake := newNetworkFirewallFake()
	if err := atomicJSON(egressTemplatePath(c.StateDir), fake.marker); err != nil {
		t.Fatal(err)
	}
	health := 0
	engine := &networkControlEngine{Commands: fake, Config: c, Now: func() time.Time { return time.Now().UTC() }, Assess: func(context.Context) (networkNativeContext, error) {
		return networkNativeContext{Report: NetworkControlReport{SchemaVersion: 1, CheckedAt: time.Now().UTC(), ContextDigest: strings.Repeat("c", 64), ProtectionDigest: strings.Repeat("b", 64), ConfigurationDigest: configDigest(c), ProtectedEgress: []ProtectedEgress{{Destination: "10.10.0.10/32", Port: 8787, Protocol: "tcp", Kind: "controller"}}, Blockers: []string{}, Egress: NetworkFeatureReport{Supported: true, Ready: true}, Quarantine: NetworkFeatureReport{Supported: true, Ready: true}}, Protection: Protection{Ready: true, Digest: strings.Repeat("b", 64), ManagementSources: []string{"10.90.0.0/24"}, SSHPorts: []int{22}}}, nil
	}, Health: func(context.Context, networkControlRequest, networkNativeContext) error { health++; return nil }, Arm: func(context.Context, string, *networkControlJournal, bool) error { return nil }, PrepareBoot: func(context.Context) error { return nil }}
	return engine, fake, &health
}

func TestOutboundNativeSafeApplyReadbackDuplicateNoOpAndNoReload(t *testing.T) {
	engine, fake, health := networkEngineFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	request := networkTestEgress(now)
	if _, err := engine.process(context.Background(), nil, egressRequest(request)); err != nil {
		t.Fatal(err)
	}
	state, err := readNetworkState(engine.Config.StateDir)
	if err != nil || state.Egress == nil || len(state.EgressRules) == 0 || *health != 2 {
		t.Fatal("native apply/readback/fresh witnesses missing", err)
	}
	firstWrites := fake.writes
	copy := *request
	copy.ID = "duplicate-plan"
	copy.Generation = 2
	copy.PlanDigest = descriptorDigest(&copy)
	if _, err := engine.process(context.Background(), nil, egressRequest(&copy)); err != nil {
		t.Fatal(err)
	}
	if fake.writes != firstWrites {
		t.Fatal("identical rule was rewritten instead of bypassed")
	}
	report := ReadNetworkControlReport(engine.Config.StateDir)
	if report.Egress.Status != "enforced" || !report.Egress.Active || report.Egress.ActiveID != copy.ID {
		t.Fatal("confirmed owned active state missing")
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "reload") || strings.Contains(call, "restart") {
			t.Fatal("normal outbound update restarted/reloaded firewalld")
		}
	}
}

func TestOutboundFailureAndWatchdogArmFailureNeverReportSuccessfulApply(t *testing.T) {
	for _, stage := range []string{"mutation", "health", "timer"} {
		t.Run(stage, func(t *testing.T) {
			engine, fake, _ := networkEngineFixture(t)
			if stage == "mutation" {
				fake.rejectWrite = 3
			}
			if stage == "timer" {
				engine.Arm = func(context.Context, string, *networkControlJournal, bool) error { return errors.New("timer failed") }
			}
			if stage == "health" {
				count := 0
				engine.Health = func(context.Context, networkControlRequest, networkNativeContext) error {
					count++
					if count == 2 {
						return errors.New("fresh SSH witness failed")
					}
					return nil
				}
			}
			request := networkTestEgress(time.Now().UTC().Truncate(time.Second))
			if _, err := engine.process(context.Background(), nil, egressRequest(request)); err == nil {
				t.Fatal("failed apply reported success")
			}
			for _, rules := range fake.rules {
				if len(rules) != 0 {
					t.Fatal("rollback did not restore exact original rules")
				}
			}
			report := ReadNetworkControlReport(engine.Config.StateDir)
			if report.Egress.Active || report.Egress.Status == "enforced" {
				t.Fatal("failed apply presented as active")
			}
			if stage == "timer" && fake.writes != 0 {
				t.Fatal("mutation preceded verified watchdog")
			}
		})
	}
}

func TestOutboundOwnershipMarkerAndForeignPolicyRulesFailClosed(t *testing.T) {
	engine, fake, _ := networkEngineFixture(t)
	if err := OwnedEgressPolicyContext(context.Background(), fake, engine.Config.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(egressTemplatePath(engine.Config.StateDir)); err != nil {
		t.Fatal(err)
	}
	if OwnedEgressPolicyContext(context.Background(), fake, engine.Config.StateDir) == nil {
		t.Fatal("matching policy name adopted without private marker")
	}
	_ = atomicJSON(egressTemplatePath(engine.Config.StateDir), fake.marker)
	fake.rules["runtime"][`rule family="ipv4" priority="32760" reject`] = true
	if OwnedEgressPolicyContext(context.Background(), fake, engine.Config.StateDir) == nil {
		t.Fatal("unrecorded native rule silently adopted")
	}
}

func TestQuarantineAtomicApplyFullReadbackAndOriginalLeaseMetadata(t *testing.T) {
	engine, fake, _ := networkEngineFixture(t)
	q := networkTestQuarantine(time.Now().UTC().Truncate(time.Second))
	if _, err := engine.process(context.Background(), &Policy{Quarantine: q}, quarantineRequest(q)); err != nil {
		t.Fatal(err)
	}
	state, err := readNetworkState(engine.Config.StateDir)
	if err != nil || state.Quarantine == nil || state.Quarantine.ExpiresAt != q.ExpiresAt || state.QuarantinePlan.LeaseSeconds > 3600 {
		t.Fatal("original lease changed", err)
	}
	report := ReadNetworkControlReport(engine.Config.StateDir)
	if report.Quarantine.Status != "quarantined" || !report.Quarantine.Active || !report.Quarantine.ActiveExpiresAt.Equal(q.ExpiresAt) {
		t.Fatal("native quarantine was not confirmed with its original deadline")
	}
	if len(fake.objects) == 0 {
		t.Fatal("no typed isolation table")
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "flush") || strings.Contains(call, "conntrack") || strings.Contains(call, "reload") {
			t.Fatal("quarantine used unsafe global mutation")
		}
	}
}

func TestQuarantineDryRunNearExpiryAndForeignTableCannotChangeAccess(t *testing.T) {
	for _, stage := range []string{"dry", "expiry", "foreign"} {
		t.Run(stage, func(t *testing.T) {
			engine, fake, _ := networkEngineFixture(t)
			q := networkTestQuarantine(time.Now().UTC().Truncate(time.Second))
			if stage == "dry" {
				fake.rejectDry = true
			}
			if stage == "expiry" {
				q.ExpiresAt = time.Now().Add(20 * time.Second)
			}
			if stage == "foreign" {
				plan := networkTestPlan(time.Now())
				fake.objects, _ = quarantineNFTObjects(plan, time.Minute)
				fake.created = time.Now()
				fake.foreign = true
			}
			if _, err := engine.process(context.Background(), nil, quarantineRequest(q)); err == nil {
				t.Fatal("unsafe quarantine staging accepted")
			}
			if fake.writes != 0 {
				t.Fatal("access changed before feature/ownership/lease safety checks")
			}
		})
	}
}

func TestQuarantineExpiredWhilePoweredOffClearsOnlyOwnedLocalState(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			engine, fake, _ := networkEngineFixture(t)
			q := networkTestQuarantine(time.Now().Add(-2 * time.Hour))
			plan := networkTestPlan(time.Now().Add(-2 * time.Hour))
			plan.ExpiresAt = q.ExpiresAt
			state := &networkControlState{SchemaVersion: 1, Quarantine: q, QuarantinePlan: &plan, QuarantineNonce: plan.Nonce}
			_ = atomicJSON(networkStatePath(engine.Config.StateDir), state)
			journal := &networkControlJournal{SchemaVersion: 1, Nonce: plan.Nonce, Kind: "quarantine", Phase: "committed", After: state}
			path := networkJournalPath(engine.Config.StateDir, plan.Nonce)
			if foreign {
				fake.objects, _ = quarantineNFTObjects(plan, time.Minute)
				fake.created = time.Now()
				fake.foreign = true
			}
			err := expireQuarantineLocked(context.Background(), fake, engine.Config.StateDir, path, journal)
			after, _ := readNetworkState(engine.Config.StateDir)
			if foreign {
				if err == nil || after.Quarantine == nil || fake.writes != 0 {
					t.Fatal("unknown table was deleted/adopted")
				}
			} else if err != nil || after.Quarantine != nil || fake.writes != 0 {
				t.Fatal("expired absent kernel table blocked safe local cleanup", err)
			}
		})
	}
}

func TestQuarantineCommittedAuthoritySurvivesEnvelopeExpiryWithoutRenewingItsLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Add(-45 * time.Minute)
	q := networkTestQuarantine(now)
	p := &Policy{ServerID: "host-a", Quarantine: q}
	c, signed := signPolicyForTest(t, p, now.Add(time.Second))
	c.AllowFirewallChanges = true
	c.AllowHostDefaultDeny = true
	committed := now.Add(2 * time.Second)
	state := &networkControlState{SchemaVersion: 1, QuarantineGeneration: q.Generation, Quarantine: q, QuarantineAuthority: signed, QuarantineNonce: strings.Repeat("a", 32)}
	journal := &networkControlJournal{SchemaVersion: 1, Phase: "committed", Nonce: state.QuarantineNonce, CommittedAt: &committed, After: state}
	if ValidatePolicySignature(c, signed) == nil {
		t.Fatal("fixture envelope did not expire")
	}
	if err := validateCommittedQuarantine(c, state, journal, now.Add(45*time.Minute)); err != nil {
		t.Fatal("original committed lease rejected solely because delivery envelope expired", err)
	}
	if validateCommittedQuarantine(c, state, journal, now.Add(61*time.Minute)) == nil {
		t.Fatal("expired lease renewed on boot")
	}
	journal.Phase = "prepared"
	if validateCommittedQuarantine(c, state, journal, now.Add(45*time.Minute)) == nil {
		t.Fatal("uncommitted authority restored")
	}
}

func TestQuarantineNativeOwnershipAndUpgradeGateDoNotTrustNameOnly(t *testing.T) {
	engine, fake, _ := networkEngineFixture(t)
	plan := networkTestPlan(time.Now())
	plan.LeaseSeconds = 60
	objects, _ := quarantineNFTObjects(plan, time.Minute)
	fake.objects = objects
	fake.created = time.Now()
	if _, err := verifyQuarantineTable(context.Background(), fake, &plan, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	fake.foreign = true
	if _, err := verifyQuarantineTable(context.Background(), fake, &plan, time.Now(), false); err == nil {
		t.Fatal("foreign named table accepted")
	}
	state := &networkControlState{SchemaVersion: 1, Quarantine: networkTestQuarantine(time.Now()), QuarantinePlan: &plan, QuarantineNonce: plan.Nonce}
	_ = atomicJSON(networkStatePath(engine.Config.StateDir), state)
	if checkNetworkControlUpgradeSafety(engine.Config) == nil {
		t.Fatal("active independent expiry binary replacement admitted")
	}
}

func TestNetworkNamespacesAndResolverPinsUseLocalEvidenceOnly(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"proc/self/ns", "proc/1/ns", "proc/2/ns", "proc/sys/net/ipv4", "proc/sys/net/ipv6/conf/all", "etc"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, pid := range []string{"self", "1", "2"} {
		if err := os.Symlink("net:[123]", filepath.Join(root, "proc", pid, "ns/net")); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(root, "proc/sys/net/ipv4/ip_forward"), []byte("0\n"), 0600)
	_ = os.WriteFile(filepath.Join(root, "proc/sys/net/ipv6/conf/all/forwarding"), []byte("0\n"), 0600)
	if _, err := networkNamespace(context.Background(), &fakeRunner{}, root); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(root, "proc/2/ns/net"))
	_ = os.Symlink("net:[456]", filepath.Join(root, "proc/2/ns/net"))
	if _, err := networkNamespace(context.Background(), &fakeRunner{}, root); err == nil {
		t.Fatal("foreign container network namespace accepted")
	}
	_ = os.WriteFile(filepath.Join(root, "etc/resolv.conf"), []byte("nameserver 127.0.0.53\nnameserver 10.10.0.53\n"), 0600)
	c := networkTestConfig(t)
	pins, err := protectedNetworkEgress(context.Background(), c, root, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.10.0.10"), netip.MustParseAddr("2001:db8::10")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	hasController, hasDNS := false, false
	for _, pin := range pins {
		if pin.Kind == "controller" && pin.Port == 8787 {
			hasController = true
		}
		if pin.Kind == "dns" && pin.Destination == "10.10.0.53/32" {
			hasDNS = true
		}
		if pin.Kind == "controller" && strings.Contains(pin.Destination, "/0") {
			t.Fatal("HTTP peer or unbounded origin widened protected controller pins")
		}
	}
	if !hasController || !hasDNS {
		t.Fatal("protected resolver/control evidence missing")
	}
}

func TestNetworkAssessmentNeverRefreshesAnUnverifiedHistoricalActiveClaim(t *testing.T) {
	fresh := NetworkFeatureReport{Supported: true, Ready: false, Status: "blocked", Error: "native owned rule readback failed"}
	previous := NetworkFeatureReport{Active: true, ActiveID: "old", Status: "enforced", ID: "old", PlanDigest: strings.Repeat("a", 64), Generation: 1}
	merged := mergeNetworkOutcome(fresh, previous)
	if merged.Ready || merged.Status != "unverified" || merged.ID != "old" || merged.Error == "" {
		t.Fatal("disk-retained enforcement became freshly verified")
	}
	now := time.Now().UTC()
	old := networkTestQuarantine(now)
	state := &networkControlState{SchemaVersion: 1, Quarantine: old}
	report := NetworkControlReport{Quarantine: NetworkFeatureReport{Status: "rolled_back", ID: "failed-new-request"}}
	fillNetworkActiveState(&report, state, now)
	if !report.Quarantine.Active || report.Quarantine.ID != "failed-new-request" || report.Quarantine.ActiveID != old.ID || !report.Quarantine.ActiveExpiresAt.Equal(old.ExpiresAt) {
		t.Fatal("failed replacement lost the old real quarantine identity/lease")
	}
}

func TestQuarantineExclusiveCreateRaceCannotDeleteForeignRules(t *testing.T) {
	engine, fake, _ := networkEngineFixture(t)
	engine.PrepareBoot = func(context.Context) error {
		foreign := networkTestPlan(time.Now())
		foreign.Nonce = strings.Repeat("f", 32)
		fake.objects, _ = quarantineNFTObjects(foreign, time.Minute)
		fake.created = time.Now()
		fake.foreign = true
		return nil
	}
	q := networkTestQuarantine(time.Now().UTC().Truncate(time.Second))
	if _, err := engine.process(context.Background(), nil, quarantineRequest(q)); err == nil {
		t.Fatal("foreign native table race adopted")
	}
	if fake.writes != 0 || !fake.foreign || len(fake.objects) == 0 {
		t.Fatal("foreign native table was removed or overwritten")
	}
	report := ReadNetworkControlReport(engine.Config.StateDir)
	if report.Quarantine.Status != "error" || report.Quarantine.Ready {
		t.Fatal("unverified rollback was reported as successful")
	}
}

func TestQuarantineStaleExpiryCannotFenceANewerMutationOrDeleteItsTable(t *testing.T) {
	engine, fake, _ := networkEngineFixture(t)
	nonce := strings.Repeat("a", 32)
	old := networkTestQuarantine(time.Now().Add(-2 * time.Hour))
	state := &networkControlState{SchemaVersion: 1, EgressRules: []string{}}
	journal := &networkControlJournal{SchemaVersion: 1, Nonce: nonce, Kind: "quarantine", Phase: "committed", PID: os.Getpid(), Deadline: time.Now().Add(-time.Hour), Before: state, After: &networkControlState{SchemaVersion: 1, Quarantine: old}, Request: networkControlRequest{Kind: "quarantine"}}
	path := networkJournalPath(engine.Config.StateDir, nonce)
	if err := atomicJSON(path, journal); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(networkStatePath(engine.Config.StateDir), state); err != nil {
		t.Fatal(err)
	}
	lock, err := managedLock(engine.Config.StateDir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExpireQuarantine(path, nonce, fake); err == nil {
		unlockManaged(lock)
		t.Fatal("busy expiry did not defer without fencing")
	}
	unlockManaged(lock)
	if err := ExpireQuarantine(path, nonce, fake); err != nil {
		t.Fatal(err)
	}
	if fake.writes != 0 {
		t.Fatal("stale expiry mutated newer state")
	}
}

func TestQuarantineBootUnitUsesFixedEntryPointWithoutPathSubstitution(t *testing.T) {
	unit, err := quarantineBootUnit("/usr/local/bin/seg-agent", "/var/lib/seg-agent")
	if err != nil || !strings.Contains(unit, "Before=network-pre.target firewalld.service") || !strings.Contains(unit, "--restore-quarantine") {
		t.Fatal("durable boot ordering/entrypoint missing", err)
	}
	for _, path := range []string{"relative", "/var/lib/%n", "/var/lib/$HOME", "/var/lib/x\nExecStart=/evil"} {
		if _, err := quarantineBootUnit("/usr/local/bin/seg-agent", path); err == nil {
			t.Fatal("boot path permitted interpreter/specifier injection")
		}
	}
}
