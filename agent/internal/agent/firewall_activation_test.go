package agent

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type activationFake struct {
	*sourceBankFake
	root                                   string
	active, ufwActive, enabled, ufwEnabled bool
	policies                               map[string]string
	writes                                 []string
	counter                                bool
	foreignRace                            bool
	allowTarget                            string
	noActiveZone                           bool
}

func (f *activationFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "firewall-offline-cmd" && len(args) == 1 {
		switch args[0] {
		case "--get-default-zone":
			return f.defaultZone, nil
		case "--check-config":
			return "", nil
		}
	}
	if name == "systemctl" {
		op := args[0]
		unit := args[len(args)-1]
		active, enabled := &f.active, &f.enabled
		if unit == "ufw.service" {
			active, enabled = &f.ufwActive, &f.ufwEnabled
		}
		switch op {
		case "is-active":
			if *active {
				return "active", nil
			}
			return "inactive", errors.New("inactive")
		case "is-enabled":
			if *enabled {
				return "enabled", nil
			}
			return "disabled", errors.New("disabled")
		case "show":
			return "", nil
		case "start", "stop", "enable", "disable":
			f.writes = append(f.writes, op+" "+unit)
			switch op {
			case "start":
				*active = true
			case "stop":
				*active = false
				if unit == "firewalld.service" && f.dropRuntimeBinding {
					f.runtimeInterfaces = f.permanentInterfaces
				}
			case "enable":
				*enabled = true
			case "disable":
				*enabled = false
			}
			return "", nil
		}
	}
	if name == "ufw" {
		if f.ufwActive {
			return "Status: active", nil
		}
		return "Status: inactive", nil
	}
	if name == "busctl" {
		if f.counter {
			return `s "yes"`, nil
		}
		return `s "no"`, nil
	}
	if name == "firewall-cmd" {
		_, allowFileErr := os.Stat(f.root + activationDefaultAllowPath)
		hasAllow := allowFileErr == nil
		scope := "runtime"
		for _, arg := range args {
			if arg == "--get-active-zones" && f.noActiveZone {
				return "", nil
			}
			if arg == "--permanent" {
				scope = "permanent"
			}
		}
		for _, arg := range args {
			if arg == "--get-active-policies" && f.active && hasAllow {
				return activationDefaultAllowName + "\n  ingress-zones: ANY\n  egress-zones: HOST\n", nil
			}
			if arg == "--policy="+activationDefaultAllowName && hasAllow {
				target := f.allowTarget
				if target == "" {
					target = "ACCEPT"
				}
				return activationDefaultAllowName + "\n  priority: 32767\n  target: " + target +
					"\n  ingress-zones: ANY\n  egress-zones: HOST\n  services:\n  ports:\n  protocols:\n" +
					"  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n", nil
			}
			if arg == "--zone=public" && hasAllow && args[len(args)-1] == "--list-all" {
				return "public\n  target: default\n", nil
			}
			if arg == "--state" {
				if f.active {
					return "running", nil
				}
				return "not running", errors.New("inactive")
			}
			if arg == "--get-policies" {
				if hasAllow {
					return activationDefaultAllowName, nil
				}
				if f.policies[scope] != "" {
					return activationEgressPolicy, nil
				}
				return "", nil
			}
			if strings.HasPrefix(arg, "--new-policy-from-file=") {
				raw, err := os.ReadFile(strings.TrimPrefix(arg, "--new-policy-from-file="))
				if err != nil {
					return "", err
				}
				var policy struct {
					Short string `xml:"short"`
				}
				if xml.Unmarshal(raw, &policy) != nil {
					return "", errors.New("invalid policy xml")
				}
				if f.foreignRace {
					policy.Short = "foreign-owner"
				}
				f.policies["permanent"] = policy.Short
				f.writes = append(f.writes, "create-policy")
				if err := os.WriteFile(f.root+"/etc/firewalld/policies/prt-egress.xml", raw, 0644); err != nil {
					return "", err
				}
				if f.foreignRace {
					return "", errors.New("ALREADY_EXISTS")
				}
				return "success", nil
			}
			if strings.HasPrefix(arg, "--delete-policy=") {
				f.writes = append(f.writes, "delete-policy")
				delete(f.policies, "permanent")
				_ = os.Remove(f.root + "/etc/firewalld/policies/prt-egress.xml")
				return "success", nil
			}
			if arg == "--policy="+activationEgressPolicy {
				if f.policies[scope] == "" {
					return "", errors.New("missing policy")
				}
				query := args[len(args)-1]
				switch query {
				case "--get-short":
					return f.policies[scope], nil
				case "--get-description":
					return activationEgressDescription, nil
				case "--get-target":
					return "CONTINUE", nil
				case "--get-priority":
					return "-30000", nil
				case "--list-ingress-zones":
					return "HOST", nil
				case "--list-egress-zones":
					return "ANY", nil
				case "--query-masquerade":
					return "no", errors.New("disabled")
				default:
					return "", nil
				}
			}
			if arg == "--reload" {
				f.writes = append(f.writes, "reload")
				if f.policies["permanent"] != "" {
					f.policies["runtime"] = f.policies["permanent"]
				} else {
					delete(f.policies, "runtime")
				}
				raw, _ := os.ReadFile(f.root + "/etc/firewalld/firewalld.conf")
				f.counter = strings.Contains(string(raw), "NftablesCounters=yes")
			}
		}
	}
	return f.sourceBankFake.Run(ctx, name, args...)
}
func activationFixture(t *testing.T, operation string) (*Agent, *activationFake, firewallActivationBaseline, Protection) {
	t.Helper()
	a, source, protection := sourceBankFixture(t)
	a.Config.StateDir, _ = filepath.EvalSymlinks(a.Config.StateDir)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/etc/firewalld/zones", "/etc/firewalld/policies", "/usr/lib/firewalld", "/etc/ufw"} {
		if err := os.MkdirAll(root+dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{"/etc/firewalld/firewalld.conf": "# Exact original\nFirewallBackend=nftables\nNftablesCounters=no\n", "/etc/ufw/ufw.conf": "# Original UFW settings\nENABLED=yes\n"} {
		if err := os.WriteFile(root+name, []byte(text), 0640); err != nil {
			t.Fatal(err)
		}
	}
	f := &activationFake{sourceBankFake: source, root: root, policies: map[string]string{}, active: !startsFirewalld(operation), enabled: operation == "deactivate_existing", ufwActive: operation == "migrate_ufw", ufwEnabled: operation == "migrate_ufw"}
	a.Commands = f
	a.Config.Zone = "public"
	files, err := activationConfigFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	facts := FirewallActivationAssessment{FirewalldActive: f.active, FirewalldEnabled: "disabled", UFWActive: f.ufwActive, UFWEnabled: "disabled", Version: "2.3.1", Backend: "nftables", Zone: "public", IPs: []string{"10.0.0.1"}, SSHPorts: protection.SSHPorts, ManagementSources: protection.ManagementSources, DiscoveredPorts: []FirewallActivationPort{{2022, "tcp"}, {8443, "tcp"}}, TranslatedRules: []FirewallActivationRule{}, CanApply: true, Blockers: []string{}, Notes: []string{}}
	if f.enabled {
		facts.FirewalldEnabled = "enabled"
	}
	if f.ufwEnabled {
		facts.UFWEnabled = "enabled"
	}
	if operation == "migrate_ufw" {
		facts.TranslatedRules = []FirewallActivationRule{{"ipv4", "10.30.0.0/24", 8443, "tcp", "accept", -29000}}
	}
	baseline := firewallActivationBaseline{Assessment: facts, Files: files}
	if f.active {
		bank, err := a.sourceBankBaseline(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		baseline.SourceBanks = &bank
		baseline.Global = shaText("fixture-global")
	}
	baseline.Digest = activationDigest(baseline)
	a.firewallActivation = &firewallActivationHooks{Root: root, ConfigurationLease: func() (*os.File, error) { return os.CreateTemp(root, "config-lease-") }, Baseline: func() (firewallActivationBaseline, Protection, error) { return baseline, protection, nil }, Health: func(FirewallActivationAssignment, Protection) error { return nil }, Arm: func(path string, j *managedJournal) error {
		loaded, err := readManagedJournal(path, j.Nonce)
		if err != nil {
			return err
		}
		if loaded.Phase != "prepared" || len(f.writes) > 0 {
			return errors.New("watchdog not durably armed before mutation")
		}
		return activationFilesMatch(root, baseline.Files, nil, false)
	}, Attestation: func(bool) error { return nil }, CounterReadback: func() error { return nil }}
	return a, f, baseline, protection
}
func activationPolicy(t *testing.T, a *Agent, operation string, baseline firewallActivationBaseline, protection Protection) *Policy {
	t.Helper()
	target := operation
	if operation == "assess" {
		target = "activate_existing"
	}
	request := &FirewallActivationAssignment{ID: "activation-" + operation, Operation: operation, TargetOperation: target, PlanDigest: shaText("plan:" + operation), ConfigurationDigest: configDigest(a.Config), ExpiresAt: time.Now().Add(10 * time.Minute)}
	if operation != "assess" {
		request.BaselineDigest = baseline.Digest
		request.ProtectionDigest = protection.Digest
		proof := singleAdminProofFixture()
		proof.PlanID = request.ID
		proof.PlanDigest = request.PlanDigest
		proof.Scope["kind"] = json.RawMessage(`"firewall_activation"`)
		request.ApprovalProof = sealDirectApproval(proof)
	}
	_, policy := signPolicyForTest(t, &Policy{ServerID: "host-a", Mode: "monitor", FirewallActivation: request}, time.Now())
	return policy
}
func TestFirewallActivationFourReviewedOperationsAndIdempotentReceipts(t *testing.T) {
	for _, operation := range []string{"activate_existing", "migrate_ufw", "prepare_egress", "enable_native_counters"} {
		t.Run(operation, func(t *testing.T) {
			a, f, baseline, protection := activationFixture(t, operation)
			policy := activationPolicy(t, a, operation, baseline, protection)
			handled, err := a.processFirewallActivation(context.Background(), policy)
			if err != nil || !handled {
				t.Fatal(handled, err)
			}
			receipt := ReadFirewallActivationStatus(a.Config.StateDir)
			if receipt == nil || receipt.Status != "completed" {
				t.Fatal(receipt)
			}
			if a.Config.Enforce || a.Config.AllowFirewallChanges {
				t.Fatal("maintenance silently elevated ordinary enforcement")
			}
			if operation == "activate_existing" || operation == "migrate_ufw" {
				if !f.active || !f.enabled || f.ufwActive || f.ufwEnabled {
					t.Fatal("service outcome not applied", f.active, f.enabled, f.ufwActive, f.ufwEnabled)
				}
			} else if f.reloads != 1 {
				t.Fatal("exactly one reviewed reload expected", f.reloads)
			}
			if operation == "prepare_egress" {
				marker, err := readEgressTemplate(a.Config.StateDir)
				if err != nil || marker.Short != f.policies["runtime"] {
					t.Fatal(marker, err)
				}
			}
			if operation == "enable_native_counters" && !f.counter {
				t.Fatal("native counter option not read back")
			}
			before := len(f.writes)
			if _, err := a.processFirewallActivation(context.Background(), policy); err != nil || len(f.writes) != before {
				t.Fatal("replay mutated", err, f.writes)
			}
		})
	}
}

func TestFirewallActivationStartsAndEnablesWithoutSSHConfiguration(t *testing.T) {
	a, commands, baseline, protection := activationFixture(t, "activate_existing")
	a.Config.ManagementSources = nil
	a.Config.ProtectedSSHPorts = nil
	baseline.Assessment.SSHPorts = []int{}
	baseline.Assessment.ManagementSources = []string{}
	baseline.Digest = activationDigest(baseline)
	protection.SSHPorts = []int{}
	protection.ManagementSources = []string{}
	protection.Digest = protectionDigest(protection)
	a.firewallActivation.Baseline = func() (firewallActivationBaseline, Protection, error) {
		return baseline, protection, nil
	}
	handled, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, "activate_existing", baseline, protection))
	receipt := ReadFirewallActivationStatus(a.Config.StateDir)
	if err != nil || !handled || !commands.active || !commands.enabled || receipt == nil || receipt.Status != "completed" {
		t.Fatal("startup without SSH settings did not complete", handled, err, receipt)
	}
}

func TestFirewallActivationStopsAndDisablesWithRollback(t *testing.T) {
	for _, failHealth := range []bool{false, true} {
		name := "verified stop"
		if failHealth {
			name = "restore after lost controller"
		}
		t.Run(name, func(t *testing.T) {
			a, commands, baseline, protection := activationFixture(t, "deactivate_existing")
			if failHealth {
				commands.permanentInterfaces = ""
				commands.dropRuntimeBinding = true
				bank, err := a.sourceBankBaseline(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				baseline.SourceBanks = &bank
				baseline.Digest = activationDigest(baseline)
				a.firewallActivation.Baseline = func() (firewallActivationBaseline, Protection, error) {
					return baseline, protection, nil
				}
				a.firewallActivation.Health = func(_ FirewallActivationAssignment, _ Protection) error {
					if !commands.enabled {
						return errors.New("outbound controller check failed")
					}
					return nil
				}
			}
			_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, "deactivate_existing", baseline, protection))
			receipt := ReadFirewallActivationStatus(a.Config.StateDir)
			if failHealth {
				if err == nil || receipt == nil || receipt.Status != "rolled_back" || !commands.active || !commands.enabled ||
					commands.runtimeInterfaces != "eth0" || commands.permanentInterfaces != "" {
					t.Fatal("original firewalld activity and enablement were not restored", err, receipt)
				}
			} else if err != nil || receipt == nil || receipt.Status != "completed" || commands.active || commands.enabled {
				t.Fatal("firewalld did not become stopped and disabled", err, receipt)
			}
			if err := activationFilesMatch(commands.root, baseline.Files, nil, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFirewallActivationDefaultAllowRequiresExactReadbackAndRollsBack(t *testing.T) {
	for _, target := range []string{"ACCEPT", "REJECT"} {
		t.Run(target, func(t *testing.T) {
			a, commands, baseline, protection := activationFixture(t, "activate_allow_all")
			commands.defaultZone = "public"
			commands.activeZones = "public\n  interfaces: eth0\n"
			if target == "ACCEPT" {
				commands.noActiveZone = true
				commands.runtimeInterfaces = ""
			}
			commands.allowTarget = target
			_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, "activate_allow_all", baseline, protection))
			receipt := ReadFirewallActivationStatus(a.Config.StateDir)
			raw, readErr := os.ReadFile(commands.root + activationDefaultAllowPath)
			if target == "ACCEPT" {
				if err != nil || receipt == nil || receipt.Status != "completed" || !commands.active || !commands.enabled ||
					readErr != nil || string(raw) != activationDefaultAllowXML {
					t.Fatal("reviewed default inbound allow was not verified", err, readErr, receipt)
				}
			} else if err == nil || receipt == nil || receipt.Status != "rolled_back" || commands.active || commands.enabled ||
				!os.IsNotExist(readErr) {
				t.Fatal("different native policy did not restore previous state", err, readErr, receipt)
			}
		})
	}
}

func TestFirewallActivationBroadChangesRefuseLocalEnforcement(t *testing.T) {
	for _, operation := range []string{"activate_allow_all", "deactivate_existing"} {
		t.Run(operation, func(t *testing.T) {
			a, commands, baseline, protection := activationFixture(t, operation)
			a.State.ManagedBundle = &ManagedBundle{HostDefaultDeny: true}
			_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, operation, baseline, protection))
			receipt := ReadFirewallActivationStatus(a.Config.StateDir)
			if err == nil || receipt == nil || receipt.Status != "blocked" || len(commands.writes) != 0 {
				t.Fatal("managed default deny did not block service change", err, receipt)
			}
		})
	}
}

func TestFirewallActivationAgentOnlyWitnessRequiresExactFreshControllerProof(t *testing.T) {
	a, _, baseline, protection := activationFixture(t, "activate_existing")
	a.inventory = &Report{IPs: []string{"192.0.2.10"}}
	policy := activationPolicy(t, a, "activate_existing", baseline, protection)
	request := *policy.FirewallActivation
	now := time.Now().UTC()
	nonce := strings.Repeat("a", 32)
	witness := firewallActivationWitness{
		ConfigurationDigest: request.ConfigurationDigest,
		HealthMode:          "agent_controller_mtls",
		sourceBankWitness: sourceBankWitness{
			ID:             request.ID,
			PlanDigest:     request.PlanDigest,
			BaselineDigest: request.BaselineDigest,
			managedWitness: managedWitness{
				Nonce: nonce, ServerID: policy.ServerID, ProtectionDigest: protection.Digest,
				CheckedAt: now, ControllerOK: true, Status: "healthy",
			},
		},
	}
	// The local baseline can still discover SSH. The controller proves only
	// the outbound connection for this operation, even with that information.
	if len(protection.SSHPorts) == 0 {
		t.Fatal("fixture must include a discovered SSH listener")
	}
	if err := a.validateFirewallActivationWitness(witness, policy, request, protection, nonce, now); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"activate_allow_all", "deactivate_existing"} {
		request.Operation = operation
		if err := a.validateFirewallActivationWitness(witness, policy, request, protection, nonce, now); err != nil {
			t.Fatalf("%s did not accept verified controller-only proof: %v", operation, err)
		}
	}
	for name, change := range map[string]func(*firewallActivationWitness){
		"legacy mode":          func(w *firewallActivationWitness) { w.HealthMode = "" },
		"configuration change": func(w *firewallActivationWitness) { w.ConfigurationDigest = shaText("other config") },
		"wrong plan":           func(w *firewallActivationWitness) { w.PlanDigest = shaText("another plan") },
		"wrong nonce":          func(w *firewallActivationWitness) { w.Nonce = "different nonce" },
		"stale receipt":        func(w *firewallActivationWitness) { w.CheckedAt = now.Add(-time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := witness
			change(&changed)
			if err := a.validateFirewallActivationWitness(changed, policy, request, protection, nonce, now); err == nil {
				t.Fatal("invalid controller proof accepted")
			}
		})
	}
	for _, operation := range []string{"migrate_ufw", "prepare_egress", "enable_native_counters"} {
		request.Operation = operation
		if err := a.validateFirewallActivationWitness(witness, policy, request, protection, nonce, now); err == nil {
			t.Fatalf("%s accepted controller-only proof", operation)
		}
	}
}

func TestFirewallActivationPostHealthFailureRestoresEveryOriginalFileAndService(t *testing.T) {
	for _, operation := range []string{"activate_existing", "migrate_ufw", "prepare_egress", "enable_native_counters"} {
		t.Run(operation, func(t *testing.T) {
			a, f, baseline, protection := activationFixture(t, operation)
			checks := 0
			a.firewallActivation.Health = func(FirewallActivationAssignment, Protection) error {
				checks++
				if checks >= 3 {
					return errors.New("post-change controller/SSH health failed")
				}
				return nil
			}
			_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, operation, baseline, protection))
			if err == nil {
				t.Fatal("failed post-health accepted")
			}
			receipt := ReadFirewallActivationStatus(a.Config.StateDir)
			if receipt == nil || receipt.Status != "rolled_back" {
				t.Fatal(receipt, err)
			}
			if err := activationFilesMatch(f.root, baseline.Files, nil, false); err != nil {
				t.Fatal(err)
			}
			if f.active != baseline.Assessment.FirewalldActive || f.ufwActive != baseline.Assessment.UFWActive || f.counter {
				t.Fatal("original activity/options not restored")
			}
			if len(f.policies) != 0 {
				t.Fatal("owned policy survived rollback")
			}
		})
	}
}
func TestFirewallActivationWatchdogFailureMakesNoHostMutation(t *testing.T) {
	a, f, baseline, p := activationFixture(t, "migrate_ufw")
	a.firewallActivation.Arm = func(string, *managedJournal) error { return errors.New("independent timer unavailable") }
	_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, "migrate_ufw", baseline, p))
	if err == nil || len(f.writes) != 0 || !f.ufwActive {
		t.Fatal(err, f.writes)
	}
	if err := activationFilesMatch(f.root, baseline.Files, nil, false); err != nil {
		t.Fatal(err)
	}
}
func TestFirewallActivationForeignPolicyRaceRefusesDeletionAndReportsError(t *testing.T) {
	a, f, baseline, p := activationFixture(t, "prepare_egress")
	f.foreignRace = true
	_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, "prepare_egress", baseline, p))
	receipt := ReadFirewallActivationStatus(a.Config.StateDir)
	if err == nil || receipt == nil || receipt.Status != "error" || f.policies["permanent"] != "foreign-owner" {
		t.Fatal(err, receipt, f.policies)
	}
	for _, op := range f.writes {
		if op == "delete-policy" {
			t.Fatal("foreign policy deleted")
		}
	}
}
func TestFirewallActivationInterruptedTransactionUsesDurableRecoveryBeforeNewPolicy(t *testing.T) {
	a, f, baseline, p := activationFixture(t, "enable_native_counters")
	policy := activationPolicy(t, a, "enable_native_counters", baseline, p)
	if _, err := a.processFirewallActivation(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(firewallActivationDirectory(a.Config.StateDir), "*.json"))
	j, err := readManagedJournal(paths[0], strings.TrimSuffix(filepath.Base(paths[0]), ".json"))
	if err != nil {
		t.Fatal(err)
	}
	j.Phase = "applying"
	j.FirewallActivation.Report.Status = "applying"
	if err := saveManagedJournal(paths[0], j); err != nil {
		t.Fatal(err)
	}
	if err := a.recoverFirewallActivationLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.counter || ReadFirewallActivationStatus(a.Config.StateDir).Status != "rolled_back" {
		t.Fatal("interrupted reload did not recover")
	}
	if err := activationFilesMatch(f.root, baseline.Files, nil, false); err != nil {
		t.Fatal(err)
	}
	before := len(f.writes)
	if _, err := a.processFirewallActivation(context.Background(), policy); err != nil || len(f.writes) != before {
		t.Fatal("recovered command replayed", err)
	}
}
func TestFirewallActivationForeignConfigEditPreventsGuessedRollback(t *testing.T) {
	a, f, baseline, p := activationFixture(t, "enable_native_counters")
	checks := 0
	a.firewallActivation.Health = func(FirewallActivationAssignment, Protection) error {
		checks++
		if checks == 3 {
			_ = os.WriteFile(f.root+"/etc/firewalld/firewalld.conf", []byte("ForeignOption=yes\n"), 0640)
			return errors.New("concurrent writer")
		}
		return nil
	}
	_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, "enable_native_counters", baseline, p))
	receipt := ReadFirewallActivationStatus(a.Config.StateDir)
	raw, _ := os.ReadFile(f.root + "/etc/firewalld/firewalld.conf")
	if err == nil || receipt == nil || receipt.Status != "error" || string(raw) != "ForeignOption=yes\n" {
		t.Fatal("foreign bytes overwritten or failure hidden", err, receipt, string(raw))
	}
}
func TestFirewallActivationAssessmentAndRejectedSignatureHaveNoHostWrites(t *testing.T) {
	a, f, baseline, p := activationFixture(t, "activate_existing")
	policy := activationPolicy(t, a, "assess", baseline, p)
	if _, err := a.processFirewallActivation(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 || ReadFirewallActivationStatus(a.Config.StateDir).Status != "assessed" {
		t.Fatal("assessment changed host")
	}
	policy = activationPolicy(t, a, "activate_existing", baseline, p)
	policy.FirewallActivation.Operation = "migrate_ufw"
	policy.FirewallActivation.TargetOperation = "migrate_ufw"
	if _, err := a.processFirewallActivation(context.Background(), policy); err == nil || len(f.writes) != 0 {
		t.Fatal("tampered assignment accepted", err)
	}
}

func TestFirewallActivationTopologyChangeAfterStartRollsBack(t *testing.T) {
	a, f, baseline, p := activationFixture(t, "activate_existing")
	baseline.NativeTopology = shaText("reviewed-host-topology")
	baseline.NativeContext = shaText("reviewed-kernel-context")
	baseline.Digest = activationDigest(baseline)
	a.firewallActivation.Baseline = func() (firewallActivationBaseline, Protection, error) { return baseline, p, nil }
	a.firewallActivation.Topology = func() (string, error) { return shaText("changed-router-context"), nil }
	_, err := a.processFirewallActivation(context.Background(), activationPolicy(t, a, "activate_existing", baseline, p))
	receipt := ReadFirewallActivationStatus(a.Config.StateDir)
	if err == nil || receipt == nil || receipt.Status != "error" || f.active || f.enabled {
		t.Fatal("changed host topology accepted", err, receipt)
	}
}

func TestFirewallActivationUsesNativeDefaultOnlyForUnconfiguredExistingStart(t *testing.T) {
	a, f, baseline, protection := activationFixture(t, "activate_existing")
	a.Config.Zone = ""
	f.defaultZone = "public"
	zone, err := inactiveActivationZone(context.Background(), f, a.Config.Zone, true)
	if err != nil || zone != "public" {
		t.Fatal("valid permanent default was not assessed", zone, err)
	}
	for _, configured := range []string{"", "trusted"} {
		if _, err := inactiveActivationZone(context.Background(), f, configured, false); err == nil {
			t.Fatal("an explicit configuration was required", configured)
		}
	}
	f.activeZones = "trusted\n  interfaces: eth0\n"
	_, err = a.processFirewallActivation(context.Background(), activationPolicy(t, a, "activate_existing", baseline, protection))
	if err == nil || !strings.Contains(err.Error(), "reviewed permanent default zone") || f.active || f.enabled {
		t.Fatal("live zone differing from the reviewed default was not rolled back", err)
	}
}

func TestFirewallActivationExpiredConfigOrDifferentProofCannotGrantMaintenance(t *testing.T) {
	for _, kind := range []string{"expired", "config", "scope", "other-server", "two-person"} {
		t.Run(kind, func(t *testing.T) {
			a, f, baseline, p := activationFixture(t, "activate_existing")
			policy := activationPolicy(t, a, "activate_existing", baseline, p)
			request := policy.FirewallActivation
			switch kind {
			case "expired":
				request.ExpiresAt = time.Now().Add(-time.Second)
			case "config":
				request.ConfigurationDigest = shaText("different-config")
			default:
				proof := singleAdminProofFixture()
				proof.PlanID = request.ID
				proof.PlanDigest = request.PlanDigest
				proof.Scope["kind"] = json.RawMessage(`"firewall_activation"`)
				if kind == "scope" {
					proof.Scope["kind"] = json.RawMessage(`"managed"`)
				}
				if kind == "other-server" {
					proof.Scope["server_ids"] = json.RawMessage(`["other-server"]`)
				}
				if kind == "two-person" {
					proof.Mode = "maker_checker"
				}
				request.ApprovalProof = sealDirectApproval(proof)
			}
			policy.Signature = nil
			policy.AssignmentDigest = ""
			_, policy = signPolicyForTest(t, policy, time.Now())
			if _, err := a.processFirewallActivation(context.Background(), policy); err == nil || len(f.writes) != 0 {
				t.Fatal("invalid reviewed authority changed host", err, f.writes)
			}
		})
	}
}
func TestFirewallActivationCounterAttestationCannotAuthorizeUnreviewedConfiguration(t *testing.T) {
	a, f, _, _ := activationFixture(t, "enable_native_counters")
	if _, err := firewallActivationGlobalConfigDigest(context.Background(), a.Config.StateDir, f.root, f); err == nil {
		t.Fatal("no attestation authorized pending global bytes")
	}
	if err := atomicJSON(activationCounterAttestationPath(a.Config.StateDir), activationCounterAttestation{SchemaVersion: 1, DaemonIdentity: "different-boot-process", ConfigHash: shaText("invented"), GlobalDigest: shaText("invented"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := firewallActivationGlobalConfigDigest(context.Background(), a.Config.StateDir, f.root, f); err == nil {
		t.Fatal("foreign daemon/binding attestation accepted")
	}
}
