package agent

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type sourceBankFake struct {
	*managedFake
	sets                                   map[string]sourceBankDefinition
	owners                                 map[string]string
	writes                                 []string
	createCount, reloads                   int
	failCreate, failReload                 int
	foreignRace                            bool
	permanentInterfaces, runtimeInterfaces string
	dropRuntimeBinding                     bool
	mutateOnReload                         bool
	commands                               int
	onCommand                              func()
	serviceDefinition                      string
	inactiveZone                           string
	permanentInactiveZone                  string
	defaultZone                            string
}

func (f *sourceBankFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	f.commands++
	if f.onCommand != nil {
		f.onCommand()
	}
	if name != "firewall-cmd" {
		return f.managedFake.Run(ctx, name, args...)
	}
	scope := "runtime"
	set := ""
	for _, arg := range args {
		if arg == "--permanent" {
			scope = "permanent"
		}
		if strings.HasPrefix(arg, "--ipset=") {
			set = strings.TrimPrefix(arg, "--ipset=")
		}
	}
	for _, arg := range args {
		switch arg {
		case "--query-panic":
			return "no", errors.New("not enabled")
		case "--get-log-denied":
			return "off", nil
		case "--get-default-zone":
			if f.defaultZone != "" {
				return f.defaultZone, nil
			}
		case "--get-ipsets":
			names := []string{}
			for key := range f.sets {
				parts := strings.SplitN(key, "|", 2)
				if parts[0] == scope {
					names = append(names, parts[1])
				}
			}
			sort.Strings(names)
			return strings.Join(names, " "), nil
		case "--list-all-zones":
			text, err := f.managedFake.Run(ctx, name, args...)
			if err != nil {
				return text, err
			}
			interfaces := f.runtimeInterfaces
			if scope == "permanent" {
				interfaces = f.permanentInterfaces
			}
			extra := f.inactiveZone
			if scope == "permanent" && f.permanentInactiveZone != "" {
				extra = f.permanentInactiveZone
			}
			return strings.Replace(text, "interfaces: eth0", "interfaces: "+interfaces, 1) + extra, nil
		case "--get-description":
			value, ok := f.owners[set]
			if !ok {
				return "", errors.New("not found")
			}
			return value, nil
		case "--get-entries":
			definition, ok := f.sets[scope+"|"+set]
			if !ok {
				return "", errors.New("not found")
			}
			return strings.Join(definition.Entries, "\n"), nil
		case "--check-config":
			return "success", nil
		case "--reload":
			f.reloads++
			f.writes = append(f.writes, "reload")
			if f.failReload == f.reloads {
				return "", errors.New("reload failed")
			}
			for key := range f.sets {
				if strings.HasPrefix(key, "runtime|") {
					delete(f.sets, key)
				}
			}
			for key, value := range f.sets {
				if strings.HasPrefix(key, "permanent|") {
					f.sets["runtime|"+strings.TrimPrefix(key, "permanent|")] = value
				}
			}
			if f.dropRuntimeBinding {
				f.runtimeInterfaces = f.permanentInterfaces
			}
			if f.mutateOnReload {
				f.target = "DROP"
			}
			return "success", nil
		}
		if strings.HasPrefix(arg, "--info-ipset=") {
			name := strings.TrimPrefix(arg, "--info-ipset=")
			definition, ok := f.sets[scope+"|"+name]
			if !ok {
				return "", errors.New("INVALID_IPSET")
			}
			options := []string{}
			for key, value := range definition.Options {
				options = append(options, key+"="+value)
			}
			sort.Strings(options)
			return name + "\n  type: hash:net\n  options: " + strings.Join(options, " ") + "\n  entries: " + strings.Join(definition.Entries, " ") + "\n", nil
		}
		if strings.HasPrefix(arg, "--info-service=") && f.serviceDefinition != "" {
			return f.serviceDefinition, nil
		}
		if strings.HasPrefix(arg, "--new-ipset-from-file=") {
			f.createCount++
			f.writes = append(f.writes, "create")
			if f.failCreate == f.createCount {
				return "", errors.New("injected create failure")
			}
			var definition struct {
				Type        string `xml:"type,attr"`
				Description string `xml:"description"`
				Options     []struct {
					Name  string `xml:"name,attr"`
					Value string `xml:"value,attr"`
				} `xml:"option"`
			}
			path := strings.TrimPrefix(arg, "--new-ipset-from-file=")
			raw, err := os.ReadFile(path)
			if err != nil || xml.Unmarshal(raw, &definition) != nil {
				return "", errors.New("bad XML")
			}
			name := ""
			for _, option := range args {
				if strings.HasPrefix(option, "--name=") {
					name = strings.TrimPrefix(option, "--name=")
				}
			}
			options := map[string]string{}
			for _, option := range definition.Options {
				options[option.Name] = option.Value
			}
			value := sourceBankDefinition{Family: options["family"], Options: options, Entries: []string{}}
			if f.foreignRace {
				f.sets["permanent|"+name] = value
				f.owners[name] = "Foreign administrative set"
				return "", errors.New("ALREADY_ENABLED")
			}
			if _, exists := f.sets["permanent|"+name]; exists {
				return "", errors.New("ALREADY_ENABLED")
			}
			f.sets["permanent|"+name] = value
			f.owners[name] = definition.Description
			return "success", nil
		}
		if strings.HasPrefix(arg, "--delete-ipset=") {
			name := strings.TrimPrefix(arg, "--delete-ipset=")
			f.writes = append(f.writes, "delete")
			delete(f.sets, "permanent|"+name)
			delete(f.owners, name)
			return "success", nil
		}
		if strings.HasPrefix(arg, "--change-interface=") {
			f.runtimeInterfaces = strings.TrimPrefix(arg, "--change-interface=")
			f.writes = append(f.writes, "restore-binding")
			return "success", nil
		}
	}
	return f.managedFake.Run(ctx, name, args...)
}

func sourceBankFixture(t *testing.T) (*Agent, *sourceBankFake, Protection) {
	t.Helper()
	a, base, protection := managedTestAgent(t)
	f := &sourceBankFake{managedFake: base, sets: map[string]sourceBankDefinition{}, owners: map[string]string{}, runtimeInterfaces: "eth0", permanentInterfaces: "eth0"}
	a.Commands = f
	a.Config.Enforce = false
	a.Config.AllowFirewallChanges = false
	a.sourceBankConfigDigest = func() (string, error) { return shaText("fixture-global"), nil }
	a.checkSourceBankHealth = func(context.Context, *Policy, *SourceBankPreparationAssignment, Protection) error { return nil }
	a.armManaged = func(_ context.Context, path string, j *managedJournal) error {
		loaded, err := readManagedJournal(path, j.Nonce)
		if err != nil {
			return err
		}
		if loaded.Phase != "prepared" || loaded.SourceBankPreparation == nil {
			return errors.New("source-bank journal not durably armed")
		}
		return nil
	}
	a.sourceBankConfigurationLease = func() (*os.File, error) { return os.CreateTemp(t.TempDir(), "configuration-lease-") }
	a.Client = &Client{}
	fixtureAuthenticatedClient(a, "host-a")
	return a, f, protection
}

func sourceBankRequest(t *testing.T, a *Agent, operation string, baseline sourceBankBaseline, protection Protection) *Policy {
	t.Helper()
	request := &SourceBankPreparationAssignment{ID: "source-bank-" + operation, Operation: operation, PlanDigest: strings.Repeat("a", 64), BaselineDigest: baseline.Digest, ProtectionDigest: protection.Digest, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	if operation == "prepare_activate" {
		proof := singleAdminProofFixture()
		proof.PlanID = request.ID
		proof.PlanDigest = request.PlanDigest
		proof.Scope["kind"] = json.RawMessage(`"source_bank_preparation"`)
		request.ApprovalProof = sealDirectApproval(proof)
	}
	c, p := signPolicyForTest(t, &Policy{ServerID: "host-a", Mode: "monitor", SourceBankPreparation: request}, time.Now())
	a.Config.PolicySigningKeys = c.PolicySigningKeys
	a.Config.PolicySigningDeploymentID = c.PolicySigningDeploymentID
	return p
}

func TestSourceBankPreparationAssessHasNoWritesAndReportsExactMissingCounts(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	p := sourceBankRequest(t, a, "assess", sourceBankBaseline{}, Protection{})
	handled, err := a.processSourceBankPreparation(context.Background(), p)
	if !handled || err != nil {
		t.Fatal(handled, err)
	}
	receipt := ReadSourceBankPreparationStatus(a.Config.StateDir)
	if receipt == nil || receipt.Status != "assessed" || receipt.MissingBanks != 256 || !receipt.ActivationRequired || len(f.writes) != 0 {
		t.Fatalf("bad assessment %+v writes%v", receipt, f.writes)
	}
	raw, _ := json.Marshal(receipt)
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	for _, key := range []string{"schema_version", "id", "operation", "plan_digest", "status", "checked_at", "baseline_digest", "protection_digest", "missing_banks", "active_banks", "permanent_banks", "created_banks", "activation_required", "blockers"} {
		if _, exists := fields[key]; !exists {
			t.Fatal("missing wire field", key)
		}
	}
	if fields["blockers"] == nil {
		t.Fatal("nil blocker array")
	}
}

func TestSourceBankPreparationCreatesAndActivatesAllBanksWithoutEnforcementOptIns(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, err := a.sourceBankBaseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	fillSourceBankReceipt(&result, baseline)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	if f.createCount != 256 || f.reloads != 1 || a.Config.Enforce || a.Config.AllowFirewallChanges || a.State.ManagedBundle != nil {
		t.Fatal("incorrect activation or elevated opt-in", f.createCount, f.reloads)
	}
	receipt := ReadSourceBankPreparationStatus(a.Config.StateDir)
	if receipt == nil || receipt.Status != "prepared" || receipt.ActiveBanks != 256 || receipt.PermanentBanks != 256 || receipt.MissingBanks != 0 || receipt.ActivationRequired {
		t.Fatalf("incomplete prepared receipt %+v", receipt)
	}
	if receipt.BaselineDigest != p.SourceBankPreparation.BaselineDigest || receipt.ProtectionDigest != p.SourceBankPreparation.ProtectionDigest {
		t.Fatal("prepared outcome lost its reviewed binding")
	}
	for _, write := range f.writes {
		if write != "create" && write != "reload" {
			t.Fatal("unexpected mutation", write)
		}
	}
	paths, _ := filepath.Glob(filepath.Join(sourceBankDirectory(a.Config.StateDir), "*.json"))
	if len(paths) != 1 {
		t.Fatal("missing durable journal")
	}
	j, err := readManagedJournal(paths[0], strings.TrimSuffix(filepath.Base(paths[0]), ".json"))
	if err != nil || j.Phase != "committed" {
		t.Fatal("bad final journal", err)
	}
}

func TestSourceBankPreparationRejectsUnrelatedRuntimePermanentPolicyDrift(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	f.set("runtime", "port", "8443/tcp", true)
	if _, err := a.sourceBankBaseline(context.Background()); err == nil || len(f.writes) != 0 {
		t.Fatal("runtime-only access accepted", err)
	}
}

func TestSourceBankPreparationSupportsRuntimeOnlyNetworkManagerBindingAndRestoresIt(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	f.permanentInterfaces = ""
	f.dropRuntimeBinding = true
	baseline, err := a.sourceBankBaseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	if f.runtimeInterfaces != "eth0" || f.permanentInterfaces != "" {
		t.Fatal("runtime binding was lost or pinned to permanent")
	}
	if !strings.Contains(strings.Join(f.writes, ","), "restore-binding") {
		t.Fatal("dropped binding not restored")
	}
}

func TestSourceBankPreparationFailedHealthRollsBackOwnedBanksAndPreservesPolicy(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, err := a.sourceBankBaseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.checkSourceBankHealth = func(context.Context, *Policy, *SourceBankPreparationAssignment, Protection) error {
		if f.reloads > 0 {
			return errors.New("controller health failed")
		}
		return nil
	}
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err == nil {
		t.Fatal("failed health marked success")
	}
	if len(f.sets) != 0 || f.reloads != 2 || f.target != "default" {
		t.Fatal("original firewall not restored", len(f.sets), f.reloads, f.target)
	}
	receipt := ReadSourceBankPreparationStatus(a.Config.StateDir)
	if receipt == nil || receipt.Status != "rolled_back" {
		t.Fatalf("incorrect failure receipt %+v", receipt)
	}
}

func TestSourceBankPreparationPreservesCommittedSmallPoliciesOnSuccessAndRollback(t *testing.T) {
	for _, failHealth := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[failHealth], func(t *testing.T) {
			a, f, protection := sourceBankFixture(t)
			policy := managedTestPolicy(protection, 1, "10.30.0.0/24")
			rules, err := managedRules(policy, protection, strings.Repeat("b", 32), false)
			if err != nil {
				t.Fatal(err)
			}
			a.State.ManagedBundle = &ManagedBundle{Version: 1, Rules: rules}
			for _, rule := range rules {
				for _, scope := range []string{"runtime", "permanent"} {
					f.set(scope, "rich_rule", rule.Rule, true)
				}
			}
			before := map[string]bool{}
			for key, value := range f.rules {
				before[key] = value
			}
			baseline, err := a.sourceBankBaseline(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if failHealth {
				a.checkSourceBankHealth = func(context.Context, *Policy, *SourceBankPreparationAssignment, Protection) error {
					if f.reloads > 0 {
						return errors.New("post-reload witness failed")
					}
					return nil
				}
			}
			p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
			result := sourceBankReceipt(p.SourceBankPreparation)
			err = a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result)
			if (err != nil) != failHealth || !reflect.DeepEqual(before, f.rules) || a.State.ManagedBundle.Version != 1 {
				t.Fatal("committed policy matrix changed during empty-bank maintenance", err)
			}
		})
	}
}

func TestSourceBankPreparationRejectsTransitiveServiceDependenciesButComparesDirectFields(t *testing.T) {
	for _, key := range []string{"includes", "helpers", "modules", "destination", "protocols", "source-ports"} {
		t.Run(key, func(t *testing.T) {
			a, f, _ := sourceBankFixture(t)
			f.set("runtime", "service", "ssh", true)
			f.set("permanent", "service", "ssh", true)
			f.serviceDefinition = "ssh\n  ports: 2022/tcp\n  " + key + ": dependency\n"
			_, err := a.sourceBankBaseline(context.Background())
			blocked := key == "includes" || key == "helpers" || key == "modules"
			if (err != nil) != blocked || len(f.writes) != 0 {
				t.Fatal("unexpected service dependency/parity result", err)
			}
		})
	}
}

func TestSourceBankPreparationAllowsUnchangedInactiveStockServiceIncludes(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	f.inactiveZone = "internal\n  target: default\n  interfaces:\n  sources:\n  services: samba-client\n  ports:\n  protocols:\n  forward: yes\n  masquerade: no\n  rich rules:\n"
	f.serviceDefinition = "samba-client\n  ports: 138/udp\n  includes: netbios-ns\n"
	if _, err := a.sourceBankBaseline(context.Background()); err != nil {
		t.Fatal("unchanged inactive stock samba-client include blocked preparation", err)
	}
	f.inactiveZone = strings.Replace(f.inactiveZone, "internal\n", "internal (active)\n", 1)
	if _, err := a.sourceBankBaseline(context.Background()); err == nil || !strings.Contains(err.Error(), "samba-client") {
		t.Fatal("active transitive service was allowed or blocker omitted its name", err)
	}
	if len(f.writes) != 0 {
		t.Fatal("service context assessment changed the firewall")
	}
}

func TestSourceBankPreparationRollbackRefusesPopulatedRuntimeBank(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(sourceBankDirectory(a.Config.StateDir), "*.json"))
	path := paths[0]
	j, err := readManagedJournal(path, strings.TrimSuffix(filepath.Base(path), ".json"))
	if err != nil {
		t.Fatal(err)
	}
	name := j.SourceBankPreparation.Created[len(j.SourceBankPreparation.Created)-1]
	active := f.sets["runtime|"+name]
	active.Entries = []string{"2001:db8::/64"}
	f.sets["runtime|"+name] = active
	beforeWrites := len(f.writes)
	if err := rollbackSourceBanks(context.Background(), f, path, j, a.sourceBankConfigDigest); err == nil || j.Phase != "rollback_failed" || len(f.writes) != beforeWrites {
		t.Fatal("rollback overwrote external runtime membership", err, j.Phase)
	}
	if len(f.sets["runtime|"+name].Entries) != 1 {
		t.Fatal("runtime source-bank membership was discarded")
	}
}

func TestSourceBankPreparationRejectsPreviouslyInactivePermanentBanksBeforeMutation(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	set := sourceBankDefinitions()[0]
	f.sets["permanent|"+set.Name] = sourceBankDefinition{Family: set.Family, Options: map[string]string{"family": set.Family, "hashsize": "1024", "maxelem": "16384"}, Entries: []string{}}
	if _, err := a.sourceBankBaseline(context.Background()); err == nil || len(f.writes) != 0 {
		t.Fatal("pre-existing inactive bank admitted an irreversible activation", err)
	}
}

func TestSourceBankPreparationPreservesStockInactiveMasqueradeZoneWithExactParity(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	f.inactiveZone = "external\n  target: default\n  interfaces:\n  sources:\n  services:\n  ports:\n  protocols:\n  forward: yes\n  masquerade: yes\n  rich rules:\n"
	if _, err := a.sourceBankBaseline(context.Background()); err != nil {
		t.Fatal("unchanged stock inactive external zone rejected", err)
	}
	f.permanentInactiveZone = strings.Replace(f.inactiveZone, "masquerade: yes", "masquerade: no", 1)
	if _, err := a.sourceBankBaseline(context.Background()); err == nil {
		t.Fatal("staged inactive-zone policy change admitted")
	}
	f.permanentInactiveZone = ""
	f.inactiveZone = strings.Replace(f.inactiveZone, "external\n", "external (active)\n", 1)
	if _, err := a.sourceBankBaseline(context.Background()); err == nil {
		t.Fatal("active masquerading admitted")
	}
	if len(f.writes) != 0 {
		t.Fatal("parity assessment changed the firewall")
	}
}

func TestSourceBankPreparationRejectsConflictingOrExtraPermanentInterfaceBindingsBeforeWrites(t *testing.T) {
	for _, example := range []string{"different-zone", "extra-interface", "unsafe-runtime-only-default"} {
		t.Run(example, func(t *testing.T) {
			a, f, _ := sourceBankFixture(t)
			switch example {
			case "different-zone":
				f.inactiveZone = "trusted\n  target: ACCEPT\n  interfaces:\n  sources:\n  services:\n  ports:\n  protocols:\n  forward: yes\n  masquerade: no\n  rich rules:\n"
				f.permanentInterfaces = ""
				f.permanentInactiveZone = strings.Replace(f.inactiveZone, "interfaces:", "interfaces: eth0", 1)
			case "extra-interface":
				f.permanentInterfaces = "eth0 eth1"
			case "unsafe-runtime-only-default":
				f.permanentInterfaces = ""
				f.defaultZone = "trusted"
			}
			if _, err := a.sourceBankBaseline(context.Background()); err == nil || len(f.writes) != 0 {
				t.Fatal("unsafe permanent/runtime interface transition admitted", err, f.writes)
			}
		})
	}
}

func TestSourceBankPreparationInterruptedCreationRecoversBanksLoadedByDaemonRestart(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(sourceBankDirectory(a.Config.StateDir), "*.json"))
	path := paths[0]
	j, err := readManagedJournal(path, strings.TrimSuffix(filepath.Base(path), ".json"))
	if err != nil {
		t.Fatal(err)
	}
	// A host/daemon restart can load partially created permanent objects before
	// the original agent reaches its own reload intent marker.
	j.Phase = "creating"
	j.SourceBankPreparation.Reloaded = false
	j.SourceBankPreparation.Report.Status = "preparing"
	if err := saveManagedJournal(path, j); err != nil {
		t.Fatal(err)
	}
	previousReloads := f.reloads
	if err := rollbackSourceBanks(context.Background(), f, path, j, a.sourceBankConfigDigest); err != nil {
		t.Fatal(err)
	}
	if f.reloads != previousReloads+1 || len(f.sets) != 0 || j.Phase != "rolled_back" {
		t.Fatal("restart-loaded partial banks were not automatically restored", f.reloads, len(f.sets), j.Phase)
	}
}

func TestSourceBankPreparationPartialCreateFailureRollsBackWithoutReload(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	f.failCreate = 7
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err == nil {
		t.Fatal("partial creation accepted")
	}
	if len(f.sets) != 0 || f.reloads != 0 {
		t.Fatal("partial definitions left active or caused reload")
	}
}

func TestSourceBankPreparationForeignNameRaceIsNeverDeletedOrReportedRolledBack(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	f.foreignRace = true
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err == nil {
		t.Fatal("foreign collision accepted")
	}
	if len(f.sets) != 1 || strings.Contains(strings.Join(f.writes, ","), "delete") {
		t.Fatal("foreign set was removed")
	}
	receipt := ReadSourceBankPreparationStatus(a.Config.StateDir)
	if receipt == nil || receipt.Status != "error" {
		t.Fatal("uncertain rollback falsely reported success", receipt)
	}
}

func TestSourceBankPreparationUnsignedOrWrongProofCannotMutate(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	p.Signature = nil
	if err := a.validateSourceBankAssignment(p, p.SourceBankPreparation, time.Now()); err == nil {
		t.Fatal("unsigned maintenance accepted")
	}
	p = sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	var proof endpointApprovalProof
	json.Unmarshal(p.SourceBankPreparation.ApprovalProof, &proof)
	proof.Scope["kind"] = json.RawMessage(`"managed_policy"`)
	p.SourceBankPreparation.ApprovalProof = sealDirectApproval(proof)
	c, p := signPolicyForTest(t, p, time.Now())
	a.Config.PolicySigningKeys = c.PolicySigningKeys
	if err := a.validateSourceBankAssignment(p, p.SourceBankPreparation, time.Now()); err == nil || len(f.writes) != 0 {
		t.Fatal("cross-operation authority accepted")
	}
}

func TestSourceBankPreparationCachesReceiptsAndRetainsReplayFence(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	a.State.Policy = p
	before := append([]string{}, f.writes...)
	handled, err := a.processSourceBankPreparation(context.Background(), p)
	if !handled || err != nil || !reflect.DeepEqual(before, f.writes) {
		t.Fatal("same assignment repeated mutations", err)
	}
	assess := sourceBankRequest(t, a, "assess", sourceBankBaseline{}, protection)
	receipt := sourceBankReceipt(assess.SourceBankPreparation)
	receipt.Status = "assessed"
	if err := a.sourceBankStatus(receipt); err != nil {
		t.Fatal(err)
	}
	handled, err = a.processSourceBankPreparation(context.Background(), p)
	if !handled || err != nil || !reflect.DeepEqual(before, f.writes) {
		t.Fatal("history replay repeated mutations", err)
	}
}

func TestSourceBankPreparationRecoveryAndUpgradeFence(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(sourceBankDirectory(a.Config.StateDir), "*.json"))
	path := paths[0]
	nonce := strings.TrimSuffix(filepath.Base(path), ".json")
	journal, err := readManagedJournal(path, nonce)
	if err != nil {
		t.Fatal(err)
	}
	journal.Phase = "activating"
	if err := saveManagedJournal(path, journal); err != nil {
		t.Fatal(err)
	}
	if err := checkEnforcementJournals(a.Config); err == nil {
		t.Fatal("upgrade did not fence active source-bank maintenance")
	}
	if err := a.recoverSourceBankPreparationLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.sets) != 0 {
		t.Fatal("interrupted activation not recovered")
	}
	if err := checkEnforcementJournals(a.Config); err != nil {
		t.Fatal("terminal recovery kept upgrade blocked", err)
	}
}

func TestSourceBankPreparationExistingAndForeignSetsArePreserved(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	definition := sourceBankDefinition{Family: "inet", Options: map[string]string{"family": "inet", "hashsize": "1024", "maxelem": "16384"}, Entries: []string{"192.0.2.1/32"}}
	f.sets["runtime|prthak_a4_00"] = definition
	f.sets["permanent|prthak_a4_00"] = definition
	if _, err := a.sourceBankBaseline(context.Background()); err != nil {
		t.Fatal("valid existing bank rejected", err)
	}
	f.sets["permanent|other_set"] = definition
	if _, err := a.sourceBankBaseline(context.Background()); err == nil {
		t.Fatal("foreign bank context accepted")
	}
	if len(f.writes) != 0 {
		t.Fatal("inspection modified existing definitions")
	}
}

func TestSourceBankPreparationJournalAreaAndCorruptionAreRejected(t *testing.T) {
	a, _, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	request := sourceBankRequest(t, a, "prepare_activate", baseline, protection).SourceBankPreparation
	j := &managedJournal{Nonce: strings.Repeat("a", 32), PID: os.Getpid(), SourceBankPreparation: &sourceBankJournal{Assignment: *request, Baseline: baseline, Report: sourceBankReceipt(request)}}
	path := managedJournalPath(a.Config.StateDir, j.Nonce)
	if err := saveManagedJournal(path, j); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedJournal(path, j.Nonce); err == nil {
		t.Fatal("source-bank journal in ordinary access area accepted")
	}
	j.SourceBankPreparation.Created = []string{"not_owned"}
	if err := validateSourceBankJournal(j); err == nil {
		t.Fatal("unowned rollback name accepted")
	}
	j.SourceBankPreparation.Created = nil
	j.SourceBankPreparation.Baseline.Digest = strings.Repeat("c", 64)
	if err := validateSourceBankJournal(j); err == nil {
		t.Fatal("corrupted baseline accepted")
	}
}

func TestSourceBankPreparationGenericOrCorruptReplayJournalBlocksWithoutPanic(t *testing.T) {
	a, _, _ := sourceBankFixture(t)
	directory := sourceBankDirectory(a.Config.StateDir)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `{"nonce":"wrong"}`, `{"source_bank_preparation":null}`} {
		path := filepath.Join(directory, strings.Repeat("a", 32)+".json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := a.previousSourceBankOperation("requested-id", strings.Repeat("a", 64)); err == nil {
			t.Fatal("unverifiable history accepted")
		}
	}
}

func TestSourceBankPreparationRevokedWitnessPrecedesEveryWrite(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	checks := 0
	a.checkSourceBankHealth = func(context.Context, *Policy, *SourceBankPreparationAssignment, Protection) error {
		checks++
		return errors.New("Admin authority revoked")
	}
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err == nil || checks != 1 || len(f.writes) != 0 {
		t.Fatal("write preceded fresh authority", err, checks, f.writes)
	}
}

func TestSourceBankPreparationTimerFailureNeverWritesFirewall(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	a.armManaged = func(context.Context, string, *managedJournal) error { return errors.New("watchdog unavailable") }
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err == nil || len(f.writes) != 0 {
		t.Fatal("unsafe unguarded mutation", err, f.writes)
	}
	status := ReadSourceBankPreparationStatus(a.Config.StateDir)
	if status == nil || status.Status != "rolled_back" {
		t.Fatal("no-write failure not durably closed", status)
	}
}

func TestGUISetupCanPinRestrictedManagementSourcesWithoutEnforcement(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(fmtInt(schema), func(t *testing.T) {
			value, _, _, now := setupFixture(t)
			value.SchemaVersion = schema
			if schema == 2 || schema == 3 {
				value.EnrollmentProfileID = "12345678-1234-1234-1234-123456789abc"
				value.EnrollmentToken = strings.Repeat("a", 64)
				value.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
				value.ControllerCA = setupCA(t, now, true, now.Add(3*time.Hour))
			}
			if schema == 3 {
				value.InstallationOptions = &HostPreparationOptions{UFWAction: "assess"}
			}
			var config Config
			json.Unmarshal(value.Config, &config)
			config.ManagementSources = []string{"10.20.1.7/24", "2001:db8::1/64"}
			value.Config, _ = json.Marshal(config)
			raw, _ := json.Marshal(value)
			parsed, _, err := parseSetup(raw, "test-host", now)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Enforce || parsed.AllowFirewallChanges || parsed.AllowHostDefaultDeny || !reflect.DeepEqual(parsed.ManagementSources, []string{"10.20.1.0/24", "2001:db8::/64"}) {
				t.Fatal("management pin changed privilege", parsed)
			}
			for _, unsafe := range [][]string{{"0.0.0.0/0"}, {"::/0"}, make([]string, 101)} {
				config.ManagementSources = unsafe
				value.Config, _ = json.Marshal(config)
				raw, _ = json.Marshal(value)
				if _, _, err := parseSetup(raw, "test-host", now); err == nil {
					t.Fatal("unsafe management sources accepted", unsafe)
				}
			}
		})
	}
}

func fmtInt(value int) string { return []string{"", "1", "2", "3"}[value] }

func TestSourceBankPreparationFullSignedHandlerCompletesWithoutChangingConfiguration(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	protection := a.sourceBankProtection(context.Background())
	baseline, err := a.sourceBankBaseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	a.State.Policy = p
	handled, err := a.processSourceBankPreparation(context.Background(), p)
	if !handled || err != nil {
		t.Fatal(handled, err)
	}
	if status := ReadSourceBankPreparationStatus(a.Config.StateDir); status == nil || status.Status != "prepared" || status.BaselineDigest != p.SourceBankPreparation.BaselineDigest || status.ProtectionDigest != p.SourceBankPreparation.ProtectionDigest {
		t.Fatal("bound outcome missing", status)
	}
	if a.Config.Enforce || a.Config.AllowFirewallChanges || a.Config.LearningAutoAllow || f.createCount != 256 || f.reloads != 1 {
		t.Fatal("handler changed local consent or omitted activation")
	}
}

func TestSourceBankPreparationFailedReloadCompensatesWithVerifiedSecondReload(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	f.failReload = 1
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err == nil {
		t.Fatal("failed reload accepted")
	}
	if len(f.sets) != 0 || f.reloads != 2 {
		t.Fatal("failed reload not compensated", len(f.sets), f.reloads)
	}
	if status := ReadSourceBankPreparationStatus(a.Config.StateDir); status == nil || status.Status != "rolled_back" {
		t.Fatal("rollback not confirmed", status)
	}
}

func TestSourceBankPreparationStaleReviewCannotCreateDefinitions(t *testing.T) {
	a, f, _ := sourceBankFixture(t)
	protection := a.sourceBankProtection(context.Background())
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	f.set("runtime", "port", "18080/tcp", true)
	f.set("permanent", "port", "18080/tcp", true)
	if handled, err := a.processSourceBankPreparation(context.Background(), p); !handled || err == nil || len(f.writes) != 0 {
		t.Fatal("changed baseline was written", handled, err, f.writes)
	}
	status := ReadSourceBankPreparationStatus(a.Config.StateDir)
	if status == nil || status.Status != "blocked" || status.BaselineDigest != p.SourceBankPreparation.BaselineDigest || status.ProtectionDigest != p.SourceBankPreparation.ProtectionDigest {
		t.Fatal("blocked receipt lost reviewed binding", status)
	}
}

func TestSourceBankPreparationWitnessRequiresExactPlanNonceAndApprovedSSH(t *testing.T) {
	a, _, protection := sourceBankFixture(t)
	a.inventory = &Report{IPs: []string{"192.0.2.10"}}
	baseline := sourceBankBaseline{Digest: strings.Repeat("b", 64)}
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	request := p.SourceBankPreparation
	now := time.Now().UTC()
	nonce := strings.Repeat("d", 32)
	w := sourceBankWitness{ID: request.ID, PlanDigest: request.PlanDigest, BaselineDigest: request.BaselineDigest, managedWitness: managedWitness{Nonce: nonce, ServerID: p.ServerID, ProtectionDigest: protection.Digest, CheckedAt: now, ControllerOK: true, Status: "healthy"}}
	check := struct {
		TargetIP          string `json:"target_ip"`
		Port              int    `json:"port"`
		SourceIP          string `json:"source_ip"`
		SSHBannerVerified bool   `json:"ssh_banner_verified"`
	}{"192.0.2.10", 2022, "10.20.0.2", true}
	w.SSHChecks = append(w.SSHChecks, check)
	if err := a.validateSourceBankWitness(w, p, request, protection, nonce, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*sourceBankWitness){func(w *sourceBankWitness) { w.ID = "different" }, func(w *sourceBankWitness) { w.PlanDigest = strings.Repeat("c", 64) }, func(w *sourceBankWitness) { w.Nonce = "wrong" }, func(w *sourceBankWitness) { w.CheckedAt = now.Add(-time.Minute) }, func(w *sourceBankWitness) { w.SSHChecks = nil }, func(w *sourceBankWitness) { w.ServerID = "other" }, func(w *sourceBankWitness) { w.ProtectionDigest = strings.Repeat("c", 64) }} {
		copy := w
		mutate(&copy)
		if err := a.validateSourceBankWitness(copy, p, request, protection, nonce, now); err == nil {
			t.Fatal("unbound maintenance witness accepted")
		}
	}
}
