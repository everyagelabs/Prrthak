package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreparationSetupSchemaStrictAndPrivate(t *testing.T) {
	for _, fleet := range []bool{false, true} {
		kit, path, output, now := setupFixture(t)
		kit.SchemaVersion = 3
		kit.InstallationOptions = &HostPreparationOptions{true, "assess"}
		if fleet {
			kit.EnrollmentProfileID = "12345678-1234-1234-1234-123456789012"
			kit.EnrollmentToken = strings.Repeat("a", 64)
			kit.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339)
			kit.ControllerCA = setupCA(t, now, true, now.Add(3*time.Hour))
		}
		writeSetup(t, path, kit)
		if err := PrepareSetupFile(path, output, "endpoint-01", now); err != nil {
			t.Fatal(err)
		}
		raw, err := readPrivateSetupBound(output+"/preparation-options.json", 1024)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `{"install_dependencies":true,"ufw_action":"assess"}` {
			t.Fatalf("unexpected private preparation data: %s", raw)
		}
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["schema_version"] = 1 },
		func(v map[string]any) { v["schema_version"] = 2 },
		func(v map[string]any) { delete(v, "installation_options") },
		func(v map[string]any) {
			v["installation_options"] = map[string]any{"install_dependencies": false, "ufw_action": "preserve"}
		},
		func(v map[string]any) { v["installation_options"] = map[string]any{"ufw_action": "assess"} },
		func(v map[string]any) {
			v["installation_options"] = map[string]any{"install_dependencies": nil, "ufw_action": "assess"}
		},
		func(v map[string]any) {
			v["installation_options"] = map[string]any{"install_dependencies": true, "ufw_action": "disable"}
		},
		func(v map[string]any) {
			v["installation_options"] = map[string]any{"install_dependencies": true, "ufw_action": "assess", "command": "anything"}
		},
	} {
		kit, path, output, now := setupFixture(t)
		kit.SchemaVersion = 3
		kit.InstallationOptions = &HostPreparationOptions{true, "assess"}
		raw, _ := json.Marshal(kit)
		var v map[string]any
		_ = json.Unmarshal(raw, &v)
		change(v)
		writeSetup(t, path, v)
		if err := PrepareSetupFile(path, output, "endpoint-01", now); err == nil {
			t.Fatal("unsafe setup accepted")
		}
		emptySetupOutput(t, output)
	}
}

func TestPreparationOptionsRejectNullBooleanIndependently(t *testing.T) {
	err := validateHostPreparationOptions(HostPreparationOptions{false, "assess"}, json.RawMessage(`{"install_dependencies":null,"ufw_action":"assess"}`))
	if err == nil {
		t.Fatal("null dependency option accepted as false")
	}
}

func TestAutomaticInstallerDependencyConsentPreservesPrivateKitAndSecurityOptions(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(string(rune('0'+schema)), func(t *testing.T) {
			kit, _, _, now := setupFixture(t)
			kit.SchemaVersion = schema
			if schema == 2 {
				kit.ExpectedHostname = ""
				kit.EnrollmentProfileID = "12345678-1234-1234-1234-123456789012"
				kit.EnrollmentToken = strings.Repeat("a", 64)
				kit.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339)
				kit.ControllerCA = setupCA(t, now, true, now.Add(3*time.Hour))
			}
			if schema == 3 {
				kit.InstallationOptions = &HostPreparationOptions{InstallDependencies: false, UFWAction: "assess"}
			}
			raw, _ := json.Marshal(kit)
			c, parsed, err := parseSetup(raw, "endpoint-01", now)
			if err != nil {
				t.Fatal(err)
			}
			options, err := preparationOptionsForSetup(parsed, true)
			if err != nil || !options.InstallDependencies {
				t.Fatalf("automatic dependency consent refused: %#v %v", options, err)
			}
			wantAction := "preserve"
			if schema == 3 {
				wantAction = "assess"
			}
			if options.UFWAction != wantAction {
				t.Fatal("automatic package consent changed the GUI UFW choice")
			}
			if c.Enforce || c.AllowFirewallChanges || c.LearningAutoAllow || c.AllowHostDefaultDeny || c.UnexpectedPortMonitorEnabled {
				t.Fatal("dependency consent enabled firewall/security instrumentation")
			}
			after, _ := json.Marshal(parsed)
			if string(after) != string(raw) {
				t.Fatal("automatic dependency consent rewrote private setup data")
			}
			_, err = preparationOptionsForSetup(parsed, false)
			if schema != 3 && err == nil {
				t.Fatal("legacy entrypoint unexpectedly gained dependency consent")
			}
		})
	}
}

func TestAutomaticInstallerUsesProtectedPackageSuppressionForOriginalKit(t *testing.T) {
	kit, _, _, now := setupFixture(t)
	raw, _ := json.Marshal(kit)
	_, parsed, err := parseSetup(raw, "endpoint-01", now)
	if err != nil {
		t.Fatal(err)
	}
	options, err := preparationOptionsForSetup(parsed, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"rhel", "ubuntu"} {
		root, config, runner := preparationFixture(t, family)
		if err := prepareHostUnder(context.Background(), root, family, config, options, runner, now); err != nil {
			t.Fatal(err)
		}
		receipt := ReadHostPreparationStatus(root + "/var/lib/seg-agent")
		if receipt == nil || receipt.Status != "prepared" || !receipt.InstallDependencies || !receipt.DependenciesChanged {
			t.Fatalf("automatic dependency result not recorded: %#v", receipt)
		}
		for _, call := range runner.calls {
			if strings.Contains(call, " start ") || strings.Contains(call, " stop ") || strings.Contains(call, "ufw disable") {
				t.Fatalf("automatic installer changed firewall activation: %s", call)
			}
		}
	}
}

type preparationFake struct {
	root              string
	calls             []string
	failPackage       bool
	preset            bool
	ufw               bool
	tamperPolicy      bool
	assertSuppression bool
	maskIneffective   bool
	ufwQueryUnknown   bool
	tamperUFW         bool
	unitMissing       bool
}

func (f *preparationFake) Run(ctx context.Context, name string, args ...string) (string, error) {
	lease := managedLeaseFromContext(ctx)
	if lease == nil || filepath.Base(filepath.Dir(lease.Name())) != "managed" || filepath.Base(lease.Name()) != "lock" {
		return "", errors.New("preparation commands must retain the actual managed lease")
	}
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if strings.Contains(call, " ufw.service") {
		if f.ufw {
			return "active", nil
		}
		return "inactive", errors.New("inactive")
	}
	if name == "/usr/bin/systemctl" {
		switch args[0] {
		case "show":
			if target, e := os.Readlink(f.root + "/run/systemd/system/firewalld.service"); e == nil && target == "/dev/null" && !f.maskIneffective {
				return "masked", nil
			}
			if f.unitMissing {
				return "not-found", nil
			}
			return "loaded", nil
		case "is-active":
			return "inactive", errors.New("inactive")
		case "is-enabled":
			if f.preset {
				return "enabled", nil
			}
			return "disabled", errors.New("disabled")
		case "disable":
			f.preset = false
			return "", nil
		case "daemon-reload":
			return "", nil
		}
	}
	if name == "/usr/sbin/ufw" {
		if strings.Join(args, " ") != "status verbose" {
			return "", errors.New("unexpected UFW mutation")
		}
		if f.ufwQueryUnknown {
			return "", errors.New("unknown UFW state")
		}
		return "Status: active\nprivate-source 10.1.2.3", nil
	}
	if name == "/usr/bin/env" || name == "/usr/bin/dnf" {
		if f.assertSuppression {
			link, e := os.Readlink(f.root + "/run/systemd/system/firewalld.service")
			if e != nil || link != "/dev/null" {
				return "", errors.New("firewall startup was not suppressed")
			}
			if name == "/usr/bin/env" {
				raw, e := os.ReadFile(f.root + "/usr/sbin/policy-rc.d")
				if e != nil || string(raw) != preparationPolicy {
					return "", errors.New("package hooks were not suppressed")
				}
			}
		}
		if strings.Contains(call, " install ") {
			f.unitMissing = false
			if name == "/usr/bin/env" && !strings.Contains(call, "--no-remove") {
				return "", errors.New("APT removal protection is required")
			}
			f.preset = true
			if f.failPackage {
				return "private package output must not leak", errors.New("failed")
			}
			for _, p := range []string{"/usr/bin/firewall-cmd", "/usr/bin/ss", "/usr/bin/flock"} {
				_ = os.WriteFile(f.root+p, []byte("test"), 0755)
			}
			if f.tamperUFW {
				_ = os.WriteFile(f.root+"/etc/ufw/user.rules", []byte("changed unexpectedly"), 0644)
			}
			for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"} {
				_ = os.WriteFile(f.root+p, []byte("fixture public CA"), 0644)
			}
		}
		return "", nil
	}
	return "", errors.New("unexpected command: " + call)
}
func preparationFixture(t *testing.T, family string) (string, Config, *preparationFake) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range []string{"/usr/bin", "/usr/sbin", "/run/systemd/system", "/etc/ufw", "/etc/default", "/etc/ssl/certs", "/etc/pki/tls/certs"} {
		if e = os.MkdirAll(root+d, 0755); e != nil {
			t.Fatal(e)
		}
	}
	for _, p := range []string{"/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/journalctl", "/usr/bin/env", "/usr/bin/apt-get", "/usr/bin/dnf"} {
		if e = os.WriteFile(root+p, []byte("fake; never executed"), 0755); e != nil {
			t.Fatal(e)
		}
	}
	version := "9.6"
	if family == "ubuntu" {
		version = "26.04"
	}
	if e = os.WriteFile(root+"/etc/os-release", []byte("ID="+family+"\nVERSION_ID="+version+"\n"), 0644); e != nil {
		t.Fatal(e)
	}
	c := defaultConfig()
	return root, c, &preparationFake{root: root, assertSuppression: true}
}
func TestDependencyPreparationSuppressesHooksRestoresStateAndReportsPartialFailure(t *testing.T) {
	for _, family := range []string{"ubuntu", "rhel"} {
		for _, failure := range []bool{false, true} {
			t.Run(family+"/"+map[bool]string{true: "failure", false: "success"}[failure], func(t *testing.T) {
				root, c, f := preparationFixture(t, family)
				f.failPackage = failure
				e := prepareHostUnder(context.Background(), root, family, c, HostPreparationOptions{true, "preserve"}, f, time.Now().UTC())
				if failure != (e != nil) {
					t.Fatalf("error=%v calls=%v", e, f.calls)
				}
				for _, path := range []string{"/usr/sbin/policy-rc.d", "/run/systemd/system/firewalld.service", preparationDirectory + "/suppression.json"} {
					if _, e := os.Lstat(root + path); !os.IsNotExist(e) {
						t.Fatalf("suppression artifact remains: %s %v", path, e)
					}
				}
				if f.preset {
					t.Fatal("package preset left firewalld enabled")
				}
				receipt := ReadHostPreparationStatus(root + "/var/lib/seg-agent")
				if receipt == nil || !receipt.DependenciesChanged || receipt.Firewalld.Active == nil || *receipt.Firewalld.Active {
					t.Fatalf("invalid receipt: %#v", receipt)
				}
				if failure && (receipt.Status != "error" || strings.Contains(receipt.Error, "private package")) {
					t.Fatalf("failure hidden or private output leaked: %#v", receipt)
				}
				for _, call := range f.calls {
					if strings.Contains(call, " start ") || strings.Contains(call, " stop ") || strings.Contains(call, "ufw disable") {
						t.Fatalf("unexpected service mutation: %s", call)
					}
				}
			})
		}
	}
}
func TestPreparationRefusesExistingPolicyAndRuntimeOverridesWithoutPackageActions(t *testing.T) {
	for _, file := range []string{"/usr/sbin/policy-rc.d", "/run/systemd/system/firewalld.service"} {
		root, c, f := preparationFixture(t, "ubuntu")
		original := []byte("administrator-owned-preserve")
		if e := os.WriteFile(root+file, original, 0755); e != nil {
			t.Fatal(e)
		}
		if e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now()); e == nil {
			t.Fatal("existing administration policy accepted")
		}
		raw, _ := os.ReadFile(root + file)
		if string(raw) != string(original) {
			t.Fatal("existing administration policy changed")
		}
		for _, call := range f.calls {
			if strings.Contains(call, "apt-get") {
				t.Fatal("packages ran before suppression was safe")
			}
		}
	}
}
func TestUFWPrivateExportAndPublicReceiptNeverContainRules(t *testing.T) {
	root, c, f := preparationFixture(t, "ubuntu")
	f.ufw = true
	for _, item := range []struct{ path, text string }{{"/usr/sbin/ufw", "fake"}, {"/etc/ufw/ufw.conf", "ENABLED=yes\n"}, {"/etc/ufw/user.rules", "private-source-rule 10.2.3.4\n"}} {
		if e := os.WriteFile(root+item.path, []byte(item.text), 0755); e != nil {
			t.Fatal(e)
		}
	}
	if e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{false, "assess"}, f, time.Now()); e != nil {
		t.Fatal(e)
	}
	receipt := ReadHostPreparationStatus(root + "/var/lib/seg-agent")
	encoded, _ := json.Marshal(receipt)
	if receipt == nil || receipt.Status != "assessment_only" || !receipt.UFW.MigrationRequired || receipt.UFW.ExportPath != ufwExportPath {
		t.Fatalf("invalid assessment: %s", encoded)
	}
	if strings.Contains(string(encoded), "private-source") {
		t.Fatal("private UFW rules leaked to report")
	}
	raw, e := readPrivateSetupBound(root+ufwExportPath, 2<<20)
	if e != nil || !strings.Contains(string(raw), "private-source-rule") {
		t.Fatalf("missing private export: %v", e)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "apt-get") || strings.Contains(call, "dnf") || strings.Contains(call, "daemon-reload") {
			t.Fatalf("assessment performed mutation: %s", call)
		}
	}
}
func TestPreparationPreservesUFWByDefaultAndRejectsUnsafeExport(t *testing.T) {
	root, c, f := preparationFixture(t, "ubuntu")
	f.ufw = true
	_ = os.WriteFile(root+"/usr/sbin/ufw", []byte("fake"), 0755)
	_ = os.WriteFile(root+"/etc/ufw/ufw.conf", []byte("ENABLED=yes\n"), 0644)
	_ = os.Symlink("/etc/passwd", root+"/etc/ufw/user.rules")
	e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{false, "assess"}, f, time.Now())
	if e == nil {
		t.Fatal("unsafe export followed symlink")
	}
	if _, e = os.Stat(root + ufwExportPath); !os.IsNotExist(e) {
		t.Fatal("unsafe export was persisted")
	}
	for _, call := range f.calls {
		if strings.Contains(call, "apt-get") {
			t.Fatal("failed assessment still installed packages")
		}
	}
}
func TestPreparationLeaseAndUnfinishedJournalBlockConcurrentPackageActions(t *testing.T) {
	root, c, f := preparationFixture(t, "ubuntu")
	lease, e := configurationLeaseUnder(root, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now()); e == nil {
		t.Fatal("concurrent installer accepted")
	}
	lease.Close()
	directory, e := preparationPrivateDirectory(root)
	if e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(directory+"/suppression.json", []byte(`{"phase":"armed"}`), 0600)
	if e = prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now()); e == nil {
		t.Fatal("unfinished preparation silently recovered")
	}
	if len(f.calls) != 0 {
		t.Fatalf("blocked preparation invoked commands: %v", f.calls)
	}
	receipt := ReadHostPreparationStatus(root + "/var/lib/seg-agent")
	if receipt == nil || receipt.Status != "blocked" {
		t.Fatalf("blocked state not visible: %#v", receipt)
	}
}

func TestPreparationRefusesHigherPriorityUnitsAndPreservesMasks(t *testing.T) {
	for _, base := range []string{"/etc/systemd/system", "/run/systemd/transient", "/run/systemd/generator.early"} {
		root, c, f := preparationFixture(t, "ubuntu")
		_ = os.MkdirAll(root+base, 0755)
		path := root + base + "/firewalld.service"
		_ = os.WriteFile(path, []byte("administrator unit must not change"), 0644)
		if e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now()); e == nil {
			t.Fatal("higher priority override accepted")
		}
		raw, _ := os.ReadFile(path)
		if string(raw) != "administrator unit must not change" {
			t.Fatal("administrator override changed")
		}
		for _, call := range f.calls {
			if strings.Contains(call, "apt-get") {
				t.Fatal("packages ran despite unsafe override")
			}
		}
	}
	root, c, f := preparationFixture(t, "ubuntu")
	_ = os.MkdirAll(root+"/etc/systemd/system", 0755)
	persistent := root + "/etc/systemd/system/firewalld.service"
	_ = os.Symlink("/dev/null", persistent)
	if e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now()); e != nil {
		t.Fatal(e)
	}
	if target, e := os.Readlink(persistent); e != nil || target != "/dev/null" {
		t.Fatal("existing permanent mask changed")
	}
}

func TestPreparationRequiresEffectiveMaskAndRetainsSuppressionIfUFWRulesChange(t *testing.T) {
	root, c, f := preparationFixture(t, "ubuntu")
	f.maskIneffective = true
	if e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now()); e == nil {
		t.Fatal("ineffective mask accepted")
	}
	for _, call := range f.calls {
		if strings.Contains(call, "apt-get") {
			t.Fatal("package action before effective mask proof")
		}
	}
	root, c, f = preparationFixture(t, "ubuntu")
	f.ufw = true
	f.tamperUFW = true
	_ = os.WriteFile(root+"/usr/sbin/ufw", []byte("fixture"), 0755)
	_ = os.WriteFile(root+"/etc/ufw/user.rules", []byte("existing private rules"), 0644)
	e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now())
	if e == nil || !strings.Contains(e.Error(), "UFW configuration changed") {
		t.Fatalf("UFW change hidden: %v", e)
	}
	for _, path := range []string{"/usr/sbin/policy-rc.d", "/run/systemd/system/firewalld.service", preparationDirectory + "/suppression.json"} {
		if _, e := os.Lstat(root + path); e != nil {
			t.Fatalf("safety suppression not retained: %s %v", path, e)
		}
	}
}
func TestUFWUnknownStateRemainsUnknownAndRequiresMigration(t *testing.T) {
	root, c, f := preparationFixture(t, "ubuntu")
	f.ufw = true
	f.ufwQueryUnknown = true
	_ = os.WriteFile(root+"/usr/sbin/ufw", []byte("fixture"), 0755)
	if e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{false, "preserve"}, f, time.Now()); e != nil {
		t.Fatal(e)
	}
	status := ReadHostPreparationStatus(root + "/var/lib/seg-agent")
	if status == nil || status.UFW.Active != nil || !status.UFW.MigrationRequired {
		t.Fatalf("unknown UFW state presented as inactive: %#v", status)
	}
	raw, _ := json.Marshal(status)
	if !strings.Contains(string(raw), `"export_path":""`) {
		t.Fatalf("required public export reference omitted: %s", raw)
	}
}

func TestPreparationInstallsWhenFirewalldUnitIsInitiallyAbsent(t *testing.T) {
	root, c, f := preparationFixture(t, "ubuntu")
	f.unitMissing = true
	if e := prepareHostUnder(context.Background(), root, "ubuntu", c, HostPreparationOptions{true, "preserve"}, f, time.Now()); e != nil {
		t.Fatal(e)
	}
	receipt := ReadHostPreparationStatus(root + "/var/lib/seg-agent")
	if receipt == nil || receipt.Status != "prepared" || !receipt.Firewalld.Installed || receipt.Firewalld.Active == nil || *receipt.Firewalld.Active {
		t.Fatalf("missing-unit installation receipt: %#v", receipt)
	}
	if f.preset {
		t.Fatal("new firewalld unit was left enabled")
	}
}
