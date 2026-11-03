package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Host preparation uses data-only GUI options or the automatic installer's
// explicit local dependency consent. It never activates a firewall or migrates
// UFW: assessment exports stay on the endpoint.
type HostPreparationOptions struct {
	InstallDependencies bool   `json:"install_dependencies"`
	UFWAction           string `json:"ufw_action"`
}
type HostPreparationService struct {
	Installed bool  `json:"installed"`
	Active    *bool `json:"active,omitempty"`
}
type HostPreparationUFW struct {
	Installed         bool   `json:"installed"`
	Active            *bool  `json:"active,omitempty"`
	Assessment        string `json:"assessment"`
	MigrationRequired bool   `json:"migration_required"`
	ExportPath        string `json:"export_path"`
}
type HostPreparationStatus struct {
	SchemaVersion       int                    `json:"schema_version"`
	Status              string                 `json:"status"`
	CheckedAt           string                 `json:"checked_at"`
	InstallDependencies bool                   `json:"install_dependencies"`
	DependenciesChanged bool                   `json:"dependencies_changed"`
	UFW                 HostPreparationUFW     `json:"ufw"`
	Firewalld           HostPreparationService `json:"firewalld"`
	Error               string                 `json:"error,omitempty"`
}

const preparationDirectory = "/var/lib/seg-agent/host-preparation"
const ufwExportPath = preparationDirectory + "/ufw-export.json"
const preparationPolicy = "#!/bin/sh\n# Prthak temporary package-hook suppression; never activate a firewall.\nexit 101\n"

func validateHostPreparationOptions(o HostPreparationOptions, raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["install_dependencies"] == nil || fields["ufw_action"] == nil || (o.UFWAction != "preserve" && o.UFWAction != "assess") || (!o.InstallDependencies && o.UFWAction != "assess") {
		return errors.New("unsupported preparation options")
	}
	boolean := strings.TrimSpace(string(fields["install_dependencies"]))
	if boolean != "true" && boolean != "false" {
		return errors.New("dependency preparation option must be a JSON boolean")
	}
	return nil
}

// ReadHostPreparationStatus exposes only bounded public metadata. Raw UFW
// configuration and command output are never loaded into an agent report.
func ReadHostPreparationStatus(stateDir string) *HostPreparationStatus {
	path := filepath.Join(stateDir, "host-preparation", "status.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	invalid := &HostPreparationStatus{SchemaVersion: 1, Status: "error", CheckedAt: time.Now().UTC().Format(time.RFC3339), UFW: HostPreparationUFW{Assessment: "error"}, Error: "Host preparation receipt is unreadable or invalid; inspect the endpoint's private preparation directory."}
	raw, err := readPrivateSetupBound(path, 8192)
	if err != nil {
		return invalid
	}
	var value HostPreparationStatus
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.SchemaVersion != 1 || len(value.Error) > 1024 || (value.UFW.ExportPath != "" && value.UFW.ExportPath != ufwExportPath) {
		return invalid
	}
	if _, err = time.Parse(time.RFC3339, value.CheckedAt); err != nil {
		return invalid
	}
	switch value.Status {
	case "prepared", "assessment_only", "error", "blocked":
	default:
		return invalid
	}
	switch value.UFW.Assessment {
	case "not_requested", "exported", "unavailable", "error":
	default:
		return invalid
	}
	if (value.UFW.Assessment == "exported") != (value.UFW.ExportPath == ufwExportPath) {
		return invalid
	}
	return &value
}

// PrepareHostFromSetup validates the exact private setup and signed runtime
// before acquiring the same installation/configuration lease used by upgrades.
// Enrollment validity at the controller is checked later by authenticated bootstrap.
func PrepareHostFromSetup(ctx context.Context, setupPathName, family, manifest, trust, binary, unit string) error {
	return PrepareHostFromSetupWithDependencies(ctx, setupPathName, family, manifest, trust, binary, unit, false)
}

// PrepareHostFromSetupWithDependencies adds the auto installer's explicit local
// package consent. The private setup remains unchanged; no firewall opt-in is
// granted. Runtime verification and complete setup validation still precede all
// dependency operations, including for original schema-1/schema-2 GUI kits.
func PrepareHostFromSetupWithDependencies(ctx context.Context, setupPathName, family, manifest, trust, binary, unit string, installDependencies bool) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("host preparation requires a native Linux root installation")
	}
	if family != "rhel" && family != "ubuntu" {
		return errors.New("unsupported preparation family")
	}
	if err := VerifyReleaseFiles(manifest, trust, binary, unit); err != nil {
		return err
	}
	raw, err := readSetupFile(setupPathName)
	if err != nil {
		return err
	}
	host, err := os.Hostname()
	if err != nil {
		return errors.New("cannot establish endpoint hostname")
	}
	c, kit, err := parseSetup(raw, host, time.Now().UTC())
	if err != nil {
		return err
	}
	options, err := preparationOptionsForSetup(kit, installDependencies)
	if err != nil {
		return err
	}
	// Prefer the existing installed state for upgrade fencing, rather than the
	// new kit's deliberately monitor-only configuration.
	if _, e := os.Lstat("/etc/seg-agent/config.json"); e == nil {
		c, err = LoadConfig("/etc/seg-agent/config.json", false)
		if err != nil || ValidateInstallConfig(c) != nil {
			return errors.New("existing endpoint configuration cannot be validated for preparation")
		}
	} else if !os.IsNotExist(e) {
		return errors.New("existing endpoint configuration cannot be inspected")
	}
	return prepareHostUnder(ctx, "", family, c, options, hostPreparationRunner{}, time.Now().UTC())
}

func preparationOptionsForSetup(kit setupFile, installDependencies bool) (HostPreparationOptions, error) {
	options := HostPreparationOptions{UFWAction: "preserve"}
	if kit.InstallationOptions != nil {
		options = *kit.InstallationOptions
	}
	if installDependencies {
		options.InstallDependencies = true
		return options, nil
	}
	if kit.SchemaVersion != 3 || kit.InstallationOptions == nil {
		return HostPreparationOptions{}, errors.New("host preparation requires explicit GUI setup options or automatic-installer dependency consent")
	}
	return options, nil
}

// Package operations get longer bounds than discovery commands, but retain the
// existing descendant-draining command supervisor and durable lease fence.
type hostPreparationRunner struct{}

func (hostPreparationRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	timeout := 20 * time.Second
	if name == "/usr/bin/apt-get" || name == "/usr/bin/dnf" || name == "/usr/bin/env" {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd, err := fencedCommand(ctx, managedLeaseFromContext(ctx), name, args...)
	if err != nil {
		return "", err
	}
	var output limitedBuffer
	output.limit = 4 << 20
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = runFencedCommand(cmd)
	return output.String(), err
}

func preparationCommandExists(root, name string) bool {
	info, err := os.Stat(root + name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && (owner.Uid == 0 || root != "" && owner.Uid == uint32(os.Geteuid()))
}
func preparationActive(ctx context.Context, commands CommandRunner, service string) *bool {
	load, _ := commands.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", service)
	if strings.TrimSpace(load) == "not-found" {
		value := false
		return &value
	}
	output, _ := commands.Run(ctx, "/usr/bin/systemctl", "is-active", service)
	var result bool
	switch strings.TrimSpace(output) {
	case "active":
		result = true
	case "inactive", "failed":
		result = false
	default:
		return nil
	}
	return &result
}
func preparationEnabled(ctx context.Context, commands CommandRunner) (string, error) {
	load, _ := commands.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", "firewalld.service")
	if strings.TrimSpace(load) == "not-found" {
		return "not-found", nil
	}
	output, _ := commands.Run(ctx, "/usr/bin/systemctl", "is-enabled", "firewalld.service")
	value := strings.TrimSpace(output)
	switch value {
	case "enabled", "enabled-runtime", "disabled", "masked", "masked-runtime", "not-found", "static", "indirect":
		return value, nil
	}
	return "", errors.New("firewalld enabled state is unknown; dependency preparation refused")
}
func preparationPrivateDirectory(root string) (string, error) {
	directory := root + preparationDirectory
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	info, err := setupPath(directory, true)
	if err != nil || info.Mode().Perm() != 0700 || validateSetupDirectoryOwner(info) != nil {
		return "", errors.New("host preparation state directory is not private and owned")
	}
	return directory, nil
}
func writePreparationStatus(directory string, status *HostPreparationStatus) error {
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return atomicPrivateFile(filepath.Join(directory, "status.json"), raw)
}

func prepareHostUnder(ctx context.Context, root, family string, c Config, options HostPreparationOptions, commands CommandRunner, now time.Time) (resultErr error) {
	if err := validatePreparationFamily(root, family); err != nil {
		return err
	}
	configurationLease, err := configurationLeaseUnder(root, 0)
	if err != nil {
		return err
	}
	defer configurationLease.Close()
	rooted := RootedConfig(c, root)
	if err = checkEnforcementUpgradeSafety(rooted, true); err != nil {
		return err
	}
	lease, err := managedLock(rooted.StateDir, true)
	if err != nil {
		return errors.New("managed enforcement or an uncertain command is active; preparation refused")
	}
	defer lease.Close()
	// Recheck after acquiring the managed lease; no mutation can race a fresh
	// transaction into the gap between the initial upgrade check and this lock.
	if err = checkEnforcementJournals(rooted); err != nil {
		return err
	}
	ctx = withManagedLease(ctx, lease)
	directory, err := preparationPrivateDirectory(root)
	if err != nil {
		return err
	}
	status := &HostPreparationStatus{SchemaVersion: 1, Status: "assessment_only", CheckedAt: now.Format(time.RFC3339), InstallDependencies: options.InstallDependencies, UFW: HostPreparationUFW{Assessment: "not_requested"}}
	defer func() {
		status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
		status.Firewalld.Installed = preparationCommandExists(root, "/usr/bin/firewall-cmd")
		if resultErr != nil {
			if status.Status != "blocked" {
				status.Status = "error"
			}
			status.Error = resultErr.Error()
			if len(status.Error) > 1024 {
				status.Error = "Host preparation failed; inspect the private endpoint preparation state."
			}
		}
		if e := writePreparationStatus(directory, status); e != nil && resultErr == nil {
			resultErr = errors.New("host preparation receipt could not be persisted")
		}
	}()
	if _, e := os.Lstat(directory + "/suppression.json"); !os.IsNotExist(e) {
		status.Status = "blocked"
		return errors.New("an unfinished package preparation exists; inspect suppression.json before retrying")
	}
	for _, name := range []string{"/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/journalctl"} {
		if !preparationCommandExists(root, name) {
			return errors.New("native systemd tools are required before automatic dependency preparation")
		}
	}
	status.Firewalld.Installed = preparationCommandExists(root, "/usr/bin/firewall-cmd")
	status.Firewalld.Active = preparationActive(ctx, commands, "firewalld.service")
	status.UFW.Installed = preparationCommandExists(root, "/usr/sbin/ufw") || preparationCommandExists(root, "/usr/bin/ufw")
	if status.UFW.Installed {
		// A oneshot unit can be inactive while UFW rules remain enabled.
		// Only the bounded read-only UFW query establishes known active state.
		status.UFW.Active = preparationUFWActive(ctx, root, commands)
		status.UFW.MigrationRequired = status.UFW.Active == nil || *status.UFW.Active
	}
	if options.UFWAction == "assess" {
		if !status.UFW.Installed {
			status.UFW.Assessment = "unavailable"
		} else if err = exportUFWAssessment(ctx, root, directory, commands, now); err != nil {
			status.UFW.Assessment = "error"
			return err
		} else {
			status.UFW.Assessment = "exported"
			status.UFW.ExportPath = ufwExportPath
		}
	}
	if !options.InstallDependencies {
		return nil
	}
	packages := []string{}
	for _, item := range []struct{ command, rhel, ubuntu string }{{"/usr/sbin/ss", "iproute", "iproute2"}, {"/usr/bin/firewall-cmd", "firewalld", "firewalld"}, {"/usr/bin/flock", "util-linux", "util-linux"}} {
		present := preparationCommandExists(root, item.command)
		if item.rhel == "iproute" {
			present = present || preparationCommandExists(root, "/usr/bin/ss")
		}
		if !present {
			if family == "rhel" {
				packages = append(packages, item.rhel)
			} else {
				packages = append(packages, item.ubuntu)
			}
		}
	}
	caPath := "/etc/pki/tls/certs/ca-bundle.crt"
	if family == "ubuntu" {
		caPath = "/etc/ssl/certs/ca-certificates.crt"
	}
	if info, e := os.Stat(root + caPath); e != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		packages = append(packages, "ca-certificates")
	}
	if len(packages) == 0 {
		status.Status = "prepared"
		return nil
	}
	if status.Firewalld.Active == nil {
		return errors.New("firewalld activity cannot be established; dependency preparation refused")
	}
	enabled, err := preparationEnabled(ctx, commands)
	if err != nil {
		return err
	}
	manager := "/usr/bin/dnf"
	if family == "ubuntu" {
		manager = "/usr/bin/apt-get"
	}
	if !preparationCommandExists(root, manager) || family == "ubuntu" && !preparationCommandExists(root, "/usr/bin/env") {
		return errors.New("the native OS package manager is unavailable")
	}
	var ufwBaseline map[string]string
	if status.UFW.Installed {
		ufwBaseline, err = ufwPreparationFingerprint(root)
		if err != nil {
			return errors.New("UFW configuration cannot be preserved safely before dependency installation")
		}
	}
	cleanup, err := suppressPreparationStartup(ctx, root, directory, family, enabled, *status.Firewalld.Active, ufwBaseline, status.UFW.Active, commands, lease)
	if err != nil {
		return err
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cleanCtx = withManagedLease(cleanCtx, lease)
		if e := cleanup(cleanCtx); e != nil {
			resultErr = e
			status.Firewalld.Active = nil
			status.UFW.Active = nil
			status.UFW.MigrationRequired = status.UFW.Installed
			return
		}
	}()
	// A package manager can partially install dependencies even when it returns an
	// error. Record that truthfully; never pretend package rollback succeeded.
	if family == "ubuntu" {
		if _, err = commands.Run(ctx, "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "/usr/bin/apt-get", "update"); err != nil {
			return errors.New("APT metadata refresh failed; firewall startup remains protected during cleanup")
		}
		args := append([]string{"DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", "/usr/bin/apt-get", "-y", "--no-install-recommends", "--no-upgrade", "--no-remove", "install"}, packages...)
		status.DependenciesChanged = true
		_, err = commands.Run(ctx, "/usr/bin/env", args...)
	} else {
		status.DependenciesChanged = true
		_, err = commands.Run(ctx, manager, append([]string{"-y", "install"}, packages...)...)
	}
	if err != nil {
		return errors.New("dependency installation failed or partially completed; inspect OS package state before retrying")
	}
	for _, name := range []string{"/usr/bin/firewall-cmd", "/usr/bin/flock"} {
		if !preparationCommandExists(root, name) {
			return errors.New("package manager returned success but a required dependency is still unavailable")
		}
	}
	if !preparationCommandExists(root, "/usr/bin/ss") && !preparationCommandExists(root, "/usr/sbin/ss") {
		return errors.New("package manager returned success but socket discovery is still unavailable")
	}
	if info, e := os.Stat(root + caPath); e != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("package manager returned success but the OS CA bundle is still unavailable")
	}
	status.Status = "prepared"
	return nil
}

func validatePreparationFamily(root, family string) error {
	file, err := os.Open(root + "/etc/os-release")
	if err != nil {
		return errors.New("cannot inspect native OS identity")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 16384 {
		return errors.New("native OS identity file is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(raw) > 16384 {
		return errors.New("native OS identity exceeds its bound")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || (parts[0] != "ID" && parts[0] != "VERSION_ID") {
			continue
		}
		if _, ok := values[parts[0]]; ok {
			return errors.New("native OS identity is ambiguous")
		}
		value := parts[1]
		if len(value) > 1 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		values[parts[0]] = value
	}
	version := values["VERSION_ID"]
	if family == "rhel" && values["ID"] == "rhel" && (version == "8" || version == "9" || strings.HasPrefix(version, "8.") || strings.HasPrefix(version, "9.")) {
		return nil
	}
	if family == "ubuntu" && values["ID"] == "ubuntu" && version == "26.04" {
		return nil
	}
	return errors.New("host preparation requires its matching RHEL 8/9 or Ubuntu 26.04 installer")
}

// Suppression is journaled before changes. An interrupted/uncertain package
// command leaves suppression in place and the next run refuses blind recovery.
func suppressPreparationStartup(ctx context.Context, root, directory, family, enabled string, expectedActive bool, ufwBaseline map[string]string, ufwActive *bool, commands CommandRunner, lease *os.File) (func(context.Context) error, error) {
	// systemd's administrator/control/transient/early-generator paths precede
	// /run/systemd/system. Never shadow or edit an existing administrator unit.
	for _, base := range []string{"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached"} {
		path := root + base + "/firewalld.service"
		if info, e := os.Lstat(path); e == nil {
			target, readErr := os.Readlink(path)
			if info.Mode()&os.ModeSymlink == 0 || readErr != nil || target != "/dev/null" {
				return nil, errors.New("existing higher-precedence firewalld unit override prevents safe package preparation")
			}
		} else if !os.IsNotExist(e) {
			return nil, errors.New("cannot inspect higher-precedence firewalld unit configuration")
		}
	}
	mask := root + "/run/systemd/system/firewalld.service"
	maskOwned := false
	if info, err := os.Lstat(mask); err == nil {
		target, e := os.Readlink(mask)
		if info.Mode()&os.ModeSymlink == 0 || e != nil || target != "/dev/null" {
			return nil, errors.New("existing runtime firewalld override prevents safe package preparation")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		maskOwned = true
	}
	policy := root + "/usr/sbin/policy-rc.d"
	if family == "ubuntu" {
		if _, err := os.Lstat(policy); !os.IsNotExist(err) {
			return nil, errors.New("existing policy-rc.d is preserved; use approved OS preparation before retrying")
		}
	}
	if _, err := setupPath(filepath.Dir(mask), true); err != nil {
		return nil, errors.New("protected systemd runtime directory is required")
	}
	if family == "ubuntu" {
		if _, err := setupPath(filepath.Dir(policy), true); err != nil {
			return nil, errors.New("protected package policy directory is required")
		}
	}
	journal, _ := json.Marshal(map[string]any{"schema_version": 1, "phase": "armed", "runtime_mask_owned": maskOwned, "policy_owned": family == "ubuntu", "original_enabled": enabled})
	if err := atomicPrivateFile(directory+"/suppression.json", journal); err != nil {
		return nil, err
	}
	policyCreated, maskCreated := false, false
	cleanup := func(cleanCtx context.Context) (cleanErr error) {
		defer func() {
			if cleanErr != nil && maskOwned && !maskCreated {
				if _, e := os.Lstat(mask); os.IsNotExist(e) {
					_ = os.Symlink("/dev/null", mask)
				}
			}
		}()
		if err := checkCommandFence(lease.Name(), false); err != nil {
			return errors.New("package descendants are not proven stopped; startup suppression retained for inspection")
		}
		// The package supervisor has drained all descendants. Remove our own
		// runtime mask to inspect real enablement; UFW and live rules remain untouched.
		if maskCreated {
			target, e := os.Readlink(mask)
			if e != nil || target != "/dev/null" {
				return errors.New("temporary firewalld mask changed; suppression retained")
			}
			if e = os.Remove(mask); e != nil {
				return errors.New("cannot remove temporary firewalld mask")
			}
			maskCreated = false
		}
		if _, err := commands.Run(cleanCtx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return errors.New("cannot reload restored service metadata; inspect startup suppression")
		}
		current, err := preparationEnabled(cleanCtx, commands)
		if err != nil {
			return errors.New("cannot verify firewalld enablement; startup suppression retained")
		}
		if (enabled == "disabled" || enabled == "not-found") && (current == "enabled" || current == "enabled-runtime") {
			args := []string{"disable", "firewalld.service"}
			if current == "enabled-runtime" {
				args = []string{"disable", "--runtime", "firewalld.service"}
			}
			if _, e := commands.Run(cleanCtx, "/usr/bin/systemctl", args...); e != nil {
				return errors.New("cannot restore disabled firewalld enablement; startup suppression retained")
			}
		}
		if enabled == "enabled" && current != "enabled" {
			if current == "enabled-runtime" {
				if _, e := commands.Run(cleanCtx, "/usr/bin/systemctl", "disable", "--runtime", "firewalld.service"); e != nil {
					return errors.New("cannot restore original persistent firewalld enablement; startup suppression retained")
				}
			}
			if _, e := commands.Run(cleanCtx, "/usr/bin/systemctl", "enable", "firewalld.service"); e != nil {
				return errors.New("cannot restore original firewalld enablement; startup suppression retained")
			}
		}
		if enabled == "enabled-runtime" && current != "enabled-runtime" {
			if current == "enabled" {
				if _, e := commands.Run(cleanCtx, "/usr/bin/systemctl", "disable", "firewalld.service"); e != nil {
					return errors.New("cannot restore original runtime firewalld enablement; startup suppression retained")
				}
			}
			if _, e := commands.Run(cleanCtx, "/usr/bin/systemctl", "enable", "--runtime", "firewalld.service"); e != nil {
				return errors.New("cannot restore original runtime firewalld enablement; startup suppression retained")
			}
		}
		verified, e := preparationEnabled(cleanCtx, commands)
		if e != nil || verified != enabled && !(enabled == "not-found" && verified == "disabled") {
			return errors.New("original firewalld enablement was not restored; startup suppression retained")
		}

		after := preparationActive(cleanCtx, commands, "firewalld.service")
		if after == nil || *after != expectedActive {
			return errors.New("firewalld service activity changed unexpectedly; startup suppression retained for inspection")
		}
		if ufwBaseline != nil {
			latest, e := ufwPreparationFingerprint(root)
			before, _ := json.Marshal(ufwBaseline)
			now, _ := json.Marshal(latest)
			if e != nil || string(before) != string(now) || (!preparationCommandExists(root, "/usr/sbin/ufw") && !preparationCommandExists(root, "/usr/bin/ufw")) {
				return errors.New("UFW configuration changed unexpectedly; inspect endpoint before enforcement")
			}
			if ufwActive != nil {
				current := preparationUFWActive(cleanCtx, root, commands)
				if current == nil || *current != *ufwActive {
					return errors.New("UFW activity changed unexpectedly; inspect endpoint before enforcement")
				}
			}
		}
		if policyCreated {
			raw, e := readPreparationSystemFile(root, "/usr/sbin/policy-rc.d", 4096)
			if e != nil || string(raw) != preparationPolicy {
				return errors.New("temporary package policy changed; suppression retained")
			}
			if e = os.Remove(policy); e != nil {
				return errors.New("cannot remove temporary package policy")
			}
		}
		return os.Remove(directory + "/suppression.json")
	}
	fail := func(err error) (func(context.Context) error, error) {
		if e := cleanup(ctx); e != nil {
			return nil, e
		}
		return nil, err
	}
	if maskOwned {
		if err := os.Symlink("/dev/null", mask); err != nil {
			return fail(errors.New("cannot install temporary firewalld startup mask"))
		}
		maskCreated = true
	}
	if family == "ubuntu" {
		file, err := os.OpenFile(policy, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if err != nil {
			return fail(errors.New("cannot install temporary package startup policy"))
		}
		policyCreated = true
		_, err = file.WriteString(preparationPolicy)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return fail(errors.New("cannot commit temporary package startup policy"))
		}
	}
	if _, err := commands.Run(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return fail(errors.New("cannot apply temporary service startup suppression"))
	}
	load, err := commands.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", "firewalld.service")
	if err != nil || strings.TrimSpace(load) != "masked" {
		return fail(errors.New("effective firewalld startup mask could not be verified; dependency installation refused"))
	}
	return cleanup, nil
}

func readPreparationSystemFile(root, name string, limit int64) ([]byte, error) {
	path := root + name
	if _, err := setupPath(path, false); err != nil {
		return nil, err
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
		return nil, errors.New("system configuration file cannot be exported safely")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("system configuration file ownership is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("system configuration file exceeds export bounds")
	}
	return raw, nil
}
func exportUFWAssessment(ctx context.Context, root, directory string, commands CommandRunner, now time.Time) error {
	files := map[string]string{}
	hashes := map[string]string{}
	for _, name := range []string{"/etc/default/ufw", "/etc/ufw/ufw.conf", "/etc/ufw/before.rules", "/etc/ufw/after.rules", "/etc/ufw/user.rules", "/etc/ufw/before6.rules", "/etc/ufw/after6.rules", "/etc/ufw/user6.rules", "/etc/ufw/sysctl.conf"} {
		if _, e := os.Lstat(root + name); os.IsNotExist(e) {
			continue
		}
		raw, err := readPreparationSystemFile(root, name, 96<<10)
		if err != nil {
			return errors.New("UFW configuration contains an unsafe or oversized file; export refused")
		}
		digest := sha256.Sum256(raw)
		files[name] = string(raw)
		hashes[name] = hex.EncodeToString(digest[:])
	}
	ufw := "/usr/sbin/ufw"
	if !preparationCommandExists(root, ufw) {
		ufw = "/usr/bin/ufw"
	}
	output, err := commands.Run(ctx, ufw, "status", "verbose")
	if err != nil || len(output) > 128<<10 {
		return errors.New("UFW status cannot be assessed within export bounds")
	}
	raw, err := json.Marshal(map[string]any{"schema_version": 1, "checked_at": now.Format(time.RFC3339), "purpose": "Private assessment only; no migration or firewall activation performed", "files": files, "sha256": hashes, "status_verbose": output})
	if err != nil || len(raw) > 2<<20 {
		return errors.New("private UFW export exceeds its byte bound")
	}
	if err = atomicPrivateFile(directory+"/ufw-export.json", raw); err != nil {
		return fmt.Errorf("private UFW assessment export could not be saved")
	}
	return nil
}

var ufwPreparationFiles = []string{"/etc/default/ufw", "/etc/ufw/ufw.conf", "/etc/ufw/before.rules", "/etc/ufw/after.rules", "/etc/ufw/user.rules", "/etc/ufw/before6.rules", "/etc/ufw/after6.rules", "/etc/ufw/user6.rules", "/etc/ufw/sysctl.conf"}

func ufwPreparationFingerprint(root string) (map[string]string, error) {
	result := map[string]string{}
	for _, name := range ufwPreparationFiles {
		if _, e := os.Lstat(root + name); os.IsNotExist(e) {
			result[name] = "absent"
			continue
		}
		raw, e := readPreparationSystemFile(root, name, 96<<10)
		if e != nil {
			return nil, e
		}
		hash := sha256.Sum256(raw)
		result[name] = hex.EncodeToString(hash[:])
	}
	return result, nil
}
func preparationUFWActive(ctx context.Context, root string, commands CommandRunner) *bool {
	ufw := "/usr/sbin/ufw"
	if !preparationCommandExists(root, ufw) {
		ufw = "/usr/bin/ufw"
	}
	output, err := commands.Run(ctx, ufw, "status", "verbose")
	if err != nil || len(output) > 128<<10 {
		return nil
	}
	first := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	var active bool
	switch first {
	case "Status: active":
		active = true
	case "Status: inactive":
		active = false
	default:
		return nil
	}
	return &active
}
