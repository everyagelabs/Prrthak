package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const activationMaxConfigBytes = 20 * 1024 * 1024

func activationFileFingerprint(raw []byte, mode os.FileMode) string {
	return fmt.Sprintf("%04o:%s", mode.Perm(), shaText(string(raw)))
}

func firewallActivationDirectory(stateDir string) string {
	return filepath.Join(managedDirectory(stateDir), "firewall-activation-transactions")
}
func firewallActivationStatusPath(stateDir string) string {
	return filepath.Join(managedDirectory(stateDir), "firewall-activation-status.json")
}
func firewallActivationOperation(operation string) bool {
	switch operation {
	case "activate_existing", "activate_allow_all", "deactivate_existing", "migrate_ufw", "prepare_egress", "enable_native_counters":
		return true
	}
	return false
}

func agentOnlyFirewallActivation(operation string) bool {
	return operation == "activate_existing" || operation == "activate_allow_all" || operation == "deactivate_existing"
}

func startsFirewalld(operation string) bool {
	return operation == "activate_existing" || operation == "activate_allow_all" || operation == "migrate_ufw"
}
func (a *Agent) activationRoot() string {
	if a.firewallActivation != nil {
		return a.firewallActivation.Root
	}
	return ""
}

func activationConfigFiles(root string) (map[string]string, error) {
	result := map[string]string{}
	total := 0
	for _, base := range []string{"/etc/firewalld", "/usr/lib/firewalld"} {
		if _, err := os.Lstat(root + base); os.IsNotExist(err) {
			return nil, errors.New("installed protected firewalld configuration directories are required")
		}
		err := filepath.WalkDir(root+base, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("firewalld configuration symlinks require manual review")
			}
			if entry.IsDir() {
				_, err := setupPath(path, true)
				return err
			}
			name := strings.TrimPrefix(path, root)
			raw, err := readPreparationSystemFile(root, name, 2<<20)
			if err != nil {
				return err
			}
			total += len(raw)
			if total > activationMaxConfigBytes || len(result) >= 8192 {
				return errors.New("firewalld configuration exceeds maintenance snapshot bound")
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			result[name] = activationFileFingerprint(raw, info.Mode())
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, name := range activationPreparationFiles() {
		if _, err := os.Lstat(root + name); os.IsNotExist(err) {
			result[name] = "absent"
			continue
		}
		raw, err := readPreparationSystemFile(root, name, 2<<20)
		if err != nil {
			return nil, err
		}
		total += len(raw)
		if total > activationMaxConfigBytes {
			return nil, errors.New("combined firewall snapshot exceeds maintenance bound")
		}
		info, err := os.Lstat(root + name)
		if err != nil {
			return nil, err
		}
		result[name] = activationFileFingerprint(raw, info.Mode())
	}
	return result, nil
}

func activationUnitState(ctx context.Context, commands CommandRunner, name string) (bool, string, error) {
	text, err := commands.Run(ctx, "systemctl", "is-active", name+".service")
	state := strings.TrimSpace(text)
	if state != "active" && state != "inactive" {
		return false, "", errors.New("service is active/failed/transitioning or its state is unknown")
	}
	if state == "active" && err != nil {
		return false, "", errors.New("service active-state query is inconsistent")
	}
	text, _ = commands.Run(ctx, "systemctl", "is-enabled", name+".service")
	enabled := strings.TrimSpace(text)
	if enabled != "enabled" && enabled != "disabled" {
		return false, "", errors.New("service enablement is masked, overridden or unsupported")
	}
	text, err = commands.Run(ctx, "systemctl", "show", "--property=DropInPaths", "--value", name+".service")
	if err != nil || strings.TrimSpace(text) != "" {
		return false, "", errors.New("service drop-ins require manual review before activation")
	}
	return state == "active", enabled, nil
}

func activationDigest(baseline firewallActivationBaseline) string {
	baseline.Digest = ""
	raw, _ := json.Marshal(baseline)
	return shaText(string(raw))
}

func inactiveActivationZone(ctx context.Context, commands CommandRunner, configured string, useDefault bool) (string, error) {
	text, err := commands.Run(ctx, "firewall-offline-cmd", "--get-default-zone")
	zone := strings.TrimSpace(text)
	if err != nil || !activationZoneName.MatchString(zone) {
		return "", errors.New("the permanent default zone could not be verified")
	}
	if configured != zone && !(configured == "" && useDefault) {
		return "", errors.New("the configured agent zone must match the permanent default zone")
	}
	return zone, nil
}

func activationDefaultZoneReadback(ctx context.Context, commands CommandRunner, expected string) error {
	text, err := commands.Run(ctx, "firewall-cmd", "--get-default-zone")
	if err != nil || strings.TrimSpace(text) != expected {
		return errors.New("the active zone did not match the reviewed permanent default zone")
	}
	text, err = commands.Run(ctx, "firewall-cmd", "--get-active-zones")
	names, valid := activePolicyNames(text)
	if err != nil || !valid || len(names) > 1 || len(names) == 1 && names[0] != expected {
		return errors.New("the active zone did not match the reviewed permanent default zone")
	}
	text, err = commands.Run(ctx, "firewall-cmd", "--list-all-zones")
	zones, parseErr := parseFirewallZones(text)
	if err != nil || parseErr != nil {
		return errors.New("the complete runtime zone bindings could not be verified")
	}
	matches := 0
	for _, zone := range zones {
		if len(zone.Fields["sources"]) != 0 ||
			zone.Name != expected && (zone.Active || len(zone.Fields["interfaces"]) != 0) {
			return errors.New("a runtime interface or source binding differs from the reviewed default zone")
		}
		if zone.Name == expected {
			matches++
		}
	}
	if matches != 1 {
		return errors.New("the runtime default zone was not found exactly once")
	}
	return nil
}

func (a *Agent) firewallActivationBaseline(ctx context.Context, operation string) (firewallActivationBaseline, Protection, error) {
	if a.firewallActivation != nil && a.firewallActivation.Baseline != nil {
		return a.firewallActivation.Baseline()
	}
	baseline := firewallActivationBaseline{Assessment: FirewallActivationAssessment{IPs: []string{}, SSHPorts: []int{}, ManagementSources: []string{}, DiscoveredPorts: []FirewallActivationPort{}, TranslatedRules: []FirewallActivationRule{}, Blockers: []string{}, Notes: []string{}}}
	facts := &baseline.Assessment
	block := func(err error) (firewallActivationBaseline, Protection, error) {
		facts.Blockers = append(facts.Blockers, boundedSourceBankError(err))
		return baseline, Protection{}, err
	}
	if !firewallActivationOperation(operation) {
		return block(errors.New("unknown firewall maintenance operation"))
	}
	var err error
	facts.FirewalldActive, facts.FirewalldEnabled, err = activationUnitState(ctx, a.Commands, "firewalld")
	if err != nil {
		return block(err)
	}
	root := a.activationRoot()
	ufwInstalled := preparationCommandExists(root, "/usr/sbin/ufw") || preparationCommandExists(root, "/usr/bin/ufw")
	facts.UFWEnabled = "absent"
	if ufwInstalled {
		text, err := a.Commands.Run(ctx, "ufw", "status")
		text = strings.TrimSpace(text)
		if err != nil || !strings.HasPrefix(text, "Status: active") && !strings.HasPrefix(text, "Status: inactive") {
			return block(errors.New("UFW state cannot be assessed exactly"))
		}
		facts.UFWActive = strings.HasPrefix(text, "Status: active")
		_, facts.UFWEnabled, err = activationUnitState(ctx, a.Commands, "ufw")
		if err != nil {
			return block(err)
		}
	}
	if !startsFirewalld(operation) {
		if !facts.FirewalldActive || facts.UFWActive {
			return block(errors.New("this operation requires running firewalld with UFW inactive"))
		}
	} else if facts.FirewalldActive {
		return block(errors.New("firewalld is already active; activation will not restart a running firewall"))
	}
	if agentOnlyFirewallActivation(operation) && facts.UFWActive {
		return block(errors.New("UFW is active; use the separate assessed migration workflow"))
	}
	if operation == "migrate_ufw" && !facts.UFWActive {
		return block(errors.New("the UFW migration workflow requires active UFW"))
	}
	versionCommand := "firewall-cmd"
	if !facts.FirewalldActive {
		versionCommand = "firewall-offline-cmd"
	}
	version, err := a.Commands.Run(ctx, versionCommand, "--version")
	if err != nil || len(strings.TrimSpace(version)) > 64 {
		return block(errors.New("firewalld version/capabilities are unavailable"))
	}
	facts.Version = strings.TrimSpace(version)
	if _, err = a.Commands.Run(ctx, versionCommand, "--check-config"); err != nil {
		return block(errors.New("the installed firewalld cannot validate its complete permanent configuration"))
	}
	raw, err := readPreparationSystemFile(root, "/etc/firewalld/firewalld.conf", 65536)
	if err != nil {
		return block(err)
	}
	options := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || options[strings.TrimSpace(key)] != "" {
			return block(errors.New("duplicate or malformed firewalld global options"))
		}
		options[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	if (!facts.FirewalldActive || operation == "deactivate_existing") && options["CleanupOnExit"] != "yes" {
		return block(errors.New("starting or stopping firewalld requires explicit CleanupOnExit=yes to verify kernel firewall cleanup"))
	}
	facts.Backend = options["FirewallBackend"]
	if facts.Backend != "nftables" && facts.Backend != "iptables" {
		return block(errors.New("an explicit supported FirewallBackend is required for maintenance"))
	}
	fresh := Discover(ctx, a.Commands, false, "")
	if fresh.DiscoveryError != "" || len(fresh.IPs) == 0 || len(fresh.Listeners) > 100 {
		return block(errors.New("fresh bounded service/interface discovery is required"))
	}
	protection := a.managedProtectionFromReport(fresh)
	facts.IPs = append([]string{}, fresh.IPs...)
	sort.Strings(facts.IPs)
	if len(protection.SSHPorts) <= 8 {
		facts.SSHPorts = append([]int{}, protection.SSHPorts...)
	}
	facts.ManagementSources = append([]string{}, protection.ManagementSources...)
	facts.Zone = protection.Zone
	if !agentOnlyFirewallActivation(operation) {
		if len(protection.ManagementSources) == 0 {
			return block(errors.New("pin restricted SSH management source IPs or CIDRs in the signed endpoint configuration"))
		}
		if len(protection.SSHPorts) == 0 || len(protection.SSHPorts) > 8 {
			return block(errors.New("verify one to eight actual SSH listeners on the endpoint and review protected SSH ports in its signed configuration"))
		}
	}
	if !facts.FirewalldActive {
		zone, err := inactiveActivationZone(ctx, a.Commands, a.Config.Zone, agentOnlyFirewallActivation(operation))
		if err != nil {
			return block(err)
		}
		protection.Zone, facts.Zone = zone, zone
		protection.Digest = protectionDigest(protection)
	} else if operation == "deactivate_existing" && protection.Zone == "" {
		text, err := a.Commands.Run(ctx, "firewall-cmd", "--get-default-zone")
		zone := strings.TrimSpace(text)
		if err != nil || !activationZoneName.MatchString(zone) {
			return block(errors.New("the active default zone could not be verified"))
		}
		protection.Zone, facts.Zone = zone, zone
		protection.Digest = protectionDigest(protection)
	} else if protection.Zone == "" {
		return block(errors.New("configure the active firewalld zone in the signed endpoint configuration"))
	}
	if err := policySigningReadiness(a.Config); err != nil {
		return block(err)
	}
	seen := map[string]bool{}
	for _, listener := range fresh.Listeners {
		key := strconv.Itoa(listener.Port) + "/" + listener.Protocol
		if !seen[key] {
			seen[key] = true
			facts.DiscoveredPorts = append(facts.DiscoveredPorts, FirewallActivationPort{listener.Port, listener.Protocol})
		}
	}
	a.inventory = &fresh
	a.forceDiscovery = true
	baseline.Files, err = activationConfigFiles(root)
	if err != nil {
		return block(err)
	}
	if facts.FirewalldActive {
		commands := a.Commands
		if operation == "deactivate_existing" {
			commands, err = firewallDeactivationCommands(ctx, commands, baseline.Files)
			if err != nil {
				return block(err)
			}
		}
		bank, err := a.sourceBankBaselineWithCommands(ctx, false, commands)
		if err != nil {
			return block(err)
		}
		baseline.SourceBanks = &bank
		baseline.Global, err = firewallActivationGlobalConfigDigest(ctx, a.Config.StateDir, root, a.Commands)
		if err != nil {
			return block(err)
		}
		if operation == "deactivate_existing" {
			baseline.NativeTopology, err = activationHostContext(ctx, a.Commands, root)
			if err != nil {
				return block(err)
			}
			facts.Notes = append(facts.Notes, "Stopping firewalld removes its live filtering and disables it at boot. Its permanent rules stay on the endpoint. Inbound services can become reachable.")
		}
	} else {
		zones, err := a.Commands.Run(ctx, "firewall-offline-cmd", "--list-all-zones")
		if err != nil {
			return block(errors.New("complete permanent zones cannot be inspected"))
		}
		parsed, err := parseFirewallZones(zones)
		if err != nil {
			return block(err)
		}
		matches := 0
		for _, zone := range parsed {
			if len(zone.Fields["interfaces"]) > 0 || len(zone.Fields["sources"]) > 0 {
				return block(errors.New("permanent interface/source bindings require manual migration review"))
			}
			if zone.Name == facts.Zone {
				if operation == "activate_allow_all" && zone.Target != "default" {
					return block(errors.New("default inbound allow requires a default zone target; explicit zone targets are preserved"))
				}
				matches++
			}
		}
		if matches != 1 {
			return block(errors.New("the permanent default zone was not found exactly once in the assessed configuration"))
		}
		facts.Notes = append(facts.Notes, "Starting firewalld applies its assessed permanent configuration; discovered services may be blocked.")
		if agentOnlyFirewallActivation(operation) {
			facts.Notes = append(facts.Notes, "This operation verifies fresh outbound agent/controller connectivity. Reachability of inbound services, including SSH, is unverified.")
		}
	}
	if operation == "activate_allow_all" {
		if err := activationDefaultAllowPreflight(ctx, a.Commands, root, facts.Version); err != nil {
			return block(err)
		}
		facts.Notes = append(facts.Notes, "Adds an IPv4/IPv6 inbound allow for all otherwise-unmatched ports and sources. Explicit zone rules still run first. The policy remains in the permanent configuration.")
	}
	if operation == "migrate_ufw" {
		if err := activationNoInitHooks(root); err != nil {
			return block(err)
		}
		for _, args := range [][]string{{"--get-policies"}, {"--direct", "--get-all-rules"}, {"--direct", "--get-all-passthroughs"}} {
			text, err := a.Commands.Run(ctx, "firewall-offline-cmd", args...)
			if err != nil || strings.TrimSpace(text) != "" {
				return block(errors.New("inactive firewalld policy/direct contexts are not supported for automatic UFW migration"))
			}
		}
		defaults, err := readPreparationSystemFile(root, "/etc/default/ufw", 65536)
		if err != nil {
			return block(err)
		}
		ipv6, err := activationUFWDefaults(string(defaults))
		if err != nil {
			return block(err)
		}
		for _, name := range []string{"/etc/ufw/before.rules", "/etc/ufw/after.rules", "/etc/ufw/before6.rules", "/etc/ufw/after6.rules"} {
			raw, err := readPreparationSystemFile(root, name, 262144)
			if err != nil {
				return block(err)
			}
			if err := activationUFWEmptyHooks(string(raw)); err != nil {
				return block(err)
			}
		}
		for _, family := range []struct{ name, path string }{{"ipv4", "/etc/ufw/user.rules"}, {"ipv6", "/etc/ufw/user6.rules"}} {
			if family.name == "ipv6" && !ipv6 {
				continue
			}
			raw, err := readPreparationSystemFile(root, family.path, 262144)
			if err != nil {
				return block(err)
			}
			rules, err := activationUFWRules(string(raw), family.name)
			if err != nil {
				return block(err)
			}
			facts.TranslatedRules = append(facts.TranslatedRules, rules...)
		}
		facts.Notes = append(facts.Notes, "Only the displayed exact numeric inbound rules are translated, preserving order. Unmapped hooks, helpers, routing, profiles and NAT block cutover. UFW stays active until the exact private backup and independent rollback watchdog are durable.")
	}
	if operation == "enable_native_counters" {
		major, err := strconv.Atoi(strings.Split(facts.Version, ".")[0])
		if err != nil || major < 2 || facts.Backend != "nftables" {
			return block(errors.New("native counter activation requires firewalld 2+ with the nftables backend"))
		}
		if _, err := activationCounterConfig(raw); err != nil {
			return block(err)
		}
		if options["NftablesCounters"] == "yes" {
			return block(errors.New("native counters are already configured; inspect the next read-only counter snapshot"))
		}
		if err := activationCounterRuntime(ctx, a.Commands, false); err != nil {
			return block(err)
		}
		facts.Notes = append(facts.Notes, "Enables only NftablesCounters=yes after explicit acknowledgement. One reviewed reload can reset counters and briefly affect traffic; counters remain unavailable until the next native readback.")
	}
	if operation == "prepare_egress" {
		if err := activationEgressAbsent(ctx, a.Commands); err != nil {
			return block(err)
		}
		facts.Notes = append(facts.Notes, "Creates only an empty marked HOST-to-ANY CONTINUE policy. One reviewed reload activates the template; this does not authorize an outbound allow/block policy.")
	}
	if !facts.FirewalldActive {
		baseline.NativeTopology, err = activationHostContext(ctx, a.Commands, root)
		if err != nil {
			return block(err)
		}
		baseline.NativeContext, err = activationInactiveContext(ctx, a.Commands, root, facts.UFWActive, facts.TranslatedRules)
		if err != nil {
			return block(err)
		}
	}
	facts.CanApply = true
	baseline.Digest = activationDigest(baseline)
	return baseline, protection, nil
}

func activationFilesMatch(root string, expected map[string]string, changes map[string]firewallActivationFile, after bool) error {
	current, err := activationConfigFiles(root)
	if err != nil {
		return err
	}
	want := map[string]string{}
	for key, value := range expected {
		want[key] = value
	}
	for name, change := range changes {
		if after {
			want[name] = activationFileFingerprint(change.After, change.Mode)
		} else if change.Absent {
			delete(want, name)
		} else {
			want[name] = activationFileFingerprint(change.Before, change.Mode)
		}
	}
	if !reflect.DeepEqual(current, want) {
		return errors.New("firewall configuration changed outside the reviewed maintenance scope")
	}
	return nil
}
