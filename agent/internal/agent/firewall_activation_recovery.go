package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

func validateFirewallActivationJournal(journal *managedJournal) error {
	value := journal.FirewallActivation
	if value == nil {
		return nil
	}
	if journal.SourceBankPreparation != nil || journal.Previous != nil || journal.Next.Generation != "" || len(journal.Mutations) > 0 || len(journal.SetMutations) > 0 || !validManagedNonce(journal.Nonce) || value.Assignment.Operation == "assess" || !firewallActivationOperation(value.Assignment.Operation) || value.Assignment.TargetOperation != value.Assignment.Operation || !validDigest(value.Assignment.PlanDigest) || !validDigest(value.Assignment.BaselineDigest) || !validDigest(value.Assignment.ProtectionDigest) || !validDigest(value.Assignment.ConfigurationDigest) || value.Baseline.Digest != value.Assignment.BaselineDigest || activationDigest(value.Baseline) != value.Baseline.Digest || !changeIDValid(value.Assignment.ID) {
		return errors.New("invalid exact firewall-maintenance rollback journal")
	}
	if len(value.Baseline.Files) > 8192 || len(value.ChangedFiles) > 2 {
		return errors.New("firewall-maintenance journal exceeds bounded file scope")
	}
	for name, hash := range value.Baseline.Files {
		safe := filepath.IsAbs(name) && filepath.Clean(name) == name && (strings.HasPrefix(name, "/etc/firewalld/") || strings.HasPrefix(name, "/usr/lib/firewalld/"))
		if !safe {
			for _, allowed := range activationPreparationFiles() {
				if name == allowed {
					safe = true
				}
			}
		}
		if !safe || len(hash) > 70 || hash != "absent" && (len(hash) != 69 || hash[4] != ':' || !validDigest(hash[5:])) {
			return errors.New("invalid protected firewall baseline path/fingerprint")
		}
	}
	for name, change := range value.ChangedFiles {
		if len(change.Before) > 2<<20 || len(change.After) > 2<<20 || change.Mode.Perm()&0022 != 0 || change.Mode != change.Mode.Perm() {
			return errors.New("invalid owned maintenance file bytes/mode")
		}
		switch value.Assignment.Operation {
		case "activate_allow_all":
			if name != activationDefaultAllowPath || !change.Absent || change.Mode != 0644 || len(change.Before) != 0 ||
				string(change.After) != activationDefaultAllowXML || value.Baseline.Files[name] != "" {
				return errors.New("default inbound allow rollback path or policy bytes differ from the exact supported scope")
			}
		case "enable_native_counters":
			if name != "/etc/firewalld/firewalld.conf" || change.Absent || value.Baseline.Files[name] != activationFileFingerprint(change.Before, change.Mode) {
				return errors.New("native-counter rollback path differs from protected baseline")
			}
			expected, err := activationCounterConfig(change.Before)
			if err != nil || !bytes.Equal(expected, change.After) || bytes.Equal(change.Before, change.After) {
				return errors.New("native-counter journal changes more than its exact supported option")
			}
		case "migrate_ufw":
			zone := "/etc/firewalld/zones/" + value.Baseline.Assessment.Zone + ".xml"
			if name == "/etc/ufw/ufw.conf" {
				expected, err := activationUFWEnabled(change.Before, false)
				if err != nil || !bytes.Equal(expected, change.After) || change.Absent || value.Baseline.Files[name] != activationFileFingerprint(change.Before, change.Mode) {
					return errors.New("invalid exact UFW enablement rollback file")
				}
			} else if name == zone {
				expected, err := activationMigrationZoneXML(journal.Nonce, value.Baseline.Assessment)
				if err != nil || !bytes.Equal(expected, change.After) || !change.Absent || len(change.Before) != 0 || value.Baseline.Files[name] != "" {
					return errors.New("invalid exact owned UFW migration zone")
				}
			} else {
				return errors.New("UFW migration journal names an unrelated file")
			}
		default:
			return errors.New("this maintenance operation cannot edit system configuration files")
		}
	}
	if (value.Assignment.Operation == "enable_native_counters" || value.Assignment.Operation == "activate_allow_all") && len(value.ChangedFiles) != 1 || value.Assignment.Operation == "migrate_ufw" && len(value.ChangedFiles) != 2 || value.CreatedPolicy && value.Assignment.Operation != "prepare_egress" || value.Reloaded && value.Baseline.SourceBanks == nil ||
		value.Assignment.Operation == "deactivate_existing" && (!value.Baseline.Assessment.FirewalldActive || value.Baseline.SourceBanks == nil) {
		return errors.New("firewall maintenance journal operation/files are inconsistent")
	}
	if value.Baseline.SourceBanks != nil {
		copy := *value.Baseline.SourceBanks
		copy.Digest = ""
		raw, _ := json.Marshal(copy)
		if shaText(string(raw)) != value.Baseline.SourceBanks.Digest || !validDigest(value.Baseline.Global) {
			return errors.New("original runtime/permanent maintenance snapshot is invalid")
		}
	}
	return validateFirewallActivationReport(value.Report)
}

func activationCurrentFilesInScope(root string, value *firewallActivationJournal) error {
	current, err := activationConfigFiles(root)
	if err != nil {
		return err
	}
	expected := map[string]string{}
	for name, hash := range value.Baseline.Files {
		expected[name] = hash
	}
	for name, change := range value.ChangedFiles {
		hash, exists := current[name]
		before := activationFileFingerprint(change.Before, change.Mode)
		after := activationFileFingerprint(change.After, change.Mode)
		if !exists && change.Absent {
			delete(expected, name)
			continue
		}
		if hash != after && (change.Absent || hash != before) {
			return errors.New("a reviewed configuration file was changed by another writer")
		}
		expected[name] = hash
	}
	if value.CreatedPolicy {
		path := "/etc/firewalld/policies/" + activationEgressPolicy + ".xml"
		if value.Baseline.Files[path] != "" {
			return errors.New("egress preparation cannot replace an existing policy file")
		}
		delete(current, path)
	}
	if !reflect.DeepEqual(current, expected) {
		return errors.New("configuration outside the exact maintenance files changed; rollback is not safe to guess")
	}
	return nil
}

func activationRestoreUnit(ctx context.Context, commands CommandRunner, name string, active bool, enabled string) error {
	operation := "disable"
	if enabled == "enabled" {
		operation = "enable"
	} else if enabled != "disabled" {
		return errors.New("original service enablement is unsupported")
	}
	if _, err := commands.Run(ctx, "systemctl", operation, name+".service"); err != nil {
		return err
	}
	operation = "stop"
	if active {
		operation = "start"
	}
	if _, err := commands.Run(ctx, "systemctl", operation, name+".service"); err != nil {
		return err
	}
	text, _ := commands.Run(ctx, "systemctl", "is-active", name+".service")
	wanted := "inactive"
	if active {
		wanted = "active"
	}
	if strings.TrimSpace(text) != wanted {
		return errors.New("restored service activity did not verify")
	}
	text, _ = commands.Run(ctx, "systemctl", "is-enabled", name+".service")
	if strings.TrimSpace(text) != enabled {
		return errors.New("restored service enablement did not verify")
	}
	return nil
}

func rollbackFirewallActivation(ctx context.Context, commands CommandRunner, path string, journal *managedJournal, hooks *firewallActivationHooks) error {
	if err := checkManagedCommandFence(ctx); err != nil {
		return err
	}
	if err := validateFirewallActivationJournal(journal); err != nil {
		return err
	}
	value := journal.FirewallActivation
	root := ""
	if hooks != nil {
		root = hooks.Root
	}
	stateDir := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	failure := func(err error) error {
		journal.Phase = "rollback_failed"
		journal.Error = boundedSourceBankError(err)
		value.Report.Status = "error"
		value.Report.Error = journal.Error
		value.Report.CheckedAt = time.Now().UTC()
		_ = saveManagedJournal(path, journal)
		_ = atomicJSON(firewallActivationStatusPath(stateDir), value.Report)
		return err
	}
	if err := activationCurrentFilesInScope(root, value); err != nil {
		return failure(err)
	}
	runtimePolicy := false
	if value.CreatedPolicy {
		for _, scope := range []string{"runtime", "permanent"} {
			present, err := activationEgressPresent(ctx, commands, scope)
			if err != nil {
				return failure(err)
			}
			if present {
				if err := activationEgressOwnedEmpty(ctx, commands, scope, journal.Nonce); err != nil {
					return failure(err)
				}
				if scope == "runtime" {
					runtimePolicy = true
				}
			}
		}
		present, err := activationEgressPresent(ctx, commands, "permanent")
		if err != nil {
			return failure(err)
		}
		if present {
			if _, err := commands.Run(ctx, "firewall-cmd", "--permanent", "--delete-policy="+activationEgressPolicy); err != nil {
				return failure(err)
			}
		}
	}
	if value.ServiceChanged && !value.Baseline.Assessment.FirewalldActive {
		if _, err := commands.Run(ctx, "systemctl", "stop", "firewalld.service"); err != nil {
			return failure(err)
		}
		text, _ := commands.Run(ctx, "systemctl", "is-active", "firewalld.service")
		if strings.TrimSpace(text) != "inactive" {
			return failure(errors.New("firewalld did not return to its original inactive state"))
		}
	}
	names := []string{}
	for name := range value.ChangedFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeActivationFile(root, name, value.ChangedFiles[name], false); err != nil {
			return failure(err)
		}
	}
	if value.Baseline.Assessment.FirewalldActive && (value.Reloaded || runtimePolicy) {
		if _, err := commands.Run(ctx, "firewall-cmd", "--check-config"); err != nil {
			return failure(err)
		}
		if _, err := commands.Run(ctx, "firewall-cmd", "--reload"); err != nil {
			return failure(err)
		}
		if err := restoreSourceBankBindings(ctx, commands, value.Baseline.SourceBanks.RuntimeBindings); err != nil {
			return failure(err)
		}
	}
	if value.ServiceChanged {
		if err := activationRestoreUnit(ctx, commands, "firewalld", value.Baseline.Assessment.FirewalldActive, value.Baseline.Assessment.FirewalldEnabled); err != nil {
			return failure(err)
		}
		if value.Assignment.Operation == "deactivate_existing" {
			if value.Baseline.NativeTopology != "" {
				restored, err := activationHostContext(ctx, commands, root)
				if err != nil || restored != value.Baseline.NativeTopology {
					return failure(errors.New("original host topology did not verify before restoring firewalld interface bindings"))
				}
			}
			if err := restoreSourceBankBindings(ctx, commands, value.Baseline.SourceBanks.RuntimeBindings); err != nil {
				return failure(err)
			}
			if value.Baseline.NativeContext != "" {
				restored, err := activationFirewallContext(ctx, commands, root, true, false, nil)
				if err != nil || restored != value.Baseline.NativeContext {
					return failure(errors.New("original foreign firewall context did not verify after restoring firewalld"))
				}
			}
		}
		if (value.Assignment.Operation == "migrate_ufw" || value.Assignment.Operation == "activate_existing") && value.Baseline.Assessment.UFWEnabled != "absent" {
			if err := activationRestoreUnit(ctx, commands, "ufw", value.Baseline.Assessment.UFWActive, value.Baseline.Assessment.UFWEnabled); err != nil {
				return failure(err)
			}
			text, _ := commands.Run(ctx, "ufw", "status")
			wanted := "Status: inactive"
			if value.Baseline.Assessment.UFWActive {
				wanted = "Status: active"
			}
			if !strings.HasPrefix(strings.TrimSpace(text), wanted) {
				return failure(errors.New("original UFW activity was not verified"))
			}
		}
	}
	if !value.Baseline.Assessment.FirewalldActive && value.ServiceChanged && value.Baseline.NativeContext != "" {
		restored, err := activationInactiveContext(ctx, commands, root, value.Baseline.Assessment.UFWActive, value.Baseline.Assessment.TranslatedRules)
		if err != nil || restored != value.Baseline.NativeContext {
			return failure(errors.New("original kernel firewall/host topology did not verify after service rollback"))
		}
	}
	if err := activationFilesMatch(root, value.Baseline.Files, nil, false); err != nil {
		return failure(err)
	}
	if value.Baseline.SourceBanks != nil {
		readback := commands
		if value.Assignment.Operation == "deactivate_existing" {
			var err error
			readback, err = firewallDeactivationCommands(ctx, commands, value.Baseline.Files)
			if err != nil {
				return failure(err)
			}
		}
		restored, err := activationOriginalPolicyBaseline(ctx, readback, stateDir, *value.Baseline.SourceBanks, value.Baseline.Global, false)
		if err != nil || !reflect.DeepEqual(restored, *value.Baseline.SourceBanks) {
			return failure(errors.New("original firewall rules/bindings were not verified after maintenance rollback"))
		}
	}
	if value.Assignment.Operation == "enable_native_counters" {
		if err := activationCounterRuntime(ctx, commands, false); err != nil {
			return failure(err)
		}
		if hooks != nil && hooks.Attestation != nil {
			if err := hooks.Attestation(false); err != nil {
				return failure(err)
			}
		} else if err := recordActivationCounterAttestation(ctx, stateDir, root, commands, false); err != nil {
			return failure(err)
		}
	}
	if value.CreatedPolicy {
		marker := activationEgressPath(stateDir)
		if raw, err := readPrivateSetupBound(marker, 4096); err == nil {
			var existing struct {
				Nonce string `json:"nonce"`
			}
			if json.Unmarshal(raw, &existing) != nil || existing.Nonce != journal.Nonce {
				return failure(errors.New("egress template marker belongs to another generation"))
			}
			if err := os.Remove(marker); err != nil {
				return failure(err)
			}
		} else if _, e := os.Lstat(marker); !os.IsNotExist(e) {
			return failure(errors.New("egress template ownership cannot be verified during rollback"))
		}
	}
	journal.Phase = "rolled_back"
	value.Report.Status = "rolled_back"
	value.Report.Error = journal.Error
	value.Report.CheckedAt = time.Now().UTC()
	if err := saveManagedJournal(path, journal); err != nil {
		return err
	}
	return atomicJSON(firewallActivationStatusPath(stateDir), value.Report)
}

func (a *Agent) recoverFirewallActivationLocked(ctx context.Context) error {
	paths, err := filepath.Glob(filepath.Join(firewallActivationDirectory(a.Config.StateDir), "*.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		nonce := strings.TrimSuffix(filepath.Base(path), ".json")
		journal, err := readManagedJournal(path, nonce)
		if err != nil {
			return err
		}
		if journal.FirewallActivation == nil {
			return errors.New("foreign journal in firewall-maintenance history")
		}
		if terminalManagedPhase(journal.Phase) {
			continue
		}
		journal.Error = "interrupted firewall maintenance recovered before any further policy writes"
		if err := rollbackFirewallActivation(ctx, a.Commands, path, journal, a.firewallActivation); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) previousFirewallActivation(id, planDigest string) (bool, error) {
	paths, err := filepath.Glob(filepath.Join(firewallActivationDirectory(a.Config.StateDir), "*.json"))
	if err != nil {
		return false, err
	}
	for _, path := range paths {
		nonce := strings.TrimSuffix(filepath.Base(path), ".json")
		journal, err := readManagedJournal(path, nonce)
		if err != nil {
			return false, err
		}
		if journal.FirewallActivation == nil {
			return false, errors.New("foreign firewall-maintenance journal")
		}
		if journal.FirewallActivation.Assignment.ID == id {
			if journal.FirewallActivation.Assignment.PlanDigest != planDigest {
				return false, errors.New("firewall maintenance ID was reused with a different plan")
			}
			return true, nil
		}
	}
	return false, nil
}

// Commit checks require exact candidate bytes, rather than accepting either
// side of a partially applied transaction as recovery does.
func activationAppliedFilesMatch(root string, value *firewallActivationJournal) error {
	current, err := activationConfigFiles(root)
	if err != nil {
		return err
	}
	expected := map[string]string{}
	for name, hash := range value.Baseline.Files {
		expected[name] = hash
	}
	for name, change := range value.ChangedFiles {
		expected[name] = activationFileFingerprint(change.After, change.Mode)
	}
	if value.CreatedPolicy {
		delete(current, "/etc/firewalld/policies/"+activationEgressPolicy+".xml")
	}
	if !reflect.DeepEqual(current, expected) {
		return errors.New("final firewall configuration differs from the exact reviewed candidate")
	}
	return nil
}
