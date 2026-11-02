package agent

import (
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

var errSourceBankPending = errors.New("source-bank maintenance needs its retained journal recovered before another assignment")

func validateSourceBankJournal(journal *managedJournal) error {
	bank := journal.SourceBankPreparation
	if bank == nil {
		return nil
	}
	if !changeIDValid(bank.Assignment.ID) || bank.Assignment.Operation != "prepare_activate" || !validDigest(bank.Assignment.PlanDigest) || !validDigest(bank.Baseline.ContextDigest) || !validDigest(bank.Baseline.Digest) || len(bank.Created) > sourceBankCount || len(journal.Mutations) > 0 || len(journal.SetMutations) > 0 || journal.Next.Generation != "" || journal.Previous != nil {
		return errors.New("invalid source-bank rollback journal")
	}
	seen := map[string]bool{}
	if len(bank.Baseline.OwnedRules) > 1024 {
		return errors.New("excessive owned maintenance baseline")
	}
	for _, rule := range bank.Baseline.OwnedRules {
		if !firewallName.MatchString(rule.Zone) || !managedOwned(rule.Rule) {
			return errors.New("invalid owned maintenance baseline")
		}
	}
	for _, name := range bank.Created {
		if _, valid := sourceBankFamily(name); !valid || seen[name] {
			return errors.New("invalid created source-bank rollback scope")
		}
		if _, exists := bank.Baseline.Permanent[name]; exists {
			return errors.New("source-bank rollback cannot remove a pre-existing definition")
		}
		seen[name] = true
	}
	for _, bindings := range []map[string]string{bank.Baseline.RuntimeBindings, bank.Baseline.PermanentBindings} {
		if len(bindings) > 1024 {
			return errors.New("excessive source-bank interface bindings")
		}
		for name, zone := range bindings {
			if !firewallName.MatchString(name) || len(name) > 64 || !firewallName.MatchString(zone) {
				return errors.New("invalid source-bank interface binding")
			}
		}
	}
	for _, scope := range []map[string]sourceBankDefinition{bank.Baseline.Runtime, bank.Baseline.Permanent} {
		if len(scope) > sourceBankCount {
			return errors.New("excessive source-bank baseline")
		}
		for name, definition := range scope {
			family, valid := sourceBankFamily(name)
			if !valid || definition.Family != family || !validManagedSet(ManagedIPSet{Name: name, Family: family, Entries: definition.Entries}) {
				return errors.New("invalid source-bank baseline definition")
			}
		}
	}
	if err := validateSourceBankReport(bank.Report); err != nil {
		return err
	}
	copy := bank.Baseline
	copy.Digest = ""
	raw, err := json.Marshal(copy)
	if err != nil || shaText(string(raw)) != bank.Baseline.Digest {
		return errors.New("source-bank baseline digest differs from journal content")
	}
	return nil
}

func restoreSourceBankBindings(ctx context.Context, commands CommandRunner, expected map[string]string) error {
	text, err := commands.Run(ctx, "firewall-cmd", "--list-all-zones")
	if err != nil {
		return errors.New("cannot inspect interface bindings after source-bank reload")
	}
	current, err := sourceBankZoneBindings(text)
	if err != nil {
		return err
	}
	for name := range current {
		if _, known := expected[name]; !known {
			return errors.New("unexpected interface appeared during reload; manual review required")
		}
	}
	names := []string{}
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if current[name] == expected[name] {
			continue
		}
		if !firewallName.MatchString(name) || !firewallName.MatchString(expected[name]) {
			return errors.New("invalid saved interface binding")
		}
		if _, err := commands.Run(ctx, "firewall-cmd", "--zone="+expected[name], "--change-interface="+name); err != nil {
			return errors.New("saved runtime interface binding could not be restored")
		}
	}
	text, err = commands.Run(ctx, "firewall-cmd", "--list-all-zones")
	if err != nil {
		return err
	}
	current, err = sourceBankZoneBindings(text)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errors.New("restored runtime interface bindings did not verify")
	}
	return nil
}

func rollbackSourceBanks(ctx context.Context, commands CommandRunner, path string, journal *managedJournal, configDigest func() (string, error)) error {
	if err := checkManagedCommandFence(ctx); err != nil {
		return err
	}
	if err := validateSourceBankJournal(journal); err != nil {
		return err
	}
	bank := journal.SourceBankPreparation
	statusPath := sourceBankStatusPath(filepath.Dir(filepath.Dir(filepath.Dir(path))))
	failure := func(err error) error {
		journal.Phase = "rollback_failed"
		journal.Error = boundedSourceBankError(err)
		bank.Report.Status = "error"
		bank.Report.Error = journal.Error
		bank.Report.CheckedAt = time.Now().UTC()
		_ = saveManagedJournal(path, journal)
		_ = atomicJSON(statusPath, bank.Report)
		return err
	}
	// Verify all access-policy context before deletion. If another writer added
	// references or changed a policy, preserve evidence rather than delete it.
	inspection := &Agent{Commands: commands, sourceBankConfigDigest: configDigest, sourceBankSkipInventory: true, sourceBankOwnedRulesOverride: bank.Baseline.OwnedRules}
	current, err := inspection.sourceBankBaseline(ctx)
	if err != nil || current.ContextDigest != bank.Baseline.ContextDigest || !reflect.DeepEqual(current.PermanentBindings, bank.Baseline.PermanentBindings) {
		return failure(errors.New("firewall policy changed outside source-bank preparation; rollback scope is uncertain"))
	}
	// Only object names we atomically created with this nonce can be removed.
	// Uncertain/foreign entries or references are never overwritten to make the
	// UI look successful; the blocking journal remains for recovery inspection.
	names, err := readBankSetNames(ctx, commands, "permanent")
	if err != nil {
		return failure(err)
	}
	presentNames := map[string]bool{}
	for _, name := range names {
		presentNames[name] = true
	}
	runtimeNames, err := readBankSetNames(ctx, commands, "runtime")
	if err != nil {
		return failure(err)
	}
	runtimePresent := map[string]bool{}
	for _, name := range runtimeNames {
		runtimePresent[name] = true
	}
	for i := len(bank.Created) - 1; i >= 0; i-- {
		name := bank.Created[i]
		var active *sourceBankDefinition
		if runtimePresent[name] {
			value, err := bankDefinition(ctx, commands, "runtime", name)
			if err != nil || len(value.Entries) != 0 {
				return failure(errors.New("runtime source bank changed; rollback refuses to overwrite populated or uncertain runtime membership"))
			}
			active = &value
		}
		if !presentNames[name] {
			continue
		}
		owner, err := commands.Run(ctx, "firewall-cmd", "--permanent", "--ipset="+name, "--get-description")
		if err != nil || strings.TrimSpace(owner) != sourceBankOwner(journal.Nonce, name) {
			return failure(errors.New("source-bank ownership changed; rollback refuses to remove an unowned definition"))
		}
		definition, err := bankDefinition(ctx, commands, "permanent", name)
		if err != nil || len(definition.Entries) != 0 {
			return failure(errors.New("source bank is not verified empty; rollback cannot remove it"))
		}
		if active != nil && !reflect.DeepEqual(*active, definition) {
			return failure(errors.New("runtime source bank definition changed; rollback refuses to overwrite uncertain runtime membership"))
		}
		if _, err := commands.Run(ctx, "firewall-cmd", "--permanent", "--delete-ipset="+name); err != nil {
			return failure(errors.New("owned source-bank rollback removal failed"))
		}
	}
	reloaded := bank.Reloaded
	// A daemon/host restart may load definitions while creation was interrupted,
	// before this agent could record its own reload intent. Empty runtime banks
	// created by this transaction still need the same reviewed recovery reload.
	created := map[string]bool{}
	for _, name := range bank.Created {
		created[name] = true
	}
	for _, name := range runtimeNames {
		if created[name] {
			reloaded = true
		}
	}
	if reloaded {
		// A failed first reload can leave the bank set between generations. The
		// original permanent access policy was never edited: reloading after only
		// our empty definitions are removed restores that reviewed policy.
		if _, err := commands.Run(ctx, "firewall-cmd", "--check-config"); err != nil {
			return failure(errors.New("restored permanent configuration is invalid"))
		}
		if _, err := commands.Run(ctx, "firewall-cmd", "--reload"); err != nil {
			return failure(errors.New("source-bank recovery reload failed"))
		}
		if err := restoreSourceBankBindings(ctx, commands, bank.Baseline.RuntimeBindings); err != nil {
			return failure(err)
		}
	}
	inspection.sourceBankSkipInventory = false
	verified, err := inspection.sourceBankBaseline(ctx)
	if err != nil || verified.Digest != bank.Baseline.Digest {
		return failure(errors.New("original firewall baseline was not verified after source-bank rollback"))
	}
	journal.Phase = "rolled_back"
	bank.Report.Status = "rolled_back"
	bank.Report.Error = journal.Error
	bank.Report.CheckedAt = time.Now().UTC()
	fillSourceBankReceipt(&bank.Report, verified)
	if err := saveManagedJournal(path, journal); err != nil {
		return err
	}
	return atomicJSON(statusPath, bank.Report)
}

func (a *Agent) recoverSourceBankPreparationLocked(ctx context.Context) error {
	paths, err := filepath.Glob(filepath.Join(sourceBankDirectory(a.Config.StateDir), "*.json"))
	if err != nil {
		return err
	}
	if len(paths) > enforcementHistoryMaxEntries {
		return errors.New("excessive source-bank recovery history")
	}
	for _, path := range paths {
		nonce := strings.TrimSuffix(filepath.Base(path), ".json")
		journal, err := readManagedJournal(path, nonce)
		if err != nil {
			return err
		}
		if terminalManagedPhase(journal.Phase) {
			continue
		}
		journal.Error = "interrupted source-bank preparation recovered before new firewall work"
		if err := rollbackSourceBanks(ctx, a.Commands, path, journal, a.sourceBankConfigDigest); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) recoverPendingSourceBankOperation(ctx context.Context) error {
	var config *os.File
	var err error
	if a.sourceBankConfigurationLease != nil {
		config, err = a.sourceBankConfigurationLease()
	} else {
		config, err = configurationLeaseUnder("", 0)
	}
	if err != nil {
		return err
	}
	defer config.Close()
	lock, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		return err
	}
	defer unlockManaged(lock)
	return a.recoverSourceBankPreparationLocked(withManagedLease(ctx, lock))
}

// Retained signed journals fence replay even after a later assessment/status
// receipt replaces the latest display. File names alone never establish scope.
func (a *Agent) previousSourceBankOperation(id, digest string) (bool, error) {
	paths, err := filepath.Glob(filepath.Join(sourceBankDirectory(a.Config.StateDir), "*.json"))
	if err != nil {
		return false, err
	}
	if len(paths) > enforcementHistoryMaxEntries {
		return false, errors.New("source-bank history exceeds its capacity")
	}
	for _, path := range paths {
		journal, err := readManagedJournal(path, strings.TrimSuffix(filepath.Base(path), ".json"))
		if err != nil {
			return false, errors.New("invalid retained source-bank history")
		}
		if journal.SourceBankPreparation.Assignment.ID == id {
			if journal.SourceBankPreparation.Assignment.PlanDigest != digest {
				return false, errors.New("source-bank operation replay diverged")
			}
			if terminalManagedPhase(journal.Phase) {
				if err := a.sourceBankStatus(journal.SourceBankPreparation.Report); err != nil {
					return false, err
				}
				return true, nil
			}
			return false, errSourceBankPending
		}
	}
	return false, nil
}
