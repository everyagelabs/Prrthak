package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// CheckInstallerUpgradeSafety recognizes only the inherited lease on the exact
// protected canonical inode. It never accepts an arbitrary descriptor as a bypass.
func CheckInstallerUpgradeSafety(c Config, descriptor int) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || c.StateDir != "/var/lib/seg-agent" {
		return errors.New("inherited installation lease requires the canonical native root installation")
	}
	return checkInstallerLeaseUnder(c, "", descriptor)
}
func checkInstallerLeaseUnder(c Config, root string, descriptor int) error {
	if descriptor < 3 || descriptor > 1024 {
		return errors.New("invalid inherited installation lease descriptor")
	}
	path := root + "/var/lib/seg-agent/configuration-transitions/lock"
	info, err := setupPath(path, false)
	if err != nil || info.Mode().Perm() != 0600 {
		return errors.New("installation lease path is not a protected regular file")
	}
	duplicate, err := syscall.Dup(descriptor)
	if err != nil {
		return err
	}
	syscall.CloseOnExec(duplicate)
	file := os.NewFile(uintptr(duplicate), path)
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) || validatePrivateFileInfo(path, actual, os.Geteuid()) != nil {
		return errors.New("inherited installation lease does not match the protected canonical inode")
	}
	if status, ok := actual.Sys().(*syscall.Stat_t); !ok || status.Nlink != 1 {
		return errors.New("installation lease cannot have aliases")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("installation does not hold the endpoint configuration lease")
	}
	return checkEnforcementUpgradeSafety(c, true)
}

// CheckEnforcementUpgradeSafety is read-only. It never compensates a journal,
// kills an agent/watchdog, creates a lock or changes firewall state. Installers
// call it before any copy, then again after stopping the normal agent unit.
func CheckEnforcementUpgradeSafety(c Config) error {
	return checkEnforcementUpgradeSafety(c, false)
}
func checkEnforcementUpgradeSafety(c Config, ownsConfigurationLock bool, ownReview ...string) error {
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("upgrade safety requires an absolute state directory")
	}
	if !ownsConfigurationLock {
		lockPath := filepath.Join(c.StateDir, "configuration-transitions", "lock")
		if info, e := os.Lstat(lockPath); e == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				return errors.New("configuration lock is unsafe")
			}
			file, e := os.Open(lockPath)
			if e != nil {
				return e
			}
			defer file.Close()
			if e = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
				return errors.New("endpoint configuration is active; replacement refused")
			}
			defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	configurationPaths, configurationErr := filepath.Glob(filepath.Join(c.StateDir, "configuration-transitions", "*.json"))
	if configurationErr != nil {
		return configurationErr
	}
	for _, path := range configurationPaths {
		raw, readErr := readPrivateSetupBound(path, 2*1024*1024)
		var journal configurationJournal
		if readErr != nil || json.Unmarshal(raw, &journal) != nil || journal.SchemaVersion != 1 {
			return errors.New("configuration rollback journal is invalid; replacement refused")
		}
		if !configurationTerminal(journal.Status) && !(journal.Status == "armed" && ownsConfigurationLock && len(ownReview) == 1 && journal.ReviewID == ownReview[0]) {
			return errors.New("independent configuration rollback is active; replacement refused")
		}
	}
	lockPath := filepath.Join(managedDirectory(c.StateDir), "lock")
	if info, e := os.Lstat(lockPath); e == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("enforcement lock ownership is not safe for replacement")
		}
		file, e := os.Open(lockPath)
		if e != nil {
			return e
		}
		defer file.Close()
		if e = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			return errors.New("enforcement or independent rollback is active; binary replacement refused")
		}
		defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	} else if !os.IsNotExist(e) {
		return e
	}
	if err := checkCommandFence(lockPath, false); err != nil {
		return err
	}
	return checkEnforcementJournals(c)
}

// The caller either holds the managed lease or has just performed the read-only
// lock/fence preflight above. Preparation rechecks while retaining both leases.
func checkEnforcementJournals(c Config) error {
	if err := checkNetworkControlUpgradeSafety(c); err != nil {
		return err
	}
	bankPaths, err := filepath.Glob(filepath.Join(sourceBankDirectory(c.StateDir), "*.json"))
	if err != nil {
		return err
	}
	if len(bankPaths) > enforcementHistoryMaxEntries {
		return errors.New("source-bank history exceeds its capacity")
	}
	for _, path := range bankPaths {
		journal, err := readManagedJournal(path, strings.TrimSuffix(filepath.Base(path), ".json"))
		if err != nil || !terminalManagedPhase(journal.Phase) {
			return errors.New("source-bank maintenance/recovery is active or unverifiable; binary replacement refused")
		}
	}
	maintenance, err := filepath.Glob(filepath.Join(firewallActivationDirectory(c.StateDir), "*.json"))
	if err != nil {
		return err
	}
	if len(maintenance) > enforcementHistoryMaxEntries {
		return errors.New("firewall maintenance history exceeds capacity")
	}
	for _, path := range maintenance {
		journal, err := readManagedJournal(path, strings.TrimSuffix(filepath.Base(path), ".json"))
		if err != nil || !terminalManagedPhase(journal.Phase) {
			return errors.New("firewall maintenance/recovery is active or unverifiable; binary replacement refused")
		}
	}
	for _, directory := range []string{managedDirectory(c.StateDir), learningAllowDirectory(c.StateDir)} {
		paths, e := filepath.Glob(filepath.Join(directory, "transactions", "*.json"))
		if e != nil {
			return e
		}
		for _, path := range paths {
			nonce := strings.TrimSuffix(filepath.Base(path), ".json")
			journal, e := readManagedJournal(path, nonce)
			if e != nil {
				return errors.New("enforcement journal cannot be verified; binary replacement refused")
			}
			if !terminalManagedPhase(journal.Phase) {
				return errors.New("nonterminal managed or learning transaction exists; keep the existing binary until independent rollback/recovery completes")
			}
		}
	}
	paths, e := filepath.Glob(filepath.Join(c.StateDir, "firewall-changes", "*.json"))
	if e != nil {
		return e
	}
	for _, path := range paths {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 2*1024*1024 {
			return errors.New("imported firewall journal cannot be verified; replacement refused")
		}
		raw, e := readPrivateSetupBound(path, 2*1024*1024)
		if e != nil {
			return e
		}
		var journal firewallJournal
		if json.Unmarshal(raw, &journal) != nil || !changeIDValid(journal.ID) || !validDigest(journal.PlanDigest) || filepath.Base(path) != shaText(journal.ID)+".json" {
			return errors.New("imported firewall journal is invalid; replacement refused")
		}
		if journal.Status != "applied" && journal.Status != "rolled_back" {
			return errors.New("nonterminal imported firewall transaction exists; replacement refused")
		}
	}
	return nil
}
