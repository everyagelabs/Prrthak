package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func managedDirectory(stateDir string) string { return filepath.Join(stateDir, "managed") }
func managedJournalPath(stateDir, nonce string) string {
	return filepath.Join(managedDirectory(stateDir), "transactions", nonce+".json")
}
func saveManagedJournal(path string, journal *managedJournal) error { return atomicJSON(path, journal) }
func managedLock(stateDir string, nonblocking bool) (*os.File, error) {
	if _, e := setupPath(stateDir, true); e != nil {
		return nil, errors.New("managed state directory must be a safe owned directory without symlink ancestors")
	}
	if e := os.MkdirAll(managedDirectory(stateDir), 0700); e != nil {
		return nil, e
	}
	if _, e := setupPath(managedDirectory(stateDir), true); e != nil {
		return nil, errors.New("managed lease directory must be safe and have no symlink ancestors")
	}
	path := filepath.Join(managedDirectory(stateDir), "lock")
	descriptor, e := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(descriptor), path)
	info, e := f.Stat()
	if e != nil || validatePrivateFileInfo("managed mutation lease", info, os.Geteuid()) != nil || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("managed mutation lease must be an owned private regular file")
	}
	if status, ok := info.Sys().(*syscall.Stat_t); !ok || status.Nlink != 1 {
		f.Close()
		return nil, errors.New("managed mutation lease cannot have hard-link aliases")
	}
	mode := syscall.LOCK_EX
	if nonblocking {
		mode |= syscall.LOCK_NB
	}
	if e = syscall.Flock(int(f.Fd()), mode); e != nil {
		f.Close()
		return nil, e
	}
	if e = checkCommandFence(f.Name(), true); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

// Close only our reference. LOCK_UN would also release the lease inherited by a
// command supervisor which is still draining an orphaned mutation process tree.
func unlockManaged(f *os.File) { _ = f.Close() }

type managedLeaseContextKey struct{}

func withManagedLease(ctx context.Context, lock *os.File) context.Context {
	return context.WithValue(ctx, managedLeaseContextKey{}, lock)
}

func managedLeaseFromContext(ctx context.Context) *os.File {
	lease, _ := ctx.Value(managedLeaseContextKey{}).(*os.File)
	return lease
}
func processIdentity(pid int) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return ""
	}
	stat, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return ""
	}
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return ""
	}
	parts := strings.Fields(string(stat)[end+1:])
	if len(parts) < 20 {
		return ""
	}
	return strings.TrimSpace(string(boot)) + ":" + parts[19]
}
func validManagedNonce(value string) bool { return len(value) == 32 && validDigest(value+value) }
func readManagedJournal(path, nonce string) (*managedJournal, error) {
	area := filepath.Base(filepath.Dir(filepath.Dir(path)))
	directory := filepath.Base(filepath.Dir(path))
	if !validManagedNonce(nonce) || !filepath.IsAbs(path) || filepath.Base(path) != nonce+".json" || (directory != "transactions" && !(directory == "source-bank-transactions" && area == "managed")) || (area != "managed" && area != "learning-allow") {
		return nil, errors.New("invalid managed watchdog journal path/nonce")
	}
	raw, e := readPrivateSetupBound(path, 16*1024*1024)
	if e != nil {
		return nil, e
	}
	var journal managedJournal
	if e = json.Unmarshal(raw, &journal); e != nil {
		return nil, e
	}
	if journal.Nonce != nonce || journal.PID < 1 || len(journal.Mutations) > 1024 {
		return nil, errors.New("managed journal identity invalid")
	}
	if e := validateManagedSetJournal(&journal); e != nil {
		return nil, e
	}
	if (directory == "source-bank-transactions") != (journal.SourceBankPreparation != nil) {
		return nil, errors.New("source-bank journal area/type mismatch")
	}
	if e := validateSourceBankJournal(&journal); e != nil {
		return nil, e
	}
	return &journal, nil
}
func terminalManagedPhase(phase string) bool {
	return phase == "committed" || phase == "rolled_back" || phase == "superseded"
}
func managedOwned(rule string) bool {
	if learningAllowOwned(rule) {
		return true
	}
	info, e := parseManagedRich(rule)
	if e != nil {
		return false
	}
	if len(info.LogPrefix) != 17 || !strings.HasPrefix(info.LogPrefix, "PRTM") || !strings.HasSuffix(info.LogPrefix, ":") || !validDigest(strings.Repeat(info.LogPrefix[4:16], 5)+info.LogPrefix[4:8]) {
		return false
	}
	if info.Port == "" {
		return hostDefaultDenyOwnedControl(info)
	}
	return managedOwnershipPriority(info.Priority) && strings.HasPrefix(info.LogPrefix, "PRTM") && len(info.LogPrefix) == 17 && strings.HasSuffix(info.LogPrefix, ":") && info.LogLevel == "debug" && info.LogLimit == "1/m" && (info.Action == "accept" || info.Action == "reject")
}
func rollbackManaged(ctx context.Context, runner CommandRunner, path string, journal *managedJournal) error {
	if journal.SourceBankPreparation != nil {
		return rollbackSourceBanks(ctx, runner, path, journal, nil)
	}
	if err := checkManagedCommandFence(ctx); err != nil {
		return err
	}
	if err := clearTrafficCaptureSidecars(ctx, filepath.Dir(filepath.Dir(filepath.Dir(path))), runner); err != nil {
		return err
	}
	failures := []string{}
	for i := len(journal.Mutations) - 1; i >= 0; i-- {
		mutation := journal.Mutations[i]
		if !firewallName.MatchString(mutation.Zone) || !managedOwned(mutation.Rule) || (mutation.Scope != "runtime" && mutation.Scope != "permanent") {
			failures = append(failures, "invalid owned rollback mutation")
			continue
		}
		present, e := firewallQuery(ctx, runner, mutation.Scope, mutation.Zone, "rich_rule", mutation.Rule)
		if e != nil {
			failures = append(failures, "rollback query failed")
			continue
		}
		if present == mutation.Before {
			continue
		}
		op := "remove"
		if mutation.Before {
			op = "add"
		}
		if e = firewallMutate(ctx, runner, firewallMutation{Scope: mutation.Scope, Zone: mutation.Zone, Kind: "rich_rule", Value: mutation.Rule, Operation: op}); e != nil {
			failures = append(failures, "rollback command failed")
			continue
		}
		check, e := firewallQuery(ctx, runner, mutation.Scope, mutation.Zone, "rich_rule", mutation.Rule)
		if e != nil || check != mutation.Before {
			failures = append(failures, "rollback read-back failed")
		}
	}
	// Rules are restored first: old-bank references become live while no new
	// bank rule remains. Only then restore the unused bank's exact prior data.
	if len(failures) == 0 {
		for i := len(journal.SetMutations) - 1; i >= 0; i-- {
			mutation := journal.SetMutations[i]
			if e := validateManagedSetJournal(journal); e != nil {
				failures = append(failures, "invalid source-set rollback journal")
				break
			}
			if e := writeManagedSetEntries(ctx, runner, filepath.Dir(path), mutation.Scope, mutation.Set, mutation.Before); e != nil {
				failures = append(failures, "source-set rollback failed")
			}
		}
	}
	if len(failures) > 0 {
		journal.Phase = "rollback_failed"
		journal.Error = strings.Join(failures, "; ")
		_ = saveManagedJournal(path, journal)
		return errors.New(journal.Error)
	}
	journal.Phase = "rolled_back"
	if e := saveManagedJournal(path, journal); e != nil {
		return e
	}
	return atomicJSON(filepath.Join(filepath.Dir(filepath.Dir(path)), "committed.json"), journal.Previous)
}

// RunManagedWatchdog is called by an independent systemd transient service. It
// fences the exact original process before taking the same write lock as apply.
// Linux command supervisors inherit that lease and release it only after all
// descendants are reaped, so owner death cannot race a late command mutation
// against compensation. A tree which cannot drain keeps compensation blocked.
func RunManagedWatchdog(ctx context.Context, path, nonce string, runner CommandRunner) error {
	journal, e := readManagedJournal(path, nonce)
	if e != nil {
		return e
	}
	if terminalManagedPhase(journal.Phase) {
		return nil
	}
	if managedCommittedSuccessor(path, journal) {
		journal.Phase = "superseded"
		journal.Error = "newer committed generation fences stale rollback"
		return saveManagedJournal(path, journal)
	}
	if journal.DeadlineBootSeconds > 0 && bootElapsedSeconds() > 0 && strings.HasPrefix(journal.ProcessIdentity, strings.Split(processIdentity(os.Getpid()), ":")[0]+":") {
		if bootElapsedSeconds() < journal.DeadlineBootSeconds {
			return errors.New("watchdog invoked before its monotonic deadline")
		}
	} else if time.Now().Before(journal.Deadline) {
		return errors.New("watchdog invoked before its recorded deadline")
	}
	stateDir := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	lock, e := managedLock(stateDir, true)
	if e != nil {
		if errors.Is(e, errUncertainCommand) {
			return e
		}
		// Re-read immediately before fencing: an old generation must never kill a
		// process which has committed that generation and started a newer one.
		journal, e = readManagedJournal(path, nonce)
		if e != nil {
			return e
		}
		if terminalManagedPhase(journal.Phase) {
			return nil
		}
		if journal.PID == os.Getpid() {
			return errors.New("refusing watchdog self-fence")
		}
		if journal.ProcessIdentity != "" && processIdentity(journal.PID) == journal.ProcessIdentity {
			if e = syscall.Kill(journal.PID, syscall.SIGKILL); e != nil && e != syscall.ESRCH {
				return e
			}
		}
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			lock, e = managedLock(stateDir, true)
			if e == nil {
				break
			}
			if errors.Is(e, errUncertainCommand) {
				return e
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if e != nil {
			return errors.New("watchdog could not fence/acquire managed lock")
		}
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	journal, e = readManagedJournal(path, nonce)
	if e != nil {
		return e
	}
	if terminalManagedPhase(journal.Phase) {
		return nil
	}
	if managedCommittedSuccessor(path, journal) {
		journal.Phase = "superseded"
		journal.Error = "newer committed generation fences stale rollback"
		return saveManagedJournal(path, journal)
	}
	journal.Error = "independent rollback deadline exceeded"
	return rollbackManaged(ctx, runner, path, journal)
}
func (a *Agent) armManagedWatchdog(ctx context.Context, path string, journal *managedJournal) error {
	if a.armManaged != nil {
		return a.armManaged(ctx, path, journal)
	}
	if runtime.GOOS != "linux" || journal.ProcessIdentity == "" {
		return errors.New("managed enforcement requires Linux process identity and systemd watchdog")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil {
		return e
	}
	return armManagedWatchdogBinary(ctx, a.Commands, path, journal, exe)
}
func armManagedWatchdogBinary(ctx context.Context, commands CommandRunner, path string, journal *managedJournal, exe string) error {
	unit := "seg-agent-rollback-" + journal.Nonce
	seconds := int(math.Ceil(time.Until(journal.Deadline).Seconds()))
	if seconds < 1 {
		return errors.New("rollback deadline already elapsed")
	}
	_, e := commands.Run(ctx, "systemd-run", "--quiet", "--unit="+unit, "--on-active="+strconv.Itoa(seconds)+"s", "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "--property=User=root", "--property=UMask=0077", "--property=NoNewPrivileges=yes", "--property=Restart=on-failure", "--property=RestartSec=5s", exe, "--rollback-journal", path, "--rollback-nonce", journal.Nonce)
	if e != nil {
		return fmt.Errorf("independent rollback timer not armed: %w", e)
	}
	active, e := commands.Run(ctx, "systemctl", "is-active", unit+".timer")
	if e != nil || strings.TrimSpace(active) != "active" {
		return errors.New("independent rollback timer could not be verified active")
	}
	return nil
}
func (a *Agent) recoverManaged(ctx context.Context) error {
	if a.Simulate {
		return nil
	}
	lock, e := managedLock(a.Config.StateDir, true)
	if e != nil {
		return fmt.Errorf("managed recovery cannot acquire safe mutation authority: %w", e)
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	return a.recoverAllEnforcementLocked(ctx)
}
func (a *Agent) recoverManagedLocked(ctx context.Context) error {
	paths, e := filepath.Glob(filepath.Join(managedDirectory(a.Config.StateDir), "transactions", "*.json"))
	if e != nil {
		return e
	}

	var committed []*managedJournal
	var failures []*managedJournal
	for _, path := range paths {
		nonce := strings.TrimSuffix(filepath.Base(path), ".json")
		journal, e := readManagedJournal(path, nonce)
		if e != nil {
			return e
		}
		if journal.Phase == "committed" {
			committed = append(committed, journal)
			continue
		}
		if journal.Phase == "superseded" {
			continue
		}
		if journal.Phase != "rolled_back" && managedCommittedSuccessor(path, journal) {
			journal.Phase = "superseded"
			journal.Error = "newer committed generation fences stale rollback"
			if e = saveManagedJournal(path, journal); e != nil {
				return e
			}
			continue
		}
		if journal.Phase != "rolled_back" {
			journal.Error = "interrupted agent apply recovered before new policy"
			if e = rollbackManaged(ctx, a.Commands, path, journal); e != nil {
				return e
			}
		}
		if len(journal.Mutations) > 0 || len(journal.SetMutations) > 0 {
			a.latchManagedFailure(journal)
		}
		failures = append(failures, journal)
	}
	var latest *managedJournal
	for _, journal := range committed {
		if latest == nil || journal.Next.Version > latest.Next.Version {
			latest = journal
			continue
		}
		if journal.Next.Version == latest.Next.Version {
			if journal.Next.Digest != latest.Next.Digest {
				return errors.New("divergent committed managed digests share one version")
			}
			if journal.Previous != nil && journal.Previous.Generation == latest.Next.Generation {
				latest = journal
			}
		}
	}
	// Resolve same-version protection-only successors without relying on wall time.
	for pass := 0; pass < len(committed); pass++ {
		for _, journal := range committed {
			if latest != nil && journal.Next.Version == latest.Next.Version && journal.Next.Digest == latest.Next.Digest && journal.Previous != nil && journal.Previous.Generation == latest.Next.Generation {
				latest = journal
			}
		}
	}
	if latest != nil {
		a.State.ManagedBundle = &latest.Next
		a.State.AppliedVersion = latest.Next.Version
		a.State.ManagedEnforcement = &ManagedEnforcement{Status: "enforced", Version: latest.Next.Version, Digest: latest.Next.Digest, ApprovalID: latest.Next.ApprovalID, UpdatedAt: time.Now().UTC()}
		if e = atomicJSON(filepath.Join(managedDirectory(a.Config.StateDir), "committed.json"), latest.Next); e != nil {
			return e
		}
		for _, rule := range latest.Next.Rules {
			for _, scope := range []string{"runtime", "permanent"} {
				present, err := firewallQuery(ctx, a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
				if err != nil || !present {
					a.State.ManagedEnforcement.Status = "error"
					a.State.ManagedEnforcement.Error = "committed managed rule drift detected during startup"
				}
			}
		}
	}
	var failed *managedJournal
	for _, journal := range failures {
		if latest == nil || journal.Next.Version > latest.Next.Version || journal.Next.Version == latest.Next.Version && journal.Next.Digest == latest.Next.Digest && journal.Next.ProtectionDigest != latest.Next.ProtectionDigest {
			preferred := a.State.Policy != nil && a.State.Policy.Enforcement != nil && a.State.Policy.Enforcement.ApprovalID == journal.Next.ApprovalID
			if failed == nil || journal.Next.Version > failed.Next.Version || journal.Next.Version == failed.Next.Version && preferred {
				failed = journal
			}
		}
	}
	if failed != nil {
		a.State.ManagedEnforcement = &ManagedEnforcement{Status: "rolled_back", Version: failed.Next.Version, Digest: failed.Next.Digest, ApprovalID: failed.Next.ApprovalID, RollbackReason: failed.Error, UpdatedAt: time.Now().UTC()}
	}
	return a.save()
}

func bootElapsedSeconds() float64 {
	raw, e := os.ReadFile("/proc/uptime")
	if e != nil {
		return 0
	}
	parts := strings.Fields(string(raw))
	if len(parts) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(parts[0], 64)
	return value
}

func managedCommittedSuccessor(path string, journal *managedJournal) bool {
	if journal.SourceBankPreparation != nil {
		return false
	}
	if journal.Next.Generation == "" {
		return false
	}
	previous := ""
	if journal.Previous != nil {
		previous = journal.Previous.Generation
	}
	paths, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.json"))
	for _, candidatePath := range paths {
		if candidatePath == path {
			continue
		}
		nonce := strings.TrimSuffix(filepath.Base(candidatePath), ".json")
		candidate, e := readManagedJournal(candidatePath, nonce)
		if e != nil || candidate.Phase != "committed" || candidate.Next.Generation == "" || candidate.Next.Generation == journal.Next.Generation {
			continue
		}
		candidatePrevious := ""
		if candidate.Previous != nil {
			candidatePrevious = candidate.Previous.Generation
		}
		if candidatePrevious == previous {
			return true
		}
	}
	return false
}

func (a *Agent) recoverAllEnforcementLocked(ctx context.Context) error {
	if err := checkManagedCommandFence(ctx); err != nil {
		return err
	}
	if e := a.recoverSourceBankPreparationLocked(ctx); e != nil {
		return e
	}
	if e := a.recoverManagedLocked(ctx); e != nil {
		return e
	}
	return a.recoverLearningAllowLocked(ctx)
}
