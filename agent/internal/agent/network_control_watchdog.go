package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type networkRuleMutation struct {
	Scope  string `json:"scope"`
	Rule   string `json:"rule"`
	Before bool   `json:"before"`
	After  bool   `json:"after"`
}
type networkControlJournal struct {
	CommittedAt            *time.Time            `json:"committed_at"`
	ExpiryBootSeconds      float64               `json:"expiry_boot_seconds"`
	ExpiryBootID           string                `json:"expiry_boot_id"`
	SchemaVersion          int                   `json:"schema_version"`
	Nonce                  string                `json:"nonce"`
	Kind                   string                `json:"kind"`
	Phase                  string                `json:"phase"`
	PID                    int                   `json:"pid"`
	ProcessIdentity        string                `json:"process_identity"`
	Deadline               time.Time             `json:"deadline"`
	DeadlineBootSeconds    float64               `json:"deadline_boot_seconds"`
	Before                 *networkControlState  `json:"before"`
	After                  *networkControlState  `json:"after"`
	Request                networkControlRequest `json:"request"`
	Report                 NetworkControlReport  `json:"report"`
	Mutations              []networkRuleMutation `json:"mutations"`
	BeforeTableHandle      string                `json:"before_table_handle"`
	TableMutationAttempted bool                  `json:"table_mutation_attempted"`
	Error                  string                `json:"error"`
}

func networkJournalPath(stateDir, nonce string) string {
	return filepath.Join(networkDirectory(stateDir), "transactions", nonce+".json")
}
func readNetworkJournal(path, nonce string) (*networkControlJournal, string, error) {
	if !filepath.IsAbs(path) || !validManagedNonce(nonce) || filepath.Base(path) != nonce+".json" || filepath.Base(filepath.Dir(path)) != "transactions" || filepath.Base(filepath.Dir(filepath.Dir(path))) != "network-control" || filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path)))) != "managed" {
		return nil, "", errors.New("network rollback path/nonce invalid")
	}
	raw, err := readPrivateSetupBound(path, 16*1024*1024)
	if err != nil {
		return nil, "", err
	}
	var result networkControlJournal
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.SchemaVersion != 1 || result.Nonce != nonce || result.PID < 1 || result.Before == nil || result.After == nil || len(result.Mutations) > 512 || result.Request.Kind != result.Kind || result.Kind != "egress" && result.Kind != "quarantine" {
		return nil, "", errors.New("network rollback journal identity/content invalid")
	}
	stateDir := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(path))))
	if networkJournalPath(stateDir, nonce) != path {
		return nil, "", errors.New("network rollback path mismatch")
	}
	return &result, stateDir, nil
}

func queryEgressRule(ctx context.Context, runner CommandRunner, scope, rule string) (bool, error) {
	text, err := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+egressPolicyName, "--query-rich-rule="+rule)...)
	text = strings.TrimSpace(text)
	if err == nil && text == "yes" {
		return true, nil
	}
	if text == "no" {
		return false, nil
	}
	return false, errors.New("owned outbound rollback query failed")
}
func rollbackNetworkJournal(ctx context.Context, runner CommandRunner, stateDir, path string, journal *networkControlJournal) error {
	if err := checkManagedCommandFence(ctx); err != nil {
		return err
	}
	before := cloneNetworkState(journal.Before)
	if journal.After.EgressGeneration > before.EgressGeneration {
		before.EgressGeneration = journal.After.EgressGeneration
	}
	if journal.After.QuarantineGeneration > before.QuarantineGeneration {
		before.QuarantineGeneration = journal.After.QuarantineGeneration
	}
	if journal.Kind == "egress" {
		for i := len(journal.Mutations) - 1; i >= 0; i-- {
			mutation := journal.Mutations[i]
			if mutation.Scope != "runtime" && mutation.Scope != "permanent" || len(mutation.Rule) > 2048 || mutation.Before == mutation.After {
				return errors.New("invalid bounded outbound rollback mutation")
			}
			present, err := queryEgressRule(ctx, runner, mutation.Scope, mutation.Rule)
			if err != nil {
				return err
			}
			if present == mutation.Before {
				continue
			}
			operation := "--remove-rich-rule="
			if mutation.Before {
				operation = "--add-rich-rule="
			}
			if _, err := runner.Run(ctx, "firewall-cmd", firewallArgs(mutation.Scope, "--policy="+egressPolicyName, operation+mutation.Rule)...); err != nil {
				return errors.New("outbound rollback command failed")
			}
		}
		if err := verifyOwnedEgressPolicy(ctx, runner, stateDir, before.EgressRules); err != nil {
			journal.Phase = "rollback_failed"
			journal.Error = boundedSourceBankError(err)
			_ = atomicJSON(path, journal)
			return err
		}
	} else if journal.TableMutationAttempted {
		now := time.Now().UTC()
		actual, handle, err := readQuarantineTable(ctx, runner)
		if err != nil {
			return err
		}
		_ = actual
		// Recognize either exact pre-state (an atomic update failed) or exact
		// attempted post-state. Never delete an unknown table based on its name.
		alreadyBefore := false
		if journal.Before.QuarantinePlan == nil && handle == "" {
			alreadyBefore = true
		} else if journal.Before.QuarantinePlan != nil {
			_, err := verifyQuarantineTable(ctx, runner, journal.Before.QuarantinePlan, now, !now.Before(journal.Before.QuarantinePlan.ExpiresAt))
			alreadyBefore = err == nil
		}
		if !alreadyBefore {
			if journal.After.QuarantinePlan == nil {
				if handle != "" {
					return errors.New("unrecognized table after quarantine release; refusing destructive rollback")
				}
			} else {
				if _, err := verifyQuarantineTable(ctx, runner, journal.After.QuarantinePlan, now, !now.Before(journal.After.QuarantinePlan.ExpiresAt)); err != nil {
					return err
				}
			}
			objects := []map[string]any{}
			if before.QuarantinePlan != nil {
				remaining := before.QuarantinePlan.ExpiresAt.Sub(now)
				if remaining > 5*time.Second {
					before.QuarantinePlan.LeaseSeconds = int64(remaining/time.Second) - 3
					objects, err = quarantineNFTObjects(*before.QuarantinePlan, time.Duration(before.QuarantinePlan.LeaseSeconds)*time.Second)
					if err != nil {
						return err
					}
				} else {
					before.Quarantine = nil
					before.QuarantinePlan = nil
					before.QuarantineAuthority = nil
					before.QuarantineNonce = ""
				}
			}
			if handle != "" || len(objects) > 0 {
				if err := runQuarantineBatch(ctx, runner, stateDir, journal.Nonce, objects, handle, false); err != nil {
					return err
				}
			}
			if _, err := verifyQuarantineTable(ctx, runner, before.QuarantinePlan, time.Now().UTC(), false); err != nil {
				return err
			}
		}
	}
	if err := atomicJSON(networkStatePath(stateDir), before); err != nil {
		return err
	}
	journal.Phase = "rolled_back"
	return atomicJSON(path, journal)
}

func recoverNetworkJournalsLocked(ctx context.Context, runner CommandRunner, stateDir string) error {
	paths, err := filepath.Glob(filepath.Join(networkDirectory(stateDir), "transactions", "*.json"))
	if err != nil {
		return err
	}
	if len(paths) > 1024 {
		return errors.New("network rollback history exceeds bounded recovery")
	}
	for _, path := range paths {
		nonce := strings.TrimSuffix(filepath.Base(path), ".json")
		journal, _, err := readNetworkJournal(path, nonce)
		if err != nil {
			return err
		}
		switch journal.Phase {
		case "committed", "rolled_back", "superseded", "expired":
			continue
		}
		journal.Error = "interrupted network control recovered before new firewall authority"
		if err := rollbackNetworkJournal(ctx, runner, stateDir, path, journal); err != nil {
			return err
		}
	}
	return nil
}

func armNetworkControlTimer(ctx context.Context, path string, journal *networkControlJournal, expiry bool) error {
	if runtime.GOOS != "linux" || journal.ProcessIdentity == "" {
		return errors.New("native Linux independent network rollback identity is unavailable")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	runner := ExecRunner{}
	return armNetworkControlTimerWithRunner(ctx, runner, exe, path, journal, expiry)
}
func armNetworkControlTimerWithRunner(ctx context.Context, runner CommandRunner, exe, path string, journal *networkControlJournal, expiry bool) error {
	deadline := journal.Deadline
	flag := "--rollback-network-control"
	prefix := "seg-agent-network-rollback-"
	if expiry {
		if journal.After.Quarantine == nil {
			return errors.New("quarantine expiry lease missing")
		}
		deadline = journal.After.Quarantine.ExpiresAt
		flag = "--expire-quarantine"
		prefix = "seg-agent-quarantine-expiry-"
		journal.ExpiryBootSeconds = bootElapsedSeconds() + time.Until(deadline).Seconds()
		journal.ExpiryBootID = strings.Split(processIdentity(os.Getpid()), ":")[0]
		if err := atomicJSON(path, journal); err != nil {
			return err
		}
	}
	seconds := int(math.Ceil(time.Until(deadline).Seconds()))
	if seconds < 1 || seconds > 3600 {
		return errors.New("network timer deadline is outside its bounded lease")
	}
	unit := prefix + journal.Nonce
	args := []string{"--quiet", "--unit=" + unit, "--on-active=" + strconv.Itoa(seconds) + "s", "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "--property=User=root", "--property=UMask=0077", "--property=NoNewPrivileges=yes", "--property=Restart=on-failure", "--property=RestartSec=5s", exe, flag, path, "--network-control-nonce", journal.Nonce}
	if _, err := runner.Run(ctx, "systemd-run", args...); err != nil {
		return errors.New("independent network rollback/expiry timer was not armed")
	}
	active, err := runner.Run(ctx, "systemctl", "is-active", unit+".timer")
	if err != nil || strings.TrimSpace(active) != "active" {
		return errors.New("independent network rollback/expiry timer did not verify active")
	}
	return nil
}

func acquireNetworkWatchdog(ctx context.Context, path, nonce string, expiry bool, runner CommandRunner) (*networkControlJournal, string, *os.File, error) {
	journal, stateDir, err := readNetworkJournal(path, nonce)
	if err != nil {
		return nil, "", nil, err
	}
	if journal.Phase == "rolled_back" || journal.Phase == "superseded" || journal.Phase == "expired" || !expiry && journal.Phase == "committed" {
		return journal, stateDir, nil, nil
	}
	now := time.Now().UTC()
	deadline := journal.Deadline
	if expiry {
		if journal.After.Quarantine == nil {
			return nil, "", nil, errors.New("quarantine expiry authority missing")
		}
		deadline = journal.After.Quarantine.ExpiresAt
	}
	tooEarly := now.Before(deadline)
	boot := strings.Split(processIdentity(os.Getpid()), ":")[0]
	if expiry && journal.ExpiryBootID != "" && journal.ExpiryBootID == boot && journal.ExpiryBootSeconds > 0 && bootElapsedSeconds() > 0 {
		tooEarly = bootElapsedSeconds() < journal.ExpiryBootSeconds
	} else if !expiry && boot != "" && strings.HasPrefix(journal.ProcessIdentity, boot+":") && journal.DeadlineBootSeconds > 0 && bootElapsedSeconds() > 0 {
		tooEarly = bootElapsedSeconds() < journal.DeadlineBootSeconds
	}
	if tooEarly {
		return nil, "", nil, errors.New("network watchdog invoked before its recorded deadline")
	}
	lock, err := managedLock(stateDir, true)
	if err != nil {
		if errors.Is(err, errUncertainCommand) {
			return nil, "", nil, err
		}
		if expiry && journal.Phase == "committed" {
			return nil, "", nil, errors.New("quarantine expiry waits for another owned firewall transaction; retry without fencing a newer operation")
		}
		current, _, readErr := readNetworkJournal(path, nonce)
		if readErr != nil {
			return nil, "", nil, readErr
		}
		if current.Phase == "committed" && !expiry || current.Phase == "rolled_back" || current.Phase == "superseded" {
			return current, stateDir, nil, nil
		}
		if current.PID == os.Getpid() {
			return nil, "", nil, errors.New("network watchdog refuses to fence itself")
		}
		if current.ProcessIdentity != "" && processIdentity(current.PID) == current.ProcessIdentity {
			if err := syscall.Kill(current.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
				return nil, "", nil, err
			}
		}
		until := time.Now().Add(15 * time.Second)
		for time.Now().Before(until) {
			lock, err = managedLock(stateDir, true)
			if err == nil {
				break
			}
			if errors.Is(err, errUncertainCommand) {
				return nil, "", nil, err
			}
			select {
			case <-ctx.Done():
				return nil, "", nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if err != nil {
			return nil, "", nil, errors.New("network watchdog could not fence and acquire the owned mutation lease")
		}
	}
	journal, _, err = readNetworkJournal(path, nonce)
	if err != nil {
		unlockManaged(lock)
		return nil, "", nil, err
	}
	return journal, stateDir, lock, nil
}

func RollbackNetworkControl(path, nonce string, runner CommandRunner) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	journal, stateDir, lock, err := acquireNetworkWatchdog(ctx, path, nonce, false, runner)
	if err != nil || lock == nil {
		return err
	}
	defer unlockManaged(lock)
	if journal.Phase == "committed" || journal.Phase == "rolled_back" || journal.Phase == "superseded" {
		return nil
	}
	return rollbackNetworkJournal(withManagedLease(ctx, lock), runner, stateDir, path, journal)
}

func expireQuarantineLocked(ctx context.Context, runner CommandRunner, stateDir, path string, journal *networkControlJournal) error {
	state, err := readNetworkState(stateDir)
	if err != nil {
		return err
	}
	if state.Quarantine == nil || state.QuarantineNonce != journal.Nonce {
		return nil
	}
	if time.Now().Before(state.Quarantine.ExpiresAt) {
		return errors.New("original quarantine lease has not expired")
	}
	_, handle, err := readQuarantineTable(ctx, runner)
	if err != nil {
		return err
	}
	if handle != "" {
		handle, err = verifyQuarantineTable(ctx, runner, state.QuarantinePlan, time.Now().UTC(), true)
		if err != nil {
			return err
		}
	}
	if handle != "" {
		if err := runQuarantineBatch(ctx, runner, stateDir, journal.Nonce, nil, handle, false); err != nil {
			return err
		}
	}
	if _, err := verifyQuarantineTable(ctx, runner, nil, time.Now().UTC(), true); err != nil {
		return err
	}
	original := state.Quarantine
	state.Quarantine = nil
	state.QuarantinePlan = nil
	state.QuarantineAuthority = nil
	state.QuarantineNonce = ""
	if err := atomicJSON(networkStatePath(stateDir), state); err != nil {
		return err
	}
	journal.Phase = "expired"
	if err := atomicJSON(path, journal); err != nil {
		return err
	}
	if report := ReadNetworkControlReport(stateDir); report != nil {
		report.Quarantine.Status = "expired"
		report.Quarantine.ExpiresAt = &original.ExpiresAt
		report.Quarantine.Error = ""
		report.CheckedAt = time.Now().UTC()
		fillNetworkActiveState(report, state, time.Now().UTC())
		return atomicJSON(networkReportPath(stateDir), report)
	}
	return nil
}
func ExpireQuarantine(path, nonce string, runner CommandRunner) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	journal, stateDir, lock, err := acquireNetworkWatchdog(ctx, path, nonce, true, runner)
	if err != nil || lock == nil {
		return err
	}
	defer unlockManaged(lock)
	if journal.Phase != "committed" && journal.Phase != "expired" && journal.Phase != "rolled_back" && journal.Phase != "superseded" {
		return rollbackNetworkJournal(withManagedLease(ctx, lock), runner, stateDir, path, journal)
	}
	return expireQuarantineLocked(withManagedLease(ctx, lock), runner, stateDir, path, journal)
}

func quarantineBootUnit(exe, stateDir string) (string, error) {
	for _, value := range []string{exe, stateDir} {
		if !filepath.IsAbs(value) || strings.ContainsAny(value, "\n\r\x00%$\"\\") {
			return "", errors.New("quarantine boot paths require literal protected absolute paths")
		}
	}
	return "# Managed by Prrthak emergency quarantine v1\n[Unit]\nDescription=Restore the remaining approved Prrthak quarantine lease\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target firewalld.service\nWants=network-pre.target\n[Service]\nType=oneshot\nUser=root\nUMask=0077\nNoNewPrivileges=yes\nTimeoutStartSec=30s\nExecStart=\"" + exe + "\" --restore-quarantine \"" + stateDir + "\"\n[Install]\nWantedBy=network-pre.target\n", nil
}
func prepareQuarantineBoot(ctx context.Context, runner CommandRunner, c Config) error {
	if runtime.GOOS != "linux" {
		return errors.New("early-boot quarantine reconciliation requires native Linux systemd")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	unit, err := quarantineBootUnit(exe, c.StateDir)
	if err != nil {
		return err
	}
	path := "/etc/systemd/system/seg-agent-quarantine-restore.service"
	if _, err := setupPath(filepath.Dir(path), true); err != nil {
		return err
	}
	if raw, err := os.ReadFile(path); err == nil {
		info, pathErr := setupPath(path, false)
		if pathErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("quarantine boot unit is not a protected owned regular file")
		}
		if string(raw) != unit {
			return errors.New("existing boot unit is unowned or belongs to another endpoint configuration")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		if err := atomicPrivateFile(path, []byte(unit)); err != nil {
			return err
		}
	}
	if _, err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return errors.New("quarantine boot unit could not be registered")
	}
	if _, err := runner.Run(ctx, "systemctl", "enable", "seg-agent-quarantine-restore.service"); err != nil {
		return errors.New("quarantine boot reconciliation could not be enabled")
	}
	text, err := runner.Run(ctx, "systemctl", "is-enabled", "seg-agent-quarantine-restore.service")
	if err != nil || strings.TrimSpace(text) != "enabled" {
		return errors.New("quarantine boot reconciliation did not verify enabled")
	}
	return nil
}

// RestoreQuarantine is an early-boot CLI and startup reconciliation path. It
// restores only an already committed, originally signed, unexpired local lease.
// Native element timeouts are recomputed from its original absolute deadline.
func RestoreQuarantine(stateDir string, runner CommandRunner) error {
	if runtime.GOOS != "linux" {
		return errors.New("native Linux quarantine reconciliation required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lock, err := managedLock(stateDir, true)
	if err != nil {
		return err
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if err := recoverNetworkJournalsLocked(ctx, runner, stateDir); err != nil {
		return err
	}
	state, err := readNetworkState(stateDir)
	if err != nil || state.Quarantine == nil {
		return err
	}
	path := networkJournalPath(stateDir, state.QuarantineNonce)
	journal, _, err := readNetworkJournal(path, state.QuarantineNonce)
	if err != nil {
		return err
	}
	if !time.Now().Before(state.Quarantine.ExpiresAt) {
		return expireQuarantineLocked(ctx, runner, stateDir, path, journal)
	}
	c, err := LoadConfig("/etc/seg-agent/config.json", false)
	if err != nil || c.StateDir != stateDir || !c.Enforce || !c.AllowFirewallChanges || !c.AllowHostDefaultDeny {
		return errors.New("committed quarantine cannot restore without the same current local opt-ins/configuration")
	}
	strict := c
	strict.Enforce = true
	if validateCommittedQuarantine(strict, state, journal, time.Now().UTC()) != nil {
		return errors.New("committed quarantine original signed authority could not be verified")
	}
	client, err := NewClient(c, false)
	if err != nil || client.identity == nil || client.identity.Load() == nil || client.identity.Load().Leaf == nil || client.identity.Load().Leaf.Subject.CommonName != state.QuarantineAuthority.ServerID {
		return errors.New("committed quarantine belongs to a different or unavailable local endpoint certificate")
	}
	actual, handle, err := readQuarantineTable(ctx, runner)
	if err != nil {
		return err
	}
	_ = actual
	if handle == "" {
		remaining := time.Until(state.Quarantine.ExpiresAt)
		if remaining < 5*time.Second {
			return nil
		}
		state.QuarantinePlan.LeaseSeconds = int64(remaining/time.Second) - 3
		objects, err := quarantineNFTObjects(*state.QuarantinePlan, time.Duration(state.QuarantinePlan.LeaseSeconds)*time.Second)
		if err != nil {
			return err
		}
		if err := runQuarantineBatch(ctx, runner, stateDir, state.QuarantineNonce, objects, "", true); err != nil {
			return err
		}
		if err := runQuarantineBatch(ctx, runner, stateDir, state.QuarantineNonce, objects, "", false); err != nil {
			return err
		}
		if err := atomicJSON(networkStatePath(stateDir), state); err != nil {
			return err
		}
	}
	if _, err := verifyQuarantineTable(ctx, runner, state.QuarantinePlan, time.Now().UTC(), false); err != nil {
		return err
	}
	return armNetworkControlTimerWithRunner(ctx, runner, "/usr/local/bin/seg-agent", path, journal, true)
}

func validateCommittedQuarantine(c Config, state *networkControlState, journal *networkControlJournal, now time.Time) error {
	if state == nil || state.Quarantine == nil || journal == nil || journal.Phase != "committed" || journal.CommittedAt == nil || journal.Nonce != state.QuarantineNonce || journal.After == nil || journal.After.Quarantine == nil || journal.After.Quarantine.PlanDigest != state.Quarantine.PlanDigest || state.QuarantineAuthority == nil || state.QuarantineAuthority.Quarantine == nil || state.QuarantineAuthority.Quarantine.PlanDigest != state.Quarantine.PlanDigest || descriptorDigest(state.Quarantine) != state.Quarantine.PlanDigest || state.QuarantineGeneration < state.Quarantine.Generation || !now.Before(state.Quarantine.ExpiresAt) || now.Before(state.Quarantine.IssuedAt) {
		return errors.New("committed quarantine origin/lease is not valid")
	}
	if err := validateQuarantineAssignment(c, state.QuarantineAuthority.ServerID, state.Quarantine, *journal.CommittedAt); err != nil {
		return err
	}
	return validatePolicySignatureAt(c, state.QuarantineAuthority, *journal.CommittedAt)
}

func checkNetworkControlUpgradeSafety(c Config) error {
	state, err := readNetworkState(c.StateDir)
	if err != nil {
		return errors.New("network-control state is unverifiable; binary replacement refused")
	}
	if state.Quarantine != nil {
		return errors.New("release quarantine and complete independent expiry cleanup before replacing its binary")
	}
	paths, err := filepath.Glob(filepath.Join(networkDirectory(c.StateDir), "transactions", "*.json"))
	if err != nil || len(paths) > enforcementHistoryMaxEntries {
		return errors.New("network-control journal history is unverifiable; binary replacement refused")
	}
	for _, path := range paths {
		journal, _, err := readNetworkJournal(path, strings.TrimSuffix(filepath.Base(path), ".json"))
		if err != nil {
			return err
		}
		switch journal.Phase {
		case "committed", "rolled_back", "superseded", "expired":
		default:
			return errors.New("pending network-control recovery requires the existing binary")
		}
	}
	return nil
}
