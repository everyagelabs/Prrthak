//go:build linux

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUncertainCommandFenceBlocksSameBootEvenAfterOwnerDisappears(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	record, path, err := createCommandFence(lease.Name())
	if err != nil {
		t.Fatal(err)
	}
	unlockManaged(lease)
	// Missing owner/supervisor PIDs are never a substitute for tree drainage.
	record.OwnerPID = 2147483647
	if err = atomicJSON(path, record); err != nil {
		t.Fatal(err)
	}
	if next, err := managedLock(directory, true); !errors.Is(err, errUncertainCommand) {
		if next != nil {
			unlockManaged(next)
		}
		t.Fatal("unlocked inode or absent owner incorrectly cleared uncertainty", err)
	}
	if err = CheckEnforcementUpgradeSafety(Config{StateDir: directory}); !errors.Is(err, errUncertainCommand) {
		t.Fatal("upgrade ignored unresolved command fence", err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("refused recovery discarded durable fence", err)
	}
}

func TestUncertainCommandFenceRefusesSameOwnerRetryAndWrongNonce(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lease)
	record, path, err := createCommandFence(lease.Name())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (ExecRunner{}).Run(withManagedLease(context.Background(), lease), "/usr/bin/touch", filepath.Join(directory, "must-not-run")); !errors.Is(err, errUncertainCommand) {
		t.Fatal("same owner compensation bypassed its unresolved command", err)
	}
	if err = clearCommandFence(path, strings.Repeat("a", 32)); !errors.Is(err, errUncertainCommand) {
		t.Fatal("wrong supervisor nonce cleared fence", err)
	}
	if _, err = os.Stat(filepath.Join(directory, "must-not-run")); !os.IsNotExist(err) {
		t.Fatal("uncertain retry executed", err)
	}
	actual, err := readCommandFence(path)
	if err != nil || actual.Nonce != record.Nonce {
		t.Fatal("retry changed the predecessor fence", err)
	}
}

func TestPreviousBootCommandFenceCanBeRetiredBeforeRecovery(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	record, path, err := createCommandFence(lease.Name())
	if err != nil {
		t.Fatal(err)
	}
	unlockManaged(lease)
	// Simulates a durable fence loaded after a verified different kernel boot;
	// no PID comparison, elapsed-time heuristic or process death is accepted.
	record.BootID = "00000000-0000-0000-0000-000000000000"
	record.OwnerIdentity = record.BootID + ":1"
	if err = atomicJSON(path, record); err != nil {
		t.Fatal(err)
	}
	if err = CheckEnforcementUpgradeSafety(Config{StateDir: directory}); err != nil {
		t.Fatal("read-only upgrade rejected a previous boot", err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("read-only upgrade check mutated the fence", err)
	}
	next, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(next)
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("new boot did not durably retire prior uncertainty", err)
	}
}

func TestCorruptOrAliasedCommandFenceFailsClosed(t *testing.T) {
	for _, kind := range []string{"truncated", "oversize", "public", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			lease, err := managedLock(directory, true)
			if err != nil {
				t.Fatal(err)
			}
			_, path, err := createCommandFence(lease.Name())
			if err != nil {
				t.Fatal(err)
			}
			unlockManaged(lease)
			switch kind {
			case "truncated":
				err = os.WriteFile(path, []byte("{"), 0600)
			case "oversize":
				err = os.WriteFile(path, []byte(strings.Repeat("x", 2049)), 0600)
			case "public":
				err = os.Chmod(path, 0644)
			case "symlink":
				err = os.Rename(path, path+".actual")
				if err == nil {
					err = os.Symlink(path+".actual", path)
				}
			case "hardlink":
				err = os.Link(path, path+".alias")
			}
			if err != nil {
				t.Fatal(err)
			}
			if next, err := managedLock(directory, true); !errors.Is(err, errUncertainCommand) {
				if next != nil {
					unlockManaged(next)
				}
				t.Fatal("invalid persistent fence admitted recovery", err)
			}
		})
	}
}

func TestExecutedCommandFailureClearsFenceOnlyAfterDrain(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lease)
	if _, err = (ExecRunner{}).Run(withManagedLease(context.Background(), lease), "/bin/sh", "-c", "exit 7"); err == nil {
		t.Fatal("failed command succeeded")
	}
	if err = checkCommandFence(lease.Name(), false); err != nil {
		t.Fatal("proven drained nonzero command left uncertainty", err)
	}
}

func TestUncertainCommandRefusesEvenEmptyDirectCompensationWithoutTerminalReceipt(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lease)
	if _, _, err = createCommandFence(lease.Name()); err != nil {
		t.Fatal(err)
	}
	ctx := withManagedLease(context.Background(), lease)
	runner := &refusedCompensationRunner{}
	journal := &managedJournal{Nonce: strings.Repeat("b", 32), Phase: "staging"}
	if err = rollbackManaged(ctx, runner, managedJournalPath(directory, journal.Nonce), journal); !errors.Is(err, errUncertainCommand) {
		t.Fatal("empty managed compensation bypassed uncertainty", err)
	}
	if journal.Phase != "staging" {
		t.Fatal("refused compensation claimed a terminal phase")
	}
	a := &Agent{Config: Config{StateDir: directory}, Commands: runner}
	imported := &firewallJournal{ID: "empty-uncertain", Status: "applying"}
	if err = a.rollbackFirewallJournal(ctx, imported); !errors.Is(err, errUncertainCommand) {
		t.Fatal("empty imported compensation bypassed uncertainty", err)
	}
	if imported.Status != "applying" {
		t.Fatal("refused imported compensation claimed a terminal phase")
	}
	if err = a.recoverAllEnforcementLocked(ctx); !errors.Is(err, errUncertainCommand) {
		t.Fatal("recovery bypassed same-owner uncertainty", err)
	}
	if runner.calls != 0 {
		t.Fatal("refused compensation called a command")
	}
}

type refusedCompensationRunner struct{ calls int }

func (r *refusedCompensationRunner) Run(context.Context, string, ...string) (string, error) {
	r.calls++
	return "", errors.New("compensation must not run before drain proof")
}

func TestSupervisorSIGKILLAndOwnerDeathNeverAdmitLateWriterCompensationRace(t *testing.T) {
	directory := t.TempDir()
	owner := exec.Command(os.Args[0], "-test.run=^TestCommandFenceHelperProcess$")
	owner.Env = append(os.Environ(), fenceFixtureMode+"=owner", fenceFixtureDir+"="+directory)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Process.Kill(); _ = owner.Wait() }()
	leaf, err := strconv.Atoi(string(waitFenceFile(t, filepath.Join(directory, "leaf-pid"))))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(leaf, syscall.SIGKILL)
	target, err := strconv.Atoi(string(waitFenceFile(t, filepath.Join(directory, "target-pid"))))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(target) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(raw[strings.LastIndex(string(raw), ")")+1:]))
	supervisor, err := strconv.Atoi(fields[1])
	if err != nil || supervisor < 2 || supervisor == os.Getpid() {
		t.Fatal("invalid private supervisor PID", supervisor, err)
	}
	nonce := strings.Repeat("d", 32)
	journal := &managedJournal{Nonce: nonce, Phase: "staging", PID: owner.Process.Pid,
		ProcessIdentity: processIdentity(owner.Process.Pid), Deadline: time.Now().Add(-time.Second)}
	path := managedJournalPath(directory, nonce)
	if err = saveManagedJournal(path, journal); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(supervisor, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err = owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = owner.Wait()
	// Prove the old FD-only exclusion really disappeared in this scenario.
	var inode *os.File
	for limit := time.Now().Add(3 * time.Second); time.Now().Before(limit); {
		inode, err = os.OpenFile(filepath.Join(managedDirectory(directory), "lock"), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Flock(int(inode.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		_ = inode.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("fixture did not reproduce lost lease exclusion", err)
	}
	_ = inode.Close()
	if err = syscall.Kill(leaf, 0); err != nil {
		t.Fatal("detached fixture leaf did not survive supervisor", err)
	}
	runner := &refusedCompensationRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = RunManagedWatchdog(ctx, path, nonce, runner); !errors.Is(err, errUncertainCommand) {
		t.Fatal("watchdog failed to preserve durable uncertainty", err)
	}
	if runner.calls != 0 {
		t.Fatal("watchdog compensated while stale writer could still run")
	}
	loaded, err := readManagedJournal(path, nonce)
	if err != nil || loaded.Phase != "staging" {
		t.Fatal("refused rollback incorrectly claimed a terminal state", err)
	}
	// Release the harmless writer after compensation was refused. Its write
	// proves why elapsed time, FD loss and owner death cannot authorize repair.
	if err = os.WriteFile(filepath.Join(directory, "release"), []byte("gate"), 0600); err != nil {
		t.Fatal(err)
	}
	if value := string(waitFenceFile(t, filepath.Join(directory, "mutation"))); value != "late mutation" {
		t.Fatal("delayed-writer fixture did not exercise the uncertain boundary", value)
	}
	if next, err := managedLock(directory, true); !errors.Is(err, errUncertainCommand) {
		if next != nil {
			unlockManaged(next)
		}
		t.Fatal("late writer exit was falsely accepted as full-tree proof", err)
	}
}
