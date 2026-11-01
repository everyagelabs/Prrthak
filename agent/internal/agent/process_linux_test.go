//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const fenceFixtureMode = "MICROSEG_FENCE_TEST_MODE"
const fenceFixtureDir = "MICROSEG_FENCE_TEST_DIRECTORY"

// Only disposable subprocesses of the test executable enter these branches.
// The delayed writer calls setsid and closes any inherited lease descriptor,
// exercising the boundary which a process-group/FD-only fence misses.
func TestCommandFenceHelperProcess(t *testing.T) {
	mode, directory := os.Getenv(fenceFixtureMode), os.Getenv(fenceFixtureDir)
	if mode == "" {
		t.Skip("private subprocess fixture")
	}
	if directory == "" {
		t.Fatal("missing fixture directory")
	}
	switch mode {
	case "owner":
		lock, err := managedLock(directory, true)
		if err != nil {
			t.Fatal(err)
		}
		defer unlockManaged(lock)
		os.Setenv(fenceFixtureMode, "target")
		_, err = (ExecRunner{}).Run(withManagedLease(context.Background(), lock), os.Args[0], "-test.run=^TestCommandFenceHelperProcess$")
		if err != nil {
			t.Fatal(err)
		}
	case "target", "exit-with-leaf":
		leaf := exec.Command(os.Args[0], "-test.run=^TestCommandFenceHelperProcess$")
		leaf.Env = append(os.Environ(), fenceFixtureMode+"=leaf")
		leaf.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := leaf.Start(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "target-pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		if mode == "exit-with-leaf" {
			waitFenceFile(t, filepath.Join(directory, "leaf-pid"))
			return
		}
		// The supervisor, not this test helper, owns descendant cleanup.
		for {
			time.Sleep(time.Second)
		}
	case "leaf":
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			link, _ := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if link == filepath.Join(managedDirectory(directory), "lock") {
				// A daemonizing child can close inherited descriptors. The
				// supervisor must retain authority over it through ancestry.
				fd, err := strconv.Atoi(entry.Name())
				if err != nil {
					t.Fatal(err)
				}
				if err := syscall.Close(fd); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := os.WriteFile(filepath.Join(directory, "leaf-pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		// A gate immediately before the side effect proves no late mutation can
		// occur after compensation even when the delayed action is released.
		for limit := time.Now().Add(30 * time.Second); time.Now().Before(limit); {
			if _, err := os.Stat(filepath.Join(directory, "release")); err == nil {
				if err := os.WriteFile(filepath.Join(directory, "mutation"), []byte("late mutation"), 0600); err != nil {
					t.Fatal(err)
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	default:
		t.Fatal("invalid fixture mode")
	}
}

func waitFenceFile(t *testing.T, path string) []byte {
	t.Helper()
	for limit := time.Now().Add(5 * time.Second); time.Now().Before(limit); {
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			return raw
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fixture did not reach gate: %s", path)
	return nil
}

func assertFenceProcessGone(t *testing.T, directory, name string) {
	t.Helper()
	pid, err := strconv.Atoi(string(waitFenceFile(t, filepath.Join(directory, name+"-pid"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("owned %s PID %d remains at compensation boundary: %v", name, pid, err)
	}
}

func TestExecRunnerCanceledTreeDrainsDetachedGrandchild(t *testing.T) {
	directory := t.TempDir()
	t.Setenv(fenceFixtureDir, directory)
	t.Setenv(fenceFixtureMode, "target")
	lock, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lock)
	ctx, cancel := context.WithCancel(withManagedLease(context.Background(), lock))
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := (ExecRunner{}).Run(ctx, os.Args[0], "-test.run=^TestCommandFenceHelperProcess$")
		finished <- err
	}()
	waitFenceFile(t, filepath.Join(directory, "leaf-pid"))
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled command succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not drain canceled command")
	}
	assertFenceProcessGone(t, directory, "target")
	assertFenceProcessGone(t, directory, "leaf")
}

func TestExecRunnerSuccessfulParentDrainsDetachedGrandchild(t *testing.T) {
	directory := t.TempDir()
	t.Setenv(fenceFixtureDir, directory)
	t.Setenv(fenceFixtureMode, "exit-with-leaf")
	if out, err := (ExecRunner{}).Run(context.Background(), os.Args[0], "-test.run=^TestCommandFenceHelperProcess$"); err != nil {
		t.Fatalf("success became failure: %s: %v", out, err)
	}
	assertFenceProcessGone(t, directory, "target")
	assertFenceProcessGone(t, directory, "leaf")
}

func TestManagedLeaseSurvivesOwnerCloseUntilTreeDrained(t *testing.T) {
	directory := t.TempDir()
	t.Setenv(fenceFixtureDir, directory)
	t.Setenv(fenceFixtureMode, "target")
	lock, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lock)
	ctx, cancel := context.WithCancel(withManagedLease(context.Background(), lock))
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := (ExecRunner{}).Run(ctx, os.Args[0], "-test.run=^TestCommandFenceHelperProcess$")
		finished <- err
	}()
	waitFenceFile(t, filepath.Join(directory, "leaf-pid"))
	unlockManaged(lock)
	if acquired, err := managedLock(directory, true); err == nil {
		unlockManaged(acquired)
		t.Fatal("owner close explicitly unlocked a still-live command tree")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not drain after owner released its lease reference")
	}
	assertFenceProcessGone(t, directory, "target")
	assertFenceProcessGone(t, directory, "leaf")
	acquired, err := managedLock(directory, true)
	if err != nil {
		t.Fatalf("drained tree retained enforcement lease: %v", err)
	}
	unlockManaged(acquired)
}

func TestFencedCommandOwnsLeaseBeforeStartAndReleasesAfterRun(t *testing.T) {
	directory := t.TempDir()
	lock, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lock)
	cmd, err := fencedCommand(context.Background(), lock, "/bin/sh", "-c", "test -e /proc/self/fd/3")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] == lock {
		t.Fatal("command reused owner's file object")
	}
	owned := cmd.ExtraFiles[0]
	t.Cleanup(func() { _ = owned.Close() })
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, owned.Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("parent duplicate can leak into unrelated exec", errno)
	}
	unlockManaged(lock)
	if acquired, err := managedLock(directory, true); err == nil {
		unlockManaged(acquired)
		t.Fatal("unstarted command lost its lease reference")
	}
	if err := runFencedCommand(cmd); err != nil {
		t.Fatal("command could not start after owner closed", err)
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("parent command descriptor was not closed", err)
	}
	acquired, err := managedLock(directory, true)
	if err != nil {
		t.Fatal("finished command retained its lease", err)
	}
	unlockManaged(acquired)
}

func TestFencedCommandFailedStartReleasesOwnedLease(t *testing.T) {
	directory := t.TempDir()
	lock, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, err := fencedCommand(ctx, lock, "/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	owned := cmd.ExtraFiles[0]
	t.Cleanup(func() { _ = owned.Close() })
	unlockManaged(lock)
	cancel()
	if err := runFencedCommand(cmd); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled Start did not fail", err)
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("failed Start leaked its descriptor", err)
	}
	acquired, err := managedLock(directory, true)
	if err != nil {
		t.Fatal("failed Start retained lease", err)
	}
	unlockManaged(acquired)
}

func TestFencedCommandConcurrentLeaseCloseFailsClosed(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		directory := t.TempDir()
		lock, err := managedLock(directory, true)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		start := make(chan struct{})
		closed := make(chan struct{})
		go func() { <-start; unlockManaged(lock); close(closed) }()
		close(start)
		cmd, err := fencedCommand(ctx, lock, "/usr/bin/touch", filepath.Join(directory, "must-not-run"))
		<-closed
		cancel()
		if err != nil {
			// RawConn.Control can return the poller's private closed-file
			// error, rather than os.ErrClosed. Either must fail before any
			// command is returned; the lock/marker checks below stay exact.
			if cmd != nil {
				t.Fatal("closing source returned a partially fenced command", err)
			}
		} else {
			if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] == lock {
				t.Fatal("concurrent close yielded an unfenced command")
			}
			if acquired, err := managedLock(directory, true); err == nil {
				unlockManaged(acquired)
				t.Fatal("constructed command lacks live lease")
			}
			if err := runFencedCommand(cmd); !errors.Is(err, context.Canceled) {
				t.Fatal("canceled command executed", err)
			}
			if _, err := cmd.ExtraFiles[0].Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("canceled command leaked descriptor", err)
			}
		}
		if _, err := os.Stat(filepath.Join(directory, "must-not-run")); !os.IsNotExist(err) {
			t.Fatal("closed/canceled command executed without authority")
		}
		acquired, err := managedLock(directory, true)
		if err != nil {
			t.Fatal("concurrent close retained lease", err)
		}
		unlockManaged(acquired)
	}
}

func TestFencedCommandExecutableStartFailureClosesOwnedLease(t *testing.T) {
	directory := t.TempDir()
	lock, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lock)
	cmd, err := fencedCommand(context.Background(), lock, "/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	owned := cmd.ExtraFiles[0]
	t.Cleanup(func() { _ = owned.Close() })
	unlockManaged(lock)
	cmd.Path = filepath.Join(directory, "nonexistent-supervisor")
	if err := runFencedCommand(cmd); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing executable did not fail Start", err)
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("failed exec leaked its owned descriptor", err)
	}
	acquired, err := managedLock(directory, true)
	if err != nil {
		t.Fatal("failed exec retained lease", err)
	}
	unlockManaged(acquired)
	if invalid, err := fencedCommand(context.Background(), lock, "/bin/true"); err == nil || invalid != nil {
		t.Fatal("closed owner produced an unfenced command", err)
	}
}

type fenceCompensationRunner struct {
	t         *testing.T
	directory string
}

func (r fenceCompensationRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name != "firewall-cmd" || managedLeaseFromContext(ctx) == nil {
		return "", errors.New("compensation command did not inherit its enforcement lease")
	}
	assertFenceProcessGone(r.t, r.directory, "target")
	assertFenceProcessGone(r.t, r.directory, "leaf")
	for _, arg := range args {
		if strings.HasPrefix(arg, "--query-rich-rule=") {
			value, err := os.ReadFile(filepath.Join(r.directory, "mutation"))
			if err != nil {
				return "", err
			}
			if string(value) == "baseline restored" {
				return "no", nil
			}
			return "yes", nil
		}
		if strings.HasPrefix(arg, "--remove-rich-rule=") {
			return "success", os.WriteFile(filepath.Join(r.directory, "mutation"), []byte("baseline restored"), 0600)
		}
	}
	return "", fmt.Errorf("unexpected compensation command %v", args)
}

func TestManagedWatchdogDrainsKilledOwnerBeforeCompensation(t *testing.T) {
	directory := t.TempDir()
	owner := exec.Command(os.Args[0], "-test.run=^TestCommandFenceHelperProcess$")
	owner.Env = append(os.Environ(), fenceFixtureMode+"=owner", fenceFixtureDir+"="+directory)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Process.Kill(); _ = owner.Wait() }()
	waitFenceFile(t, filepath.Join(directory, "leaf-pid"))
	if lock, err := managedLock(directory, true); err == nil {
		unlockManaged(lock)
		t.Fatal("fixture owner did not hold enforcement lease")
	}
	if err := os.WriteFile(filepath.Join(directory, "mutation"), []byte("mutation present"), 0600); err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("c", 32)
	rules, err := managedRules(&Policy{Mode: "enforce", Services: []Service{{Port: 18080, Protocol: "tcp", Mode: "enforce", Sources: []string{"10.30.0.0/24"}}}}, Protection{Zone: "public"}, nonce, true)
	if err != nil || len(rules) == 0 {
		t.Fatalf("fixture rules: %v", err)
	}
	journal := &managedJournal{Nonce: nonce, Phase: "staging", PID: owner.Process.Pid, ProcessIdentity: processIdentity(owner.Process.Pid), Deadline: time.Now().Add(-time.Second), Mutations: []managedMutation{{Scope: "runtime", Zone: rules[0].Zone, Rule: rules[0].Rule, Before: false, After: true}}}
	path := managedJournalPath(directory, nonce)
	if journal.ProcessIdentity == "" {
		t.Fatal("fixture owner identity unavailable")
	}
	if err := saveManagedJournal(path, journal); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := RunManagedWatchdog(ctx, path, nonce, fenceCompensationRunner{t, directory}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "release"), []byte("release delayed mutation"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	value, err := os.ReadFile(filepath.Join(directory, "mutation"))
	if err != nil || string(value) != "baseline restored" {
		t.Fatalf("mutation survived compensation: %q %v", value, err)
	}
	loaded, err := readManagedJournal(path, nonce)
	if err != nil || loaded.Phase != "rolled_back" {
		t.Fatalf("rollback was not durably read back: %+v %v", loaded, err)
	}
}
