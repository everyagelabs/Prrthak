//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const commandSupervisorArgument = "--microseg-private-command-supervisor"
const commandSupervisorParent = "MICROSEG_PRIVATE_COMMAND_PARENT"
const commandSupervisorLease = "MICROSEG_PRIVATE_COMMAND_LEASE"

// The supervisor runs from this same executable, including in tests. Its only
// entry point is this private argv/environment pair; no agent startup, recovery
// or command-line processing runs inside it.
func init() {
	if len(os.Args) < 3 || os.Args[1] != commandSupervisorArgument || os.Getenv(commandSupervisorParent) == "" {
		return
	}
	code, err := superviseCommand(os.Args[2], os.Args[3:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "command supervisor:", err)
	}
	os.Exit(code)
}

func fencedCommand(ctx context.Context, lease *os.File, name string, args ...string) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, append([]string{commandSupervisorArgument, name}, args...)...)
	cmd.Env = append(os.Environ(), commandSupervisorParent+"="+strconv.Itoa(os.Getpid()), commandSupervisorLease+"=0")
	if lease != nil {
		owned, err := duplicateCommandLease(lease)
		if err != nil {
			return nil, fmt.Errorf("retain command enforcement lease: %w", err)
		}
		// This object belongs to the command. The owner may Close its own
		// *os.File concurrently without racing StartProcess's Fd access.
		cmd.ExtraFiles = []*os.File{owned}
		cmd.Env = append(cmd.Env, commandSupervisorLease+"=1")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	// Do not use CommandContext's default SIGKILL: the helper must retain its
	// lease until even detached grandchildren have been killed and reaped.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	return cmd, nil
}

func duplicateCommandLease(lease *os.File) (*os.File, error) {
	raw, err := lease.SyscallConn()
	if err != nil {
		return nil, err
	}
	descriptor := -1
	var duplicateErr error
	// Control keeps the original descriptor alive against concurrent Close.
	// Atomic CLOEXEC avoids leaking the new reference into unrelated execs.
	err = raw.Control(func(source uintptr) {
		for {
			duplicate, _, errno := syscall.Syscall(syscall.SYS_FCNTL, source, syscall.F_DUPFD_CLOEXEC, 3)
			if errno == syscall.EINTR {
				continue
			}
			if errno != 0 {
				duplicateErr = errno
			} else {
				descriptor = int(duplicate)
			}
			return
		}
	})
	if err != nil || duplicateErr != nil {
		if descriptor >= 0 {
			_ = syscall.Close(descriptor)
		}
		if err != nil {
			return nil, err
		}
		return nil, duplicateErr
	}
	return os.NewFile(uintptr(descriptor), "command-enforcement-lease"), nil
}

func runFencedCommand(cmd *exec.Cmd) error {
	// Linux delivers Pdeathsig when the thread which created the helper exits.
	// Keep that runtime thread alive for the whole owned command lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// fencedCommand gives each ExtraFiles entry independent ownership. Close
	// on every Run result, including failed/canceled Start, after the helper
	// has drained its tree. Close only: LOCK_UN would unlock inherited copies.
	defer func() {
		for _, owned := range cmd.ExtraFiles {
			_ = owned.Close()
		}
	}()
	return cmd.Run()
}

func superviseCommand(name string, args []string) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	parent, err := strconv.Atoi(os.Getenv(commandSupervisorParent))
	if err != nil || parent < 1 {
		return 125, errors.New("invalid command owner")
	}
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(terms)
	// PR_SET_CHILD_SUBREAPER makes double-forked or setsid descendants our
	// children when their parents die. Process groups alone cannot fence them.
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 36, 1, 0, 0, 0, 0); errno != 0 {
		return 125, fmt.Errorf("enable child subreaper: %w", errno)
	}
	// Parent death before signal.Notify is harmless: no command has started.
	// Recheck after installing the handler to close the startup race.
	if os.Getppid() != parent {
		return 125, errors.New("command owner exited before startup")
	}
	select {
	case <-terms:
		return 125, errors.New("command owner canceled before startup")
	default:
	}
	var lease *os.File
	if os.Getenv(commandSupervisorLease) == "1" {
		lease = os.NewFile(3, "enforcement-mutation-lease")
		if lease == nil {
			return 125, errors.New("missing inherited enforcement lease")
		}
		defer lease.Close()
	}
	child := exec.Command(name, args...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = cleanSupervisorEnvironment()
	child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if lease != nil {
		child.ExtraFiles = []*os.File{lease}
	}
	if err := child.Start(); err != nil {
		return 125, err
	}
	defer child.Process.Release()
	return drainCommandTree(child.Process.Pid, terms)
}

func cleanSupervisorEnvironment() []string {
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, commandSupervisorParent+"=") && !strings.HasPrefix(value, commandSupervisorLease+"=") {
			env = append(env, value)
		}
	}
	return env
}

func drainCommandTree(commandPID int, terms <-chan os.Signal) (int, error) {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	draining, code := false, 125
	for {
		// Only this goroutine reaps children. A PID read from our children list
		// cannot be reused before we reap it, so no unrelated process is killed.
		if draining {
			// Retain the lease and retry even if /proc cannot be read. Avoid
			// diagnostics on this path: a closed output pipe must not terminate
			// the supervisor before it has drained all descendants.
			_ = killSupervisorChildren()
		}
		for {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.ECHILD {
				return code, nil
			}
			if err != nil {
				// Fail closed: do not release the lease while child state is
				// uncertain. EINTR/ECHILD are the ordinary wait transitions.
				draining = true
				break
			}
			if pid == 0 {
				break
			}
			if pid == commandPID {
				if !draining {
					if status.Exited() {
						code = status.ExitStatus()
					} else if status.Signaled() {
						code = 128 + int(status.Signal())
					}
				}
				// A successful command may leave grandchildren behind. Drain
				// those before reporting its original exit status to the owner.
				draining = true
			}
		}
		select {
		case <-terms:
			draining = true
			code = 124
		case <-deadline.C:
			draining = true
			code = 124
		case <-tick.C:
		}
	}
}

func killSupervisorChildren() error {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	for _, task := range tasks {
		raw, err := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "children"))
		if os.IsNotExist(err) { // A runtime thread can exit between the reads.
			continue
		}
		if err != nil {
			return err
		}
		for _, value := range strings.Fields(string(raw)) {
			pid, err := strconv.Atoi(value)
			if err != nil || pid < 1 {
				return errors.New("invalid supervisor child PID")
			}
			if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
				return err
			}
		}
	}
	return nil
}
