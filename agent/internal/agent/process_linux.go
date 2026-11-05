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
const commandSupervisorFence = "MICROSEG_PRIVATE_COMMAND_FENCE"
const commandSupervisorFenceNonce = "MICROSEG_PRIVATE_COMMAND_FENCE_NONCE"

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
	return os.NewFile(uintptr(descriptor), lease.Name()), nil
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
	var fence *commandFence
	var path string
	if len(cmd.ExtraFiles) > 0 {
		var err error
		if len(cmd.Args) < 3 || cmd.Args[1] != commandSupervisorArgument {
			return errors.New("invalid private command supervisor invocation")
		}
		fence, path, err = createCommandFenceForCommand(cmd.ExtraFiles[0].Name(), cmd.Args[2], cmd.Args[3:])
		if err != nil {
			return err
		}
		cmd.Env = append(cmd.Env, commandSupervisorFence+"="+path, commandSupervisorFenceNonce+"="+fence.Nonce)
	}
	err := cmd.Run()
	if fence != nil {
		if cmd.Process == nil {
			// StartProcess did not execute a supervisor, so no descendant could
			// have run. An executed supervisor's status is never sufficient.
			if clearErr := clearCommandFence(path, fence.Nonce); clearErr != nil {
				return clearErr
			}
		} else if fenceErr := checkCommandFence(cmd.ExtraFiles[0].Name(), false); fenceErr != nil {
			// Wait has observed this exact supervisor exit, but that alone is
			// never a tree-drain receipt. Preserve its originating command and
			// final observed stage even when the supervisor was killed outright.
			_ = updateCommandDiagnostic(path, fence.Nonce, func(d *commandDiagnostic) {
				d.Stage = "supervisor-exited-unproven"
				d.LastEvidence = "supervisor-exit-without-drain-receipt"
				if d.Supervisor == nil {
					d.Supervisor = &commandProcessDiagnostic{PID: cmd.Process.Pid}
				}
				if cmd.ProcessState != nil {
					code := cmd.ProcessState.ExitCode()
					d.SupervisorExitCode = &code
				}
			})
			return fenceErr
		}
	}
	return err
}

func superviseCommand(name string, args []string) (code int, result error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	parent, err := strconv.Atoi(os.Getenv(commandSupervisorParent))
	if err != nil || parent < 1 {
		return 125, errors.New("invalid command owner")
	}
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(terms)
	var diagnosticPath, diagnosticNonce string
	if os.Getenv(commandSupervisorLease) == "1" {
		path, nonce := os.Getenv(commandSupervisorFence), os.Getenv(commandSupervisorFenceNonce)
		record, err := readCommandFence(path)
		if err != nil || record.Nonce != nonce || record.OwnerPID != parent {
			return 125, errUncertainCommand
		}
		diagnosticPath, diagnosticNonce = path, nonce
		defer func() {
			// SIGKILL cannot run this defer: its durable record survives even
			// if every descendant closes all inherited lease descriptors.
			if !commandTreeProvenDrained() {
				_ = updateCommandDiagnostic(path, nonce, func(d *commandDiagnostic) {
					d.Stage, d.LastEvidence = "drain-unproven", "kernel-echild-unproven"
				})
				code, result = 125, errUncertainCommand
			} else if err := clearCommandFence(path, nonce); err != nil {
				code, result = 125, err
			}
		}()
		if record.OwnerIdentity != processIdentity(parent) {
			// No command was started; the defer still requires kernel ECHILD
			// before retiring this exact never-executed startup reservation.
			return 125, errors.New("command owner exited before startup")
		}
		if err := updateCommandDiagnostic(path, nonce, func(d *commandDiagnostic) {
			d.Supervisor = commandProcessIdentity(os.Getpid())
			d.Stage = "supervisor-started"
		}); err != nil {
			// No worker has started. The defer still requires kernel proof
			// before retiring the reservation; diagnostics grant no authority.
			return 125, errors.New("cannot persist command supervisor identity")
		}
	}
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
	var diagnosticErr error
	if diagnosticPath != "" {
		diagnosticErr = updateCommandDiagnostic(diagnosticPath, diagnosticNonce, func(d *commandDiagnostic) {
			d.Worker = commandProcessIdentity(child.Process.Pid)
			d.Stage, d.LastEvidence = "worker-running", "worker-started"
		})
		if diagnosticErr != nil {
			// The worker may already have run. Retain the independent helper
			// and drain it normally instead of returning past a live subtree.
			select {
			case terms <- syscall.SIGTERM:
			default: // An existing cancellation already requests the same drain.
			}
		}
	}
	noteDrain := func(reason string) {
		if diagnosticPath == "" {
			return
		}
		_ = updateCommandDiagnostic(diagnosticPath, diagnosticNonce, func(d *commandDiagnostic) {
			d.Stage, d.LastEvidence = "draining", reason
			if d.DrainStartedAt == "" {
				d.DrainStartedAt = time.Now().UTC().Format(time.RFC3339Nano)
				d.DrainReason = reason
			}
		})
	}
	if diagnosticErr != nil {
		noteDrain("diagnostic-write-failed")
	}
	code, result = drainCommandTree(child.Process.Pid, terms, noteDrain)
	if diagnosticErr != nil {
		return 125, errors.New("command worker diagnostic failed; worker tree drained")
	}
	return code, result
}

func cleanSupervisorEnvironment() []string {
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, commandSupervisorParent+"=") && !strings.HasPrefix(value, commandSupervisorLease+"=") && !strings.HasPrefix(value, commandSupervisorFence+"=") && !strings.HasPrefix(value, commandSupervisorFenceNonce+"=") {
			env = append(env, value)
		}
	}
	return env
}

func drainCommandTree(commandPID int, terms <-chan os.Signal, noteDrain func(string)) (int, error) {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	draining, code, workerReaped := false, 125, false
	reportedEvidence := map[string]bool{}
	note := func(evidence string) {
		if !reportedEvidence[evidence] {
			noteDrain(evidence)
			reportedEvidence[evidence] = true
		}
	}
	for {
		// Only this goroutine reaps children. A PID read from our children list
		// cannot be reused before we reap it, so no unrelated process is killed.
		if draining {
			// Retain the lease and retry even if /proc cannot be read. Avoid
			// diagnostics on this path: a closed output pipe must not terminate
			// the supervisor before it has drained all descendants.
			if err := killSupervisorChildren(); err != nil {
				note("children-signal-failed")
			}
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
				note("wait-failed")
				break
			}
			if pid == 0 {
				break
			}
			if pid == commandPID {
				workerReaped = true
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
				// Normal short-lived commands need no extra drain I/O. Their
				// fence is removed only after ECHILD, as before.
			}
		}
		if workerReaped {
			// Persist normal worker exit only if children still remain. A
			// successful command with no descendants returns at ECHILD above.
			note("worker-exited")
		}
		select {
		case <-terms:
			draining = true
			code = 124
			note("owner-canceled")
		case <-deadline.C:
			draining = true
			code = 124
			note("deadline-expired")
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
