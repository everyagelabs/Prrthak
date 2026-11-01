//go:build !linux

package agent

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

// Managed enforcement requires Linux. Other supported Unix hosts still cancel
// the entire command process group instead of only the immediate child.
func fencedCommand(ctx context.Context, _ *os.File, name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	return cmd, nil
}

func runFencedCommand(cmd *exec.Cmd) error { return cmd.Run() }
