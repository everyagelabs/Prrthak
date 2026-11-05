package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestConfigurationWatchdogUsesRHEL8CompatiblePropertiesAndVerifiesTimer(t *testing.T) {
	unit := "prthak-config-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	journal := "/var/lib/seg-agent/configuration-transitions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.json"
	var calls [][]string
	runner := &fakeRunner{fn: func(name string, args []string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "systemd-run" {
			// Saved RHEL 8 isolation: the otherwise identical transient timer
			// succeeds until this property is included, then returns EINVAL.
			if strings.Contains(strings.Join(args, " "), "RestartPreventExitStatus") {
				return "Failed to create bus message: Invalid argument", errors.New("exit status 1")
			}
			return "Running timer as unit: " + unit + ".timer", nil
		}
		if reflect.DeepEqual(args, []string{"is-active", unit + ".timer"}) {
			return "active\n", nil
		}
		return "", errors.New("unexpected command")
	}}
	if err := armConfigurationWatchdog(context.Background(), runner, unit, "/usr/local/bin/seg-agent", journal); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0][0] != "systemd-run" || !reflect.DeepEqual(calls[1], []string{"systemctl", "is-active", unit + ".timer"}) {
		t.Fatal("independent timer not armed and read back before returning", calls)
	}
	for _, flag := range []string{"--on-active=90s", "--timer-property=AccuracySec=1s", "--property=Type=simple", "--property=Restart=on-abnormal", "--property=RestartSec=3s", "--property=StartLimitIntervalSec=0", "--property=TimeoutStartSec=0"} {
		if !slices.Contains(calls[0], flag) {
			t.Fatal("missing bounded independent watchdog property", flag, calls)
		}
	}
	command := calls[0][len(calls[0])-7:]
	if !reflect.DeepEqual(command, []string{"/bin/sh", "-c", strings.ReplaceAll(configurationRollbackSupervisor, "$", "$$"), "prthak-configuration-watchdog", "/usr/local/bin/seg-agent", "--rollback-configuration", journal}) {
		t.Fatal("watchdog parameters were interpolated into shell source", command)
	}
	if strings.ReplaceAll(command[2], "$$", "$") != configurationRollbackSupervisor || strings.Contains(command[2], "%") {
		t.Fatal("one manager expansion did not recover the exact fixed shell source")
	}
}

func TestConfigurationWatchdogDelayFailureRemainsAbnormalAndRecoverable(t *testing.T) {
	// Inject only the fixed delay executable so this negative path does not
	// depend on breaking the host's real /bin/sleep or waiting three seconds.
	script := strings.Replace(configurationRollbackSupervisor, "/bin/sleep 3", "/usr/bin/false", 1)
	command := exec.Command("/bin/sh", "-c", script, "prthak-configuration-watchdog", "/usr/bin/false")
	output, err := command.CombinedOutput()
	var failed *exec.ExitError
	if !errors.As(err, &failed) || failed.ExitCode() != -1 || !strings.Contains(string(output), "retry delay failed") {
		t.Fatal("delay failure did not retain abnormal restart supervision", err, string(output))
	}
	status, ok := failed.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("delay failure cannot trigger systemd on-abnormal restart", failed.ProcessState)
	}
}

func TestConfigurationWatchdogMissingOrUnreadableReviewNeverRestoresOrReportsSuccess(t *testing.T) {
	for _, mode := range []string{"missing", "invalid", "public"} {
		t.Run(mode, func(t *testing.T) {
			root, journal, _ := configurationRestartFixture(t)
			pointer := root + "/var/lib/seg-agent/configuration-transitions/active"
			switch mode {
			case "missing":
				if err := os.Remove(pointer); err != nil {
					t.Fatal(err)
				}
			case "invalid":
				if err := os.WriteFile(pointer, []byte("unreadable review JSON"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(pointer, 0644); err != nil {
					t.Fatal(err)
				}
			}
			commands := &configurationCommands{}
			path := "/var/lib/seg-agent/configuration-transitions/" + journal.ReviewID + ".json"
			if err := rollbackEndpointConfigurationUnder(root, path, commands); !errors.Is(err, ErrStaleConfigurationReview) {
				t.Fatal("unproven review was reported restored", err)
			}
			current, _ := os.ReadFile(root + journal.ConfigPath)
			fresh, err := configurationJournalReadUnder(root, path)
			if err != nil || fresh.Status != "armed" || string(current) != string(journal.CandidateConfig) || len(commands.calls) != 0 {
				t.Fatal("refused rollback modified live files or its journal", fresh, commands.calls, err)
			}
		})
	}
}

func TestConfigurationWatchdogNeverAcceptsFailedArmingOrUnverifiedTimer(t *testing.T) {
	for _, test := range []struct {
		name, active    string
		armErr, readErr error
	}{
		{name: "native rejection", armErr: errors.New("Failed to create bus message: Invalid argument")},
		{name: "inactive timer", active: "inactive"},
		{name: "failed timer", active: "failed"},
		{name: "readback error", active: "active", readErr: errors.New("systemd unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls [][]string
			runner := &fakeRunner{fn: func(name string, args []string) (string, error) {
				calls = append(calls, append([]string{name}, args...))
				if name == "systemd-run" {
					return "", test.armErr
				}
				if len(args) > 0 && args[0] == "is-active" {
					return test.active, test.readErr
				}
				return "", nil
			}}
			if err := armConfigurationWatchdog(context.Background(), runner, "prthak-config-test", "/usr/local/bin/seg-agent", "/protected/journal.json"); err == nil {
				t.Fatal("unverified rollback authority allowed a configuration transition")
			}
			if test.armErr != nil && len(calls) != 1 {
				t.Fatal("native arming error triggered a weaker retry/fallback", calls)
			}
			for _, call := range calls {
				if slices.Contains(call, "seg-agent.service") {
					t.Fatal("failed arming touched the ordinary agent service", calls)
				}
			}
		})
	}
}

const configurationSupervisorFixture = `#!/bin/sh
count=0
if [ -f "$WATCHDOG_CALLS" ]; then IFS= read -r count < "$WATCHDOG_CALLS"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$WATCHDOG_CALLS"
printf '%s\n' "$@" > "$WATCHDOG_ARGUMENTS"
case "$WATCHDOG_MODE:$count" in
    success:*) exit 0 ;;
    refuse:*) exit 3 ;;
    transient:1|transient-refuse:1) exit 1 ;;
    transient:*) exit 0 ;;
    transient-refuse:*) exit 3 ;;
esac
exit 7
`

func TestConfigurationWatchdogSupervisorRetainsTerminalFailuresAndRetriesRealErrors(t *testing.T) {
	for _, test := range []struct {
		mode                string
		wantExit, wantCalls int
	}{
		{"success", 0, 1}, {"refuse", 3, 1}, {"transient", 0, 2}, {"transient-refuse", 3, 2},
	} {
		t.Run(test.mode, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			helper := filepath.Join(directory, "agent with spaces; $(not-a-command)")
			if err := os.WriteFile(helper, []byte(configurationSupervisorFixture), 0700); err != nil {
				t.Fatal(err)
			}
			calls, arguments := filepath.Join(directory, "calls"), filepath.Join(directory, "arguments")
			journal := filepath.Join(directory, "journal; $(touch SHOULD_NOT_EXIST).json")
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/sh", "-c", configurationRollbackSupervisor, "prthak-configuration-watchdog", helper, "--rollback-configuration", journal)
			command.Env = append(os.Environ(), "WATCHDOG_MODE="+test.mode, "WATCHDOG_CALLS="+calls, "WATCHDOG_ARGUMENTS="+arguments)
			output, err := command.CombinedOutput()
			exit := 0
			if err != nil {
				var failed *exec.ExitError
				if !errors.As(err, &failed) {
					t.Fatal(err)
				}
				exit = failed.ExitCode()
			}
			if exit != test.wantExit {
				t.Fatalf("rollback supervisor changed the result: exit=%d want=%d output=%s", exit, test.wantExit, output)
			}
			count, _ := os.ReadFile(calls)
			if string(count) != strconv.Itoa(test.wantCalls)+"\n" {
				t.Fatal("wrong rollback retry count", string(count), test.wantCalls)
			}
			actual, _ := os.ReadFile(arguments)
			if string(actual) != "--rollback-configuration\n"+journal+"\n" {
				t.Fatal("rollback journal was interpreted as shell source", string(actual))
			}
			if test.wantExit == 3 && !strings.Contains(string(output), "refused; no restoration was performed") {
				t.Fatal("refused rollback lacks an explicit non-success diagnostic", string(output))
			}
			if test.wantCalls > 1 && !strings.Contains(string(output), "retrying in 3 seconds") {
				t.Fatal("recoverable failure did not retain retry supervision", string(output))
			}
		})
	}
}

func TestConfigurationWatchdogMissingExecutableNeverReportsSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", configurationRollbackSupervisor, "prthak-configuration-watchdog", "/not-installed/seg-agent", "--rollback-configuration", "/protected/journal.json")
	command.WaitDelay = 100 * time.Millisecond
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "failed (exit 127)") {
		t.Fatal("missing rollback executable was treated as a successful restore", err, string(output))
	}
}
