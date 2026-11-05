package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// RHEL 8 rejects the transient RestartPreventExitStatus property. Keep retry
// supervision in this fixed script instead: preserve the helper's success path,
// while an inactive/unreadable review remains a visible exit-3 failure.
// The executable and journal are positional arguments, never shell source.
const configurationRollbackSupervisor = `while :; do
    "$@"
    result=$?
    case "$result" in
        0) exit 0 ;;
        3) echo 'Configuration rollback refused; no restoration was performed. Inspect the active review and recovery journal.' >&2; exit 3 ;;
    esac
    echo "Configuration rollback failed (exit $result); retrying in 3 seconds." >&2
    /bin/sleep 3
    delay_result=$?
    if [ "$delay_result" -ne 0 ]; then
        echo "Configuration rollback retry delay failed (exit $delay_result); recovery is incomplete." >&2
        kill -KILL "$$"
        exit 125
    fi
done`

func armConfigurationWatchdog(ctx context.Context, commands CommandRunner, unit, executable, journalPath string) error {
	// systemd 239 disallows restart supervision on Type=oneshot. A simple
	// service keeps this independent retry process supervised until it exits.
	// systemd expands dollars in ExecStart arguments before /bin/sh sees them.
	// Escaping fixed source here preserves both shell variables and its $$ PID.
	script := strings.ReplaceAll(configurationRollbackSupervisor, "$", "$$")
	_, err := commands.Run(ctx, "systemd-run", "--unit="+unit, "--on-active=90s", "--timer-property=AccuracySec=1s", "--property=Type=simple", "--property=Restart=on-abnormal", "--property=RestartSec=3s", "--property=StartLimitIntervalSec=0", "--property=TimeoutStartSec=0", "/bin/sh", "-c", script, "prthak-configuration-watchdog", executable, "--rollback-configuration", journalPath)
	if err != nil {
		return fmt.Errorf("independent configuration rollback timer was not armed: %w", err)
	}
	active, err := commands.Run(ctx, "systemctl", "is-active", unit+".timer")
	if err != nil || strings.TrimSpace(active) != "active" {
		// No ordinary service or configuration has changed yet. The caller
		// records not_started and clears the generation pointer on this error.
		_, _ = commands.Run(context.Background(), "systemctl", "stop", unit+".timer", unit+".service")
		return errors.New("independent configuration rollback timer could not be verified active")
	}
	return nil
}
