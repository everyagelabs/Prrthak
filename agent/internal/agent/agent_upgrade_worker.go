package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

// The worker is an independently installed copy of the verified initial agent.
// Its executable and manifest do not participate in managed binary replacement.
func agentUpgradeWorkerConfig() (Config, []byte, []byte, error) {
	var c Config
	executable, err := os.Executable()
	if err != nil || executable != upgradeHelper || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return c, nil, nil, errors.New("agent upgrade recovery requires the canonical native root helper")
	}
	c, err = LoadConfig(upgradeConfig, false)
	if err == nil {
		err = ValidateInstallConfig(c)
	}
	if err != nil {
		return c, nil, nil, err
	}
	trust, err := runtimeRead(upgradeTrust, 16384, 0)
	if err != nil {
		return c, nil, nil, err
	}
	unit, err := runtimeRead(upgradeUnit, 65536, 0)
	if err != nil {
		return c, nil, nil, err
	}
	helper, err := runtimeRead(upgradeHelper, upgradeRuntimeLimit, 0)
	if err != nil {
		return c, nil, nil, err
	}
	manifest, err := runtimeRead(upgradeHelperManifest, 65536, 0)
	if err != nil {
		return c, nil, nil, err
	}
	if err = (agentUpgradeRuntime{Binary: helper, Manifest: manifest}).verify(Version, trust, unit); err != nil {
		return c, nil, nil, fmt.Errorf("installed upgrade helper integrity failed: %w", err)
	}
	return c, trust, unit, nil
}

func (j agentUpgradeJournal) confirm(ctx context.Context, c Config) error {
	client, err := NewClient(c, false)
	if err != nil {
		return err
	}
	defer client.HTTP.CloseIdleConnections()
	certificate := client.identity.Load()
	if certificate == nil || certificate.Leaf == nil || certificate.Leaf.Subject.CommonName != j.ServerID {
		return errors.New("agent upgrade identity no longer matches this host")
	}
	policy, _, err := client.Policy(ctx, "")
	if err != nil {
		return err
	}
	if policy == nil || policy.Signature == nil || !policySigningRequired(c) || policy.ServerID != j.ServerID ||
		policy.AssignmentGeneration < j.Generation || (policy.AssignmentGeneration == j.Generation && policy.AssignmentDigest != j.AssignmentDigest) ||
		!validDigest(policy.AssignmentDigest) {
		return errors.New("current signed agent upgrade authority is unavailable")
	}
	if err = ValidatePolicySignature(c, policy); err != nil {
		return err
	}
	assignment := policy.AgentUpgrade
	if assignment == nil || !assignment.ExpiresAt.Equal(j.Assignment.ExpiresAt) || !time.Now().Before(assignment.ExpiresAt) {
		return errors.New("signed upgrade assignment is no longer active")
	}
	// time.Time permits equivalent offsets. Compare the other fields directly.
	received, expected := *assignment, j.Assignment
	received.ExpiresAt, expected.ExpiresAt = time.Time{}, time.Time{}
	if received != expected {
		return errors.New("the active signed upgrade differs from the locally verified package")
	}
	return nil
}

func agentUpgradeSystemctl(ctx context.Context, action string) error {
	command, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// Only fixed internal call sites can select these operations.
	switch action {
	case "stop", "start", "is-active":
		return exec.CommandContext(command, "/usr/bin/systemctl", action, upgradeUnitName).Run()
	default:
		return errors.New("unknown agent upgrade service operation")
	}
}

func (j *agentUpgradeJournal) restore(c Config, trust, unit []byte) error {
	previous, err := readAgentUpgradeRuntime(c, "previous")
	if err != nil {
		return err
	}
	return j.restoreRuntime(c, previous, trust, unit, func() error {
		installed, err := readAgentUpgradeRuntime(c, "")
		if err == nil && bytes.Equal(previous.Binary, installed.Binary) && bytes.Equal(previous.Manifest, installed.Manifest) {
			return nil // The stop was interrupted before any replacement.
		}
		return previous.install()
	})
}

func (j *agentUpgradeJournal) restoreRuntime(c Config, previous agentUpgradeRuntime, trust, unit []byte, install func() error) error {
	if err := previous.verify(j.PreviousVersion, trust, unit); err != nil {
		return fmt.Errorf("previous agent runtime could not be verified: %w", err)
	}
	if err := j.save(c, "rollback_replacing", j.Error); err != nil {
		return err
	}
	if err := install(); err != nil {
		return err
	}
	return j.save(c, "restoring", j.Error)
}

func (j *agentUpgradeJournal) rollback(c Config, trust, unit []byte, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := agentUpgradeSystemctl(ctx, "stop"); err != nil {
		return errors.Join(cause, fmt.Errorf("could not stop the candidate for rollback: %w", err))
	}
	j.Error = cause.Error()
	if err := j.restore(c, trust, unit); err != nil {
		return errors.Join(cause, fmt.Errorf("could not restore the verified previous runtime: %w", err))
	}
	if err := agentUpgradeSystemctl(ctx, "start"); err != nil {
		return errors.Join(cause, fmt.Errorf("could not start the restored agent: %w", err))
	}
	if err := agentUpgradeSystemctl(ctx, "is-active"); err != nil {
		return errors.Join(cause, fmt.Errorf("restored agent is not active: %w", err))
	}
	return j.save(c, "rolled_back", j.Error)
}

func (j agentUpgradeJournal) awaitReady(ctx context.Context, c Config, started time.Time) error {
	ready, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if status, err := ReadReadyStatus(c); err == nil && status.AgentVersion == j.Assignment.Version &&
			status.ServerID == j.ServerID && !status.UpdatedAt.Before(started) {
			if matching, _ := ReadyStatusMatches(c, status, time.Now()); matching {
				if err := agentUpgradeSystemctl(ready, "is-active"); err == nil {
					return nil
				}
			}
		}
		select {
		case <-ready.Done():
			return errors.New("candidate agent did not complete a fresh authenticated report before its deadline")
		case <-ticker.C:
		}
	}
}

// RunAgentUpgrade is called in an independent systemd unit, outside the
// restarted agent's cgroup and read-only mount sandbox.
func RunAgentUpgrade(ctx context.Context) error {
	c, trust, unit, err := agentUpgradeWorkerConfig()
	if err != nil {
		return err
	}
	lock, err := agentUpgradeLock(c)
	if err != nil {
		return err
	}
	defer lock.Close()
	journal, err := readAgentUpgrade(c)
	if err != nil {
		return err
	}
	if journal.Phase != "staged" && !journal.fencing() {
		return nil
	}
	lease, err := configurationLeaseUnder("", 2*time.Second)
	if err != nil {
		if journal.Phase == "staged" {
			return journal.save(c, "blocked", "An endpoint configuration or recovery transaction is active")
		}
		return err
	}
	defer lease.Close()
	if journal.fencing() {
		return journal.rollback(c, trust, unit, errors.New("independent upgrade worker restarted before completion"))
	}
	if err = checkEnforcementUpgradeSafety(c, true); err != nil {
		return journal.save(c, "blocked", err.Error())
	}
	candidate, err := readAgentUpgradeRuntime(c, "candidate")
	if err == nil {
		err = candidate.verify(journal.Assignment.Version, trust, unit)
	}
	if err != nil {
		return journal.save(c, "error", "Staged candidate runtime is invalid: "+err.Error())
	}
	previous, err := readAgentUpgradeRuntime(c, "")
	if err == nil {
		err = previous.verify(journal.PreviousVersion, trust, unit)
	}
	if err == nil {
		err = previous.stage(c, "previous")
	}
	if err != nil {
		return journal.save(c, "blocked", "Could not establish a verified rollback copy: "+err.Error())
	}
	if err = journal.confirm(ctx, c); err != nil {
		return journal.save(c, "blocked", "Current signed upgrade authorization could not be verified: "+err.Error())
	}
	if err = journal.save(c, "stopping", ""); err != nil {
		return err
	}
	if err = agentUpgradeSystemctl(ctx, "stop"); err != nil {
		return journal.rollback(c, trust, unit, fmt.Errorf("could not stop the existing agent: %w", err))
	}
	// Check again after the stopped process has drained its own cgroup. An
	// independently running enforcement rollback must finish with its binary.
	if err = checkEnforcementUpgradeSafety(c, true); err != nil {
		if startErr := journal.save(c, "restoring", err.Error()); startErr != nil {
			return errors.Join(err, startErr)
		}
		if startErr := agentUpgradeSystemctl(ctx, "start"); startErr != nil {
			return errors.Join(err, startErr)
		}
		return journal.save(c, "blocked", err.Error())
	}
	if err = journal.save(c, "replacing", ""); err != nil {
		return journal.rollback(c, trust, unit, err)
	}
	if err = candidate.install(); err != nil {
		return journal.rollback(c, trust, unit, err)
	}
	if err = journal.save(c, "starting", ""); err != nil {
		return journal.rollback(c, trust, unit, err)
	}
	started := time.Now()
	if err = agentUpgradeSystemctl(ctx, "start"); err == nil {
		err = journal.awaitReady(ctx, c, started)
	}
	if err != nil {
		return journal.rollback(c, trust, unit, err)
	}
	if err = journal.save(c, "applied", ""); err != nil {
		return journal.rollback(c, trust, unit, err)
	}
	return nil
}

// RecoverAgentUpgrade is the fixed ExecStartPre command. It restores only the
// two signed runtime files if the independent worker disappeared or the host
// rebooted mid-transaction. It never starts a service or changes configuration.
func RecoverAgentUpgrade() error {
	c, err := LoadConfig(upgradeConfig, false)
	if err != nil {
		return err
	}
	journal, err := readAgentUpgrade(c)
	if os.IsNotExist(err) || err == nil && !journal.fencing() {
		return nil
	}
	if err != nil {
		return err
	}
	c, trust, unit, err := agentUpgradeWorkerConfig()
	if err != nil {
		return err
	}
	lock, err := agentUpgradeLock(c)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		// A live worker alone may start an installed candidate or previous pair.
		latest, readErr := readAgentUpgrade(c)
		if readErr != nil {
			return readErr
		}
		if latest.Phase == "starting" || latest.Phase == "restoring" || !latest.fencing() {
			return nil
		}
		return errors.New("agent startup is fenced during a runtime replacement")
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	journal, err = readAgentUpgrade(c)
	if err != nil || !journal.fencing() {
		return err
	}
	lease, err := configurationLeaseUnder("", 2*time.Second)
	if err != nil {
		return err
	}
	defer lease.Close()
	journal.Error = "Previous signed runtime restored after an interrupted agent upgrade"
	if err = journal.restore(c, trust, unit); err != nil {
		return err
	}
	return journal.save(c, "rolled_back", journal.Error)
}
