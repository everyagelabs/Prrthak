//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCommandDiagnosticClassifiesOriginalOperationWithoutCredentialValues(t *testing.T) {
	secret := "DO-NOT-RECORD-credential-user-password"
	for _, test := range []struct {
		name, operation string
		args            []string
	}{
		{"/private/" + secret + "/firewall-cmd", "firewall-readback", []string{"--permanent", "--list-rich-rules", "--zone=" + secret, "--password", secret, "https://user:" + secret + "@host/"}},
		{"firewall-cmd", "firewall-mutation", []string{"--zone=" + secret, "--add-rich-rule=rule source address=\"" + secret + "\" accept"}},
		{"systemctl", "service-mutation", []string{"--property=Environment=PASSWORD=" + secret, "restart", secret + ".service"}},
		{"nft", "nft-mutation-or-check", []string{"-f", "/private/" + secret}},
		{"nft", "nft-readback", []string{"--json", "list", "ruleset", secret}},
		{"ip", "network-mutation", []string{"netns", "add", secret}},
		{"ip", "network-observation", []string{"-j", "route", "show", secret}},
		{"/private/" + secret, "unclassified", []string{"-c", "echo " + secret, "--token=" + secret}},
	} {
		t.Run(test.operation+"-"+filepath.Base(test.name), func(t *testing.T) {
			d := newCommandDiagnostic(test.name, test.args)
			if d.Operation != test.operation {
				t.Fatalf("wrong command classification: %q", d.Operation)
			}
			raw, err := json.Marshal(d)
			if err != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "https://") || strings.Contains(string(raw), "/private/") {
				t.Fatal("diagnostic retained a credential, value or executable path")
			}
			if !validCommandDiagnostic(d, "") || d.ArgumentCount != len(test.args) {
				t.Fatal("safe original classification or argument cardinality was lost")
			}
		})
	}
	args := []string{"--permanent", "--zone=x", "--state", "--get-active-zones", "--get-ipsets", "--get-target", "--get-policies", "--get-default-zone", "--list-all", "--remove-rich-rule=secret"}
	d := newCommandDiagnostic("firewall-cmd", args)
	if len(d.Flags) != 8 || d.Operation != "firewall-mutation" {
		t.Fatal("bounded flag summary concealed a later mutation")
	}
}

func waitCommandDiagnostic(t *testing.T, path string, ready func(*commandDiagnostic) bool) *commandFence {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if record, err := readCommandFence(path); err == nil && record.Diagnostic != nil && ready(record.Diagnostic) {
			return record
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("private command diagnostic did not reach its test gate")
	return nil
}

func TestCommandDiagnosticSurvivesSupervisorLossAndEmptyCurrentProcessState(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lease)
	executable := filepath.Join(directory, "firewall-cmd")
	// exec keeps one disposable worker and no detached subprocess. Its exact
	// arguments still exercise a realistic rich-rule readback classification.
	if err = os.WriteFile(executable, []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	secret := "sensitive-zone-token-never-persist"
	cmd, err := fencedCommand(context.Background(), lease, executable, "--permanent", "--list-rich-rules", "--zone="+secret)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(cmd.Env, "PASSWORD="+secret)
	done := make(chan error, 1)
	go func() { done <- runFencedCommand(cmd) }()
	path, _ := commandFencePath(lease.Name())
	original := waitCommandDiagnostic(t, path, func(d *commandDiagnostic) bool { return d.Stage == "worker-running" })
	if original.Diagnostic.Supervisor == nil || original.Diagnostic.Worker == nil || original.Diagnostic.Supervisor.Identity == "" || original.Diagnostic.Worker.Identity == "" {
		t.Fatal("worker ran without durable supervisor/worker start identities")
	}
	defer syscall.Kill(original.Diagnostic.Supervisor.PID, syscall.SIGKILL)
	defer syscall.Kill(original.Diagnostic.Worker.PID, syscall.SIGKILL)
	if err = syscall.Kill(original.Diagnostic.Supervisor.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, errUncertainCommand) {
			t.Fatal("supervisor death did not retain fail-closed uncertainty", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("killed supervisor did not complete its disposable owner")
	}
	retained, err := readCommandFence(path)
	if err != nil || retained.Diagnostic.Stage != "supervisor-exited-unproven" || retained.Diagnostic.LastEvidence != "supervisor-exit-without-drain-receipt" {
		t.Fatal("supervisor loss erased its last durable proof stage", err)
	}
	d := retained.Diagnostic
	if d.Operation != "firewall-readback" || d.Executable != "firewall-cmd" || d.Supervisor.Identity != original.Diagnostic.Supervisor.Identity || d.Worker.Identity != original.Diagnostic.Worker.Identity || d.SupervisorExitCode == nil || *d.SupervisorExitCode != -1 {
		t.Fatal("uncertainty no longer identifies the original command/processes")
	}
	raw, _ := os.ReadFile(path)
	if len(raw) > 2048 || strings.Contains(string(raw), secret) {
		t.Fatal("durable diagnostic exceeded its bound or exposed argv/environment credentials")
	}
	unlockManaged(lease)
	if next, err := managedLock(directory, true); !errors.Is(err, errUncertainCommand) {
		if next != nil {
			unlockManaged(next)
		}
		t.Fatal("missing supervisor/currently empty state authorized a new mutation", err)
	}
}

func TestCommandDiagnosticWrongNonceOrInvalidEvidenceNeverRewritesOrigin(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lease)
	record, path, err := createCommandFenceForCommand(lease.Name(), "firewall-cmd", []string{"--add-rich-rule=secret"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	for _, nonce := range []string{strings.Repeat("a", 32), record.Nonce} {
		err = updateCommandDiagnostic(path, nonce, func(d *commandDiagnostic) { d.LastEvidence = "private-password-secret" })
		if err == nil {
			t.Fatal("wrong nonce/unsanitized evidence was persisted")
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatal("failed diagnostic update rewrote the original fence")
		}
	}
	if err := checkCommandFence(lease.Name(), false); !errors.Is(err, errUncertainCommand) {
		t.Fatal("failed diagnostic update granted mutation authority", err)
	}
}

func TestCommandDiagnosticPriorBootRetirementPreservesHistoryAndLegacyUnknownOrigin(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "classified", true: "legacy-unknown"}[legacy], func(t *testing.T) {
			directory := t.TempDir()
			lease, err := managedLock(directory, true)
			if err != nil {
				t.Fatal(err)
			}
			record, path, err := createCommandFenceForCommand(lease.Name(), "firewall-cmd", []string{"--permanent", "--remove-rich-rule=secret"})
			if err != nil {
				t.Fatal(err)
			}
			unlockManaged(lease)
			record.BootID = "00000000-0000-0000-0000-000000000000"
			record.OwnerIdentity = record.BootID + ":1"
			if legacy {
				record.Diagnostic = nil // Exactly the .25 schema1 historical format.
			}
			if err = atomicJSON(path, record); err != nil {
				t.Fatal(err)
			}
			journalPath := filepath.Join(managedDirectory(directory), "unchanged-journal.json")
			journal := []byte("private existing transaction history")
			if err = os.WriteFile(journalPath, journal, 0600); err != nil {
				t.Fatal(err)
			}
			if err = checkCommandFence(lease.Name(), false); err != nil {
				t.Fatal("read-only previous-boot inspection refused valid historical fence", err)
			}
			historyPath := filepath.Join(managedDirectory(directory), commandUncertaintyHistoryFilename)
			if _, err = os.Stat(historyPath); !os.IsNotExist(err) {
				t.Fatal("read-only inspection mutated diagnostic history")
			}
			next, err := managedLock(directory, true)
			if err != nil {
				t.Fatal("verified new kernel boot did not preserve and retire old fence", err)
			}
			defer unlockManaged(next)
			raw, err := readPrivateSetupBound(historyPath, 4096)
			var history struct {
				Fence         *commandFence `json:"fence"`
				RetiredByBoot string        `json:"retired_by_boot"`
				Reason        string        `json:"reason"`
			}
			if err != nil || json.Unmarshal(raw, &history) != nil || history.Fence == nil || history.Fence.Nonce != record.Nonce || history.Reason != "verified-new-kernel-boot" || history.RetiredByBoot == record.BootID {
				t.Fatal("new boot erased the original uncertainty evidence", err)
			}
			if legacy && history.Fence.Diagnostic != nil || !legacy && history.Fence.Diagnostic.Operation != "firewall-mutation" {
				t.Fatal("historical unknown origin was invented or classified origin lost")
			}
			if after, _ := os.ReadFile(journalPath); string(after) != string(journal) {
				t.Fatal("new boot diagnostic retirement modified transaction history")
			}
		})
	}
}

func TestCommandDiagnosticUnavailableHistoryBlocksRetirementWithoutDiscardingFence(t *testing.T) {
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
	record.BootID, record.OwnerIdentity = "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000:1"
	if err = atomicJSON(path, record); err != nil {
		t.Fatal(err)
	}
	historyPath := filepath.Join(managedDirectory(directory), commandUncertaintyHistoryFilename)
	if err = os.Symlink(path, historyPath); err != nil {
		t.Fatal(err)
	}
	if next, err := managedLock(directory, true); !errors.Is(err, errUncertainCommand) {
		if next != nil {
			unlockManaged(next)
		}
		t.Fatal("unwritable/aliased diagnostic history was ignored", err)
	}
	if retained, err := readCommandFence(path); err != nil || retained.Nonce != record.Nonce {
		t.Fatal("failed history persistence discarded the unresolved operation", err)
	}
}

func TestCommandDiagnosticBoundedStagesKeepOriginalOperationAndDrainEvidence(t *testing.T) {
	directory := t.TempDir()
	lease, err := managedLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lease)
	record, path, err := createCommandFenceForCommand(lease.Name(), "firewall-cmd", []string{"--permanent", "--zone=secret", "--remove-rich-rule=secret"})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*commandDiagnostic){
		func(d *commandDiagnostic) {
			d.Stage, d.Supervisor = "supervisor-started", commandProcessIdentity(os.Getpid())
		},
		func(d *commandDiagnostic) { d.Stage, d.Worker = "worker-running", commandProcessIdentity(os.Getpid()) },
		func(d *commandDiagnostic) {
			d.Stage, d.DrainReason, d.LastEvidence = "draining", "deadline-expired", "deadline-expired"
			d.DrainStartedAt = time.Now().UTC().Format(time.RFC3339Nano)
		},
		func(d *commandDiagnostic) { d.LastEvidence = "children-signal-failed" },
		func(d *commandDiagnostic) { d.Stage, d.LastEvidence = "drain-unproven", "kernel-echild-unproven" },
	} {
		if err = updateCommandDiagnostic(path, record.Nonce, change); err != nil {
			t.Fatal("bounded supervisor failure stage was not durable", err)
		}
	}
	before, _ := os.ReadFile(path)
	if len(before) > 2048 {
		t.Fatal("normal diagnostic stage history exceeded its bounded fence")
	}
	for _, change := range []func(*commandDiagnostic){
		func(d *commandDiagnostic) { d.Operation = "firewall-readback" },
		func(d *commandDiagnostic) { d.Flags[0] = "--state" },
		func(d *commandDiagnostic) { d.Supervisor.PID++ },
		func(d *commandDiagnostic) {
			d.DrainStartedAt = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		},
	} {
		if err = updateCommandDiagnostic(path, record.Nonce, change); !errors.Is(err, errUncertainCommand) {
			t.Fatal("failure annotation relabelled the original operation or proof identity", err)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Fatal("rejected annotation changed original uncertainty evidence")
		}
	}
	if err = checkCommandFence(lease.Name(), false); !errors.Is(err, errUncertainCommand) {
		t.Fatal("diagnostic failure stages were mistaken for kernel drain proof", err)
	}
}

func TestMissingOrCorruptCommandDiagnosticNeverAuthorizesSameBootRecovery(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "corrupt", true: "missing"}[legacy], func(t *testing.T) {
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
			record.OwnerPID = 2147483647
			if legacy {
				record.Diagnostic = nil
			} else {
				record.Diagnostic.Stage = "all-processes-absent-therefore-safe"
			}
			if err = atomicJSON(path, record); err != nil {
				t.Fatal(err)
			}
			if next, err := managedLock(directory, true); !errors.Is(err, errUncertainCommand) {
				if next != nil {
					unlockManaged(next)
				}
				t.Fatal("missing/corrupt diagnostics or absent owner authorized recovery", err)
			}
			if _, err = os.Stat(path); err != nil {
				t.Fatal("unreadable original uncertainty fence was discarded")
			}
		})
	}
}
