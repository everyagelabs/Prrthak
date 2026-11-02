package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type journalBudgetNoCommands struct{ calls int }

func (r *journalBudgetNoCommands) Run(context.Context, string, ...string) (string, error) {
	r.calls++
	return "", errors.New("journal admission must not run a firewall command")
}

func budgetHistoryPath(stateDir, area string) string {
	if area == "firewall-changes" {
		return filepath.Join(stateDir, area)
	}
	return filepath.Join(stateDir, area, "transactions")
}

func makeOverBudgetHistory(t *testing.T, stateDir, area string) string {
	t.Helper()
	directory := budgetHistoryPath(stateDir, area)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, ".retained-history-padding")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse logical size exercises byte admission without allocating a GiB.
	err = file.Truncate(enforcementHistoryMaxBytes - enforcementJournalReserveBytes + 1)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnforcementJournalBudgetRefusesLargeRetainedHistoryWithoutPruning(t *testing.T) {
	for _, area := range []string{"managed", "learning-allow", "firewall-changes"} {
		t.Run(area, func(t *testing.T) {
			stateDir := t.TempDir()
			path := makeOverBudgetHistory(t, stateDir, area)
			if err := checkNewEnforcementJournalBudget(stateDir, area); !errors.Is(err, errEnforcementHistoryCapacity) {
				t.Fatal("oversized retained history admitted new transaction", err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() != enforcementHistoryMaxBytes-enforcementJournalReserveBytes+1 {
				t.Fatal("admission altered retained evidence", err)
			}
		})
	}
}

func TestEnforcementJournalBudgetBoundedCountAndAtomicWriteReserve(t *testing.T) {
	stateDir := t.TempDir()
	directory := budgetHistoryPath(stateDir, "managed")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < enforcementHistoryMaxEntries; index++ {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("%05d.json", index)), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkNewEnforcementJournalBudget(stateDir, "managed"); !errors.Is(err, errEnforcementHistoryCapacity) {
		t.Fatal("high-count retained history admitted new transaction", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != enforcementHistoryMaxEntries {
		t.Fatal("capacity check removed historical replay evidence", err)
	}
}

func TestEnforcementJournalBudgetRejectsSymlinkAndAliasedOrPublicHistory(t *testing.T) {
	for _, kind := range []string{"symlink-entry", "symlink-directory", "hardlink", "public", "subdirectory"} {
		t.Run(kind, func(t *testing.T) {
			stateDir := t.TempDir()
			directory := budgetHistoryPath(stateDir, "managed")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "retained.json")
			if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink-entry":
				err = os.Symlink(path, filepath.Join(directory, "alias.json"))
			case "symlink-directory":
				err = os.Rename(directory, directory+".actual")
				if err == nil {
					err = os.Symlink(directory+".actual", directory)
				}
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "public":
				err = os.Chmod(path, 0644)
			case "subdirectory":
				err = os.Mkdir(filepath.Join(directory, "unexpected"), 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = checkNewEnforcementJournalBudget(stateDir, "managed"); !errors.Is(err, errEnforcementHistoryCapacity) {
				t.Fatal("unsafe history admitted access transaction", err)
			}
		})
	}
}

func TestEnforcementJournalBudgetAcceptsSupportedFortyThousandIPv6JournalSize(t *testing.T) {
	stateDir := t.TempDir()
	directory := budgetHistoryPath(stateDir, "managed")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(directory, "large-valid-size.json"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// Actual previously measured supported 40kIPv6 source journal bound.
	err = file.Truncate(13522888)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = checkNewEnforcementJournalBudget(stateDir, "managed"); err != nil {
		t.Fatal("supported journal size lost admission", err)
	}
}

func TestManagedJournalBudgetRefusesBeforeAnyFirewallCommand(t *testing.T) {
	a, _, protection := managedTestAgent(t)
	makeOverBudgetHistory(t, a.Config.StateDir, "managed")
	runner := &journalBudgetNoCommands{}
	a.Commands = runner
	policy := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if err := a.applyManaged(context.Background(), policy, protection); !errors.Is(err, errEnforcementHistoryCapacity) {
		t.Fatal("new managed transaction ignored history capacity", err)
	}
	if runner.calls != 0 || a.State.ManagedEnforcement == nil || !strings.Contains(a.State.ManagedEnforcement.Error, "history capacity") {
		t.Fatal("capacity refusal queried/wrote firewall or hid its error", runner.calls)
	}
}

func TestLearningJournalBudgetRefusesBeforeDiscoveryOrFirewallCommand(t *testing.T) {
	a, _, protection, session := learningTestAgent(t)
	makeOverBudgetHistory(t, a.Config.StateDir, "learning-allow")
	runner := &journalBudgetNoCommands{}
	a.Commands = runner
	assignment := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	if err := a.processLearningAllow(context.Background(), assignment); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 || a.State.LearningAllowOutcome == nil || a.State.LearningAllowOutcome.Status != "blocked" || !strings.Contains(a.State.LearningAllowOutcome.Error, "history capacity") {
		t.Fatal("capacity refusal queried/wrote firewall or hid its error", runner.calls, a.State.LearningAllowOutcome)
	}
}

func TestImportedJournalBudgetRefusesBeforeAnyFirewallCommand(t *testing.T) {
	commands := newFirewallFake()
	a := firewallAgent(t, commands)
	change := firewallPlan(commands, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", NewValue: "8443/tcp", Operation: "add"})
	makeOverBudgetHistory(t, a.Config.StateDir, "firewall-changes")
	runner := &journalBudgetNoCommands{}
	a.Commands = runner
	result := a.applyFirewallChange(context.Background(), change)
	if runner.calls != 0 || result.Status != "failed" || !strings.Contains(result.Message, "history capacity") {
		t.Fatal("imported capacity refusal queried/wrote firewall or hid its error", runner.calls, result)
	}
}

func TestJournalBudgetDoesNotBlockExistingCompensation(t *testing.T) {
	a, commands, protection := managedTestAgent(t)
	policy := managedTestPolicy(protection, 1, "10.30.0.0/24")
	if err := a.applyManaged(context.Background(), policy, protection); err != nil {
		t.Fatal(err)
	}
	makeOverBudgetHistory(t, a.Config.StateDir, "managed")
	nonce := strings.Repeat("e", 32)
	rule := a.State.ManagedBundle.Rules[0]
	commands.set("runtime", "rich_rule", rule.Rule, true)
	journal := &managedJournal{Nonce: nonce, Phase: "staging", PID: os.Getpid(),
		Previous: a.State.ManagedBundle, Next: ManagedBundle{Version: 2},
		Mutations: []managedMutation{{Scope: "runtime", Zone: rule.Zone, Rule: rule.Rule, Before: false, After: true}}}
	path := managedJournalPath(a.Config.StateDir, nonce)
	if err := saveManagedJournal(path, journal); err != nil {
		t.Fatal(err)
	}
	lease, err := managedLock(a.Config.StateDir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockManaged(lease)
	if err = rollbackManaged(withManagedLease(context.Background(), lease), commands, path, journal); err != nil {
		t.Fatal("history capacity blocked existing independent compensation", err)
	}
	if journal.Phase != "rolled_back" || commands.has("runtime", "rich_rule", rule.Rule) {
		t.Fatal("existing rollback did not complete at admission capacity")
	}
}
