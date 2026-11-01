package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeGuardIsReadOnlyAndBlocksEveryNonterminalEnforcementScope(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "absent-state")
	c := Config{StateDir: directory}
	if e := CheckEnforcementUpgradeSafety(c); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(directory); !os.IsNotExist(e) {
		t.Fatal("read-only check created state")
	}
	for _, scope := range []string{"managed", "learning-allow"} {
		t.Run(scope, func(t *testing.T) {
			c := Config{StateDir: t.TempDir()}
			nonce := strings.Repeat("a", 32)
			path := filepath.Join(c.StateDir, scope, "transactions", nonce+".json")
			j := &managedJournal{Nonce: nonce, PID: os.Getpid(), Phase: "staging"}
			if e := saveManagedJournal(path, j); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadFile(path)
			if CheckEnforcementUpgradeSafety(c) == nil {
				t.Fatal("pending generation permitted binary replacement")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("upgrade check mutated rollback journal")
			}
			for _, phase := range []string{"committed", "rolled_back", "superseded"} {
				j.Phase = phase
				if e := saveManagedJournal(path, j); e != nil {
					t.Fatal(e)
				}
				if e := CheckEnforcementUpgradeSafety(c); e != nil {
					t.Fatal(e)
				}
			}
			j.Phase = "rollback_failed"
			if e := saveManagedJournal(path, j); e != nil {
				t.Fatal(e)
			}
			if CheckEnforcementUpgradeSafety(c) == nil {
				t.Fatal("failed rollback permitted replacement")
			}
		})
	}
}
func TestUpgradeGuardRefusesBusyRollbackLockAndPendingImportedPlan(t *testing.T) {
	c := Config{StateDir: t.TempDir()}
	lock, e := managedLock(c.StateDir, true)
	if e != nil {
		t.Fatal(e)
	}
	if CheckEnforcementUpgradeSafety(c) == nil {
		t.Fatal("active independent rollback lock ignored")
	}
	unlockManaged(lock)
	path := filepath.Join(c.StateDir, "firewall-changes", shaText("change-1")+".json")
	j := &firewallJournal{ID: "change-1", PlanDigest: strings.Repeat("a", 64), Status: "prepared"}
	if e = atomicJSON(path, j); e != nil {
		t.Fatal(e)
	}
	if CheckEnforcementUpgradeSafety(c) == nil {
		t.Fatal("pending imported operation permitted replacement")
	}
	j.Status = "rolled_back"
	if e = atomicJSON(path, j); e != nil {
		t.Fatal(e)
	}
	if e = CheckEnforcementUpgradeSafety(c); e != nil {
		t.Fatal(e)
	}
}
