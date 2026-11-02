package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedLockRejectsUnsafeCustomPathAndLeaseAliases(t *testing.T) {
	for _, kind := range []string{"state-symlink", "managed-symlink", "lock-symlink", "lock-hardlink", "lock-public", "writable-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			state := filepath.Join(base, "state")
			if err := os.MkdirAll(managedDirectory(state), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(managedDirectory(state), "lock")
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "state-symlink", "managed-symlink":
				target := state
				if kind == "managed-symlink" {
					target = managedDirectory(state)
				}
				err = os.Rename(target, target+".actual")
				if err == nil {
					err = os.Symlink(target+".actual", target)
				}
			case "lock-symlink":
				err = os.Rename(path, path+".actual")
				if err == nil {
					err = os.Symlink(path+".actual", path)
				}
			case "lock-hardlink":
				err = os.Link(path, path+".alias")
			case "lock-public":
				err = os.Chmod(path, 0644)
			case "writable-ancestor":
				err = os.Chmod(base, 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			if lease, err := managedLock(state, true); err == nil {
				unlockManaged(lease)
				t.Fatal("unsafe custom path acquired mutation authority")
			}
		})
	}
}

func TestManagedJournalReaderBoundsAndValidatesBeforeDecode(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "oversize", "directory-symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			nonce := strings.Repeat("c", 32)
			path := managedJournalPath(directory, nonce)
			journal := &managedJournal{Nonce: nonce, PID: os.Getpid(), Phase: "committed", Deadline: time.Now().Add(time.Hour)}
			if err := saveManagedJournal(path, journal); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Rename(path, path+".actual")
				if err == nil {
					err = os.Symlink(path+".actual", path)
				}
			case "hardlink":
				err = os.Link(path, path+".alias")
			case "public":
				err = os.Chmod(path, 0644)
			case "oversize":
				var file *os.File
				file, err = os.OpenFile(path, os.O_WRONLY, 0)
				if err == nil {
					err = file.Truncate(16*1024*1024 + 1)
					_ = file.Close()
				}
			case "directory-symlink":
				dir := filepath.Dir(path)
				err = os.Rename(dir, dir+".actual")
				if err == nil {
					err = os.Symlink(dir+".actual", dir)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = readManagedJournal(path, nonce); err == nil {
				t.Fatal("unsafe history was loaded for rollback/replay")
			}
		})
	}
}

func TestImportedJournalReplayRefusesUnsafeFileBeforeFirewallCommand(t *testing.T) {
	commands := newFirewallFake()
	a := firewallAgent(t, commands)
	change := firewallPlan(commands, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", NewValue: "8443/tcp", Operation: "add"})
	path := a.firewallJournalPath(change.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Truncate(2*1024*1024 + 1)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	runner := &journalBudgetNoCommands{}
	a.Commands = runner
	if err = a.processApprovedChanges(context.Background(), []FirewallChange{change}); err == nil || runner.calls != 0 {
		t.Fatal("unsafe imported replay fell through to a fresh firewall transaction", err, runner.calls)
	}
}
