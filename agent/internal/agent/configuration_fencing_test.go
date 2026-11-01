package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This represents a watchdog which loaded armed review A, then lost its CPU
// while startup recovery completed A and an operator began fresh retry B.
// The fixture does not run systemd, kill a process or use a network/database.
func TestAuditConfigurationStaleRollbackMustFenceActiveSuccessor(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := root + "/var/lib/seg-agent/configuration-transitions"
	for _, path := range []string{root + "/etc/seg-agent", directory} {
		if err = os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	a := &configurationJournal{SchemaVersion: 1, ReviewID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Status: "armed", Deadline: time.Now().Add(-time.Minute), ConfigPath: "/etc/seg-agent/config.json", OldConfig: []byte("previous exact config"), CandidateConfig: []byte("identical legitimate retry candidate"), OldCA: []byte("old CA"), CandidateCA: []byte("candidate CA")}
	finishedA := *a
	finishedA.Status = "rolled_back"
	if err = atomicJSON(directory+"/"+a.ReviewID+".json", &finishedA); err != nil {
		t.Fatal(err)
	}
	b := *a
	b.ReviewID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	b.Status = "armed"
	b.Deadline = time.Now().Add(time.Minute)
	if err = atomicJSON(directory+"/"+b.ReviewID+".json", &b); err != nil {
		t.Fatal(err)
	}
	if err = atomicJSON(directory+"/active", map[string]string{"review_id": b.ReviewID}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(root+b.ConfigPath, b.CandidateConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(root+"/etc/seg-agent/controller-ca.crt", b.CandidateCA, 0600); err != nil {
		t.Fatal(err)
	}
	commands := &configurationCommands{}
	err = restoreConfigurationUnder(root, directory+"/"+a.ReviewID+".json", a, commands)
	current, readErr := os.ReadFile(root + b.ConfigPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	pointer, readErr := os.ReadFile(directory + "/active")
	if readErr != nil {
		t.Fatal(readErr)
	}
	t.Logf("staleRollbackAccepted=%t successorConfigOverwritten=%t successorPointerRetained=%t fakeServiceRestartCount=%d", err == nil, bytes.Equal(current, a.OldConfig), bytes.Contains(pointer, []byte(b.ReviewID)), len(commands.calls))
	if err == nil || !bytes.Equal(current, b.CandidateConfig) {
		t.Fatal("stale A restored through B's active generation; expected stale rollback refusal with B unchanged")
	}
}
