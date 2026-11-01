package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func learningLabAgent(t *testing.T, dir string) *Agent {
	a := managedLabAgent(t, dir)
	a.Config.LearningAutoAllow = true
	a.inventory = &Report{IPs: []string{"10.231.0.1"}}
	a.protection = nil
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error {
		if !managedLabProbe("10.231.0.2", "2022", true) {
			return errors.New("real independent SSH management probe failed")
		}
		return nil
	}
	return a
}
func TestLearningAllowCrashHelper(t *testing.T) {
	if os.Getenv("PRTHAK_LEARNING_CRASH_HELPER") != "1" {
		t.Skip("isolated learning subprocess helper")
	}
	privateManagedLab(t)
	dir := os.Getenv("PRTHAK_LEARNING_STATE")
	a := learningLabAgent(t, dir)
	raw, e := os.ReadFile(filepath.Join(dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &a.State); e != nil {
		t.Fatal(e)
	}
	protection, _ := a.managedProtection(context.Background())
	a.protection = &protection
	session := Session{ID: "learning-session-123", ExpiresAt: time.Now().Add(time.Hour), Ports: []Port{{Port: 443, Protocol: "tcp"}}}
	p := learningTestAssignment(a, protection, session, 3, "10.231.0.3/32")
	p.Authorities[0].Kind = "reviewed"
	a.armManaged = func(ctx context.Context, path string, j *managedJournal) error {
		j.Deadline = time.Now().Add(25 * time.Second)
		j.DeadlineBootSeconds = bootElapsedSeconds() + 25
		if e := saveManagedJournal(path, j); e != nil {
			return e
		}
		return armManagedWatchdogBinary(ctx, a.Commands, path, j, os.Getenv("PRTHAK_WATCHDOG_BINARY"))
	}
	calls := 0
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error {
		calls++
		if calls == 2 {
			if !managedLabProbe("10.231.0.3", "443", false) {
				return errors.New("staged learning source not reachable")
			}
			if e := os.WriteFile(filepath.Join(dir, "learning-crash-ready"), []byte("ready"), 0600); e != nil {
				return e
			}
			for {
				time.Sleep(time.Second)
			}
		}
		return nil
	}
	if e = a.processLearningAllow(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	t.Fatal("independent watchdog did not kill learning helper")
}
func TestRealLearningAllowSystemdLab(t *testing.T) {
	privateManagedLab(t)
	ctx := context.Background()
	dir := t.TempDir()
	a := learningLabAgent(t, dir)
	listener, e := net.Listen("tcp", "10.231.0.1:443")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		for {
			connection, e := listener.Accept()
			if e != nil {
				return
			}
			connection.Close()
		}
	}()
	session := Session{ID: "learning-session-123", PolicyAction: "auto_allow", ServerIDs: []string{"host-a"}, Ports: []Port{{Port: 443, Protocol: "tcp"}}, StartsAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), Status: "active"}
	a.State.Policy = &Policy{ServerID: "host-a", Version: 1, Mode: "monitor", Services: []Service{}, LearningSessions: []Session{session}}
	a.State.Policy.Digest, _ = compiledPolicyDigest(a.State.Policy)
	a.confirmed = true
	a.State.Coverage = map[string]*Coverage{}
	a.State.JournalSince = time.Now().Add(-time.Second)
	if e = a.LearningTick(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if len(a.State.Rules) != 1 {
		t.Fatal("learning did not instrument exactly443")
	}
	if managedLabProbe("10.231.0.2", "443", false) {
		t.Fatal("fresh443 fixture unexpectedly open before learned grant")
	}
	evidenceKey := learningTuple("10.231.0.2", "tcp", 443)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if e = a.LearningTick(ctx, time.Now()); e != nil {
			t.Fatal(e)
		}
		if _, ok := a.State.LearningEvidence[session.ID][evidenceKey]; ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, ok := a.State.LearningEvidence[session.ID][evidenceKey]; !ok {
		t.Fatal("actual kernel ingress hit was not captured as local exact443 evidence")
	}
	protection, _ := a.managedProtection(ctx)
	a.protection = &protection
	p := learningTestAssignment(a, protection, session, 1, "10.231.0.2/32")
	if e = a.processLearningAllow(ctx, p); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "applied" {
		t.Fatalf("real learning overlay failed: %+v", a.State.LearningAllowOutcome)
	}
	// Stop instrumentation so a deliberate denied probe is not itself a new
	// automatically trusted observation. Previously committed accepts stay durable.
	stopped := session
	stopped.Status = "stopped"
	at := time.Now()
	stopped.StoppedAt = &at
	a.rememberLearningTransition(&Policy{LearningTombstones: []Session{stopped}}, at)
	a.State.Policy.LearningSessions = nil
	a.State.Policy.LearningTombstones = []Session{stopped}
	if e = a.LearningTick(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if !managedLabProbe("10.231.0.2", "443", false) || managedLabProbe("10.231.0.3", "443", false) {
		t.Fatal("real source-specific learning allow behavior incorrect")
	}
	if !managedLabProbe("10.231.0.2", "2022", true) {
		t.Fatal("overlay changed SSH management")
	}
	// A reviewed new source still goes through runtime-first health and rollback.
	second := learningTestAssignment(a, protection, session, 2, "10.231.0.2/32")
	second.Services[0].Sources = append(second.Services[0].Sources, "10.231.0.3/32")
	second.Authorities[0].Services = second.Services
	second.Authorities[0].Kind = "reviewed"
	second.Digest, _ = learningAllowDigest(second)
	second.BindingDigest = learningAllowBinding(second)
	calls := 0
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("injected management outage after learning stage")
		}
		return nil
	}
	if e = a.processLearningAllow(ctx, second); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "rolled_back" || !managedLabProbe("10.231.0.2", "443", false) || managedLabProbe("10.231.0.3", "443", false) {
		t.Fatal("learning health failure did not restore exact prior overlay")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestLearningAllowCrashHelper$", "-test.v")
	command.Env = append(os.Environ(), "PRTHAK_LEARNING_CRASH_HELPER=1", "PRTHAK_LEARNING_STATE="+dir)
	logPath := filepath.Join(dir, "learning-helper.log")
	log, e := os.Create(logPath)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	command.Stdout = log
	command.Stderr = log
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	defer command.Process.Kill()
	deadline = time.Now().Add(35 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if _, e = os.Stat(filepath.Join(dir, "learning-crash-ready")); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		raw, _ := os.ReadFile(logPath)
		t.Fatalf("learning helper failed to stage: %s", raw)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		exited, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("learning helper was not killed: %v", err)
		}
		status, ok := exited.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			raw, _ := os.ReadFile(logPath)
			t.Fatalf("learning helper did not receive watchdog SIGKILL: %v %s", err, raw)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("independent systemd watchdog did not fence learning helper")
	}
	deadline = time.Now().Add(30 * time.Second)
	independentDone := false
	for time.Now().Before(deadline) {
		paths, _ := filepath.Glob(filepath.Join(dir, "learning-allow", "transactions", "*.json"))
		for _, path := range paths {
			nonce := strings.TrimSuffix(filepath.Base(path), ".json")
			journal, err := readManagedJournal(path, nonce)
			if err == nil && journal.Next.Version == 3 && journal.Phase == "rolled_back" && journal.Error == "independent rollback deadline exceeded" {
				independentDone = true
			}
		}
		if independentDone {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !independentDone {
		t.Fatal("independent watchdog did not finish rollback before agent recovery")
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		e = a.recoverManaged(ctx)
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if a.State.LearningAllowBundle == nil || a.State.LearningAllowBundle.Assignment.Generation != 1 || !managedLabProbe("10.231.0.2", "443", false) || managedLabProbe("10.231.0.3", "443", false) {
		t.Fatal("independent learning rollback lost prior generation/packet behavior")
	}
	deletion := &LearningAllow{ServerID: "host-a", Generation: 4, Services: []Service{}, PolicyIDs: []string{}, Authorities: []LearningAuthority{{PolicyID: "learn-a", Kind: "reviewed", Services: []Service{}, ExpiresAt: time.Now().Add(time.Hour)}}, ProtectionDigest: protection.Digest, TargetIPsDigest: p.TargetIPsDigest, Authorized: true, ExpiresAt: time.Now().Add(time.Hour)}
	deletion.Digest, _ = learningAllowDigest(deletion)
	deletion.BindingDigest = learningAllowBinding(deletion)
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error { return nil }
	if e = a.processLearningAllow(ctx, deletion); e != nil {
		t.Fatal(e)
	}
	if a.State.LearningAllowOutcome.Status != "applied" || managedLabProbe("10.231.0.2", "443", false) {
		t.Fatal("reviewed overlay deletion did not restore closed443")
	}
	t.Log("PASS: real kernel source→443 learning evidence; exact accept-only runtime/permanent grant; stop persistence; SSH untouched; staged-health rollback; independent systemd SIGKILL watchdog restoration; reviewed deletion")
}
