package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func privateManagedLab(t *testing.T) {
	t.Helper()
	if os.Getenv("PRTHAK_MANAGED_SYSTEMD_LAB") != "1" {
		t.Skip("dedicated disposable Linux VM only")
	}
}
func managedLabProbe(source string, port string, ssh bool) bool {
	script := `import socket,sys
s=socket.socket();s.settimeout(2);s.bind((sys.argv[1],0))
try:
 s.connect(('10.231.0.1',int(sys.argv[2])))
 if sys.argv[3]=='ssh': assert s.recv(256).startswith(b'SSH-2.0')
except Exception: sys.exit(1)
`
	mode := "tcp"
	if ssh {
		mode = "ssh"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "ip", "netns", "exec", "prthak-managed-client", "python3", "-c", script, source, port, mode).Run() == nil
}
func managedLabAgent(t *testing.T, dir string) *Agent {
	t.Helper()
	a := &Agent{Config: Config{StateDir: dir, Enforce: true, Zone: "public", ControllerURL: "https://controller.example.internal:8787", ManagementSources: []string{"10.231.0.2/32"}}, Commands: ExecRunner{}, State: State{Coverage: map[string]*Coverage{}}}
	fixturePolicyTrust(t, a)
	a.armManaged = func(ctx context.Context, path string, j *managedJournal) error {
		binary := os.Getenv("PRTHAK_WATCHDOG_BINARY")
		if binary == "" {
			return errors.New("lab watchdog binary missing")
		}
		if os.Getenv("PRTHAK_MANAGED_CRASH_HELPER") == "1" {
			j.Deadline = time.Now().Add(25 * time.Second)
			j.DeadlineBootSeconds = bootElapsedSeconds() + 25
			if e := saveManagedJournal(path, j); e != nil {
				return e
			}
		}
		return armManagedWatchdogBinary(ctx, a.Commands, path, j, binary)
	}
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		if !managedLabProbe("10.231.0.2", "2022", true) {
			return errors.New("independent SSH2022 management probe failed")
		}
		return nil
	}
	return a
}
func TestManagedCrashHelper(t *testing.T) {
	if os.Getenv("PRTHAK_MANAGED_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	privateManagedLab(t)
	dir := os.Getenv("PRTHAK_MANAGED_STATE")
	a := managedLabAgent(t, dir)
	raw, e := os.ReadFile(filepath.Join(dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &a.State); e != nil {
		t.Fatal(e)
	}
	protection, _ := a.managedProtection(context.Background())
	p := managedTestPolicy(protection, 3, "10.231.0.3/32")
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			if !managedLabProbe("10.231.0.3", "18080", false) {
				return errors.New("staged new source was not reachable")
			}
			if e := os.WriteFile(filepath.Join(dir, "crash-ready"), []byte("ready"), 0600); e != nil {
				return e
			}
			for {
				time.Sleep(time.Second)
			}
		}
		return nil
	}
	if e = a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	t.Fatal("watchdog did not kill blocked applying process")
}
func TestRealManagedSystemdLab(t *testing.T) {
	privateManagedLab(t)
	ctx := context.Background()
	dir := t.TempDir()
	a := managedLabAgent(t, dir)
	listener, e := net.Listen("tcp", "10.231.0.1:18080")
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
	protection, e := a.managedProtection(ctx)
	if e != nil || !protection.Ready {
		t.Fatalf("lab protection not ready %+v %v", protection, e)
	}
	p := managedTestPolicy(protection, 1, "10.231.0.2/32")
	p.Services = append(p.Services, Service{Port: 2022, Protocol: "tcp", Mode: "enforce", Sources: []string{"10.231.0.2/32"}})
	p.Digest, _ = compiledPolicyDigest(p)
	p.Enforcement.ApprovedDigest = p.Digest
	p.Enforcement.BindingDigest = enforcementBinding(p, protection.Digest)
	if e = a.applyManaged(ctx, p, protection); e != nil {
		t.Fatal(e)
	}
	if !managedLabProbe("10.231.0.2", "18080", false) || managedLabProbe("10.231.0.3", "18080", false) {
		t.Fatal("real allowed/denied TCP source behavior incorrect")
	}
	if !managedLabProbe("10.231.0.2", "2022", true) || managedLabProbe("10.231.0.3", "2022", true) {
		t.Fatal("actual SSH2022 management guard failed")
	}
	// Controller/management outage after staging restores both permanent and runtime.
	second := managedTestPolicy(protection, 2, "10.231.0.3/32")
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("injected controller/management outage")
		}
		return nil
	}
	if a.applyManaged(ctx, second, protection) == nil {
		t.Fatal("outage accepted")
	}
	if !managedLabProbe("10.231.0.2", "18080", false) || managedLabProbe("10.231.0.3", "18080", false) || a.State.AppliedVersion != 1 {
		t.Fatal("health rollback did not restore traffic and version")
	}
	// A genuinely separate transient systemd service must kill the applying helper
	// and roll it back without any code continuing in that helper process.
	command := exec.Command(os.Args[0], "-test.run=^TestManagedCrashHelper$", "-test.v")
	command.Env = append(os.Environ(), "PRTHAK_MANAGED_CRASH_HELPER=1", "PRTHAK_MANAGED_STATE="+dir)
	logPath := filepath.Join(dir, "helper.log")
	logFile, e := os.Create(logPath)
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	command.Stdout = logFile
	command.Stderr = logFile
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	defer command.Process.Kill()
	deadline := time.Now().Add(50 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if _, e = os.Stat(filepath.Join(dir, "crash-ready")); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		raw, _ := os.ReadFile(logPath)
		t.Fatalf("helper failed to stage: %s", raw)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case e = <-wait:
		exited, ok := e.(*exec.ExitError)
		if !ok {
			t.Fatalf("helper was not killed: %v", e)
		}
		status, ok := exited.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("helper did not receive watchdog SIGKILL: %v", e)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("independent watchdog did not fence applying helper")
	}
	deadline = time.Now().Add(30 * time.Second)
	restored := false
	for time.Now().Before(deadline) {
		if managedLabProbe("10.231.0.2", "18080", false) && !managedLabProbe("10.231.0.3", "18080", false) {
			restored = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !restored {
		t.Fatal("independent watchdog did not restore prior packet policy")
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
	if a.State.AppliedVersion != 1 {
		t.Fatal("crash recovery lost previous committed version")
	}
	// Explicit approved cleanup keeps every unrelated rule, including VM SSH22.
	cleanup := managedTestPolicy(protection, 4)
	cleanup.Mode = "monitor"
	cleanup.Services = []Service{}
	cleanup.Digest, _ = compiledPolicyDigest(cleanup)
	cleanup.Enforcement.ApprovedDigest = cleanup.Digest
	cleanup.Enforcement.BindingDigest = enforcementBinding(cleanup, protection.Digest)
	cleanup.Enforcement.Intent = "remove_managed_rules"
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return nil }
	if e = a.applyManaged(ctx, cleanup, protection); e != nil {
		t.Fatal(e)
	}
	t.Log("PASS: real TCP allow/deny, SSH2022 guard, runtime/permanent commit, health-outage rollback, independent systemd watchdog SIGKILL fencing and exact rollback, explicit cleanup")
}

func TestRealManagedUserlandRulesLinux(t *testing.T) {
	if os.Getenv("PRTHAK_MANAGED_USERLAND_LAB") != "1" {
		t.Skip("private Linux firewalld container only")
	}
	a := &Agent{Config: Config{StateDir: t.TempDir(), Enforce: true, Zone: "public", ControllerURL: "https://controller.example.internal:8787", ManagementSources: []string{"127.0.0.1/32"}}, Commands: ExecRunner{}, State: State{Coverage: map[string]*Coverage{}}}
	fixturePolicyTrust(t, a)
	a.armManaged = func(_ context.Context, path string, j *managedJournal) error {
		_, e := readManagedJournal(path, j.Nonce)
		return e
	}
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return nil }
	protection, _ := a.managedProtection(context.Background())
	if !protection.Ready {
		t.Fatalf("protection unavailable: %+v", protection)
	}
	p := managedTestPolicy(protection, 1, "10.233.0.2/32")
	if e := a.applyManaged(context.Background(), p, protection); e != nil {
		t.Fatal(e)
	}
	for _, rule := range a.State.ManagedBundle.Rules {
		for _, scope := range []string{"runtime", "permanent"} {
			present, e := firewallQuery(context.Background(), a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
			if e != nil || !present {
				t.Fatal("actual firewalld commit absent")
			}
		}
	}
	previous := append([]ManagedRule{}, a.State.ManagedBundle.Rules...)
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("injected management witness failure")
		}
		return nil
	}
	second := managedTestPolicy(protection, 2, "10.233.0.3/32")
	if a.applyManaged(context.Background(), second, protection) == nil {
		t.Fatal("injected failure accepted")
	}
	for _, rule := range previous {
		for _, scope := range []string{"runtime", "permanent"} {
			present, e := firewallQuery(context.Background(), a.Commands, scope, rule.Zone, "rich_rule", rule.Rule)
			if e != nil || !present {
				t.Fatal("actual firewalld rollback lost prior bundle")
			}
		}
	}
	if a.State.AppliedVersion != 1 {
		t.Fatal("rollback claimed failed version")
	}
	t.Log("PASS: actual RHEL userland firewalld runtime/permanent managed rules and staged-health inverse rollback; watchdog and remote witness injected for this container-only test")
}
