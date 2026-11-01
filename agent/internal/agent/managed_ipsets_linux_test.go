package agent

// Explicit isolated Docker network adapter smoke only. A mocked management
// witness/timer keeps it distinct from native systemd/SSH-witness acceptance.
import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRealPrivateManagedIPSetLinux(t *testing.T) {
	if os.Getenv("PRTHAK_PRIVATE_IPSET_LINUX") != "1" || runtime.GOOS != "linux" {
		t.Skip("explicit isolated Linux network only")
	}
	ctx := context.Background()
	a := &Agent{Config: Config{StateDir: t.TempDir(), Enforce: true, Zone: "public", ControllerURL: "https://controller.example.internal:8787", ManagementSources: []string{"10.254.231.0/24"}}, Commands: ExecRunner{}, State: State{Coverage: map[string]*Coverage{}}}
	a.armManaged = func(_ context.Context, path string, j *managedJournal) error {
		_, e := readManagedJournal(path, j.Nonce)
		return e
	}
	fixturePolicyTrust(t, a)
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return nil }
	a.checkLearningHealth = func(context.Context, *LearningAllow, Protection, string) error { return nil }
	protection, e := a.managedProtection(ctx)
	if e != nil || !protection.Ready {
		t.Fatalf("management preflight: %+v %v", protection, e)
	}
	a.protection = &protection
	a.inventory = &Report{IPs: []string{"10.254.231.2"}}
	listener, e := net.Listen("tcp", "0.0.0.0:18080")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "private-source-set-ok") })}
	go server.Serve(listener)
	defer server.Close()
	phase := func(number string) {
		fmt.Println("PRTHAK_IPSET_PHASE=" + number)
		deadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) {
			if _, e := os.Stat("/tmp/advance-" + number); e == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("private harness did not acknowledge phase " + number)
	}
	sources := func(client string) []string { return append(largeSources(0, 4999), client+"/32", "2001:db8:2::/64") }
	first := managedTestPolicy(protection, 1, sources("10.254.231.3")...)
	if e = a.applyManaged(ctx, first, protection); e != nil {
		t.Fatal(e)
	}
	phase("managed-a")
	second := managedTestPolicy(protection, 2, sources("10.254.231.4")...)
	if e = a.applyManaged(ctx, second, protection); e != nil {
		t.Fatal(e)
	}
	phase("managed-b")
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("private staged witness failure")
		}
		return nil
	}
	third := managedTestPolicy(protection, 3, sources("10.254.231.3")...)
	if e = a.applyManaged(ctx, third, protection); e == nil {
		t.Fatal("staged failure did not roll back")
	}
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return nil }
	phase("managed-rollback")
	// Separate accepts-only learned bank must override exactly its observed
	// source without changing ordinary managed policy version/source sets.
	a.Config.LearningAutoAllow = true
	session := Session{ID: "private-learning-ipset", PolicyAction: "auto_allow", ServerIDs: []string{"host-a"}, Ports: []Port{{Port: 18080, Protocol: "tcp"}}, StartsAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), Status: "active"}
	a.State.Policy = &Policy{ServerID: "host-a", LearningSessions: []Session{session}}
	learnedSources := append(largeSources(0, 4999), "10.254.231.3/32", "2001:db8::3/128")
	service := Service{Port: 18080, Protocol: "tcp", Sources: learnedSources}
	p := &LearningAllow{ServerID: "host-a", Generation: 1, Services: []Service{service}, PolicyIDs: []string{"private-learned"}, ProtectionDigest: protection.Digest, TargetIPsDigest: targetIPsDigest(a.inventory.IPs), Authorized: true, ExpiresAt: session.ExpiresAt, Authorities: []LearningAuthority{{PolicyID: "private-learned", SessionID: session.ID, Kind: "auto", ExpiresAt: session.ExpiresAt, Ports: session.Ports, Services: []Service{service}}}}
	for _, source := range learnedSources {
		prefix, _ := netip.ParsePrefix(source)
		learningEvidenceFor(a, session, prefix.Addr().String(), 18080)
	}
	p.Digest, _ = learningAllowDigest(p)
	p.BindingDigest = learningAllowBinding(p)
	if e = a.processLearningAllow(ctx, p); e != nil || a.State.LearningAllowOutcome.Status != "applied" {
		t.Fatalf("learned source sets: %+v %v", a.State.LearningAllowOutcome, e)
	}
	if a.State.AppliedVersion != 2 {
		t.Fatal("learning changed ordinary policy version")
	}
	phase("learning-allow")
	cleanup := *p
	cleanup.Generation = 2
	cleanup.Services = []Service{}
	cleanup.PolicyIDs = []string{}
	cleanup.Authorities = []LearningAuthority{{PolicyID: "private-learned", Kind: "reviewed", ExpiresAt: session.ExpiresAt, Services: []Service{}}}
	cleanup.Digest, _ = learningAllowDigest(&cleanup)
	cleanup.BindingDigest = learningAllowBinding(&cleanup)
	if e = a.processLearningAllow(ctx, &cleanup); e != nil || a.State.LearningAllowOutcome.Status != "applied" {
		t.Fatalf("learned cleanup: %+v %v", a.State.LearningAllowOutcome, e)
	}
	phase("learning-cleanup")
	remove := managedTestPolicy(protection, 4)
	remove.Mode = "monitor"
	remove.Services = []Service{}
	remove.Digest, _ = compiledPolicyDigest(remove)
	remove.Enforcement.ApprovedDigest = remove.Digest
	remove.Enforcement.BindingDigest = enforcementBinding(remove, protection.Digest)
	remove.Enforcement.Intent = "remove_managed_rules"
	if e = a.applyManaged(ctx, remove, protection); e != nil {
		t.Fatal(e)
	}
	phase("managed-cleanup")
	for _, scope := range []string{"runtime", "permanent"} {
		raw, e := a.Commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--zone=public", "--list-rich-rules")...)
		if e != nil || strings.Contains(raw, "PRTM") || strings.Contains(raw, "PRTL") {
			t.Fatal("owned rules survived reviewed cleanup")
		}
	}
}
