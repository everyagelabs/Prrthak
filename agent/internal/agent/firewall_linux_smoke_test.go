package agent

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

type firewallSmokeRemoveFailure struct{ failed bool }

func (r *firewallSmokeRemoveFailure) Run(ctx context.Context, name string, args ...string) (string, error) {
	for _, arg := range args {
		if !r.failed && arg == "--remove-port=18081/tcp" {
			r.failed = true
			return "", errors.New("injected command failure before old-rule removal")
		}
	}
	return (ExecRunner{}).Run(ctx, name, args...)
}

// Explicit disposable private-network-namespace test only. Never enable on a host.
func TestRealApprovedFirewallPrivateLinuxSmoke(t *testing.T) {
	if os.Getenv("PRTHAK_PRIVATE_FIREWALL_SMOKE") != "1" {
		t.Skip("private NET_ADMIN container only")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	ctx := context.Background()
	commands := ExecRunner{}
	before := CollectFirewallSnapshot(ctx, commands, nil)
	if before.Status != "ok" {
		t.Fatalf("fresh inventory unavailable: %s", before.Error)
	}
	a := &Agent{Config: Config{StateDir: t.TempDir(), AllowFirewallChanges: true}, Commands: commands, State: State{Coverage: map[string]*Coverage{}}}
	// This private adapter-only fixture has no controller. Wire authorization is
	// exercised separately; bypass is a non-exported test callback, never config.
	a.checkFirewallAuthorization = func(context.Context, FirewallChange, string) error { return nil }
	change := FirewallChange{ID: "private-linux-firewall-smoke", PlanDigest: strings.Repeat("b", 64), ExpectedSnapshotDigest: before.Digest, ConfirmationCount: 2, RequiresDoubleConfirmation: true, ExpiresAt: time.Now().Add(2 * time.Minute), Operations: []FirewallOperation{
		{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "18080/tcp", NewValue: "18081/tcp", Operation: "replace"},
		{Scope: "permanent", Zone: "public", Kind: "port", OldValue: "18080/tcp", NewValue: "18081/tcp", Operation: "replace"},
	}}
	result := a.applyFirewallChange(ctx, change)
	if result.Status != "applied" {
		t.Fatalf("real firewall apply failed: %+v", result)
	}
	for _, scope := range []string{"runtime", "permanent"} {
		old, e := firewallQuery(ctx, commands, scope, "public", "port", "18080/tcp")
		if e != nil || old {
			t.Fatal("old port still present")
		}
		current, e := firewallQuery(ctx, commands, scope, "public", "port", "18081/tcp")
		if e != nil || !current {
			t.Fatal("new port not present")
		}
	}
	a.Commands = &firewallSmokeRemoveFailure{}
	rollback := FirewallChange{ID: "private-linux-rollback-smoke", PlanDigest: strings.Repeat("c", 64), ExpectedSnapshotDigest: CollectFirewallSnapshot(ctx, commands, nil).Digest, ConfirmationCount: 2, ExpiresAt: time.Now().Add(time.Minute), Operations: []FirewallOperation{{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "18081/tcp", NewValue: "18082/tcp", Operation: "replace"}}}
	failed := a.applyFirewallChange(ctx, rollback)
	if failed.Status != "failed" {
		t.Fatalf("injected rollback case did not fail %+v", failed)
	}
	old, e := firewallQuery(ctx, commands, "runtime", "public", "port", "18081/tcp")
	if e != nil || !old {
		t.Fatal("rollback lost original rule")
	}
	temporary, e := firewallQuery(ctx, commands, "runtime", "public", "port", "18082/tcp")
	if e != nil || temporary {
		t.Fatal("rollback left its temporary replacement")
	}
	t.Log("PASS: private Linux firewalld runtime+permanent exact replacement and inverse rollback, default ICMPv6 policy preserved")
}
