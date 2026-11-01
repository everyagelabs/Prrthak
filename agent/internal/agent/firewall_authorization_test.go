package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFirewallAuthorizationRejectsRevocationBeforeAnyMutation(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", NewValue: "8081/tcp", Operation: "replace"})
	a.checkFirewallAuthorization = func(context.Context, FirewallChange, string) error { return errors.New("requester disabled") }
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "failed" || len(f.writes) > 0 {
		t.Fatal("revoked approval changed access")
	}
}
func TestFirewallAuthorizationRevokedBetweenOperationsRollsBackCompletedChanges(t *testing.T) {
	f := newFirewallFake()
	f.set("runtime", "port", "8080/tcp", true)
	f.set("permanent", "port", "8080/tcp", true)
	a := firewallAgent(t, f)
	plan := firewallPlan(f, FirewallOperation{Scope: "runtime", Zone: "public", Kind: "port", OldValue: "8080/tcp", NewValue: "8081/tcp", Operation: "replace"}, FirewallOperation{Scope: "permanent", Zone: "public", Kind: "port", OldValue: "8080/tcp", NewValue: "8081/tcp", Operation: "replace"})
	checks := 0
	a.checkFirewallAuthorization = func(context.Context, FirewallChange, string) error {
		checks++
		if checks >= 3 {
			return errors.New("checker disabled")
		}
		return nil
	}
	result := a.applyFirewallChange(context.Background(), plan)
	if result.Status != "failed" || !strings.Contains(result.Message, "rolled back") {
		t.Fatalf("unexpected outcome %+v", result)
	}
	for _, scope := range []string{"runtime", "permanent"} {
		if !f.has(scope, "port", "8080/tcp") || f.has(scope, "port", "8081/tcp") {
			t.Fatal("revocation compensation did not restore previous rule")
		}
	}
}
func TestFirewallAuthorizationWitnessRequiresEnrolledIdentityAndExactFreshBinding(t *testing.T) {
	now := time.Now().UTC()
	change := FirewallChange{ID: "plan-1", PlanDigest: strings.Repeat("a", 64), ExpiresAt: now.Add(time.Minute)}
	w := firewallAuthorizationWitness{Status: "authorized", ServerID: "enrolled-server", PlanID: change.ID, PlanDigest: change.PlanDigest, Nonce: "nonce", CheckedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	if e := validateFirewallAuthorizationWitness(w, "enrolled-server", change, "nonce", now); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*firewallAuthorizationWitness){func(v *firewallAuthorizationWitness) { v.ServerID = "other" }, func(v *firewallAuthorizationWitness) { v.PlanDigest = "bad" }, func(v *firewallAuthorizationWitness) { v.Nonce = "replayed" }, func(v *firewallAuthorizationWitness) { v.CheckedAt = now.Add(-time.Minute) }, func(v *firewallAuthorizationWitness) { v.ExpiresAt = now.Add(2 * time.Minute) }} {
		v := w
		mutate(&v)
		if validateFirewallAuthorizationWitness(v, "enrolled-server", change, "nonce", now) == nil {
			t.Fatal("invalid authorization witness accepted")
		}
	}
}
