package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

type firewallAuthorizationWitness struct {
	Status     string    `json:"status"`
	ServerID   string    `json:"server_id"`
	PlanID     string    `json:"plan_id"`
	PlanDigest string    `json:"plan_digest"`
	Nonce      string    `json:"nonce"`
	CheckedAt  time.Time `json:"checked_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (a *Agent) firewallAuthorization(ctx context.Context, change FirewallChange) error {
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return e
	}
	nonce := hex.EncodeToString(raw)
	if a.checkFirewallAuthorization != nil {
		return a.checkFirewallAuthorization(ctx, change, nonce)
	}
	if a.Client == nil || a.Client.simulate {
		return errors.New("fresh authenticated firewall approval witness unavailable")
	}
	fresh, e := NewClient(a.Config, false)
	if e != nil {
		return e
	}
	transport := fresh.HTTP.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	identities := transport.TLSClientConfig.Certificates
	if len(identities) != 1 || identities[0].Leaf == nil || identities[0].Leaf.Subject.CommonName == "" {
		return errors.New("enrolled client identity unavailable for firewall approval witness")
	}
	response, e := fresh.request(ctx, "POST", "/api/v1/agent/firewall/check", map[string]any{"plan_id": change.ID, "plan_digest": change.PlanDigest, "nonce": nonce}, "")
	if e != nil {
		return e
	}
	var witness firewallAuthorizationWitness
	if e = decodeResponse(response, &witness); e != nil {
		return e
	}
	return validateFirewallAuthorizationWitness(witness, identities[0].Leaf.Subject.CommonName, change, nonce, time.Now().UTC())
}
func validateFirewallAuthorizationWitness(w firewallAuthorizationWitness, server string, change FirewallChange, nonce string, now time.Time) error {
	if w.Status != "authorized" || w.ServerID != server || w.PlanID != change.ID || w.PlanDigest != change.PlanDigest || w.Nonce != nonce {
		return errors.New("firewall approval witness identity/plan/nonce mismatch")
	}
	if w.CheckedAt.Before(now.Add(-30*time.Second)) || w.CheckedAt.After(now.Add(5*time.Second)) || !w.ExpiresAt.After(now) || w.ExpiresAt.After(change.ExpiresAt) {
		return errors.New("firewall approval witness is stale or exceeds the reviewed plan expiry")
	}
	return nil
}
