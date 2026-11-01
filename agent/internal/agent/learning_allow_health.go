package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

func (a *Agent) learningAllowHealth(ctx context.Context, p *LearningAllow, protection Protection) error {
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return e
	}
	nonce := hex.EncodeToString(raw)
	if a.checkLearningHealth != nil {
		return a.checkLearningHealth(ctx, p, protection, nonce)
	}
	if a.Client == nil || a.Client.simulate {
		return errors.New("fresh authenticated learning management witness unavailable")
	}
	fresh, e := NewClient(a.Config, false)
	if e != nil {
		return e
	}
	transport := fresh.HTTP.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	payload := map[string]any{"generation": p.Generation, "digest": p.Digest, "protection_digest": p.ProtectionDigest, "target_ips_digest": p.TargetIPsDigest, "binding_digest": p.BindingDigest, "nonce": nonce, "ssh_ports": protection.SSHPorts}
	response, e := fresh.request(ctx, "POST", "/api/v1/agent/learning-allow/check", payload, "")
	if e != nil {
		return e
	}
	var witness managedWitness
	if e = decodeResponse(response, &witness); e != nil {
		return e
	}
	if witness.Generation != p.Generation || witness.TargetIPsDigest != p.TargetIPsDigest {
		return errors.New("learning management witness generation/IP binding mismatch")
	}
	// The shared verifier checks fresh nonce, mTLS-reported host identity, exact
	// content/protection/binding digests, time and actual SSH sources/ports.
	witness.Version = p.Generation
	expected := &Policy{ServerID: p.ServerID, Version: p.Generation, Digest: p.Digest, Enforcement: &EnforcementAuthorization{BindingDigest: p.BindingDigest}}
	return a.validateManagedWitness(witness, expected, protection, nonce, time.Now().UTC())
}
