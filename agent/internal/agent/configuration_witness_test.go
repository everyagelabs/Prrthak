package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signConfigurationWitness(value configurationWitnessBody, key ed25519.PrivateKey, keyID string) signedConfigurationWitness {
	payload, _ := json.Marshal(map[string]any{"domain": "prthak-package-manifest-v1", "manifest": value})
	return signedConfigurationWitness{configurationWitnessBody: value, Signature: PolicySignature{Algorithm: "Ed25519", KeyID: keyID, Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}}
}
func TestConfigurationWitnessRequiresFreshSignedNonceAndEveryBinding(t *testing.T) {
	c, kit, key, _, now := configurationFixture(t)
	var proof configurationProof
	json.Unmarshal(kit.Manifest.Approval, &proof)
	nonce := strings.Repeat("a", 32)
	candidate := strings.Repeat("b", 64)
	body := configurationWitnessBody{Kind: "prthak-endpoint-configuration-witness-v1", Nonce: nonce, ServerID: kit.Manifest.Scope.ServerID, ReviewID: kit.Manifest.ReviewID, PlanDigest: proof.PlanDigest, CandidateDigest: candidate, Phase: "before", DeploymentID: kit.Manifest.DeploymentID, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	value := signConfigurationWitness(body, key, kit.Signature.KeyID)
	raw, _ := json.Marshal(value)
	var decoded signedConfigurationWitness
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	value = decoded
	if err := validateConfigurationWitness(c, &kit, value, nonce, candidate, "before", now, now); err != nil {
		t.Fatal(err)
	}
	if validateConfigurationWitness(c, &kit, value, strings.Repeat("c", 32), candidate, "before", now, now) == nil {
		t.Fatal("captured signed witness replayed for a new request nonce")
	}
	for _, alter := range []func(*configurationWitnessBody){func(v *configurationWitnessBody) { v.Phase = "after" }, func(v *configurationWitnessBody) { v.ServerID = "another-endpoint" }, func(v *configurationWitnessBody) { v.CandidateDigest = strings.Repeat("c", 64) }, func(v *configurationWitnessBody) { v.ExpiresAt = now.Add(time.Minute) }, func(v *configurationWitnessBody) {
		v.IssuedAt = now.Add(-time.Minute)
		v.ExpiresAt = now.Add(-30 * time.Second)
	}} {
		other := body
		alter(&other)
		signed := signConfigurationWitness(other, key, kit.Signature.KeyID)
		if validateConfigurationWitness(c, &kit, signed, nonce, candidate, "before", now, now) == nil {
			t.Fatal("rebound or stale signed witness accepted")
		}
	}
	value.Nonce = strings.Repeat("c", 32)
	if validateConfigurationWitness(c, &kit, value, value.Nonce, candidate, "before", now, now) == nil {
		t.Fatal("TLS-only response mutation substituted for pinned signed witness")
	}
}
