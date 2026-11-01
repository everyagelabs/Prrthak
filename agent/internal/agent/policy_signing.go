package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type PolicySignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type policyTrust struct {
	DeploymentID string            `json:"deployment_id"`
	Keys         map[string]string `json:"keys"`
}
type signedPolicyEnvelope struct {
	Domain       string `json:"domain"`
	DeploymentID string `json:"deployment_id"`
	IssuedAt     int64  `json:"issued_at"`
	ExpiresAt    int64  `json:"expires_at"`
	Policy       Policy `json:"policy"`
}

func ValidatePolicySignature(c Config, p *Policy) error {
	return validatePolicySignatureAt(c, p, time.Now())
}
func policySigningRequired(c Config) bool {
	if c.Enforce || c.AllowHostDefaultDeny || c.LearningAutoAllow || c.AllowFirewallChanges || c.PolicySigningTrustFile != "" || len(c.PolicySigningKeys) > 0 {
		return true
	}
	_, e := os.Lstat(filepath.Join(c.StateDir, "policy-signing-trust.json"))
	return e == nil
}
func loadPolicySigningTrust(c Config) (policyTrust, error) {
	keys := map[string]string{}
	for identifier, value := range c.PolicySigningKeys {
		keys[identifier] = value
	}
	trust := policyTrust{DeploymentID: c.PolicySigningDeploymentID, Keys: keys}
	path := c.PolicySigningTrustFile
	if path == "" && len(c.PolicySigningKeys) == 0 {
		path = filepath.Join(c.StateDir, "policy-signing-trust.json")
	}
	if path != "" {
		if !filepath.IsAbs(path) {
			return trust, errors.New("policy signing public trust path must be absolute")
		}
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 16384 {
			return trust, errors.New("policy signing trust must be a regular non-writable public manifest")
		}
		raw, e := os.ReadFile(path)
		// Decode into a fresh map: unmarshalling into an existing map merges
		// entries and can silently retain a key removed from the trust file.
		var current policyTrust
		if e != nil || json.Unmarshal(raw, &current) != nil {
			return trust, errors.New("policy signing public trust is invalid")
		}
		trust = current
	}
	if trust.DeploymentID == "" || len(trust.DeploymentID) > 128 || len(trust.Keys) == 0 || len(trust.Keys) > 8 {
		return trust, errors.New("mutating assignments require a separately pinned policy signing deployment and key")
	}
	for key, encoded := range trust.Keys {
		public, e := base64.StdEncoding.Strict().DecodeString(encoded)
		id := sha256.Sum256(public)
		if e != nil || len(public) != ed25519.PublicKeySize || hex.EncodeToString(id[:])[:32] != key {
			return trust, errors.New("invalid pinned policy signing public key")
		}
	}
	return trust, nil
}
func policySigningReadiness(c Config) error {
	if !policySigningRequired(c) {
		return nil
	}
	_, e := loadPolicySigningTrust(c)
	return e
}
func validatePolicySignatureAt(c Config, p *Policy, now time.Time) error {
	if !policySigningRequired(c) {
		return nil
	}
	trust, e := loadPolicySigningTrust(c)
	if e != nil {
		return e
	}
	if p == nil || p.Signature == nil {
		return errors.New("a signed policy assignment is required before mutation")
	}
	s := p.Signature
	if s.Algorithm != "Ed25519" || len(s.Payload) > 6*1024*1024 {
		return errors.New("invalid policy signature envelope")
	}
	public, e := base64.StdEncoding.Strict().DecodeString(trust.Keys[s.KeyID])
	id := sha256.Sum256(public)
	if e != nil || len(public) != ed25519.PublicKeySize || hex.EncodeToString(id[:])[:32] != s.KeyID {
		return errors.New("policy signer is not pinned in local trust")
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if e != nil || len(payload) > 4*1024*1024 {
		return errors.New("invalid signed policy payload")
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if e != nil || !ed25519.Verify(public, payload, signature) {
		return errors.New("policy signature did not verify")
	}
	var document signedPolicyEnvelope
	if json.Unmarshal(payload, &document) != nil || document.Domain != "prthak-policy-assignment-v1" || document.DeploymentID != trust.DeploymentID || document.IssuedAt > now.Unix()+60 || document.ExpiresAt <= document.IssuedAt || document.ExpiresAt-document.IssuedAt > 1800 || now.Unix() >= document.ExpiresAt {
		return errors.New("signed policy deployment or validity is invalid")
	}
	if document.Policy.Signature != nil {
		return errors.New("nested assignment signature refused")
	}
	actual := *p
	actual.Signature = nil
	// Typed canonicalization normalizes timestamps/HTML escaping identically on
	// both sides without assuming Python and Go emit identical raw JSON bytes.
	a := configurationCanonical(actual)
	b := configurationCanonical(document.Policy)
	if a == nil || b == nil || !bytes.Equal(a, b) {
		return errors.New("signed policy content differs from delivered assignment")
	}
	return nil
}
