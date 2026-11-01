package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func signPolicyForTest(t *testing.T, p *Policy, now time.Time) (Config, *Policy) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	h := sha256.Sum256(public)
	id := hex.EncodeToString(h[:])[:32]
	copyPolicy := *p
	copyPolicy.Signature = nil
	if copyPolicy.AssignmentGeneration == 0 {
		copyPolicy.AssignmentGeneration = 1
	}
	if copyPolicy.AssignmentDigest == "" {
		body, err := json.Marshal(copyPolicy)
		if err != nil {
			t.Fatal(err)
		}
		copyPolicy.AssignmentDigest = shaText(string(body))
	}
	doc := signedPolicyEnvelope{Domain: "prthak-policy-assignment-v1", DeploymentID: "signing-test-deployment", IssuedAt: now.Unix() - 1, ExpiresAt: now.Unix() + 1700, Policy: copyPolicy}
	raw, e := json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	copyPolicy.Signature = &PolicySignature{Algorithm: "Ed25519", KeyID: id, Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
	return Config{Enforce: true, PolicySigningDeploymentID: doc.DeploymentID, PolicySigningKeys: map[string]string{id: base64.StdEncoding.EncodeToString(public)}}, &copyPolicy
}
func fixturePolicyTrust(t *testing.T, a *Agent) {
	t.Helper()
	c, _ := signPolicyForTest(t, &Policy{}, time.Now())
	a.Config.PolicySigningKeys = c.PolicySigningKeys
	a.Config.PolicySigningDeploymentID = c.PolicySigningDeploymentID
}
func TestPolicySignatureBindsEntireDeliveredAssignment(t *testing.T) {
	now := time.Now()
	c, p := signPolicyForTest(t, &Policy{ServerID: "endpoint", Version: 7, Digest: "a", Mode: "enforce", Services: []Service{{Port: 443, Protocol: "tcp", Sources: []string{"10.0.0.0/8"}}}}, now)
	if e := validatePolicySignatureAt(c, p, now); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Policy){func(v *Policy) { v.ServerID = "other" }, func(v *Policy) { v.Version++ }, func(v *Policy) { v.Enforcement = &EnforcementAuthorization{Authorized: true} }, func(v *Policy) { v.Services = nil }, func(v *Policy) { v.PollingSettings = &PollingSettings{Version: 10} }} {
		v := *p
		mutate(&v)
		if validatePolicySignatureAt(c, &v, now) == nil {
			t.Fatal("unsigned content modification accepted")
		}
	}
	if validatePolicySignatureAt(c, p, now.Add(time.Hour)) == nil {
		t.Fatal("expired signed assignment accepted")
	}
	c.PolicySigningDeploymentID = "other"
	if validatePolicySignatureAt(c, p, now) == nil {
		t.Fatal("foreign deployment accepted")
	}
}
func TestPolicyTrustIsPinnedOutsideHTTPSAndProtectedFromWritableFiles(t *testing.T) {
	now := time.Now()
	c, p := signPolicyForTest(t, &Policy{ServerID: "endpoint", Mode: "monitor"}, now)
	path := filepath.Join(t.TempDir(), "public-trust.json")
	raw, _ := json.Marshal(policyTrust{DeploymentID: c.PolicySigningDeploymentID, Keys: c.PolicySigningKeys})
	if e := os.WriteFile(path, raw, 0644); e != nil {
		t.Fatal(e)
	}
	c.PolicySigningTrustFile = path
	c.PolicySigningKeys = nil
	c.PolicySigningDeploymentID = ""
	if e := validatePolicySignatureAt(c, p, now); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0666); e != nil {
		t.Fatal(e)
	}
	if validatePolicySignatureAt(c, p, now) == nil {
		t.Fatal("writable trust file accepted")
	}
	for _, config := range []Config{{Enforce: true}, {LearningAutoAllow: true}, {AllowFirewallChanges: true}} {
		if validatePolicySignatureAt(config, &Policy{}, now) == nil {
			t.Fatal("mutating policy accepted without pinned key")
		}
	}
}
func TestPolicySigningDefaultEnrollmentPinAndReadiness(t *testing.T) {
	now := time.Now()
	c, p := signPolicyForTest(t, &Policy{ServerID: "endpoint", Mode: "monitor"}, now)
	dir := t.TempDir()
	raw, _ := json.Marshal(policyTrust{DeploymentID: c.PolicySigningDeploymentID, Keys: c.PolicySigningKeys})
	if e := os.WriteFile(filepath.Join(dir, "policy-signing-trust.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	config := Config{StateDir: dir}
	if e := validatePolicySignatureAt(config, p, now); e != nil {
		t.Fatal(e)
	}
	if e := validatePolicySignatureAt(config, &Policy{}, now); e == nil {
		t.Fatal("enrolled monitoring agent ignored its pinned signing authority")
	}
	config.Enforce = true
	if e := policySigningReadiness(config); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(dir, "policy-signing-trust.json")); e != nil {
		t.Fatal(e)
	}
	if policySigningReadiness(config) == nil {
		t.Fatal("missing trust did not block enforcement readiness")
	}
}
func TestPythonEd25519AssignmentVerifiesInNativeGoWithTimestampNormalization(t *testing.T) {
	raw, e := os.ReadFile("../../../controller/tests/fixtures/policy-signature.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		At     int64       `json:"at"`
		Trust  policyTrust `json:"trust"`
		Policy Policy      `json:"policy"`
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	c := Config{Enforce: true, PolicySigningDeploymentID: fixture.Trust.DeploymentID, PolicySigningKeys: fixture.Trust.Keys}
	if e = validatePolicySignatureAt(c, &fixture.Policy, time.Unix(fixture.At, 0)); e != nil {
		t.Fatal(e)
	}
	fixture.Policy.Services[0].Sources[0] = "0.0.0.0/0"
	if validatePolicySignatureAt(c, &fixture.Policy, time.Unix(fixture.At, 0)) == nil {
		t.Fatal("modified Python assignment accepted")
	}
}
