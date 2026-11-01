package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type configurationWitnessBody struct {
	Kind            string    `json:"kind"`
	Nonce           string    `json:"nonce"`
	ServerID        string    `json:"server_id"`
	ReviewID        string    `json:"review_id"`
	PlanDigest      string    `json:"plan_digest"`
	CandidateDigest string    `json:"candidate_digest"`
	Phase           string    `json:"phase"`
	DeploymentID    string    `json:"deployment_id"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}
type signedConfigurationWitness struct {
	configurationWitnessBody
	Signature PolicySignature `json:"signature"`
}

func validateConfigurationWitness(c Config, kit *configurationKit, value signedConfigurationWitness, nonce, candidateDigest, phase string, started, now time.Time) error {
	trust, err := loadPolicySigningTrust(c)
	if err != nil {
		return err
	}
	s := value.Signature
	if len(s.Payload) > 24*1024 || len(s.Signature) > 128 || len(s.KeyID) != 32 {
		return errors.New("configuration witness signature exceeds its bound")
	}
	public, keyErr := base64.StdEncoding.Strict().DecodeString(trust.Keys[s.KeyID])
	payload, payloadErr := base64.StdEncoding.Strict().DecodeString(s.Payload)
	signature, sigErr := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if s.Algorithm != "Ed25519" || keyErr != nil || payloadErr != nil || sigErr != nil || len(public) != ed25519.PublicKeySize || len(payload) > 16*1024 || !ed25519.Verify(public, payload, signature) {
		return errors.New("fresh configuration witness signature did not verify")
	}
	var envelope struct {
		Domain   string                   `json:"domain"`
		Manifest configurationWitnessBody `json:"manifest"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if strictSetupJSON(payload) != nil || decoder.Decode(&envelope) != nil || envelope.Domain != "prthak-package-manifest-v1" || !bytes.Equal(configurationCanonical(envelope.Manifest), configurationCanonical(value.configurationWitnessBody)) {
		return errors.New("configuration witness differs from the pinned signed response")
	}
	var proof configurationProof
	_ = json.Unmarshal(kit.Manifest.Approval, &proof)
	if value.Kind != "prthak-endpoint-configuration-witness-v1" || value.Nonce != nonce || value.ServerID != kit.Manifest.Scope.ServerID || value.ReviewID != kit.Manifest.ReviewID || value.PlanDigest != proof.PlanDigest || value.CandidateDigest != candidateDigest || value.Phase != phase || value.DeploymentID != kit.Manifest.DeploymentID || value.DeploymentID != trust.DeploymentID {
		return errors.New("configuration witness nonce, identity or authority binding mismatch")
	}
	if value.IssuedAt.Before(started.Add(-5*time.Second)) || value.IssuedAt.After(now.Add(5*time.Second)) || !value.ExpiresAt.After(now) || !value.ExpiresAt.After(value.IssuedAt) || value.ExpiresAt.Sub(value.IssuedAt) > 30*time.Second {
		return errors.New("configuration witness is stale or exceeds its short validity")
	}
	return nil
}
