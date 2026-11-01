package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// Initial authenticated enrollment can establish public policy trust once.
// Existing pins/configured operator trust are never replaced by a TLS reply.
func (c *Client) pinEnrollmentSigningTrust(raw []byte) error {
	if c.config.PolicySigningTrustFile != "" || len(c.config.PolicySigningKeys) > 0 {
		return nil
	}
	var trust policyTrust
	if len(raw) > 16384 || json.Unmarshal(raw, &trust) != nil || len(trust.DeploymentID) != 36 || len(trust.Keys) < 1 || len(trust.Keys) > 8 {
		return errors.New("enrollment returned invalid policy signing public trust")
	}
	if value, err := hex.DecodeString(strings.ReplaceAll(trust.DeploymentID, "-", "")); err != nil || len(value) != 16 {
		return errors.New("policy signing deployment identity is invalid")
	}
	for id, encoded := range trust.Keys {
		public, err := base64.StdEncoding.Strict().DecodeString(encoded)
		hash := sha256.Sum256(public)
		if err != nil || len(public) != 32 || id != hex.EncodeToString(hash[:])[:32] {
			return errors.New("policy signing public key identity is invalid")
		}
	}
	value, err := json.Marshal(trust)
	if err != nil {
		return err
	}
	return writeOrVerifyPrivate(filepath.Join(c.config.StateDir, "policy-signing-trust.json"), value)
}
