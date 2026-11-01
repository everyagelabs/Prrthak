package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

type SingleAdminPilotScope struct {
	Revision  int       `json:"revision"`
	ExpiresAt time.Time `json:"expires_at"`
	ServerIDs []string  `json:"server_ids"`
}
type pilotConfirmation struct {
	NonceHash   string    `json:"nonce_sha256"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}
type endpointApprovalProof struct {
	ProviderAuthority map[string]string          `json:"provider_authority,omitempty"`
	Scope             map[string]json.RawMessage `json:"scope,omitempty"`
	BindingDigest     string                     `json:"binding_digest,omitempty"`
	Scheme            string                     `json:"scheme"`
	Mode              string                     `json:"mode"`
	Stage             string                     `json:"stage"`
	PlanID            string                     `json:"plan_id"`
	PlanDigest        string                     `json:"plan_digest"`
	Requester         configurationPerson        `json:"requester"`
	SubmittedBy       configurationPerson        `json:"submitted_by"`
	ApprovedBy        configurationPerson        `json:"approved_by"`
	Pilot             *SingleAdminPilotScope     `json:"pilot,omitempty"`
	Confirmations     []pilotConfirmation        `json:"pilot_confirmations,omitempty"`
}

// Legacy independent proof decoding remains for retained signed assignments.
// New actions use single_admin; retired pilot grants cannot authorize mutation.
func validateLegacyEndpointApproval(c Config, raw json.RawMessage, serverID string, now time.Time, configurationConsent bool) error {
	var p endpointApprovalProof
	if json.Unmarshal(raw, &p) != nil || p.Mode != "independent_entra" || p.Requester.UserID == "" || p.Requester.UserID != p.SubmittedBy.UserID || p.Requester.UserID == p.ApprovedBy.UserID || p.ApprovedBy.UserID == "" || p.Requester.TenantID == "" || p.Requester.TenantID != p.SubmittedBy.TenantID || p.Requester.TenantID != p.ApprovedBy.TenantID {
		return errors.New("invalid retained independent authorization")
	}
	return nil
}
func validateEndpointApproval(c Config, raw json.RawMessage, serverID string, now time.Time, configurationConsent bool, expectedKinds ...string) error {
	if len(raw) == 0 {
		return nil
	} // Compatibility for previously signed production assignments.
	if len(raw) > 16*1024 {
		return errors.New("endpoint approval proof exceeds its bound")
	}
	var proof endpointApprovalProof
	if json.Unmarshal(raw, &proof) != nil || proof.Scheme != "prthak-maker-checker-v1" || proof.Stage != "approved" {
		return errors.New("invalid endpoint approval proof")
	}
	if proof.Mode == "independent_entra" {
		return validateLegacyEndpointApproval(c, raw, serverID, now, configurationConsent)
	}
	if proof.Mode != "single_admin" {
		return errors.New("retired, unknown or lab-only approval mode cannot authorize a new mutation")
	}
	a, b, d := proof.Requester, proof.SubmittedBy, proof.ApprovedBy
	if a.UserID == "" || a.UserID != b.UserID || a.UserID != d.UserID || a.TenantID == "" || a.TenantID != b.TenantID || a.TenantID != d.TenantID ||
		!validDigest(proof.PlanDigest) || proof.PlanID == "" || !validDigest(proof.ProviderAuthority["fingerprint"]) ||
		proof.ProviderAuthority["epoch"] != "" && !validDigest(proof.ProviderAuthority["epoch"]) {
		return errors.New("single-admin authority requires one attributed Entra actor and provider binding")
	}
	if err := validateDirectApprovalBinding(raw, proof.BindingDigest); err != nil {
		return err
	}
	if len(expectedKinds) > 0 {
		var kind string
		_ = json.Unmarshal(proof.Scope["kind"], &kind)
		matches := false
		for _, expected := range expectedKinds {
			if kind == expected {
				matches = true
			}
		}
		if !matches {
			return errors.New("single-admin authority belongs to a different operation kind")
		}
	}
	return validateDirectApprovalScope(proof.Scope, serverID, configurationConsent)
}

// Match controller.store.digest: sorted JSON with ensure_ascii=True.
func directApprovalDigest(value any) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return ""
	}
	var ascii strings.Builder
	for _, r := range strings.TrimSuffix(buffer.String(), "\n") {
		if r < 127 {
			ascii.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&ascii, "\\u%04x", r)
		} else {
			a, b := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, "\\u%04x\\u%04x", a, b)
		}
	}
	hash := sha256.Sum256([]byte(ascii.String()))
	return fmt.Sprintf("%x", hash[:])
}
func validateDirectApprovalBinding(raw json.RawMessage, expected string) error {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if !validDigest(expected) || decoder.Decode(&value) != nil {
		return errors.New("single-admin proof binding is missing")
	}
	authority, ok := value["provider_authority"].(map[string]any)
	if !ok {
		return errors.New("single-admin provider binding is missing")
	}
	if _, ok := authority["epoch"].(string); !ok {
		return errors.New("single-admin provider epoch must be an opaque string")
	}
	delete(value, "binding_digest")
	if directApprovalDigest(value) != expected {
		return errors.New("single-admin proof content changed after authorization")
	}
	return nil
}
func validateDirectApprovalScope(scope map[string]json.RawMessage, serverID string, configurationConsent bool) error {
	var kind string
	if json.Unmarshal(scope["kind"], &kind) != nil {
		return errors.New("single-admin proof has no typed scope")
	}
	if configurationConsent && kind != "endpoint_configuration" {
		return errors.New("endpoint configuration requires its exact authorization kind")
	}
	switch kind {
	case "endpoint_configuration", "managed_policy", "managed_rollout", "imported_firewall", "learning":
	default:
		return errors.New("single-admin scope cannot authorize this endpoint operation")
	}
	if ids, ok := scope["server_ids"]; ok {
		var values []string
		if json.Unmarshal(ids, &values) != nil || len(values) == 0 {
			return errors.New("single-admin endpoint scope is empty")
		}
		seen := map[string]bool{}
		found := false
		for _, id := range values {
			if id == "" || len(id) > 100 || seen[id] {
				return errors.New("single-admin endpoint scope is invalid")
			}
			seen[id] = true
			if id == serverID {
				found = true
			}
		}
		if !found {
			return errors.New("single-admin scope belongs to a different endpoint")
		}
		return nil
	}
	if kind == "endpoint_configuration" {
		return errors.New("configuration authorization requires an exact endpoint")
	}
	var count int
	var digest string
	if json.Unmarshal(scope["target_count"], &count) == nil && count > 0 && json.Unmarshal(scope["target_digest"], &digest) == nil && validDigest(digest) {
		return nil
	}
	var policies []string
	if kind == "managed_policy" && json.Unmarshal(scope["policy_ids"], &policies) == nil && len(policies) > 0 && json.Unmarshal(scope["intent_digest"], &digest) == nil && validDigest(digest) {
		seen := map[string]bool{}
		for _, id := range policies {
			if id == "" || len(id) > 100 || seen[id] {
				return errors.New("single-admin policy scope is invalid")
			}
			seen[id] = true
		}
		return nil
	}
	return errors.New("single-admin proof requires an exact signed target or intent scope")
}
