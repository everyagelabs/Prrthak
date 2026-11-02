package agent

import (
	"encoding/json"
	"time"
)

const SourceBankPreparationCapability = "source_bank_preparation_v1"
const sourceBankCount = 4 * 2 * managedSetSlots

// This is a dedicated maintenance authority, never policy-enforcement consent.
// Only canonical empty owned definitions may be added, and a reviewed reload is
// allowed only when the effective runtime/permanent configuration is identical.
type SourceBankPreparationAssignment struct {
	ID               string          `json:"id"`
	Operation        string          `json:"operation"`
	PlanDigest       string          `json:"plan_digest"`
	BaselineDigest   string          `json:"baseline_digest"`
	ProtectionDigest string          `json:"protection_digest"`
	ExpiresAt        time.Time       `json:"expires_at"`
	ApprovalProof    json.RawMessage `json:"approval_proof,omitempty"`
}

type SourceBankPreparationReport struct {
	SchemaVersion      int       `json:"schema_version"`
	ID                 string    `json:"id"`
	Operation          string    `json:"operation"`
	PlanDigest         string    `json:"plan_digest"`
	Status             string    `json:"status"`
	CheckedAt          time.Time `json:"checked_at"`
	BaselineDigest     string    `json:"baseline_digest"`
	ProtectionDigest   string    `json:"protection_digest"`
	MissingBanks       int       `json:"missing_banks"`
	ActiveBanks        int       `json:"active_banks"`
	PermanentBanks     int       `json:"permanent_banks"`
	CreatedBanks       int       `json:"created_banks"`
	ActivationRequired bool      `json:"activation_required"`
	Blockers           []string  `json:"blockers"`
	Error              string    `json:"error,omitempty"`
}

type sourceBankDefinition struct {
	Family  string            `json:"family"`
	Options map[string]string `json:"options"`
	Entries []string          `json:"entries"`
}

type sourceBankBaseline struct {
	OwnedRules        []ManagedRule                   `json:"owned_rules"`
	ContextDigest     string                          `json:"context_digest"`
	RuntimeBindings   map[string]string               `json:"runtime_bindings"`
	PermanentBindings map[string]string               `json:"permanent_bindings"`
	Runtime           map[string]sourceBankDefinition `json:"runtime"`
	Permanent         map[string]sourceBankDefinition `json:"permanent"`
	Digest            string                          `json:"digest"`
}

type sourceBankJournal struct {
	Assignment SourceBankPreparationAssignment `json:"assignment"`
	Baseline   sourceBankBaseline              `json:"baseline"`
	Created    []string                        `json:"created"`
	Reloaded   bool                            `json:"reloaded"`
	Report     SourceBankPreparationReport     `json:"report"`
}
