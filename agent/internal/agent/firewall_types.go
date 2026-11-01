package agent

import (
	"encoding/json"
	"time"
)

type FirewallRule struct {
	Fingerprint string                `json:"fingerprint"`
	LogicalKey  string                `json:"logical_key"`
	Scope       string                `json:"scope"`
	Zone        string                `json:"zone"`
	Kind        string                `json:"kind"`
	Value       string                `json:"value"`
	Action      string                `json:"action"`
	Risk        string                `json:"risk"`
	Editable    bool                  `json:"editable"`
	Reason      string                `json:"reason,omitempty"`
	Ports       []FirewallServicePort `json:"ports,omitempty"`
}
type FirewallServicePort struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}
type FirewallSnapshot struct {
	CollectedAt  time.Time      `json:"collected_at"`
	Status       string         `json:"status"`
	Digest       string         `json:"digest"`
	Rules        []FirewallRule `json:"rules"`
	Error        string         `json:"error,omitempty"`
	Capabilities []string       `json:"capabilities"`
}
type FirewallOperation struct {
	Scope     string `json:"scope"`
	Zone      string `json:"zone"`
	Kind      string `json:"kind"`
	OldValue  string `json:"old_value"`
	NewValue  string `json:"new_value"`
	Operation string `json:"operation"`
}
type FirewallChange struct {
	ApprovalProof              json.RawMessage     `json:"approval_proof,omitempty"`
	ID                         string              `json:"id"`
	PlanDigest                 string              `json:"plan_digest"`
	ExpectedSnapshotDigest     string              `json:"expected_snapshot_digest"`
	RequiresDoubleConfirmation bool                `json:"requires_double_confirmation"`
	ConfirmationCount          int                 `json:"confirmation_count"`
	Operations                 []FirewallOperation `json:"operations"`
	ExpiresAt                  time.Time           `json:"expires_at"`
}
type FirewallChangeResult struct {
	ID             string    `json:"id"`
	PlanDigest     string    `json:"plan_digest"`
	Status         string    `json:"status"`
	Message        string    `json:"message"`
	CompletedAt    time.Time `json:"completed_at"`
	SnapshotDigest string    `json:"snapshot_digest,omitempty"`
	Acknowledged   bool      `json:"acknowledged,omitempty"`
}
type firewallMutation struct {
	PreviousValue string `json:"previous_value,omitempty"`
	Scope         string `json:"scope"`
	Zone          string `json:"zone"`
	Kind          string `json:"kind"`
	Value         string `json:"value"`
	Operation     string `json:"operation"`
	Completed     bool   `json:"completed"`
}
type firewallJournal struct {
	ID         string             `json:"id"`
	PlanDigest string             `json:"plan_digest"`
	Status     string             `json:"status"`
	Before     FirewallSnapshot   `json:"before"`
	Mutations  []firewallMutation `json:"mutations"`
	UpdatedAt  time.Time          `json:"updated_at"`
}
