package agent

import (
	"encoding/json"
	"time"
)

const EgressControlCapability = "egress_control_v1"
const QuarantineCapability = "emergency_quarantine_v1"

// Auxiliary signed authorities are separate from the existing inbound matrix.
// Assess is read-only; apply/enable always require all existing local firewall
// opt-ins, an exact current context and dedicated administrative authority.
type EgressService struct {
	Port         int      `json:"port"`
	Protocol     string   `json:"protocol"`
	Destinations []string `json:"destinations"`
}
type EgressAssignment struct {
	SchemaVersion     int             `json:"schema_version"`
	ID                string          `json:"id"`
	PlanDigest        string          `json:"plan_digest"`
	Generation        int             `json:"generation"`
	Operation         string          `json:"operation"`
	ProtectionDigest  string          `json:"protection_digest"`
	ContextDigest     string          `json:"context_digest"`
	IssuedAt          time.Time       `json:"issued_at"`
	ApprovalExpiresAt time.Time       `json:"approval_expires_at"`
	ApprovalProof     json.RawMessage `json:"approval_proof,omitempty"`
	DowntimeAck       bool            `json:"downtime_ack"`
	DefaultDeny       bool            `json:"default_deny"`
	Services          []EgressService `json:"services"`
}
type QuarantineAssignment struct {
	SchemaVersion     int             `json:"schema_version"`
	ID                string          `json:"id"`
	PlanDigest        string          `json:"plan_digest"`
	Generation        int             `json:"generation"`
	Operation         string          `json:"operation"`
	ProtectionDigest  string          `json:"protection_digest"`
	ContextDigest     string          `json:"context_digest"`
	IssuedAt          time.Time       `json:"issued_at"`
	ApprovalExpiresAt time.Time       `json:"approval_expires_at"`
	ApprovalProof     json.RawMessage `json:"approval_proof,omitempty"`
	DowntimeAck       bool            `json:"downtime_ack"`
	ExpiresAt         time.Time       `json:"expires_at"`
}
type ProtectedEgress struct {
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Kind        string `json:"kind"`
}
type NetworkFeatureReport struct {
	Active           bool       `json:"active"`
	ActiveID         string     `json:"active_id"`
	ActivePlanDigest string     `json:"active_plan_digest"`
	ActiveGeneration int        `json:"active_generation"`
	ActiveExpiresAt  *time.Time `json:"active_expires_at"`
	Supported        bool       `json:"supported"`
	Ready            bool       `json:"ready"`
	Status           string     `json:"status"`
	ID               string     `json:"id"`
	PlanDigest       string     `json:"plan_digest"`
	Generation       int        `json:"generation"`
	ExpiresAt        *time.Time `json:"expires_at"`
	Error            string     `json:"error"`
}
type NetworkControlReport struct {
	SchemaVersion       int                  `json:"schema_version"`
	CheckedAt           time.Time            `json:"checked_at"`
	ProtectionDigest    string               `json:"protection_digest"`
	ContextDigest       string               `json:"context_digest"`
	ConfigurationDigest string               `json:"configuration_digest"`
	ProtectedEgress     []ProtectedEgress    `json:"protected_egress"`
	Egress              NetworkFeatureReport `json:"egress"`
	Quarantine          NetworkFeatureReport `json:"quarantine"`
	Blockers            []string             `json:"blockers"`
}
