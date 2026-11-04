package agent

import (
	"encoding/json"
	"os"
	"time"
)

const FirewallActivationCapability = "firewall_activation_v1"

type FirewallActivationAssignment struct {
	ID                  string          `json:"id"`
	Operation           string          `json:"operation"`
	TargetOperation     string          `json:"target_operation"`
	PlanDigest          string          `json:"plan_digest"`
	BaselineDigest      string          `json:"baseline_digest"`
	ProtectionDigest    string          `json:"protection_digest"`
	ConfigurationDigest string          `json:"configuration_digest"`
	ExpiresAt           time.Time       `json:"expires_at"`
	ApprovalProof       json.RawMessage `json:"approval_proof,omitempty"`
}

type FirewallActivationRule struct {
	Family   string `json:"family"`
	Source   string `json:"source"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Priority int    `json:"priority"`
}

type FirewallActivationPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type FirewallActivationAssessment struct {
	FirewalldActive   bool                     `json:"firewalld_active"`
	FirewalldEnabled  string                   `json:"firewalld_enabled"`
	UFWActive         bool                     `json:"ufw_active"`
	UFWEnabled        string                   `json:"ufw_enabled"`
	Version           string                   `json:"version"`
	Backend           string                   `json:"backend"`
	Zone              string                   `json:"zone"`
	IPs               []string                 `json:"ips"`
	SSHPorts          []int                    `json:"ssh_ports"`
	ManagementSources []string                 `json:"management_sources"`
	DiscoveredPorts   []FirewallActivationPort `json:"discovered_ports"`
	TranslatedRules   []FirewallActivationRule `json:"translated_rules"`
	CanApply          bool                     `json:"can_apply"`
	Blockers          []string                 `json:"blockers"`
	Notes             []string                 `json:"notes"`
}

type FirewallActivationReport struct {
	SchemaVersion       int                           `json:"schema_version"`
	ID                  string                        `json:"id"`
	Operation           string                        `json:"operation"`
	TargetOperation     string                        `json:"target_operation"`
	PlanDigest          string                        `json:"plan_digest"`
	BaselineDigest      string                        `json:"baseline_digest"`
	ProtectionDigest    string                        `json:"protection_digest"`
	ConfigurationDigest string                        `json:"configuration_digest"`
	Status              string                        `json:"status"`
	CheckedAt           time.Time                     `json:"checked_at"`
	Assessment          *FirewallActivationAssessment `json:"assessment,omitempty"`
	Error               string                        `json:"error,omitempty"`
}

type firewallActivationFile struct {
	Before []byte      `json:"before"`
	After  []byte      `json:"after"`
	Mode   os.FileMode `json:"mode"`
	Absent bool        `json:"absent"`
}

type firewallActivationBaseline struct {
	NativeTopology string                       `json:"native_topology"`
	NativeContext  string                       `json:"native_context"`
	Assessment     FirewallActivationAssessment `json:"assessment"`
	Files          map[string]string            `json:"files"`
	Global         string                       `json:"global"`
	SourceBanks    *sourceBankBaseline          `json:"source_banks,omitempty"`
	Digest         string                       `json:"digest"`
}

type firewallActivationJournal struct {
	Assignment     FirewallActivationAssignment      `json:"assignment"`
	Baseline       firewallActivationBaseline        `json:"baseline"`
	ChangedFiles   map[string]firewallActivationFile `json:"changed_files"`
	CreatedPolicy  bool                              `json:"created_policy"`
	Reloaded       bool                              `json:"reloaded"`
	ServiceChanged bool                              `json:"service_changed"`
	UFWDisabled    bool                              `json:"ufw_disabled"`
	Report         FirewallActivationReport          `json:"report"`
}

// Hooks are private test injection only; none is configurable through JSON or
// a controller assignment. Real execution uses protected host paths and mTLS.
type firewallActivationHooks struct {
	Root               string
	ConfigurationLease func() (*os.File, error)
	Baseline           func() (firewallActivationBaseline, Protection, error)
	Health             func(FirewallActivationAssignment, Protection) error
	Arm                func(string, *managedJournal) error
	Attestation        func(bool) error
	CounterReadback    func() error
	Topology           func() (string, error)
}
