package agent

import (
	"encoding/json"
	"time"
)

type EnforcementAuthorization struct {
	HostDefaultDenyAck                 bool            `json:"host_default_deny_ack,omitempty"`
	HostDefaultDenyRevision            int             `json:"host_default_deny_revision,omitempty"`
	HostDefaultDenyConfigurationDigest string          `json:"host_default_deny_configuration_digest,omitempty"`
	ApprovalProof                      json.RawMessage `json:"approval_proof,omitempty"`
	Intent                             string          `json:"intent,omitempty"`
	Authorized                         bool            `json:"authorized"`
	ApprovalID                         string          `json:"approval_id"`
	ApprovedDigest                     string          `json:"approved_digest"`
	ApprovedVersion                    int             `json:"approved_version"`
	ProtectionDigest                   string          `json:"protection_digest"`
	BindingDigest                      string          `json:"binding_digest"`
	ConfirmationCount                  int             `json:"confirmation_count"`
	ExpiresAt                          time.Time       `json:"expires_at"`
}
type Protection struct {
	HostDefaultDenyReady          bool     `json:"host_default_deny_ready,omitempty"`
	HostDefaultDenyContextDigest  string   `json:"host_default_deny_context_digest,omitempty"`
	HostDefaultDenyBlockers       []string `json:"host_default_deny_blockers,omitempty"`
	HostDefaultDenyControlProfile string   `json:"host_default_deny_control_profile,omitempty"`
	Digest                        string   `json:"digest"`
	Ready                         bool     `json:"ready"`
	ManagementSources             []string `json:"management_sources"`
	SSHPorts                      []int    `json:"ssh_ports"`
	ControllerURL                 string   `json:"controller_url"`
	ManagementProbeURL            string   `json:"management_probe_url"`
	Zone                          string   `json:"zone"`
	Blockers                      []string `json:"blockers"`
}
type ManagedEnforcement struct {
	ManagedRulesPresent   *bool     `json:"managed_rules_present,omitempty"`
	HostDefaultDenyActive bool      `json:"host_default_deny_active"`
	LastGoodVersion       int       `json:"last_good_version"`
	LastGoodDigest        string    `json:"last_good_digest"`
	Status                string    `json:"status"`
	Version               int       `json:"version"`
	Digest                string    `json:"digest"`
	ApprovalID            string    `json:"approval_id,omitempty"`
	RollbackReason        string    `json:"rollback_reason,omitempty"`
	Error                 string    `json:"error,omitempty"`
	UpdatedAt             time.Time `json:"updated_at"`
}
type ManagedRule struct {
	Zone string `json:"zone"`
	Rule string `json:"rule"`
}
type ManagedBundle struct {
	HostDefaultDeny         bool                 `json:"host_default_deny,omitempty"`
	HostDefaultDenyServices []Service            `json:"host_default_deny_services,omitempty"`
	HostDefaultDenyMode     string               `json:"host_default_deny_mode,omitempty"`
	Learning                *LearningAllowBundle `json:"learning_allow,omitempty"`
	TopologyDigest          string               `json:"topology_digest"`
	Generation              string               `json:"generation"`
	ProtectionDigest        string               `json:"protection_digest"`
	Version                 int                  `json:"version"`
	Digest                  string               `json:"digest"`
	ApprovalID              string               `json:"approval_id"`
	Rules                   []ManagedRule        `json:"rules"`
	IPSets                  []ManagedIPSet       `json:"ipsets,omitempty"`
}
type managedMutation struct {
	Scope  string `json:"scope"`
	Zone   string `json:"zone"`
	Rule   string `json:"rule"`
	Before bool   `json:"before"`
	After  bool   `json:"after"`
}
type managedJournal struct {
	SourceBankPreparation *sourceBankJournal     `json:"source_bank_preparation,omitempty"`
	Nonce                 string                 `json:"nonce"`
	Phase                 string                 `json:"phase"`
	DeadlineBootSeconds   float64                `json:"deadline_boot_seconds"`
	Deadline              time.Time              `json:"deadline"`
	PID                   int                    `json:"pid"`
	ProcessIdentity       string                 `json:"process_identity"`
	Previous              *ManagedBundle         `json:"previous,omitempty"`
	Next                  ManagedBundle          `json:"next"`
	Mutations             []managedMutation      `json:"mutations"`
	SetMutations          []managedIPSetMutation `json:"set_mutations,omitempty"`
	Error                 string                 `json:"error,omitempty"`
}

type ManagedFailure struct {
	Version    int    `json:"version"`
	Digest     string `json:"digest"`
	ApprovalID string `json:"approval_id"`
	Reason     string `json:"reason"`
}
