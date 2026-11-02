package agent

import "time"

const PolicyVerificationCapability = "policy_verification_v1"

// A signed, endpoint-specific observation lease. It cannot authorize any access
// change, traffic generation, learning session or automatic allow grant.
type PolicyVerificationAssignment struct {
	SchemaVersion    int       `json:"schema_version"`
	ID               string    `json:"id"`
	DeploymentID     string    `json:"deployment_id"`
	ServerID         string    `json:"server_id"`
	Version          int       `json:"version"`
	Digest           string    `json:"digest"`
	ApprovalID       string    `json:"approval_id"`
	ProtectionDigest string    `json:"protection_digest"`
	TargetIPsDigest  string    `json:"target_ips_digest"`
	Ports            []Port    `json:"ports"`
	StartsAt         time.Time `json:"starts_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	WindowSeconds    int       `json:"window_seconds"`
}

type PolicyVerificationEvidence struct {
	EventID             string     `json:"event_id"`
	SourceIP            string     `json:"source_ip"`
	DestinationIP       string     `json:"destination_ip"`
	Port                int        `json:"port"`
	Protocol            string     `json:"protocol"`
	AddressFamily       string     `json:"address_family"`
	CaptureKind         string     `json:"capture_kind"`
	CaptureBackend      string     `json:"capture_backend"`
	CountUnit           string     `json:"count_unit"`
	ExpectedAction      string     `json:"expected_action"`
	ObservedAt          time.Time  `json:"observed_at"`
	ReceivedAt          time.Time  `json:"received_at"`
	CaptureEpoch        string     `json:"capture_epoch"`
	ConnectionStartedAt *time.Time `json:"connection_started_at,omitempty"`
	RulePrefix          string     `json:"rule_prefix,omitempty"`
}

type PolicyVerificationCase struct {
	Status   string                      `json:"status"`
	Reason   string                      `json:"reason"`
	Evidence *PolicyVerificationEvidence `json:"evidence,omitempty"`
}

type PolicyVerificationPort struct {
	Port     int                    `json:"port"`
	Protocol string                 `json:"protocol"`
	Allow    PolicyVerificationCase `json:"allow"`
	Deny     PolicyVerificationCase `json:"deny"`
}

type PolicyVerificationReport struct {
	SchemaVersion     int                      `json:"schema_version"`
	ID                string                   `json:"id"`
	DeploymentID      string                   `json:"deployment_id"`
	ServerID          string                   `json:"server_id"`
	Version           int                      `json:"version"`
	Digest            string                   `json:"digest"`
	ApprovalID        string                   `json:"approval_id"`
	ProtectionDigest  string                   `json:"protection_digest"`
	TargetIPsDigest   string                   `json:"target_ips_digest"`
	StartsAt          time.Time                `json:"starts_at"`
	ExpiresAt         time.Time                `json:"expires_at"`
	WindowSeconds     int                      `json:"window_seconds"`
	Sequence          int                      `json:"sequence"`
	State             string                   `json:"state"`
	AppliedGeneration string                   `json:"applied_generation"`
	ArmedAt           *time.Time               `json:"armed_at"`
	CommittedAt       *time.Time               `json:"committed_at"`
	CheckedAt         time.Time                `json:"checked_at"`
	Ports             []PolicyVerificationPort `json:"ports"`
	Error             string                   `json:"error,omitempty"`
}

// Private provenance is deliberately separate from the historical Flow wire.
// It cannot upgrade a journal hit or a receive timestamp into a new lifecycle.
type policyVerificationState struct {
	Assignment PolicyVerificationAssignment          `json:"assignment"`
	Report     PolicyVerificationReport              `json:"report"`
	ArmEpoch   string                                `json:"arm_epoch"`
	ReadbackAt *time.Time                            `json:"readback_at,omitempty"`
	Deadline   time.Time                             `json:"-"`
	Matchers   map[string]*verificationSourceMatcher `json:"-"`
	Confirmed  bool                                  `json:"-"` // Never restore authority across process restart.
}
