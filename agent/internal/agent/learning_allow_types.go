package agent

import (
	"encoding/json"
	"time"
)

const LearningAutoAllowCapability = "learning_auto_allow_v1"
const LearningIPSetCapability = "learning_ipsets_v1"
const maxLearningSourceEntries = 10000
const learningAllowCanonicalPriority = -31003
const learningAllowStagePriority = -31004

type LearningAuthority struct {
	ObservationKinds []string        `json:"observation_kinds,omitempty"`
	ApprovalProof    json.RawMessage `json:"approval_proof,omitempty"`
	PolicyID         string          `json:"policy_id"`
	SessionID        string          `json:"session_id,omitempty"`
	Kind             string          `json:"kind"`
	ExpiresAt        time.Time       `json:"expires_at"`
	Ports            []Port          `json:"ports"`
	Services         []Service       `json:"services"`
}
type LearningAllow struct {
	ServerID         string              `json:"server_id"`
	Generation       int                 `json:"generation"`
	Digest           string              `json:"digest"`
	Services         []Service           `json:"services"`
	PolicyIDs        []string            `json:"policy_ids"`
	Authorities      []LearningAuthority `json:"authorities"`
	ProtectionDigest string              `json:"protection_digest"`
	TargetIPsDigest  string              `json:"target_ips_digest"`
	BindingDigest    string              `json:"binding_digest"`
	Authorized       bool                `json:"authorized"`
	Reason           string              `json:"reason,omitempty"`
	ExpiresAt        time.Time           `json:"expires_at"`
}
type LearningAllowOutcome struct {
	Generation        int       `json:"generation"`
	Digest            string    `json:"digest"`
	BindingDigest     string    `json:"binding_digest"`
	Status            string    `json:"status"`
	Error             string    `json:"error,omitempty"`
	AppliedGeneration int       `json:"applied_generation"`
	AppliedDigest     string    `json:"applied_digest"`
	UpdatedAt         time.Time `json:"updated_at"`
}
type LearningAllowBundle struct {
	Assignment     LearningAllow  `json:"assignment"`
	CommitNonce    string         `json:"commit_nonce"`
	TopologyDigest string         `json:"topology_digest"`
	Rules          []ManagedRule  `json:"rules"`
	IPSets         []ManagedIPSet `json:"ipsets,omitempty"`
}
type LearningEvidence struct {
	SourceIP  string    `json:"source_ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
