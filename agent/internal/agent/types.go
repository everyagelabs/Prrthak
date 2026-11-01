package agent

import "time"

const Version = "0.8.0"

const LearningDiscoveryCapability = "learning_discovery_v1"
const HostDefaultDenyCapability = "host_default_deny_v1"

type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}
type Service struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Sources  []string `json:"sources"`
	Mode     string   `json:"mode,omitempty"`
}
type Session struct {
	PolicyAction     string     `json:"policy_action,omitempty"`
	ID               string     `json:"id"`
	SelectionMode    string     `json:"selection_mode,omitempty"`
	DiscoveryPending bool       `json:"discovery_pending,omitempty"`
	ServerIDs        []string   `json:"server_ids"`
	Ports            []Port     `json:"ports"`
	StartsAt         time.Time  `json:"starts_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	Status           string     `json:"status"`
	StoppedAt        *time.Time `json:"stopped_at,omitempty"`
}
type Policy struct {
	AssignmentGeneration int                       `json:"assignment_generation,omitempty"`
	AssignmentDigest     string                    `json:"assignment_digest,omitempty"`
	Signature            *PolicySignature          `json:"signature,omitempty"`
	PollingSettings      *PollingSettings          `json:"polling_settings,omitempty"`
	LearningAllow        *LearningAllow            `json:"learning_allow,omitempty"`
	Enforcement          *EnforcementAuthorization `json:"enforcement,omitempty"`
	ServerID             string                    `json:"server_id"`
	Version              int                       `json:"version"`
	Digest               string                    `json:"digest"`
	Mode                 string                    `json:"mode"`
	HostDefaultDeny      bool                      `json:"host_default_deny,omitempty"`
	Services             []Service                 `json:"services"`
	LearningSessions     []Session                 `json:"learning_sessions"`
	HitMonitors          []HitMonitorAssignment    `json:"hit_monitors,omitempty"`
	LearningTombstones   []Session                 `json:"learning_tombstones,omitempty"`
	GeneratedAt          time.Time                 `json:"generated_at"`
	FirewallChanges      []FirewallChange          `json:"firewall_changes,omitempty"`
}
type Listener struct {
	ProtectedSSH bool   `json:"protected_ssh,omitempty"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	Address      string `json:"address"`
	Process      string `json:"process"`
	PID          int    `json:"pid,omitempty"`
	Service      string `json:"service"`
	Application  string `json:"application,omitempty"`
	SystemdUnit  string `json:"systemd_unit,omitempty"`
}
type Coverage struct {
	SessionID     string     `json:"session_id"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	DroppedEvents int        `json:"dropped_events"`
	RateLimited   bool       `json:"rate_limited"`
	Error         string     `json:"error,omitempty"`
}
type Report struct {
	HitMonitor                  *HitMonitorCoverage         `json:"hit_monitor,omitempty"`
	HitMonitoring               []HitMonitorStatus          `json:"hit_monitoring,omitempty"`
	PollingSettings             *PollingSettingsReport      `json:"polling_settings,omitempty"`
	LearningAllowOutcome        *LearningAllowOutcome       `json:"learning_allow_outcome,omitempty"`
	AgentVersion                string                      `json:"agent_version"`
	Capabilities                []string                    `json:"capabilities"`
	LearningDiscoverySessionIDs []string                    `json:"learning_discovery_session_ids,omitempty"`
	Protection                  *Protection                 `json:"protection,omitempty"`
	ManagedEnforcement          *ManagedEnforcement         `json:"managed_enforcement,omitempty"`
	Hostname                    string                      `json:"hostname"`
	IPs                         []string                    `json:"ips"`
	OS                          string                      `json:"os"`
	OSVersion                   string                      `json:"os_version"`
	FirewalldVersion            string                      `json:"firewalld_version"`
	FirewallBackend             string                      `json:"firewall_backend"`
	FirewalldState              string                      `json:"firewalld_state"`
	UFWActive                   bool                        `json:"ufw_active"`
	Listeners                   []Listener                  `json:"listeners"`
	AppliedVersion              int                         `json:"applied_version"`
	ApplyStatus                 string                      `json:"apply_status"`
	ApplyError                  string                      `json:"apply_error"`
	CollectorStatus             string                      `json:"collector_status"`
	LearningCoverage            *Coverage                   `json:"learning_coverage,omitempty"`
	DiscoveryError              string                      `json:"discovery_error,omitempty"`
	DiscoveryPerformed          bool                        `json:"discovery_performed"`
	DiscoveredAt                *time.Time                  `json:"discovered_at,omitempty"`
	DiscoveryIntervalSeconds    int                         `json:"discovery_interval_seconds"`
	ControlIntervalSeconds      int                         `json:"control_interval_seconds"`
	ConfigurationState          *EndpointConfigurationState `json:"configuration_state,omitempty"`
	FirewallSnapshot            *FirewallSnapshot           `json:"firewall_snapshot,omitempty"`
	FirewallChangeResults       []FirewallChangeResult      `json:"firewall_change_results,omitempty"`
	SecurityEvents              []SecurityEvent             `json:"security_events,omitempty"`
	SecurityMonitor             *SecurityMonitorCoverage    `json:"security_monitor,omitempty"`
	discoverySequence           uint64                      // local acknowledgement guard; never serialized on the API
}
type Flow struct {
	SourceIP  string    `json:"source_ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Verdict   string    `json:"verdict"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
type Batch struct {
	BatchID   string `json:"batch_id"`
	SessionID string `json:"session_id"`
	Events    []Flow `json:"events"`
}
type OwnedRule struct {
	SessionID string    `json:"session_id"`
	Zone      string    `json:"zone"`
	Rule      string    `json:"rule"`
	ExpiresAt time.Time `json:"expires_at"`
}
type State struct {
	AssignmentGeneration        int                                    `json:"assignment_generation,omitempty"`
	AssignmentDigest            string                                 `json:"assignment_digest,omitempty"`
	SessionCutoffs              map[string]time.Time                   `json:"session_cutoffs,omitempty"`
	LearningAllowFailedSessions map[string]string                      `json:"learning_allow_failed_sessions,omitempty"`
	LearningAllowBundle         *LearningAllowBundle                   `json:"learning_allow_bundle,omitempty"`
	LearningAllowOutcome        *LearningAllowOutcome                  `json:"learning_allow_outcome,omitempty"`
	LearningEvidence            map[string]map[string]LearningEvidence `json:"learning_evidence,omitempty"`
	LearningAllowFailures       map[string]string                      `json:"learning_allow_failures,omitempty"`
	ManagedFailures             map[string]ManagedFailure              `json:"managed_failures,omitempty"`
	ManagedBundle               *ManagedBundle                         `json:"managed_bundle,omitempty"`
	ManagedEnforcement          *ManagedEnforcement                    `json:"managed_enforcement,omitempty"`
	Policy                      *Policy                                `json:"policy,omitempty"`
	ETag                        string                                 `json:"etag"`
	AppliedVersion              int                                    `json:"applied_version"`
	Rules                       []OwnedRule                            `json:"rules"`
	Coverage                    map[string]*Coverage                   `json:"coverage"`
	Cursor                      string                                 `json:"journal_cursor"`
	JournalSince                time.Time                              `json:"journal_since"`
	SpoolError                  string                                 `json:"spool_error,omitempty"`
	PendingDrains               map[string]Session                     `json:"pending_drains,omitempty"`
	FirewallChangeResults       []FirewallChangeResult                 `json:"firewall_change_results,omitempty"`
}
