package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	ProtectedSSHPorts            []int                  `json:"protected_ssh_ports,omitempty"`
	PolicySigningTrustFile       string                 `json:"policy_signing_trust_file"`
	PolicySigningKeys            map[string]string      `json:"policy_signing_keys,omitempty"`
	PolicySigningDeploymentID    string                 `json:"policy_signing_deployment_id"`
	LearningAutoAllow            bool                   `json:"learning_auto_allow"`
	ManagementProbeURL           string                 `json:"management_probe_url"`
	ManagementProbeCACert        string                 `json:"management_probe_ca_cert"`
	ControllerURL                string                 `json:"controller_url"`
	ControlURL                   string                 `json:"control_url,omitempty"`
	DiscoveryURL                 string                 `json:"discovery_url,omitempty"`
	StateDir                     string                 `json:"state_dir"`
	CACert                       string                 `json:"ca_cert"`
	EndpointCACert               string                 `json:"endpoint_ca_cert,omitempty"`
	Certificate                  string                 `json:"certificate"`
	PrivateKey                   string                 `json:"private_key"`
	EnrollmentTokenFile          string                 `json:"enrollment_token_file"`
	IntervalSeconds              int                    `json:"interval_seconds"`
	DiscoveryIntervalSeconds     int                    `json:"discovery_interval_seconds"`
	RequestTimeoutSeconds        int                    `json:"request_timeout_seconds"`
	Zone                         string                 `json:"zone"`
	Enforce                      bool                   `json:"enforce"`
	AllowHostDefaultDeny         bool                   `json:"allow_host_default_deny,omitempty"`
	AllowFirewallChanges         bool                   `json:"allow_firewall_changes"`
	AllowSingleAdminPilot        bool                   `json:"allow_single_admin_pilot,omitempty"`
	SingleAdminPilotScope        *SingleAdminPilotScope `json:"single_admin_pilot_scope,omitempty"`
	UnexpectedPortMonitorEnabled bool                   `json:"unexpected_port_monitor_enabled"`
	ProbeLogRatePerSecond        int                    `json:"probe_log_rate_per_second"`
	ManagementSources            []string               `json:"management_sources"`
	DemoAgentID                  string                 `json:"demo_agent_id"`
	MaxSpoolBatches              int                    `json:"max_spool_batches"`
}

func defaultConfig() Config {
	return Config{ControllerURL: "https://controller.example.internal:8787", StateDir: "/var/lib/seg-agent", IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 15, MaxSpoolBatches: 500, ProbeLogRatePerSecond: 5}
}
func LoadConfig(path string, simulate bool) (Config, error) {
	c := defaultConfig()
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	return validateConfig(c, simulate)
}
func validateConfig(c Config, simulate bool) (Config, error) {
	if c.Certificate == "" {
		c.Certificate = filepath.Join(c.StateDir, "agent.crt")
	}
	if c.PrivateKey == "" {
		c.PrivateKey = filepath.Join(c.StateDir, "agent.key")
	}
	if c.IntervalSeconds < 5 || c.IntervalSeconds > 3600 {
		return c, errors.New("interval_seconds must be 5..3600")
	}
	if c.DiscoveryIntervalSeconds < 60 || c.DiscoveryIntervalSeconds > 86400 {
		return c, errors.New("discovery_interval_seconds must be 60..86400")
	}
	if c.RequestTimeoutSeconds < 1 || c.RequestTimeoutSeconds > 120 {
		return c, errors.New("request_timeout_seconds must be 1..120")
	}
	if c.MaxSpoolBatches < 1 || c.MaxSpoolBatches > 10000 {
		return c, errors.New("max_spool_batches must be 1..10000")
	}
	if c.ProbeLogRatePerSecond < 1 || c.ProbeLogRatePerSecond > 100 {
		return c, errors.New("probe_log_rate_per_second must be 1..100")
	}
	if !filepath.IsAbs(c.StateDir) {
		return c, errors.New("state_dir must be absolute")
	}
	u, e := url.Parse(c.ControllerURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return c, errors.New("controller_url must be an origin URL without credentials or path")
	}
	if u.Scheme != "https" && !(simulate && u.Scheme == "http" && isLoopback(u.Hostname())) {
		return c, errors.New("HTTPS required; simulation permits HTTP only on loopback")
	}
	if !simulate && c.CACert == "" {
		return c, errors.New("ca_cert is required; bootstrap never skips TLS verification")
	}
	for _, endpoint := range []string{c.ControlURL, c.DiscoveryURL} {
		if endpoint == "" {
			continue
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || parsed.Scheme != "https" && !(simulate && parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
			return c, errors.New("agent channel URLs must be trusted origin URLs without credentials, path, query or fragment")
		}
	}
	if !simulate && c.DemoAgentID != "" {
		return c, errors.New("demo_agent_id is only accepted with --simulate")
	}
	if c.ManagementProbeURL != "" {
		probeURL, err := url.Parse(c.ManagementProbeURL)
		if err != nil || probeURL.Scheme != "https" || probeURL.Host == "" || probeURL.User != nil || probeURL.RawQuery != "" || probeURL.Fragment != "" || c.ManagementProbeURL != configuredManagedProbe(c) {
			return c, errors.New("management_probe_url must be an HTTPS URL without credentials/query/fragment")
		}
	}
	for _, s := range c.ManagementSources {
		if _, e := parsePrefix(s); e != nil {
			return c, fmt.Errorf("invalid management source %q", s)
		}
	}
	if len(c.ProtectedSSHPorts) > 32 {
		return c, errors.New("protected_ssh_ports supports at most32 explicit local ports")
	}
	seenSSH := map[int]bool{}
	for _, port := range c.ProtectedSSHPorts {
		if port < 1 || port > 65535 || seenSSH[port] {
			return c, errors.New("protected_ssh_ports requires unique ports1..65535")
		}
		seenSSH[port] = true
	}
	return c, nil
}
func isLoopback(s string) bool {
	if s == "localhost" {
		return true
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}
func parsePrefix(s string) (netip.Prefix, error) {
	if a, e := netip.ParseAddr(s); e == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.ParsePrefix(s)
}
func ValidatePolicy(p *Policy) error {
	if p.HostDefaultDeny && p.Mode != "enforce" {
		return errors.New("whole-server default deny requires an enforce-mode bundle")
	}
	if p.Version < 0 || p.Digest == "" {
		return errors.New("invalid policy identity")
	}
	if p.Mode != "monitor" && p.Mode != "enforce" {
		return errors.New("invalid policy mode")
	}
	seen := map[string]bool{}
	for _, s := range p.Services {
		if s.Port < 1 || s.Port > 65535 || (s.Protocol != "tcp" && s.Protocol != "udp") {
			return errors.New("invalid policy service")
		}
		if s.Mode != "" && s.Mode != "monitor" && s.Mode != "enforce" {
			return errors.New("invalid service mode")
		}
		k := fmt.Sprintf("%s/%d", s.Protocol, s.Port)
		if seen[k] {
			return errors.New("duplicate compiled service")
		}
		seen[k] = true
		for _, src := range s.Sources {
			if _, e := parsePrefix(src); e != nil {
				return fmt.Errorf("invalid source %q", src)
			}
		}
	}
	if len(p.LearningSessions)+len(p.LearningTombstones) > 1000 {
		return errors.New("too many learning sessions")
	}
	for _, s := range append(append([]Session{}, p.LearningSessions...), p.LearningTombstones...) {
		if err := validateObservationKinds(s.ObservationKinds); err != nil {
			return err
		}
		if s.DenyLogCompatibility && !captureKindSelected(s.ObservationKinds, captureDenied) {
			return errors.New("deny log compatibility requires a signed denied traffic scope")
		}
		if s.TrafficCollectionMode != "" && (s.Purpose != "traffic" || s.TrafficCollectionMode != "sampled" && s.TrafficCollectionMode != "hits") {
			return errors.New("invalid traffic collection mode")
		}
		if s.PolicyAction != "" && s.PolicyAction != "observe" && s.PolicyAction != "auto_allow" {
			return errors.New("invalid learning policy_action")
		}
		if len(s.ID) < 8 || len(s.ID) > 128 || strings.IndexFunc(s.ID, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
		}) >= 0 {
			return errors.New("invalid learning ID")
		}
		maximumDuration := 7 * 24 * time.Hour
		switch s.Purpose {
		case "", "policy":
		case "traffic":
			if s.PolicyAction != "observe" || len(s.ObservationKinds) == 0 {
				return errors.New("traffic discovery requires typed observe-only capture")
			}
			maximumDuration = 30 * 24 * time.Hour
		default:
			return errors.New("invalid learning purpose")
		}
		if !s.ExpiresAt.After(s.StartsAt) || s.ExpiresAt.Sub(s.StartsAt) > maximumDuration {
			return errors.New("invalid learning time window")
		}
		if s.StoppedAt != nil && s.StoppedAt.Before(s.StartsAt) {
			return errors.New("invalid learning stop cutoff")
		}
		if s.SelectionMode != "" && s.SelectionMode != "manual" && s.SelectionMode != "discovered" {
			return errors.New("invalid learning selection mode")
		}
		if len(s.Ports) > 100 || (s.DiscoveryPending && (s.SelectionMode != "discovered" || len(s.Ports) != 0)) {
			return errors.New("invalid learning discovery assignment")
		}
		if len(s.Ports) == 0 && s.SelectionMode != "discovered" {
			return errors.New("learning requires selected ports")
		}
		for _, port := range s.Ports {
			if port.Port < 1 || port.Port > 65535 || (port.Protocol != "tcp" && port.Protocol != "udp") {
				return errors.New("invalid learning port")
			}
		}
	}
	return nil
}
func atomicJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, b) {
		return nil
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".seg-tmp-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	directory, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer directory.Close()
	return directory.Sync()
}
