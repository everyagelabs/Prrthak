package agent

// Endpoint configuration is deliberately not a polling assignment. Its signed
// maker/checker kit is applied locally by root under an independent watchdog.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

type EndpointConfigurationSettings struct {
	ControllerURL                string   `json:"controller_url"`
	ControlURL                   string   `json:"control_url"`
	DiscoveryURL                 string   `json:"discovery_url"`
	Enforce                      bool     `json:"enforce"`
	AllowHostDefaultDeny         bool     `json:"allow_host_default_deny,omitempty"`
	AllowFirewallChanges         bool     `json:"allow_firewall_changes"`
	LearningAutoAllow            bool     `json:"learning_auto_allow"`
	UnexpectedPortMonitorEnabled bool     `json:"unexpected_port_monitor_enabled"`
	ManagementSources            []string `json:"management_sources"`
	ProtectedSSHPorts            []int    `json:"protected_ssh_ports"`
	Zone                         string   `json:"zone"`
}
type EndpointConfigurationState struct {
	EndpointConfigurationSettings
	Digest string `json:"digest"`
}
type configurationScope struct {
	ServerID             string                        `json:"server_id"`
	Hostname             string                        `json:"hostname"`
	IPs                  []string                      `json:"ips"`
	ExpectedConfigDigest string                        `json:"expected_config_digest"`
	TargetBinding        string                        `json:"target_binding"`
	Settings             EndpointConfigurationSettings `json:"settings"`
	ControllerCA         string                        `json:"controller_ca_pem"`
	RetainOldOrigin      bool                          `json:"retain_old_origin"`
}
type configurationPerson struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
}
type configurationProof = endpointApprovalProof
type configurationManifest struct {
	Kind         string             `json:"kind"`
	ReviewID     string             `json:"review_id"`
	IssuedAt     time.Time          `json:"issued_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
	Scope        configurationScope `json:"scope"`
	Approval     json.RawMessage    `json:"approval"`
	DeploymentID string             `json:"deployment_id"`
}
type configurationKit struct {
	SchemaVersion int                   `json:"schema_version"`
	Manifest      configurationManifest `json:"manifest"`
	Signature     PolicySignature       `json:"signature"`
}
type configurationJournal struct {
	SchemaVersion       int       `json:"schema_version"`
	ReviewID            string    `json:"review_id"`
	Status              string    `json:"status"`
	Deadline            time.Time `json:"deadline"`
	DeadlineBootSeconds float64   `json:"deadline_boot_seconds"`
	ConfigPath          string    `json:"config_path"`
	OldConfig           []byte    `json:"old_config"`
	CandidateConfig     []byte    `json:"candidate_config"`
	OldCA               []byte    `json:"old_ca"`
	CandidateCA         []byte    `json:"candidate_ca"`
	OldEndpointCA       []byte    `json:"old_endpoint_ca"`
	CandidateEndpointCA []byte    `json:"candidate_endpoint_ca"`
	CoordinatorPID      int       `json:"coordinator_pid"`
	CoordinatorIdentity string    `json:"coordinator_identity"`
}

func configurationCanonical(value any) []byte {
	raw, _ := json.Marshal(value)
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&generic) != nil {
		return nil
	}
	encoded, _ := json.Marshal(generic)
	return encoded
}

func configDigest(c Config) string {
	raw, _ := json.Marshal(c)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func configurationMutationBlocked(c Config) bool {
	directory := filepath.Join(c.StateDir, "configuration-transitions")
	pointer := filepath.Join(directory, "active")
	if _, err := os.Lstat(pointer); os.IsNotExist(err) {
		return false
	}
	raw, err := readPrivateSetupBound(pointer, 1024)
	var active struct {
		ReviewID string `json:"review_id"`
	}
	if err != nil || json.Unmarshal(raw, &active) != nil || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(active.ReviewID) {
		return true
	}
	raw, err = readPrivateSetupBound(filepath.Join(directory, active.ReviewID+".json"), 2*1024*1024)
	var journal configurationJournal
	return err != nil || json.Unmarshal(raw, &journal) != nil || journal.SchemaVersion != 1 || journal.ReviewID != active.ReviewID || journal.Status != "committed" && journal.Status != "rolled_back"
}
func configurationState(c Config) *EndpointConfigurationState {
	sources := []string{}
	for _, value := range c.ManagementSources {
		if network, err := parsePrefix(value); err == nil {
			sources = append(sources, network.Masked().String())
		}
	}
	sort.Strings(sources)
	ports := append([]int{}, c.ProtectedSSHPorts...)
	sort.Ints(ports)
	return &EndpointConfigurationState{EndpointConfigurationSettings: EndpointConfigurationSettings{ControllerURL: c.ControllerURL, ControlURL: c.ControlURL, DiscoveryURL: c.DiscoveryURL, Enforce: c.Enforce, AllowHostDefaultDeny: c.AllowHostDefaultDeny, AllowFirewallChanges: c.AllowFirewallChanges, LearningAutoAllow: c.LearningAutoAllow, UnexpectedPortMonitorEnabled: c.UnexpectedPortMonitorEnabled, ManagementSources: sources, ProtectedSSHPorts: ports, Zone: c.Zone}, Digest: configDigest(c)}
}

// EndpointConfigurationReceipt exposes only public operational settings and a
// digest; no key, token, signing material or credential path is returned.
func EndpointConfigurationReceipt(configPath string) (*EndpointConfigurationState, error) {
	c, err := LoadConfig(configPath, false)
	if err != nil {
		return nil, err
	}
	return configurationState(c), nil
}
func CheckEndpointConfiguration(path, configPath string) error {
	c, err := LoadConfig(configPath, false)
	if err != nil {
		return err
	}
	_, err = readConfigurationKit(path, c, time.Now().UTC())
	return err
}
func transitionConfig(c Config, settings EndpointConfigurationSettings) (Config, error) {
	if settings.AllowHostDefaultDeny && (!settings.Enforce || settings.LearningAutoAllow) {
		return c, errors.New("whole-server default deny requires enforcement and prohibits automatic learned grants")
	}
	if settings.LearningAutoAllow && !settings.Enforce {
		return c, errors.New("automatic learned access requires the managed-enforcement local opt-in")
	}
	if (settings.Enforce || settings.AllowFirewallChanges || settings.LearningAutoAllow || settings.UnexpectedPortMonitorEnabled) && (len(settings.ManagementSources) == 0 || len(settings.ProtectedSSHPorts) == 0 || settings.Zone == "") {
		return c, errors.New("configuration opt-ins need explicit SSH and management protection")
	}
	for _, source := range settings.ManagementSources {
		network, err := parsePrefix(source)
		if err != nil || network.Bits() == 0 {
			return c, errors.New("configuration management protection must be a bounded network")
		}
	}
	if settings.Zone != "" && !regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`).MatchString(settings.Zone) {
		return c, errors.New("invalid configuration zone")
	}
	if c.ControllerURL != settings.ControllerURL || c.ControlURL != settings.ControlURL {
		c.ManagementProbeURL = ""
		c.ManagementProbeCACert = ""
	}
	c.ControllerURL, c.ControlURL, c.DiscoveryURL = settings.ControllerURL, settings.ControlURL, settings.DiscoveryURL
	c.Enforce, c.AllowFirewallChanges, c.LearningAutoAllow, c.UnexpectedPortMonitorEnabled = settings.Enforce, settings.AllowFirewallChanges, settings.LearningAutoAllow, settings.UnexpectedPortMonitorEnabled
	c.AllowHostDefaultDeny = settings.AllowHostDefaultDeny
	// Retired approval-mode fields are cleared only by explicit local
	// reconfiguration. They never elevate unrelated firewall opt-ins.
	c.AllowSingleAdminPilot = false
	c.SingleAdminPilotScope = nil
	c.ManagementSources = append([]string{}, settings.ManagementSources...)
	c.ProtectedSSHPorts = append([]int{}, settings.ProtectedSSHPorts...)
	c.Zone = settings.Zone
	return validateConfig(c, false)
}
func readConfigurationKit(path string, c Config, now time.Time) (*configurationKit, error) {
	raw, err := readSetupFile(path)
	if err != nil {
		return nil, err
	}
	if err = strictSetupJSON(raw); err != nil {
		return nil, err
	}
	var kit configurationKit
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&kit) != nil || kit.SchemaVersion != 1 {
		return nil, errors.New("unsupported endpoint configuration schema")
	}
	m := kit.Manifest
	if m.Kind != "prthak-endpoint-configuration-v1" || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(m.ReviewID) || m.IssuedAt.After(now.Add(time.Minute)) || !m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.IssuedAt) || m.ExpiresAt.Sub(m.IssuedAt) > 15*time.Minute {
		return nil, errors.New("endpoint configuration identity or validity is invalid")
	}
	trust, err := loadPolicySigningTrust(c)
	if err != nil {
		return nil, err
	}
	if m.DeploymentID != trust.DeploymentID || kit.Signature.Algorithm != "Ed25519" {
		return nil, errors.New("endpoint configuration signer is not independently pinned")
	}
	key, keyErr := base64.StdEncoding.Strict().DecodeString(trust.Keys[kit.Signature.KeyID])
	payload, payloadErr := base64.StdEncoding.Strict().DecodeString(kit.Signature.Payload)
	signature, signatureErr := base64.StdEncoding.Strict().DecodeString(kit.Signature.Signature)
	if keyErr != nil || payloadErr != nil || signatureErr != nil || len(key) != ed25519.PublicKeySize || len(payload) > maxSetupFileBytes || !ed25519.Verify(key, payload, signature) {
		return nil, errors.New("endpoint configuration signature did not verify")
	}
	var envelope struct {
		Domain   string                `json:"domain"`
		Manifest configurationManifest `json:"manifest"`
	}
	if strictSetupJSON(payload) != nil {
		return nil, errors.New("invalid signed configuration document")
	}
	decoder = json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.Domain != "prthak-package-manifest-v1" {
		return nil, errors.New("invalid configuration signature domain")
	}
	a := configurationCanonical(m)
	b := configurationCanonical(envelope.Manifest)
	if !bytes.Equal(a, b) {
		return nil, errors.New("configuration differs from independent signature")
	}
	var proof configurationProof
	if json.Unmarshal(m.Approval, &proof) != nil || proof.PlanID != m.ReviewID || !validDigest(proof.PlanDigest) {
		return nil, errors.New("independent endpoint configuration approval is missing")
	}
	if err = validateEndpointApproval(c, m.Approval, m.Scope.ServerID, now, true); err != nil {
		return nil, err
	}
	if m.Scope.ExpectedConfigDigest != configDigest(c) || !validDigest(m.Scope.TargetBinding) {
		return nil, errors.New("endpoint configuration changed since review")
	}
	if (c.ControllerURL != m.Scope.Settings.ControllerURL || c.ControlURL != m.Scope.Settings.ControlURL || c.DiscoveryURL != m.Scope.Settings.DiscoveryURL) && !m.Scope.RetainOldOrigin {
		return nil, errors.New("controller migration requires retained old and new origins")
	}
	scopeHash := sha256.Sum256(configurationCanonical(m.Scope))
	if proof.PlanDigest != hex.EncodeToString(scopeHash[:]) {
		return nil, errors.New("configuration approval does not bind its exact scope")
	}
	if m.Scope.ControllerCA != "" && !validSetupCA(m.Scope.ControllerCA, m.ExpiresAt, now) {
		return nil, errors.New("configuration requires a public CA valid through its expiry")
	}
	if _, err = configurationCandidate(c, m); err != nil {
		return nil, err
	}
	return &kit, nil
}
func configurationCandidate(c Config, m configurationManifest) (Config, error) {
	return transitionConfig(c, m.Scope.Settings)
}

func configurationWitness(ctx context.Context, c Config, kit *configurationKit, candidateDigest, phase string) error {
	client, err := NewClient(c, false)
	if err != nil {
		return err
	}
	defer client.HTTP.CloseIdleConnections()
	var proof configurationProof
	_ = json.Unmarshal(kit.Manifest.Approval, &proof)
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	nonce := hex.EncodeToString(random)
	started := time.Now().UTC()
	request := map[string]string{"review_id": kit.Manifest.ReviewID, "plan_digest": proof.PlanDigest, "candidate_digest": candidateDigest, "phase": phase, "nonce": nonce}
	response, err := client.request(ctx, "POST", "/api/v1/agent/configuration/check", request, "")
	if err != nil {
		return err
	}
	var value signedConfigurationWitness
	if err = decodeResponse(response, &value); err != nil {
		return err
	}
	return validateConfigurationWitness(c, kit, value, nonce, candidateDigest, phase, started, time.Now().UTC())
}

func readConfigurationPublic(path string) ([]byte, error) {
	info, err := setupPath(path, false)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > maxSetupCABytes {
		return nil, errors.New("configuration trust must be a protected regular public file")
	}
	return os.ReadFile(path)
}
func atomicPrivateFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return errors.New("configuration artifact is not a protected regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".prthak-configuration-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func configurationJournalRead(path string) (*configurationJournal, error) {
	return configurationJournalReadUnder("", path)
}
func configurationJournalReadUnder(root, path string) (*configurationJournal, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != "/var/lib/seg-agent/configuration-transitions" {
		return nil, errors.New("invalid configuration journal path")
	}
	raw, err := readPrivateSetupBound(root+path, 2*1024*1024)
	if err != nil {
		return nil, err
	}
	var journal configurationJournal
	if json.Unmarshal(raw, &journal) != nil || journal.SchemaVersion != 1 || filepath.Base(path) != journal.ReviewID+".json" || journal.ConfigPath != "/etc/seg-agent/config.json" {
		return nil, errors.New("invalid configuration rollback journal")
	}
	return &journal, nil
}
func restoreConfiguration(path string, journal *configurationJournal, commands CommandRunner) error {
	return restoreConfigurationUnder("", path, journal, commands)
}

// ErrStaleConfigurationReview means no rollback was performed: another review
// owns the generation, so reporting this as a successful restore is incorrect.
var ErrStaleConfigurationReview = errors.New("configuration rollback refuses an inactive review generation")
var errStaleConfigurationReview = ErrStaleConfigurationReview
var errConfigurationAlreadyCompleted = errors.New("configuration journal was already completed; no restore was performed")

func configurationTerminal(status string) bool {
	return status == "committed" || status == "rolled_back" || status == "not_started"
}

func configurationLeaseUnder(root string, wait time.Duration) (*os.File, error) {
	directory := root + "/var/lib/seg-agent/configuration-transitions"
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if _, err := setupPath(directory, true); err != nil {
		return nil, err
	}
	path := directory + "/lock"
	descriptor, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if info, e := file.Stat(); e != nil || validatePrivateFileInfo(path, info, os.Geteuid()) != nil {
		file.Close()
		return nil, errors.New("configuration generation lock ownership is unsafe")
	}
	deadline := time.Now().Add(wait)
	for {
		if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return file, nil
		}
		if !time.Now().Before(deadline) {
			file.Close()
			return nil, errors.New("configuration generation is busy")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func configurationActiveReview(root string) (string, error) {
	raw, err := readPrivateSetupBound(root+"/var/lib/seg-agent/configuration-transitions/active", 1024)
	if err != nil {
		return "", err
	}
	var active struct {
		ReviewID string `json:"review_id"`
	}
	if json.Unmarshal(raw, &active) != nil || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(active.ReviewID) {
		return "", errors.New("invalid configuration active generation")
	}
	return active.ReviewID, nil
}
func restoreConfigurationUnder(root, path string, journal *configurationJournal, commands CommandRunner) error {
	lease, err := configurationLeaseUnder(root, 2*time.Second)
	if err != nil {
		return err
	}
	defer lease.Close()
	return restoreConfigurationLockedUnder(root, path, journal, commands, lease)
}
func restoreConfigurationLockedUnder(root, path string, journal *configurationJournal, commands CommandRunner, lease *os.File) error {
	if lease == nil {
		return errors.New("configuration restore requires the generation lease")
	}
	lockInfo, err := os.Lstat(root + "/var/lib/seg-agent/configuration-transitions/lock")
	leasedInfo, leaseErr := lease.Stat()
	if err != nil || leaseErr != nil || !os.SameFile(lockInfo, leasedInfo) || syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("configuration restore generation lease changed")
	}
	logical := "/var/lib/seg-agent/configuration-transitions/" + journal.ReviewID + ".json"
	if path != root+logical {
		return errors.New("configuration restore journal path changed")
	}
	fresh, err := configurationJournalReadUnder(root, logical)
	if err != nil {
		return err
	}
	active, activeErr := configurationActiveReview(root)
	if activeErr != nil {
		if os.IsNotExist(activeErr) && configurationTerminal(fresh.Status) {
			return errConfigurationAlreadyCompleted
		}
		return errStaleConfigurationReview
	}
	if active != journal.ReviewID {
		return errStaleConfigurationReview
	}
	if configurationTerminal(fresh.Status) {
		return errConfigurationAlreadyCompleted
	}
	if fresh.Status != "armed" || fresh.ReviewID != active {
		return errStaleConfigurationReview
	}
	*journal = *fresh
	configPath := root + journal.ConfigPath
	caPath := root + "/etc/seg-agent/controller-ca.crt"
	endpointPath := root + "/etc/seg-agent/endpoint-ca.crt"
	current, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(current, journal.CandidateConfig) && !bytes.Equal(current, journal.OldConfig) {
		return errors.New("configuration rollback refuses a different active generation")
	}
	if err = atomicPrivateFile(configPath, journal.OldConfig); err != nil {
		return err
	}
	if err = atomicPrivateFile(caPath, journal.OldCA); err != nil {
		return err
	}
	if len(journal.OldEndpointCA) > 0 {
		err = atomicPrivateFile(endpointPath, journal.OldEndpointCA)
	} else if len(journal.CandidateEndpointCA) > 0 {
		err = os.Remove(endpointPath)
		if os.IsNotExist(err) {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	journal.Status = "rolled_back"
	if err = atomicJSON(path, journal); err != nil {
		return err
	}
	clearConfigurationPointer(path, journal.ReviewID)
	_, err = commands.Run(context.Background(), "systemctl", "restart", "seg-agent.service")
	return err
}
func clearConfigurationPointer(path, reviewID string) {
	pointer := filepath.Join(filepath.Dir(path), "active")
	raw, err := readPrivateSetupBound(pointer, 1024)
	var active struct {
		ReviewID string `json:"review_id"`
	}
	if err == nil && json.Unmarshal(raw, &active) == nil && active.ReviewID == reviewID {
		_ = os.Remove(pointer)
	}
}

// RollbackEndpointConfiguration is executed by an independent systemd timer,
// with a root-only journal. Committed generations never restore old settings.
func RollbackEndpointConfiguration(path string, commands CommandRunner) error {
	return rollbackEndpointConfigurationUnder("", path, commands)
}
func rollbackEndpointConfigurationUnder(root, path string, commands CommandRunner) error {
	journal, err := configurationJournalReadUnder(root, path)
	if err != nil {
		return err
	}
	if journal.Status != "armed" {
		if configurationTerminal(journal.Status) {
			return nil
		}
		return errors.New("configuration rollback journal has an invalid status")
	}
	if !configurationDeadlinePassed(journal) {
		return errors.New("configuration rollback deadline has not arrived")
	}
	active, activeErr := configurationActiveReview(root)
	if activeErr != nil || active != journal.ReviewID {
		return errStaleConfigurationReview
	}
	if journal.CoordinatorPID > 1 && journal.CoordinatorPID != os.Getpid() && journal.CoordinatorIdentity != "" && processIdentity(journal.CoordinatorPID) == journal.CoordinatorIdentity {
		if err = syscall.Kill(journal.CoordinatorPID, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
	}
	err = restoreConfigurationUnder(root, root+path, journal, commands)
	if errors.Is(err, errConfigurationAlreadyCompleted) {
		return nil
	}
	return err
}
func configurationDeadlinePassed(journal *configurationJournal) bool {
	if journal.DeadlineBootSeconds > 0 {
		if elapsed := bootElapsedSeconds(); elapsed > 0 {
			return elapsed >= journal.DeadlineBootSeconds
		}
	}
	return !time.Now().Before(journal.Deadline)
}
func configurationCoordinatorAlive(journal *configurationJournal) bool {
	return journal.CoordinatorPID > 1 && journal.CoordinatorIdentity != "" && processIdentity(journal.CoordinatorPID) == journal.CoordinatorIdentity
}

type configurationNoRestart struct{}

func (configurationNoRestart) Run(context.Context, string, ...string) (string, error) { return "", nil }

// Startup recovery covers a reboot/lost transient timer or a dead coordinator.
// Files are restored without recursively restarting this ExecStart process;
// one failure lets systemd reload the previous configuration on its next start.
func RecoverEndpointConfiguration(configPath string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || configPath != "/etc/seg-agent/config.json" {
		return nil
	}
	return recoverConfigurationUnder("", configurationCoordinatorAlive, func(j *configurationJournal) error {
		if j.CoordinatorPID == os.Getpid() {
			return errors.New("configuration coordinator identity points at this daemon")
		}
		if configurationCoordinatorAlive(j) {
			err := syscall.Kill(j.CoordinatorPID, syscall.SIGKILL)
			if err != nil && err != syscall.ESRCH {
				return err
			}
		}
		return nil
	})
}
func recoverConfigurationUnder(root string, alive func(*configurationJournal) bool, kill func(*configurationJournal) error) error {
	directory := "/var/lib/seg-agent/configuration-transitions"
	pointer := root + directory + "/active"
	if _, err := os.Lstat(pointer); os.IsNotExist(err) {
		return nil
	}
	raw, err := readPrivateSetupBound(pointer, 1024)
	var active struct {
		ReviewID string `json:"review_id"`
	}
	if err != nil || json.Unmarshal(raw, &active) != nil || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(active.ReviewID) {
		return errors.New("configuration recovery pointer is invalid")
	}
	path := directory + "/" + active.ReviewID + ".json"
	journal, err := configurationJournalReadUnder(root, path)
	if err != nil {
		return err
	}
	if journal.Status != "armed" {
		if !configurationTerminal(journal.Status) {
			return errors.New("configuration recovery journal has an invalid status")
		}
		lease, lockErr := configurationLeaseUnder(root, 0)
		if lockErr != nil {
			return nil
		}
		defer lease.Close()
		current, currentErr := configurationActiveReview(root)
		if currentErr == nil && current != journal.ReviewID {
			return errStaleConfigurationReview
		}
		if currentErr == nil && current == journal.ReviewID {
			fresh, freshErr := configurationJournalReadUnder(root, path)
			if freshErr == nil && fresh.Status != "armed" {
				clearConfigurationPointer(root+path, journal.ReviewID)
			}
		}
		return nil
	}
	if alive(journal) && !configurationDeadlinePassed(journal) {
		return nil
	}
	if alive(journal) {
		if err = kill(journal); err != nil {
			return err
		}
	}
	lease, err := configurationLeaseUnder(root, 2*time.Second)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err = restoreConfigurationLockedUnder(root, root+path, journal, configurationNoRestart{}, lease); err != nil {
		if errors.Is(err, errConfigurationAlreadyCompleted) {
			return nil
		}
		return err
	}
	return errors.New("abandoned endpoint configuration restored; systemd will reload the previous configuration")
}

// ApplyEndpointConfiguration never changes identity or signing trust. It first
// verifies both old and proposed control paths with the exact same enrolled key.
func ApplyEndpointConfiguration(ctx context.Context, path, configPath string, commands CommandRunner) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || configPath != "/etc/seg-agent/config.json" {
		return errors.New("configuration application requires root on the native canonical Linux installation")
	}
	if _, err := setupPath(configPath, false); err != nil {
		return err
	}
	if err := checkPrivateFile(configPath); err != nil {
		return err
	}
	c, err := LoadConfig(configPath, false)
	if err != nil {
		return err
	}
	if err = ValidateInstallConfig(c); err != nil {
		return err
	}
	directory := filepath.Join(c.StateDir, "configuration-transitions")
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if _, err = setupPath(directory, true); err != nil {
		return err
	}
	lock, lockErr := configurationLeaseUnder("", 0)
	if lockErr != nil {
		return lockErr
	}
	defer lock.Close()
	if err = checkEnforcementUpgradeSafety(c, true); err != nil {
		return err
	}
	kit, err := readConfigurationKit(path, c, time.Now().UTC())
	if err != nil {
		return err
	}
	host, err := os.Hostname()
	if err != nil || host != kit.Manifest.Scope.Hostname {
		return errors.New("configuration kit belongs to another hostname")
	}
	client, err := NewClient(c, false)
	if err != nil {
		return err
	}
	defer client.HTTP.CloseIdleConnections()
	identity := client.identity.Load()
	if identity == nil || identity.Leaf == nil || identity.Leaf.Subject.CommonName != kit.Manifest.Scope.ServerID {
		return errors.New("configuration kit belongs to another enrolled identity")
	}
	candidate, err := configurationCandidate(c, kit.Manifest)
	if err != nil {
		return err
	}
	oldConfig, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	oldCA, err := readConfigurationPublic(c.CACert)
	if err != nil {
		return err
	}
	var oldEndpointCA []byte
	if c.EndpointCACert != "" {
		oldEndpointCA, err = readConfigurationPublic(c.EndpointCACert)
		if err != nil {
			return err
		}
	}
	newCA := oldCA
	if kit.Manifest.Scope.ControllerCA != "" {
		newCA = []byte(kit.Manifest.Scope.ControllerCA)
	}
	newEndpointCA := oldEndpointCA
	if !bytes.Equal(newCA, oldCA) && c.EndpointCACert == "" {
		candidate.EndpointCACert = "/etc/seg-agent/endpoint-ca.crt"
		newEndpointCA = oldCA
	}
	candidateRaw, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return err
	}
	candidateRaw = append(candidateRaw, '\n')
	candidateDigest := configDigest(candidate)
	if err = configurationWitness(ctx, c, kit, candidateDigest, "before"); err != nil {
		return err
	}
	work, err := os.MkdirTemp("/var/lib/seg-agent", "configuration-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err = atomicPrivateFile(filepath.Join(work, "controller-ca.crt"), newCA); err != nil {
		return err
	}
	probe := candidate
	probe.CACert = filepath.Join(work, "controller-ca.crt")
	if len(newEndpointCA) > 0 {
		if err = atomicPrivateFile(filepath.Join(work, "endpoint-ca.crt"), newEndpointCA); err != nil {
			return err
		}
		probe.EndpointCACert = filepath.Join(work, "endpoint-ca.crt")
	}
	if err = configurationWitness(ctx, probe, kit, candidateDigest, "before"); err != nil {
		return err
	}
	if err = checkEnforcementUpgradeSafety(c, true); err != nil {
		return err
	}
	if !kit.Manifest.ExpiresAt.After(time.Now().Add(100 * time.Second)) {
		return errors.New("configuration kit needs at least 100 seconds of remaining validity; obtain a fresh review or download")
	}
	restartOld := func() { _, _ = commands.Run(context.Background(), "systemctl", "start", "seg-agent.service") }
	current, err := LoadConfig(configPath, false)
	if err != nil || configDigest(current) != configDigest(c) {
		restartOld()
		return errors.New("active configuration changed during review")
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		restartOld()
		return err
	}
	if _, err = setupPath(directory, true); err != nil {
		restartOld()
		return err
	}
	journalPath := filepath.Join(directory, kit.Manifest.ReviewID+".json")
	if _, err = os.Lstat(journalPath); !os.IsNotExist(err) {
		restartOld()
		return errors.New("configuration review has already been attempted; create a fresh review")
	}
	journal := &configurationJournal{SchemaVersion: 1, ReviewID: kit.Manifest.ReviewID, Status: "armed", Deadline: time.Now().Add(90 * time.Second), ConfigPath: configPath, OldConfig: oldConfig, CandidateConfig: candidateRaw, OldCA: oldCA, CandidateCA: newCA, OldEndpointCA: oldEndpointCA, CandidateEndpointCA: newEndpointCA, CoordinatorPID: os.Getpid(), CoordinatorIdentity: processIdentity(os.Getpid())}
	if elapsed := bootElapsedSeconds(); elapsed > 0 {
		journal.DeadlineBootSeconds = elapsed + 90
	} else {
		restartOld()
		return errors.New("independent configuration rollback requires a monotonic boot clock")
	}
	if journal.CoordinatorIdentity == "" {
		restartOld()
		return errors.New("independent configuration rollback requires process identity")
	}
	if err = atomicJSON(journalPath, journal); err != nil {
		restartOld()
		return err
	}
	if err = atomicJSON(filepath.Join(directory, "active"), map[string]string{"review_id": journal.ReviewID}); err != nil {
		journal.Status = "not_started"
		_ = atomicJSON(journalPath, journal)
		restartOld()
		return err
	}
	unit := "prthak-config-" + strings.ReplaceAll(kit.Manifest.ReviewID, "-", "")
	executable := "/usr/local/bin/seg-agent"
	if info, checkErr := setupPath(executable, false); checkErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		journal.Status = "not_started"
		_ = atomicJSON(journalPath, journal)
		clearConfigurationPointer(journalPath, journal.ReviewID)
		restartOld()
		return errors.New("independent rollback requires the protected installed agent executable")
	}
	if _, err = commands.Run(ctx, "systemd-run", "--unit="+unit, "--on-active=90s", "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "--property=Restart=on-failure", "--property=RestartSec=3s", "--property=RestartPreventExitStatus=3", executable, "--rollback-configuration", journalPath); err != nil {
		journal.Status = "not_started"
		_ = atomicJSON(journalPath, journal)
		clearConfigurationPointer(journalPath, journal.ReviewID)
		restartOld()
		return err
	}
	failed := func(cause error) error {
		if restoreErr := restoreConfigurationLockedUnder("", journalPath, journal, commands, lock); restoreErr != nil {
			return fmt.Errorf("configuration failed and independent rollback remains armed: %w", cause)
		}
		return cause
	}
	// The independent timer is already armed before stopping the ordinary
	// service, so loss of this helper cannot strand an unchanged daemon stopped.
	if _, err = commands.Run(ctx, "systemctl", "stop", "seg-agent.service"); err != nil {
		return failed(err)
	}
	if err = checkEnforcementUpgradeSafety(c, true, journal.ReviewID); err != nil {
		return failed(err)
	}
	current, err = LoadConfig(configPath, false)
	if err != nil || configDigest(current) != configDigest(c) {
		return failed(errors.New("configuration changed after service stop"))
	}
	if err = atomicPrivateFile(configPath, candidateRaw); err != nil {
		return failed(err)
	}
	if err = atomicPrivateFile(c.CACert, newCA); err != nil {
		return failed(err)
	}
	if len(newEndpointCA) > 0 {
		if err = atomicPrivateFile(candidate.EndpointCACert, newEndpointCA); err != nil {
			return failed(err)
		}
	}
	if _, err = commands.Run(ctx, "systemctl", "start", "seg-agent.service"); err != nil {
		return failed(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		err = configurationWitness(ctx, candidate, kit, candidateDigest, "after")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return failed(errors.New("new configuration did not produce a fresh exact report; restored previous settings"))
		}
		select {
		case <-ctx.Done():
			return failed(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	if bootElapsedSeconds() >= journal.DeadlineBootSeconds-5 || !time.Now().Before(journal.Deadline.Add(-5*time.Second)) {
		return failed(errors.New("configuration confirmation missed its rollback deadline"))
	}
	journal.Status = "committed"
	if err = atomicJSON(journalPath, journal); err != nil {
		return failed(err)
	}
	clearConfigurationPointer(journalPath, journal.ReviewID)
	_, _ = commands.Run(context.Background(), "systemctl", "stop", unit+".timer")
	return nil
}
