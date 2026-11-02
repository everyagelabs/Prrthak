package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func configurationFixture(t *testing.T) (Config, configurationKit, ed25519.PrivateKey, string, time.Time) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := sha256.Sum256(public)
	keyID := hex.EncodeToString(keyHash[:])[:32]
	c := defaultConfig()
	c.ControllerURL = "https://controller.example"
	c.CACert = "/etc/seg-agent/controller-ca.crt"
	c.Certificate = "/var/lib/seg-agent/agent.crt"
	c.PrivateKey = "/var/lib/seg-agent/agent.key"
	c.EnrollmentTokenFile = "/etc/seg-agent/enrollment-token"
	c.PolicySigningTrustFile = filepath.Join(directory, "trust.json")
	if err = atomicJSON(c.PolicySigningTrustFile, policyTrust{DeploymentID: "11111111-1111-1111-1111-111111111111", Keys: map[string]string{keyID: base64.StdEncoding.EncodeToString(public)}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	settings := configurationState(c).EndpointConfigurationSettings
	settings.Enforce = true
	settings.ManagementSources = []string{"10.90.0.0/24"}
	settings.ProtectedSSHPorts = []int{2022}
	settings.Zone = "public"
	scope := configurationScope{ServerID: "endpoint-one", Hostname: "endpoint-one", IPs: []string{"10.70.0.1"}, ExpectedConfigDigest: configDigest(c), TargetBinding: strings.Repeat("b", 64), Settings: settings}
	kit := configurationKit{SchemaVersion: 1, Manifest: configurationManifest{Kind: "prthak-endpoint-configuration-v1", ReviewID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Scope: scope, DeploymentID: "11111111-1111-1111-1111-111111111111"}}
	setConfigurationProof(t, &kit, "single_admin", "maker", "maker")
	signConfiguration(t, &kit, key, keyID)
	path := filepath.Join(directory, "private-configuration.json")
	writeSetup(t, path, kit)
	return c, kit, key, path, now
}
func setConfigurationProof(t *testing.T, kit *configurationKit, mode, maker, checker string) {
	t.Helper()
	hash := sha256.Sum256(configurationCanonical(kit.Manifest.Scope))
	proof := configurationProof{Scheme: "prthak-maker-checker-v1", Mode: mode, Stage: "approved", PlanID: kit.Manifest.ReviewID, PlanDigest: hex.EncodeToString(hash[:]), Requester: configurationPerson{UserID: maker, TenantID: "same-tenant"}, SubmittedBy: configurationPerson{UserID: maker, TenantID: "same-tenant"}, ApprovedBy: configurationPerson{UserID: checker, TenantID: "same-tenant"}}
	if mode == "single_admin" {
		proof.ProviderAuthority = map[string]string{"fingerprint": strings.Repeat("a", 64), "epoch": ""}
		ids, _ := json.Marshal([]string{kit.Manifest.Scope.ServerID})
		proof.Scope = map[string]json.RawMessage{"kind": json.RawMessage("\"endpoint_configuration\""), "server_ids": ids}
		kit.Manifest.Approval = sealDirectApproval(proof)
		return
	}
	kit.Manifest.Approval, _ = json.Marshal(proof)
}
func signConfiguration(t *testing.T, kit *configurationKit, key ed25519.PrivateKey, keyID string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"domain": "prthak-package-manifest-v1", "manifest": kit.Manifest})
	kit.Signature = PolicySignature{Algorithm: "Ed25519", KeyID: keyID, Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
}

func TestEndpointConfigurationRequiresPinnedExactIndependentSignature(t *testing.T) {
	c, kit, key, path, now := configurationFixture(t)
	if _, err := readConfigurationKit(path, c, now); err != nil {
		t.Fatal(err)
	}
	kit.Manifest.Scope.Settings.LearningAutoAllow = true
	writeSetup(t, path, kit)
	if _, err := readConfigurationKit(path, c, now); err == nil {
		t.Fatal("unsigned setting alteration accepted")
	}
	for _, mode := range []string{"lab_only", "independent_entra"} {
		setConfigurationProof(t, &kit, mode, "same", "same")
		signConfiguration(t, &kit, key, kit.Signature.KeyID)
		writeSetup(t, path, kit)
		if _, err := readConfigurationKit(path, c, now); err == nil {
			t.Fatal("non-independent approval accepted")
		}
	}
}
func TestEndpointConfigurationRejectsStaleReplaySignerAndConfigBindings(t *testing.T) {
	c, kit, key, path, now := configurationFixture(t)
	for _, change := range []func(*configurationKit){func(k *configurationKit) { k.Manifest.ExpiresAt = now.Add(-time.Second) }, func(k *configurationKit) { k.Manifest.DeploymentID = "another-deployment" }, func(k *configurationKit) { k.Manifest.Scope.ExpectedConfigDigest = strings.Repeat("c", 64) }, func(k *configurationKit) { k.Signature.KeyID = "unknown" }} {
		altered := kit
		change(&altered)
		signConfiguration(t, &altered, key, altered.Signature.KeyID)
		writeSetup(t, path, altered)
		if _, err := readConfigurationKit(path, c, now); err == nil {
			t.Fatal("stale or rebound configuration accepted")
		}
	}
	writeSetup(t, path, kit)
	changed := c
	changed.IntervalSeconds = 30
	if _, err := readConfigurationKit(path, changed, now); err == nil {
		t.Fatal("old configuration authority replayed after config changed")
	}
	if err := os.Remove(c.PolicySigningTrustFile); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigurationKit(path, c, now); err == nil {
		t.Fatal("network authority substituted for missing local signing trust")
	}
}
func TestEndpointConfigurationRequiresManagementSSHAndRetainedMigrationScope(t *testing.T) {
	c, kit, key, path, now := configurationFixture(t)
	for _, change := range []func(*configurationKit){func(k *configurationKit) { k.Manifest.Scope.Settings.ManagementSources = []string{} }, func(k *configurationKit) { k.Manifest.Scope.Settings.ManagementSources = []string{"0.0.0.0/0"} }, func(k *configurationKit) { k.Manifest.Scope.Settings.ProtectedSSHPorts = []int{} }, func(k *configurationKit) { k.Manifest.Scope.Settings.Zone = "" }, func(k *configurationKit) { k.Manifest.Scope.Settings.ControlURL = "https://dr.example:8788" }, func(k *configurationKit) { k.Manifest.Scope.Settings.ControlURL = "http://controller.example" }} {
		altered := kit
		change(&altered)
		setConfigurationProof(t, &altered, "independent_entra", "maker", "checker")
		signConfiguration(t, &altered, key, kit.Signature.KeyID)
		writeSetup(t, path, altered)
		if _, err := readConfigurationKit(path, c, now); err == nil {
			t.Fatal("unsafe migration/protection scope accepted")
		}
	}
	kit.Manifest.Scope.RetainOldOrigin = true
	kit.Manifest.Scope.Settings.ControlURL = "https://dr.example:8788"
	setConfigurationProof(t, &kit, "independent_entra", "maker", "checker")
	signConfiguration(t, &kit, key, kit.Signature.KeyID)
	writeSetup(t, path, kit)
	if _, err := readConfigurationKit(path, c, now); err != nil {
		t.Fatal(err)
	}
}
func TestEndpointConfigurationReportIsPublicStableAndScopeBound(t *testing.T) {
	c, _, _, _, _ := configurationFixture(t)
	state := configurationState(c)
	raw, _ := json.Marshal(state)
	if len(state.Digest) != 64 || strings.Contains(string(raw), "private_key") || strings.Contains(string(raw), "policy_signing_keys") {
		t.Fatal("receipt exposed private configuration artifacts")
	}
	c.LearningAutoAllow = true
	if configurationState(c).Digest == state.Digest {
		t.Fatal("privilege change did not change configuration receipt")
	}
}

type configurationTransport func(*http.Request) (*http.Response, error)

func (f configurationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
func TestEndpointChannelURLsRouteControlAndDiscoveryWithoutManagementFallback(t *testing.T) {
	seen := map[string][]string{}
	transport := configurationTransport(func(request *http.Request) (*http.Response, error) {
		seen[request.URL.Host] = append(seen[request.URL.Host], request.URL.Path)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
	})
	c := defaultConfig()
	c.ControllerURL = "https://management.example"
	c.ControlURL = "https://control.example:8788"
	c.DiscoveryURL = "https://discovery.example:8789"
	client, err := NewClient(c, true)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = transport
	for _, path := range []string{"/api/v1/agent/policy", "/api/v1/agent/enforcement/check", "/api/v1/agent/source-banks/check", "/api/v1/agent/firewall/check", "/api/v1/agent/learning-allow/check", "/api/v1/agent/configuration/check", "/api/v1/agent/certificates/renew", "/api/v1/agent/enroll", "/api/v1/agent/certificates/recover", "/api/v1/agent/report", "/api/v1/agent/flows", "/api/v1/agent/hits"} {
		response, err := client.request(context.Background(), "POST", path, map[string]string{}, "")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	if len(seen["management.example"]) != 0 || len(seen["control.example:8788"]) != 7 || len(seen["discovery.example:8789"]) != 5 {
		t.Fatalf("incorrect listener routing: %v", seen)
	}
	c.ControlURL = ""
	c.DiscoveryURL = ""
	client, err = NewClient(c, true)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = transport
	response, err := client.request(context.Background(), "GET", "/api/v1/agent/policy", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(seen["management.example"]) != 1 {
		t.Fatal("legacy combined fallback unavailable")
	}
}
func TestEndpointConfigurationUsesControlOriginForExactManagementProtection(t *testing.T) {
	c := defaultConfig()
	c.CACert = "/etc/seg-agent/controller-ca.crt"
	c.ControlURL = "https://controller.example:8788"
	c.ManagementProbeURL = configuredManagedProbe(c)
	if c.ManagementProbeURL != "https://controller.example:8788/api/v1/agent/enforcement/check" {
		t.Fatal("management witness used GUI listener")
	}
	if _, err := validateConfig(c, false); err != nil {
		t.Fatal(err)
	}
	c.ManagementProbeURL = "https://unrelated.example/api/v1/agent/enforcement/check"
	if _, err := validateConfig(c, false); err == nil {
		t.Fatal("arbitrary management probe origin accepted")
	}
}

type configurationCommands struct {
	calls []string
	err   error
}

func persistConfigurationAttempt(t *testing.T, root string, journal *configurationJournal) string {
	t.Helper()
	directory := root + "/var/lib/seg-agent/configuration-transitions"
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := directory + "/" + journal.ReviewID + ".json"
	if err := atomicJSON(path, journal); err != nil {
		t.Fatal(err)
	}
	if err := atomicJSON(directory+"/active", map[string]string{"review_id": journal.ReviewID}); err != nil {
		t.Fatal(err)
	}
	return path
}

func (r *configurationCommands) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return "", r.err
}
func TestEndpointConfigurationInverseRestoresOnlyExactGenerationAndRetainsIdentity(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc/seg-agent")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal := &configurationJournal{SchemaVersion: 1, ReviewID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Status: "armed", ConfigPath: "/etc/seg-agent/config.json", OldConfig: []byte("old-config"), CandidateConfig: []byte("candidate-config"), OldCA: []byte("old-public-ca"), CandidateCA: []byte("new-public-ca"), CandidateEndpointCA: []byte("preserved-issuer")}
	for name, value := range map[string][]byte{"config.json": journal.CandidateConfig, "controller-ca.crt": journal.CandidateCA, "endpoint-ca.crt": journal.CandidateEndpointCA, "unrelated-identity": []byte("do-not-touch")} {
		if err := os.WriteFile(filepath.Join(directory, name), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	commands := &configurationCommands{}
	path := persistConfigurationAttempt(t, root, journal)
	if err := restoreConfigurationUnder(root, path, journal, commands); err != nil {
		t.Fatal(err)
	}
	config, _ := os.ReadFile(filepath.Join(directory, "config.json"))
	ca, _ := os.ReadFile(filepath.Join(directory, "controller-ca.crt"))
	identity, _ := os.ReadFile(filepath.Join(directory, "unrelated-identity"))
	if string(config) != "old-config" || string(ca) != "old-public-ca" || string(identity) != "do-not-touch" || journal.Status != "rolled_back" || !reflect.DeepEqual(commands.calls, []string{"systemctl restart seg-agent.service"}) {
		t.Fatal("exact inverse did not restore old state and service")
	}
	if _, err := os.Stat(filepath.Join(directory, "endpoint-ca.crt")); !os.IsNotExist(err) {
		t.Fatal("new issuer fallback file not removed")
	}
	os.WriteFile(filepath.Join(directory, "config.json"), []byte("unrelated-new-generation"), 0600)
	commands.calls = nil
	journal.Status = "armed"
	persistConfigurationAttempt(t, root, journal)
	if err := restoreConfigurationUnder(root, path, journal, commands); err == nil || len(commands.calls) != 0 {
		t.Fatal("inverse overwrote unrelated generation")
	}
}
func TestEndpointConfigurationBlocksMutationsAndReplacementUntilCommit(t *testing.T) {
	c := defaultConfig()
	c.StateDir = t.TempDir()
	directory := filepath.Join(c.StateDir, "configuration-transitions")
	os.MkdirAll(directory, 0700)
	identifier := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	path := filepath.Join(directory, identifier+".json")
	journal := configurationJournal{SchemaVersion: 1, ReviewID: identifier, Status: "armed"}
	if err := atomicJSON(path, journal); err != nil {
		t.Fatal(err)
	}
	atomicJSON(filepath.Join(directory, "active"), map[string]string{"review_id": identifier})
	if !configurationMutationBlocked(c) || CheckEnforcementUpgradeSafety(c) == nil {
		t.Fatal("uncommitted configuration allowed firewall processing or binary replacement")
	}
	journal.Status = "committed"
	atomicJSON(path, journal)
	if configurationMutationBlocked(c) {
		t.Fatal("committed configuration still blocked")
	}
	if err := CheckEnforcementUpgradeSafety(c); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("broken-journal"), 0600)
	if !configurationMutationBlocked(c) || CheckEnforcementUpgradeSafety(c) == nil {
		t.Fatal("unverifiable journal did not fail closed")
	}
}
func TestEndpointConfigurationNativeApplicationIsNeverSimulatedOrStaged(t *testing.T) {
	commands := &configurationCommands{err: errors.New("must not run")}
	if err := ApplyEndpointConfiguration(context.Background(), "/missing-kit", "/tmp/noncanonical-config", commands); err == nil || len(commands.calls) != 0 {
		t.Fatal("noncanonical configuration application executed commands")
	}
}

func TestEndpointConfigurationRecoveryAfterDeadCoordinatorOrReboot(t *testing.T) {
	root := t.TempDir()
	directory := root + "/var/lib/seg-agent/configuration-transitions"
	os.MkdirAll(directory, 0700)
	os.MkdirAll(root+"/etc/seg-agent", 0700)
	identifier := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	path := directory + "/" + identifier + ".json"
	journal := &configurationJournal{SchemaVersion: 1, ReviewID: identifier, Status: "armed", Deadline: time.Now().Add(time.Minute), ConfigPath: "/etc/seg-agent/config.json", OldConfig: []byte("old"), CandidateConfig: []byte("candidate"), OldCA: []byte("old-ca"), CandidateCA: []byte("new-ca")}
	os.WriteFile(root+journal.ConfigPath, journal.CandidateConfig, 0600)
	os.WriteFile(root+"/etc/seg-agent/controller-ca.crt", journal.CandidateCA, 0600)
	atomicJSON(path, journal)
	atomicJSON(directory+"/active", map[string]string{"review_id": identifier})
	if err := recoverConfigurationUnder(root, func(*configurationJournal) bool { return true }, func(*configurationJournal) error { t.Fatal("live unexpired coordinator killed"); return nil }); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(root + journal.ConfigPath)
	if string(current) != "candidate" {
		t.Fatal("legitimate staged daemon was reverted before confirmation")
	}
	if err := recoverConfigurationUnder(root, func(*configurationJournal) bool { return false }, func(*configurationJournal) error { t.Fatal("dead coordinator killed"); return nil }); err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatal("lost timer/reboot did not restore old config and request a clean reload")
	}
	current, _ = os.ReadFile(root + journal.ConfigPath)
	ca, _ := os.ReadFile(root + "/etc/seg-agent/controller-ca.crt")
	if string(current) != "old" || string(ca) != "old-ca" {
		t.Fatal("startup recovery did not preserve previous settings/trust")
	}
	if _, err := os.Stat(directory + "/active"); !os.IsNotExist(err) {
		t.Fatal("recovered generation left mutation gate armed")
	}
}
func TestEndpointConfigurationInverseHandlesDeathBeforeTrustFileCommit(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(root+"/etc/seg-agent", 0700)
	journal := &configurationJournal{SchemaVersion: 1, ReviewID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Status: "armed", ConfigPath: "/etc/seg-agent/config.json", OldConfig: []byte("old"), CandidateConfig: []byte("candidate"), OldCA: []byte("old-ca"), CandidateCA: []byte("new-ca"), CandidateEndpointCA: []byte("issuer-not-written-yet")}
	os.WriteFile(root+journal.ConfigPath, journal.CandidateConfig, 0600)
	os.WriteFile(root+"/etc/seg-agent/controller-ca.crt", journal.OldCA, 0600)
	commands := &configurationCommands{}
	path := persistConfigurationAttempt(t, root, journal)
	if err := restoreConfigurationUnder(root, path, journal, commands); err != nil {
		t.Fatal(err)
	}
	if journal.Status != "rolled_back" || len(commands.calls) != 1 {
		t.Fatal("partial trust write prevented restoration/restart")
	}
}

func TestEndpointConfigurationStaleRollbackCannotOverwriteIdenticalSuccessor(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(root+"/etc/seg-agent", 0700)
	a := &configurationJournal{SchemaVersion: 1, ReviewID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Status: "armed", Deadline: time.Now().Add(-time.Minute), ConfigPath: "/etc/seg-agent/config.json", OldConfig: []byte("old-a"), CandidateConfig: []byte("identical-candidate"), OldCA: []byte("old-ca"), CandidateCA: []byte("candidate-ca")}
	path := persistConfigurationAttempt(t, root, a)
	finished := *a
	finished.Status = "rolled_back"
	atomicJSON(path, &finished)
	b := *a
	b.ReviewID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	b.Status = "armed"
	persistConfigurationAttempt(t, root, &b)
	os.WriteFile(root+b.ConfigPath, b.CandidateConfig, 0600)
	os.WriteFile(root+"/etc/seg-agent/controller-ca.crt", b.CandidateCA, 0600)
	commands := &configurationCommands{}
	if err := restoreConfigurationUnder(root, path, a, commands); !errors.Is(err, errStaleConfigurationReview) {
		t.Fatalf("stale review was not refused: %v", err)
	}
	current, _ := os.ReadFile(root + b.ConfigPath)
	active, err := configurationActiveReview(root)
	if string(current) != string(b.CandidateConfig) || err != nil || active != b.ReviewID || len(commands.calls) != 0 {
		t.Fatal("stale watchdog changed its successor or restarted service")
	}
}
func TestPolicySigningTrustReloadDoesNotMutateConfigOrRetainRemovedKeys(t *testing.T) {
	c, _, _, _, _ := configurationFixture(t)
	keyA, _, _ := ed25519.GenerateKey(rand.Reader)
	keyB, _, _ := ed25519.GenerateKey(rand.Reader)
	id := func(key []byte) string { hash := sha256.Sum256(key); return hex.EncodeToString(hash[:])[:32] }
	c.PolicySigningKeys = map[string]string{id(keyA): base64.StdEncoding.EncodeToString(keyA)}
	before := configDigest(c)
	fileTrust := policyTrust{DeploymentID: "11111111-1111-1111-1111-111111111111", Keys: map[string]string{id(keyB): base64.StdEncoding.EncodeToString(keyB)}}
	atomicJSON(c.PolicySigningTrustFile, fileTrust)
	loaded, err := loadPolicySigningTrust(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Keys) != 1 || loaded.Keys[id(keyA)] != "" || len(c.PolicySigningKeys) != 1 || c.PolicySigningKeys[id(keyB)] != "" || configDigest(c) != before {
		t.Fatal("file trust merged removed key into config or changed configuration digest")
	}
	fileTrust.Keys = map[string]string{id(keyA): base64.StdEncoding.EncodeToString(keyA)}
	atomicJSON(c.PolicySigningTrustFile, fileTrust)
	loaded, err = loadPolicySigningTrust(c)
	if err != nil || loaded.Keys[id(keyB)] != "" {
		t.Fatal("revoked file key survived a fresh reload")
	}
	c.PolicySigningTrustFile = ""
	loaded, err = loadPolicySigningTrust(Config{PolicySigningKeys: c.PolicySigningKeys, PolicySigningDeploymentID: fileTrust.DeploymentID})
	if err != nil {
		t.Fatal(err)
	}
	delete(loaded.Keys, id(keyA))
	if len(c.PolicySigningKeys) != 1 {
		t.Fatal("inline trust result aliases mutable configuration")
	}
}

func TestInstallerLeaseDescriptorMustMatchProtectedCanonicalInode(t *testing.T) {
	root := t.TempDir()
	lease, err := configurationLeaseUnder(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	c := RootedConfig(defaultConfig(), root)
	if err = checkInstallerLeaseUnder(c, root, int(lease.Fd())); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.OpenFile(filepath.Join(root, "unrelated-file"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if err = checkInstallerLeaseUnder(c, root, int(foreign.Fd())); err == nil {
		t.Fatal("unrelated descriptor bypassed the generation lease")
	}
	if err = checkInstallerLeaseUnder(c, root, 1); err == nil {
		t.Fatal("standard output accepted as installation lease")
	}
	if err = os.Chmod(root+"/var/lib/seg-agent/configuration-transitions/lock", 0644); err != nil {
		t.Fatal(err)
	}
	if err = checkInstallerLeaseUnder(c, root, int(lease.Fd())); err == nil {
		t.Fatal("nonprivate inherited lease accepted")
	}
}

func TestEndpointConfigurationWatchdogAndStartupNeverReportRefusedRollbackAsSuccess(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(root+"/etc/seg-agent", 0700)
	a := &configurationJournal{SchemaVersion: 1, ReviewID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Status: "armed", Deadline: time.Now().Add(-time.Minute), ConfigPath: "/etc/seg-agent/config.json", OldConfig: []byte("old"), CandidateConfig: []byte("same-candidate"), OldCA: []byte("old-ca"), CandidateCA: []byte("new-ca")}
	persistConfigurationAttempt(t, root, a)
	b := *a
	b.ReviewID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	b.Deadline = time.Now().Add(time.Minute)
	persistConfigurationAttempt(t, root, &b)
	os.WriteFile(root+a.ConfigPath, b.CandidateConfig, 0600)
	os.WriteFile(root+"/etc/seg-agent/controller-ca.crt", b.CandidateCA, 0600)
	commands := &configurationCommands{}
	logical := "/var/lib/seg-agent/configuration-transitions/" + a.ReviewID + ".json"
	if err := rollbackEndpointConfigurationUnder(root, logical, commands); !errors.Is(err, ErrStaleConfigurationReview) {
		t.Fatalf("watchdog reported refusal as success: %v", err)
	}
	// Force a successor to become active after startup loads A's snapshot.
	persistConfigurationAttempt(t, root, a)
	switched := false
	err := recoverConfigurationUnder(root, func(*configurationJournal) bool {
		if !switched {
			persistConfigurationAttempt(t, root, &b)
			switched = true
		}
		return false
	}, func(*configurationJournal) error { return errors.New("must not kill") })
	if !errors.Is(err, ErrStaleConfigurationReview) {
		t.Fatalf("startup reported refused restore as success: %v", err)
	}
	current, _ := os.ReadFile(root + a.ConfigPath)
	if string(current) != string(b.CandidateConfig) || len(commands.calls) != 0 {
		t.Fatal("refused rollback wrote successor state or restarted service")
	}
	finished := *a
	finished.Status = "rolled_back"
	atomicJSON(root+logical, &finished)
	if err := rollbackEndpointConfigurationUnder(root, logical, commands); err != nil {
		t.Fatal("already restored journal was not idempotent", err)
	}
}
func TestEndpointConfigurationSecondSafetyCheckExemptsOnlyItsOwnArmedReview(t *testing.T) {
	c := defaultConfig()
	c.StateDir = t.TempDir()
	directory := filepath.Join(c.StateDir, "configuration-transitions")
	os.MkdirAll(directory, 0700)
	identifier := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	atomicJSON(filepath.Join(directory, identifier+".json"), configurationJournal{SchemaVersion: 1, ReviewID: identifier, Status: "armed"})
	if err := checkEnforcementUpgradeSafety(c, true, identifier); err != nil {
		t.Fatal(err)
	}
	other := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	atomicJSON(filepath.Join(directory, other+".json"), configurationJournal{SchemaVersion: 1, ReviewID: other, Status: "armed"})
	if err := checkEnforcementUpgradeSafety(c, true, identifier); err == nil {
		t.Fatal("own-review exception bypassed another active rollback")
	}
}
