package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupCA(t *testing.T, now time.Time, isCA bool, expires time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "private setup fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: expires, IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func setupFixture(t *testing.T) (setupFile, string, string, time.Time) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	config := defaultConfig()
	config.CACert = "/etc/seg-agent/controller-ca.crt"
	config.Certificate = "/var/lib/seg-agent/agent.crt"
	config.PrivateKey = "/var/lib/seg-agent/agent.key"
	config.EnrollmentTokenFile = "/etc/seg-agent/enrollment-token"
	config.IntervalSeconds, config.DiscoveryIntervalSeconds = 30, 900
	config.ManagementSources = []string{}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	value := setupFile{SchemaVersion: 1, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339), Config: encoded, ControllerCA: setupCA(t, now, true, now.Add(time.Hour)), EnrollmentToken: strings.Repeat("a", 43)}
	path := filepath.Join(directory, "setup.json")
	output := filepath.Join(directory, "prepared")
	if err = os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	return value, path, output, now
}

func writeSetup(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}

func emptySetupOutput(t *testing.T, output string) {
	t.Helper()
	files, err := os.ReadDir(output)
	if err != nil || len(files) != 0 {
		t.Fatalf("invalid setup wrote private output: %v %v", files, err)
	}
}

func TestPrivateSetupPreparesCanonicalMonitorDataWithoutEnrollment(t *testing.T) {
	value, path, output, now := setupFixture(t)
	value.ExpectedHostname = "endpoint-01"
	writeSetup(t, path, value)
	if err := PrepareSetupFile(path, output, "endpoint-01", now); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(output)
	if len(files) != 3 {
		t.Fatalf("unexpected prepared file count: %d", len(files))
	}
	for _, file := range files {
		info, _ := file.Info()
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("private data permissions: %s %v", file.Name(), info.Mode())
		}
	}
	config, err := LoadConfig(filepath.Join(output, "agent.json"), false)
	if err != nil || ValidateInstallConfig(config) != nil || config.Enforce || config.IntervalSeconds != 30 || config.DiscoveryIntervalSeconds != 900 {
		t.Fatalf("prepared config invalid: %v %#v", err, config)
	}
	token, _ := os.ReadFile(filepath.Join(output, "enrollment-token"))
	if string(token) != value.EnrollmentToken {
		t.Fatal("private token did not survive data preparation")
	}
	if _, err = os.Stat(filepath.Join(output, "agent.key")); !os.IsNotExist(err) {
		t.Fatal("setup preparation generated an endpoint identity")
	}
}

func TestPrivateSetupSupportsSeparatePublicEndpointIssuer(t *testing.T) {
	value, path, output, now := setupFixture(t)
	var config Config
	_ = json.Unmarshal(value.Config, &config)
	config.EndpointCACert = "/etc/seg-agent/endpoint-ca.crt"
	value.Config, _ = json.Marshal(config)
	value.EndpointCA = setupCA(t, now, true, now.Add(2*time.Hour))
	writeSetup(t, path, value)
	if err := PrepareSetupFile(path, output, "endpoint-01", now); err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(filepath.Join(output, "endpoint-ca.crt"))
	if string(actual) != value.EndpointCA {
		t.Fatal("separate issuer was not preserved")
	}
}

func TestPrivateSetupRejectsSecurityOptInsAndUnsafeConfigBeforeWriting(t *testing.T) {
	changes := []func(map[string]any){
		func(c map[string]any) { c["enforce"] = true },
		func(c map[string]any) { c["allow_firewall_changes"] = true },
		func(c map[string]any) { c["learning_auto_allow"] = true },
		func(c map[string]any) { c["unexpected_port_monitor_enabled"] = true },
		func(c map[string]any) { c["allow_single_admin_pilot"] = true },
		func(c map[string]any) {
			c["single_admin_pilot_scope"] = map[string]any{"revision": 1, "server_ids": []string{"injected"}, "expires_at": "2099-01-01T00:00:00Z"}
		},
		func(c map[string]any) { c["state_dir"] = "/root" },
		func(c map[string]any) { c["private_key"] = "/root/private-key" },
		func(c map[string]any) { c["policy_signing_trust_file"] = "/root/authorized_keys" },
		func(c map[string]any) { c["management_probe_ca_cert"] = "/root/private" },
		func(c map[string]any) { c["controller_url"] = "http://controller.example.internal" },
		func(c map[string]any) { c["commands"] = "must not execute" },
		func(c map[string]any) { c["tags"] = map[string]any{"application": "billing"} },
	}
	for index, change := range changes {
		value, path, output, now := setupFixture(t)
		var config map[string]any
		_ = json.Unmarshal(value.Config, &config)
		change(config)
		value.Config, _ = json.Marshal(config)
		writeSetup(t, path, value)
		if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
			t.Fatalf("unsafe config variation %d accepted", index)
		}
		emptySetupOutput(t, output)
	}
}

func TestPrivateSetupAcceptsExistingIntervalBoundsAndRefusesOutOfBounds(t *testing.T) {
	for _, intervals := range [][2]int{{5, 60}, {3600, 86400}, {4, 900}, {30, 86401}} {
		value, path, output, now := setupFixture(t)
		var config Config
		_ = json.Unmarshal(value.Config, &config)
		config.IntervalSeconds, config.DiscoveryIntervalSeconds = intervals[0], intervals[1]
		value.Config, _ = json.Marshal(config)
		writeSetup(t, path, value)
		err := PrepareSetupFile(path, output, "endpoint", now)
		valid := intervals[0] >= 5 && intervals[1] <= 86400
		if (err == nil) != valid {
			t.Fatalf("interval bounds %v: %v", intervals, err)
		}
	}
}

func TestPrivateSetupExpiryHostnameAndTokenAreBounded(t *testing.T) {
	changes := []func(*setupFile, time.Time){
		func(v *setupFile, n time.Time) { v.ExpiresAt = n.Format(time.RFC3339) },
		func(v *setupFile, n time.Time) { v.ExpiresAt = n.Add(16 * time.Minute).Format(time.RFC3339) },
		func(v *setupFile, n time.Time) { v.IssuedAt = n.Add(3 * time.Minute).Format(time.RFC3339) },
		func(v *setupFile, n time.Time) { v.ExpiresAt = "not a timestamp" },
		func(v *setupFile, n time.Time) { v.ExpectedHostname = "another-endpoint" },
		func(v *setupFile, n time.Time) { v.ExpectedHostname = "endpoint\ncommand" },
		func(v *setupFile, n time.Time) { v.EnrollmentToken = "short" },
		func(v *setupFile, n time.Time) { v.EnrollmentToken += "\ncommand" },
	}
	for index, change := range changes {
		value, path, output, now := setupFixture(t)
		change(&value, now)
		writeSetup(t, path, value)
		if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
			t.Fatalf("invalid lifetime/recipient/token variation %d accepted", index)
		}
		emptySetupOutput(t, output)
	}
}

func TestPrivateSetupRejectsPrivateKeysLeafsAndExpiredCABundles(t *testing.T) {
	for _, variant := range []string{"private", "leaf", "expires", "oversized", "issuer-mismatch"} {
		value, path, output, now := setupFixture(t)
		switch variant {
		case "private":
			value.ControllerCA += string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private material")}))
		case "leaf":
			value.ControllerCA = setupCA(t, now, false, now.Add(time.Hour))
		case "expires":
			value.ControllerCA = setupCA(t, now, true, now.Add(time.Minute))
		case "oversized":
			value.ControllerCA = strings.Repeat("A", maxSetupCABytes+1)
		case "issuer-mismatch":
			value.EndpointCA = value.ControllerCA
		}
		writeSetup(t, path, value)
		if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
			t.Fatalf("unsafe CA variant accepted: %s", variant)
		}
		emptySetupOutput(t, output)
	}
}

func TestPrivateSetupStrictJSONRejectsDuplicatesUnknownFieldsAndNulls(t *testing.T) {
	for _, variant := range []string{"duplicate", "config-duplicate", "unknown", "null", "trailing", "nested"} {
		value, path, output, now := setupFixture(t)
		encoded, _ := json.Marshal(value)
		switch variant {
		case "duplicate":
			encoded = append(encoded[:len(encoded)-1], []byte(`,"schema_version":1}`)...)
		case "config-duplicate":
			encoded = bytes.Replace(encoded, []byte(`"enforce":false`), []byte(`"enforce":false,"enforce":false`), 1)
		case "unknown":
			encoded = append(encoded[:len(encoded)-1], []byte(`,"script":"untrusted code"}`)...)
		case "null":
			encoded = bytes.Replace(encoded, []byte(`"enforce":false`), []byte(`"enforce":null`), 1)
		case "trailing":
			encoded = append(encoded, []byte(`{}`)...)
		case "nested":
			encoded = []byte(strings.Repeat("[", 18) + "1" + strings.Repeat("]", 18))
		}
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
			t.Fatalf("unsafe JSON accepted: %s", variant)
		}
		emptySetupOutput(t, output)
	}
}

func TestPrivateSetupRejectsUnsafeFileModesLinksAndOutputDirectories(t *testing.T) {
	value, path, output, now := setupFixture(t)
	writeSetup(t, path, value)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
		t.Fatal("world-readable setup accepted")
	}
	_ = os.Chmod(path, 0600)
	for _, variant := range []string{"file-link", "parent-link", "output-link", "output-mode", "output-nonempty", "hard-link"} {
		input, destination := path, output
		switch variant {
		case "file-link":
			input = filepath.Join(filepath.Dir(path), "alias.json")
			_ = os.Symlink(path, input)
		case "parent-link":
			parent := filepath.Join(filepath.Dir(path), "alias-dir")
			_ = os.Symlink(filepath.Dir(path), parent)
			input = filepath.Join(parent, filepath.Base(path))
		case "output-link":
			destination = filepath.Join(filepath.Dir(path), "output-alias")
			_ = os.Symlink(output, destination)
		case "output-mode":
			_ = os.Chmod(output, 0755)
		case "output-nonempty":
			_ = os.WriteFile(filepath.Join(output, "keep-me"), []byte("must survive"), 0600)
		case "hard-link":
			_ = os.Link(path, filepath.Join(filepath.Dir(path), "hard-alias"))
		}
		if err := PrepareSetupFile(input, destination, "endpoint", now); err == nil {
			t.Fatalf("unsafe path accepted: %s", variant)
		}
		_ = os.Chmod(output, 0700)
	}
	content, err := os.ReadFile(filepath.Join(output, "keep-me"))
	if err != nil || string(content) != "must survive" {
		t.Fatal("refused output overwrote an existing file")
	}
}

func TestPrivateSetupRejectsOversizedFileBeforeParsingAndDoesNotLeakToken(t *testing.T) {
	value, path, output, now := setupFixture(t)
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), maxSetupFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
		t.Fatal("oversized private setup accepted")
	}
	value.EnrollmentToken += "\nsecret-marker-never-in-errors"
	writeSetup(t, path, value)
	err := PrepareSetupFile(path, output, "endpoint", now)
	if err == nil || strings.Contains(err.Error(), "secret-marker") {
		t.Fatal("bad token accepted or disclosed in error")
	}
	emptySetupOutput(t, output)
}
