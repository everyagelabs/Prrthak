package agent

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fleetSetupFixture(t *testing.T) (setupFile, string, string, time.Time) {
	t.Helper()
	value, path, output, now := setupFixture(t)
	value.SchemaVersion = 2
	value.EnrollmentProfileID = "812e8407-74eb-487c-8e62-87a624c93803"
	value.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339Nano)
	value.EnrollmentToken = strings.Repeat("b", 64)
	value.ControllerCA = setupCA(t, now, true, now.Add(31*24*time.Hour))
	return value, path, output, now
}

func TestFleetSetupReusableDataCreatesDistinctLocalKeysAndStableRetries(t *testing.T) {
	value, path, _, now := fleetSetupFixture(t)
	writeSetup(t, path, value)
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[[32]byte]bool{}
	for index := 0; index < 20; index++ {
		output := filepath.Join(filepath.Dir(path), fmt.Sprintf("prepared-%02d", index))
		if err := os.Mkdir(output, 0700); err != nil {
			t.Fatal(err)
		}
		if err := PrepareSetupFile(path, output, fmt.Sprintf("endpoint-%02d", index), now); err != nil {
			t.Fatal("same reusable setup did not prepare another hostname", err)
		}
		files, err := os.ReadDir(output)
		if err != nil || len(files) != 3 {
			t.Fatal("fleet setup unexpectedly contains identity or executable files", err)
		}
		config, err := LoadConfig(filepath.Join(output, "agent.json"), false)
		if err != nil || ValidateInstallConfig(config) != nil || config.Enforce || config.AllowFirewallChanges || config.LearningAutoAllow || config.AllowHostDefaultDeny || config.UnexpectedPortMonitorEnabled {
			t.Fatal("fleet setup changed canonical monitor-only defaults", err)
		}
		credential, err := os.ReadFile(filepath.Join(output, "enrollment-token"))
		if err != nil || string(credential) != value.EnrollmentToken {
			t.Fatal("reusable credential not retained privately", err)
		}
		for _, entry := range files {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatal("prepared data is not private", err)
			}
		}
		// Each fresh endpoint starts with empty local state, not a private key
		// distributed in its common setup bundle. Exercise the real key/CSR
		// generator and persisted retry path without a controller or firewall.
		state := filepath.Join(filepath.Dir(path), fmt.Sprintf("state-%02d", index))
		if err := os.Mkdir(state, 0700); err != nil {
			t.Fatal(err)
		}
		key, csr, hostname, err := pendingEnrollment(state)
		if err != nil {
			t.Fatal(err)
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(public)
		if seen[digest] {
			t.Fatal("fresh endpoints reused a private identity")
		}
		seen[digest] = true
		block, _ := pem.Decode(csr)
		if block == nil {
			t.Fatal("missing enrollment CSR")
		}
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || request.CheckSignature() != nil {
			t.Fatal("locally generated enrollment CSR is invalid", err)
		}
		retryKey, retryCSR, retryHostname, err := pendingEnrollment(state)
		if err != nil || !retryKey.PublicKey.Equal(&key.PublicKey) || !bytes.Equal(retryCSR, csr) || retryHostname != hostname {
			t.Fatal("retry changed its pending identity", err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || len(seen) != 20 {
		t.Fatal("reusing the setup changed its input or failed unique identities", err)
	}
}

func TestFleetSetupValidLifetimeBoundsAndRemainingWindow(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Hour, 24 * time.Hour, maxFleetSetupLifetime} {
		value, _, _, now := fleetSetupFixture(t)
		value.ExpiresAt = now.Add(lifetime).Format(time.RFC3339Nano)
		encoded, _ := json.Marshal(value)
		if _, _, err := parseSetup(encoded, "any-new-endpoint", now); err != nil {
			t.Fatal("valid configured enrollment lifetime refused", lifetime, err)
		}
		// A configured hour remains usable until its end, including the last
		// minute; the bound is issued-to-expiry, not minimum time remaining.
		if _, _, err := parseSetup(encoded, "later-endpoint", now.Add(lifetime-time.Minute)); err != nil {
			t.Fatal("valid remaining enrollment window refused", lifetime, err)
		}
	}
}

func TestFleetSetupRejectsInvalidProfileLifetimeAndCredentialBeforeWriting(t *testing.T) {
	changes := map[string]func(*setupFile, time.Time){
		"profile missing":   func(v *setupFile, _ time.Time) { v.EnrollmentProfileID = "" },
		"profile malformed": func(v *setupFile, _ time.Time) { v.EnrollmentProfileID = "not-a-profile" },
		"profile uppercase": func(v *setupFile, _ time.Time) { v.EnrollmentProfileID = strings.ToUpper(v.EnrollmentProfileID) },
		"profile zero":      func(v *setupFile, _ time.Time) { v.EnrollmentProfileID = "00000000-0000-0000-0000-000000000000" },
		"hostname bound":    func(v *setupFile, _ time.Time) { v.ExpectedHostname = "endpoint-01" },
		"expired":           func(v *setupFile, n time.Time) { v.ExpiresAt = n.Format(time.RFC3339Nano) },
		"lifetime too short": func(v *setupFile, n time.Time) {
			v.ExpiresAt = n.Add(time.Hour - time.Nanosecond).Format(time.RFC3339Nano)
		},
		"lifetime too long": func(v *setupFile, n time.Time) {
			v.ExpiresAt = n.Add(maxFleetSetupLifetime + time.Nanosecond).Format(time.RFC3339Nano)
		},
		"issued in future":     func(v *setupFile, n time.Time) { v.IssuedAt = n.Add(3 * time.Minute).Format(time.RFC3339Nano) },
		"invalid issued":       func(v *setupFile, _ time.Time) { v.IssuedAt = "not-a-time" },
		"invalid expires":      func(v *setupFile, _ time.Time) { v.ExpiresAt = "not-a-time" },
		"short credential":     func(v *setupFile, _ time.Time) { v.EnrollmentToken = strings.Repeat("b", 43) },
		"long credential":      func(v *setupFile, _ time.Time) { v.EnrollmentToken += "b" },
		"credential delimiter": func(v *setupFile, _ time.Time) { v.EnrollmentToken = strings.Repeat("b", 63) + "\n" },
		"unknown schema":       func(v *setupFile, _ time.Time) { v.SchemaVersion = 3 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			value, path, output, now := fleetSetupFixture(t)
			change(&value, now)
			writeSetup(t, path, value)
			if err := PrepareSetupFile(path, output, "endpoint-01", now); err == nil || strings.Contains(err.Error(), value.EnrollmentToken) {
				t.Fatal("invalid fleet scope was accepted or exposed its credential")
			}
			emptySetupOutput(t, output)
		})
	}
}

func TestFleetSetupCannotEnableAccessOrReplaceIdentityPaths(t *testing.T) {
	changes := map[string]func(*Config){
		"enforce":          func(c *Config) { c.Enforce = true },
		"default deny":     func(c *Config) { c.AllowHostDefaultDeny = true },
		"imported writes":  func(c *Config) { c.AllowFirewallChanges = true },
		"automatic access": func(c *Config) { c.LearningAutoAllow = true },
		"instrumentation":  func(c *Config) { c.UnexpectedPortMonitorEnabled = true },
		"identity path":    func(c *Config) { c.PrivateKey = "/root/shared.key" },
		"state path":       func(c *Config) { c.StateDir = "/etc/shared-agent" },
		"credential path":  func(c *Config) { c.EnrollmentTokenFile = "/root/fleet-key" },
		"plaintext URL":    func(c *Config) { c.ControllerURL = "http://controller.example.internal" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			value, path, output, now := fleetSetupFixture(t)
			var config Config
			if err := json.Unmarshal(value.Config, &config); err != nil {
				t.Fatal(err)
			}
			change(&config)
			value.Config, _ = json.Marshal(config)
			writeSetup(t, path, value)
			if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
				t.Fatal("fleet setup granted authority or used unsafe paths")
			}
			emptySetupOutput(t, output)
		})
	}
}

func TestFleetSetupRequiresTrustValidForItsWholeEnrollmentWindow(t *testing.T) {
	for _, variant := range []string{"expires early", "private material", "leaf", "separate issuer mismatch"} {
		t.Run(variant, func(t *testing.T) {
			value, path, output, now := fleetSetupFixture(t)
			switch variant {
			case "expires early":
				value.ControllerCA = setupCA(t, now, true, now.Add(time.Hour))
			case "private material":
				value.ControllerCA += string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-deployment-key")}))
			case "leaf":
				value.ControllerCA = setupCA(t, now, false, now.Add(31*24*time.Hour))
			case "separate issuer mismatch":
				value.EndpointCA = value.ControllerCA
			}
			writeSetup(t, path, value)
			if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
				t.Fatal("fleet enrollment trust did not cover its contract")
			}
			emptySetupOutput(t, output)
		})
	}
}

func TestOneUseSetupRefusesFleetMetadataEvenWhenEmpty(t *testing.T) {
	for _, profile := range []string{"", "812e8407-74eb-487c-8e62-87a624c93803"} {
		value, path, output, now := setupFixture(t)
		encoded, _ := json.Marshal(value)
		var body map[string]any
		_ = json.Unmarshal(encoded, &body)
		body["enrollment_profile_id"] = profile
		writeSetup(t, path, body)
		if err := PrepareSetupFile(path, output, "endpoint", now); err == nil {
			t.Fatal("historical one-use schema accepted fleet authority metadata")
		}
		emptySetupOutput(t, output)
	}
}
