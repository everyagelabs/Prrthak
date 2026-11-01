package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func bootstrapFixture(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Prṛthak (पृथक्) bootstrap test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	caPath := filepath.Join(dir, "ca.crt")
	if e = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		t.Fatal(e)
	}
	token := filepath.Join(dir, "token")
	if e = os.WriteFile(token, []byte("private-test-token"), 0600); e != nil {
		t.Fatal(e)
	}
	return Config{ControllerURL: "https://controller.example.internal:8787", CACert: caPath, StateDir: dir, Certificate: filepath.Join(dir, "agent.crt"), PrivateKey: filepath.Join(dir, "agent.key"), EnrollmentTokenFile: token, IntervalSeconds: 60, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
}
func TestBootstrapPreflightRequiresPrivateToken(t *testing.T) {
	t.Setenv("SEG_ENROLLMENT_TOKEN", "")
	t.Setenv("SEG_ENROLLMENT_TOKEN_FILE", "")
	c := bootstrapFixture(t)
	enrolled, e := CheckBootstrap(c)
	if e != nil || enrolled {
		t.Fatalf("valid new bootstrap failed: %v %v", enrolled, e)
	}
	if e = os.Chmod(c.EnrollmentTokenFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = CheckBootstrap(c); e == nil || !strings.Contains(e.Error(), "private permissions") {
		t.Fatalf("world-readable token accepted: %v", e)
	}
	if e = os.Remove(c.EnrollmentTokenFile); e != nil {
		t.Fatal(e)
	}
	if _, e = CheckBootstrap(c); e == nil {
		t.Fatal("missing token accepted")
	}
}
func TestPendingEnrollmentCSRStableAcrossControllerFailures(t *testing.T) {
	t.Setenv("SEG_ENROLLMENT_TOKEN", "")
	t.Setenv("SEG_ENROLLMENT_TOKEN_FILE", "")
	c := bootstrapFixture(t)
	client, e := NewClient(c, false)
	if e != nil {
		t.Fatal(e)
	}
	csrs := []string{}
	hosts := []string{}
	client.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body map[string]string
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Fatal(e)
		}
		csrs = append(csrs, body["csr"])
		hosts = append(hosts, body["hostname"])
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"error":"temporarily unavailable"}`)), Header: http.Header{}}, nil
	})
	for i := 0; i < 2; i++ {
		if e = client.Enroll(context.Background()); e == nil {
			t.Fatal("temporary controller failure hidden")
		}
	}
	if len(csrs) != 2 || csrs[0] == "" || csrs[0] != csrs[1] || hosts[0] != hosts[1] {
		t.Fatal("enrollment retry changed CSR or hostname")
	}
	for _, name := range []string{"enrollment-pending.key", "enrollment-pending.csr"} {
		info, e := os.Stat(filepath.Join(c.StateDir, name))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("pending artifact not protected: %s %v", name, e)
		}
	}
}
func TestBootstrapBackoffAndCancel(t *testing.T) {
	previous := time.Duration(0)
	for attempt := 0; attempt < 20; attempt++ {
		delay := BootstrapBackoff(attempt)
		if delay < previous || delay > 5*time.Minute {
			t.Fatalf("unbounded/nonincreasing retry delay %s", delay)
		}
		previous = delay
	}
	t.Setenv("SEG_ENROLLMENT_TOKEN", "")
	t.Setenv("SEG_ENROLLMENT_TOKEN_FILE", "")
	c := bootstrapFixture(t)
	a, e := New(c, false, "")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Client.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"error":"offline"}`)), Header: http.Header{}}, nil
	})
	if e = a.Run(ctx, false); e != nil {
		t.Fatal(e)
	}
	status, e := ReadReadyStatus(c)
	if e != nil || status.Status != "enrollment_retrying" {
		t.Fatalf("retry state not persisted %+v %v", status, e)
	}
}
func TestSuccessfulFirstSyncPersistsAutomaticRegistrationReady(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5, DemoAgentID: "new-auto-server"}
	a, e := New(c, true, "auto-enrolled-host")
	if e != nil {
		t.Fatal(e)
	}
	reports := 0
	a.Client.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := "{}"
		if strings.HasSuffix(r.URL.Path, "/policy") {
			body = `{"server_id":"new-auto-server","version":1,"digest":"first-policy","mode":"monitor","services":[],"learning_sessions":[]}`
		} else {
			reports++
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	if e = a.Run(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	status, e := ReadReadyStatus(c)
	if e != nil || status.Status != "ready" || status.ServerID != "new-auto-server" || status.Hostname != "auto-enrolled-host" || reports < 1 {
		t.Fatalf("automatic discovery status incorrect %+v %v reports=%d", status, e, reports)
	}
}
func TestStockInstallerRejectsPathsItsUnitCannotWrite(t *testing.T) {
	c := Config{StateDir: "/var/lib/seg-agent", CACert: "/etc/seg-agent/controller-ca.crt", Certificate: "/var/lib/seg-agent/agent.crt", PrivateKey: "/var/lib/seg-agent/agent.key", EnrollmentTokenFile: "/etc/seg-agent/enrollment-token"}
	if e := ValidateInstallConfig(c); e != nil {
		t.Fatal(e)
	}
	c.StateDir = "/etc/another-service"
	if ValidateInstallConfig(c) == nil {
		t.Fatal("installer accepted a state path outside unit writable scope")
	}
	rooted := RootedConfig(Config{StateDir: "/var/lib/seg-agent", CACert: "/etc/seg-agent/controller-ca.crt", EndpointCACert: "/etc/seg-agent/endpoint-ca.crt"}, "/staging")
	if rooted.StateDir != "/staging/var/lib/seg-agent" || rooted.CACert != "/staging/etc/seg-agent/controller-ca.crt" || rooted.EndpointCACert != "/staging/etc/seg-agent/endpoint-ca.crt" {
		t.Fatalf("staging path map wrong %+v", rooted)
	}
}

func TestPrivateCredentialMetadataRejectsDifferentServiceOwner(t *testing.T) {
	c := bootstrapFixture(t)
	info, e := os.Lstat(c.EnrollmentTokenFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = validatePrivateFileInfo(c.EnrollmentTokenFile, info, os.Geteuid()); e != nil {
		t.Fatal(e)
	}
	if e = validatePrivateFileInfo(c.EnrollmentTokenFile, info, os.Geteuid()+1); e == nil || !strings.Contains(e.Error(), "owned by the service user") {
		t.Fatalf("credential owned by a different user accepted: %v", e)
	}
}

func TestPrivateArtifactFailureNeverCommitsPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enrollment-pending.key")
	injected := errors.New("simulated disk full")
	e := createPrivateAtomic(path, []byte("complete-private-key"), func(file *os.File, data []byte) (int, error) { n, _ := file.Write(data[:4]); return n, injected })
	if !errors.Is(e, injected) {
		t.Fatalf("write failure hidden: %v", e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("failed write committed a partial key at final path")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".seg-private-*")); len(matches) != 0 {
		t.Fatal("failed private temp artifact was not removed")
	}
	e = createPrivateAtomic(path, []byte("complete-private-key"), func(file *os.File, data []byte) (int, error) { n, _ := file.Write(data[:2]); return n, nil })
	if !errors.Is(e, io.ErrShortWrite) {
		t.Fatalf("short write accepted: %v", e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("short write committed a partial key")
	}
	if e = writePrivate(path, []byte("complete-private-key")); e != nil {
		t.Fatal(e)
	}
	if e = writePrivate(path, []byte("different-private-key")); !os.IsExist(e) {
		t.Fatalf("no-clobber identity protection missing: %v", e)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "complete-private-key" {
		t.Fatal("existing identity was overwritten")
	}
}
func TestPartialExistingCertificateCannotClaimEnrollmentSuccess(t *testing.T) {
	c := bootstrapFixture(t)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.Certificate, []byte("-----BEGIN CERTIFICATE-----\npartial"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = NewClient(c, false); e == nil {
		t.Fatal("client accepted a partial persisted certificate")
	}
	requests := 0
	client := &Client{config: c, HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("should not contact controller")
	})}}
	if e = client.Enroll(context.Background()); e == nil || !strings.Contains(e.Error(), "identity reload failed") {
		t.Fatalf("existing partial cert incorrectly completed enrollment: %v", e)
	}
	if requests != 0 {
		t.Fatal("corrupt identity caused an unauthenticated report instead of an explicit error")
	}
}
func TestPartialPendingKeyFailsWithoutIssuingAnotherIdentity(t *testing.T) {
	t.Setenv("SEG_ENROLLMENT_TOKEN", "")
	t.Setenv("SEG_ENROLLMENT_TOKEN_FILE", "")
	c := bootstrapFixture(t)
	if e := os.WriteFile(filepath.Join(c.StateDir, "enrollment-pending.key"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	client, e := NewClient(c, false)
	if e != nil {
		t.Fatal(e)
	}
	requests := 0
	client.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("should not enroll with a different key")
	})
	if e = client.Enroll(context.Background()); e == nil || !strings.Contains(e.Error(), "invalid pending enrollment key") {
		t.Fatalf("invalid persisted pending key was ignored: %v", e)
	}
	if requests != 0 {
		t.Fatal("partial pending key was silently replaced and re-enrolled")
	}
}
func TestReadinessRejectsOtherControllerGenerationAndStaleReport(t *testing.T) {
	c := Config{StateDir: t.TempDir(), ControllerURL: "https://controller-a.example:8787"}
	generation, e := PrepareReadiness(c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	ready := ReadyStatus{Status: "ready", ServerID: "node-unique", ControllerURL: c.ControllerURL, UpdatedAt: now, Generation: generation}
	if ok, reason := ReadyStatusMatches(c, ready, now); !ok {
		t.Fatalf("current readiness rejected: %s", reason)
	}
	other := c
	other.ControllerURL = "https://controller-b.example:8787"
	if ok, _ := ReadyStatusMatches(other, ready, now); ok {
		t.Fatal("readiness from previous controller accepted")
	}
	previous := ready
	previous.Generation = "earlier-process"
	if ok, _ := ReadyStatusMatches(c, previous, now); ok {
		t.Fatal("readiness from previous process accepted")
	}
	stale := ready
	stale.UpdatedAt = now.Add(-4 * time.Minute)
	if ok, _ := ReadyStatusMatches(c, stale, now); ok {
		t.Fatal("stale readiness accepted")
	}
	future := ready
	future.UpdatedAt = now.Add(time.Minute)
	if ok, _ := ReadyStatusMatches(c, future, now); ok {
		t.Fatal("future readiness accepted")
	}
	if e = atomicJSON(filepath.Join(c.StateDir, "status.json"), ready); e != nil {
		t.Fatal(e)
	}
	next, e := PrepareReadiness(c)
	if e != nil || next == generation {
		t.Fatalf("restart readiness generation was not rotated: %v", e)
	}
	if _, e = os.Stat(filepath.Join(c.StateDir, "status.json")); !os.IsNotExist(e) {
		t.Fatal("restart did not remove prior ready status")
	}
	// A final report from the old process after preparation cannot pass the new generation check.
	if e = atomicJSON(filepath.Join(c.StateDir, "status.json"), ready); e != nil {
		t.Fatal(e)
	}
	if ok, _ := ReadyStatusMatches(c, ready, now); ok {
		t.Fatal("old daemon race satisfied readiness for new restart")
	}
}
