package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type ReadyStatus struct {
	Status        string    `json:"status"`
	ServerID      string    `json:"server_id,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	ControllerURL string    `json:"controller_url"`
	UpdatedAt     time.Time `json:"updated_at"`
	Error         string    `json:"error,omitempty"`
	Generation    string    `json:"generation"`
}

func ValidateInstallConfig(c Config) error {
	if c.StateDir != "/var/lib/seg-agent" || c.CACert != "/etc/seg-agent/controller-ca.crt" || c.Certificate != "/var/lib/seg-agent/agent.crt" || c.PrivateKey != "/var/lib/seg-agent/agent.key" {
		return errors.New("stock systemd installer requires state_dir=/var/lib/seg-agent, ca_cert=/etc/seg-agent/controller-ca.crt, and identity files agent.crt/agent.key inside state_dir")
	}
	if c.EnrollmentTokenFile != "" && c.EnrollmentTokenFile != "/etc/seg-agent/enrollment-token" {
		return errors.New("stock systemd installer requires enrollment_token_file=/etc/seg-agent/enrollment-token (or empty when an installed bootstrap override is used)")
	}
	if c.EndpointCACert != "" && c.EndpointCACert != "/etc/seg-agent/endpoint-ca.crt" {
		return errors.New("stock systemd installer requires endpoint_ca_cert=/etc/seg-agent/endpoint-ca.crt when a separate endpoint issuing CA is used")
	}
	return nil
}
func rootedPath(root, path string) string {
	if root == "" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}
func RootedConfig(c Config, root string) Config {
	c.StateDir = rootedPath(root, c.StateDir)
	c.CACert = rootedPath(root, c.CACert)
	if c.EndpointCACert != "" {
		c.EndpointCACert = rootedPath(root, c.EndpointCACert)
	}
	c.Certificate = rootedPath(root, c.Certificate)
	c.PrivateKey = rootedPath(root, c.PrivateKey)
	if c.EnrollmentTokenFile != "" {
		c.EnrollmentTokenFile = rootedPath(root, c.EnrollmentTokenFile)
	}
	return c
}
func checkPrivateFile(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	return validatePrivateFileInfo(path, info, os.Geteuid())
}
func validatePrivateFileInfo(path string, info os.FileInfo, serviceUID int) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file, not a symlink or directory", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must have private permissions (0600 or0400)", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(serviceUID) {
		return fmt.Errorf("%s must be owned by the service user", path)
	}
	return nil
}
func EnrollmentToken(c Config) (string, error) {
	if token := strings.TrimSpace(os.Getenv("SEG_ENROLLMENT_TOKEN")); token != "" {
		return token, nil
	}
	path := strings.TrimSpace(os.Getenv("SEG_ENROLLMENT_TOKEN_FILE"))
	if path == "" {
		path = c.EnrollmentTokenFile
	}
	if path == "" {
		return "", errors.New("provide an enrollment credential through enrollment_token_file, SEG_ENROLLMENT_TOKEN_FILE, or SEG_ENROLLMENT_TOKEN")
	}
	if e := checkPrivateFile(path); e != nil {
		return "", fmt.Errorf("enrollment token: %w", e)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("enrollment token file is empty")
	}
	return token, nil
}
func verifiedIdentity(c Config, roots *x509.CertPool) (tls.Certificate, error) {
	if e := checkPrivateFile(c.PrivateKey); e != nil {
		return tls.Certificate{}, fmt.Errorf("invalid existing mTLS private key: %w", e)
	}
	pair, e := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
	if e != nil {
		return tls.Certificate{}, fmt.Errorf("invalid existing mTLS certificate/keypair: %w", e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return tls.Certificate{}, e
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if cert, e := x509.ParseCertificate(der); e == nil {
			intermediates.AddCert(cert)
		}
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return tls.Certificate{}, fmt.Errorf("existing mTLS identity is invalid: %w", e)
	}
	if leaf.Subject.CommonName == "" {
		return tls.Certificate{}, errors.New("existing certificate has no server identity")
	}
	pair.Leaf = leaf
	return pair, nil
}
func CheckBootstrap(c Config) (bool, error) {
	if _, e := NewClient(c, false); e != nil {
		return false, e
	}
	// NewClient verifies both persisted artifacts and loads an authenticated identity.
	if _, e := os.Stat(c.Certificate); e == nil {
		return true, nil
	} else if !os.IsNotExist(e) {
		return false, e
	}
	_, e := EnrollmentToken(c)
	return false, e
}

type readinessGeneration struct {
	Generation string `json:"generation"`
}

func PrepareReadiness(c Config) (string, error) {
	generation := batchID()
	if e := atomicJSON(filepath.Join(c.StateDir, "readiness-generation.json"), readinessGeneration{generation}); e != nil {
		return "", e
	}
	if e := os.Remove(filepath.Join(c.StateDir, "status.json")); e != nil && !os.IsNotExist(e) {
		return "", e
	}
	return generation, nil
}
func ReadyStatusMatches(c Config, status ReadyStatus, now time.Time) (bool, string) {
	if strings.TrimRight(status.ControllerURL, "/") != strings.TrimRight(c.ControllerURL, "/") {
		return false, "stored readiness belongs to a different controller"
	}
	b, e := os.ReadFile(filepath.Join(c.StateDir, "readiness-generation.json"))
	if e != nil {
		return false, "waiting for this service instance readiness generation"
	}
	var expected readinessGeneration
	if json.Unmarshal(b, &expected) != nil || expected.Generation == "" || status.Generation != expected.Generation {
		return false, "stored readiness belongs to an earlier service instance"
	}
	if status.Status != "ready" {
		return false, status.Status
	}
	age := now.Sub(status.UpdatedAt)
	if age < 0 || age >= 3*time.Minute {
		return false, "last successful controller report is stale"
	}
	if status.ServerID == "" {
		return false, "server identity has not been confirmed"
	}
	return true, ""
}
func (a *Agent) writeReadyStatus(status string, err error) error {
	host, _ := os.Hostname()
	if a.Simulate && a.SimulateHostname != "" {
		host = a.SimulateHostname
	}
	record := ReadyStatus{Status: status, Hostname: host, ControllerURL: a.Config.ControllerURL, UpdatedAt: time.Now().UTC(), Generation: a.Generation}
	if a.State.Policy != nil {
		record.ServerID = a.State.Policy.ServerID
	}
	if err != nil {
		record.Error = err.Error()
	}
	return atomicJSON(filepath.Join(a.Config.StateDir, "status.json"), record)
}
func ReadReadyStatus(c Config) (ReadyStatus, error) {
	var status ReadyStatus
	b, e := os.ReadFile(filepath.Join(c.StateDir, "status.json"))
	if e != nil {
		return status, e
	}
	e = json.Unmarshal(b, &status)
	return status, e
}

// Retry delays are bounded and grow on bootstrap failures to avoid synchronized fleet retries.
func BootstrapBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 6 {
		attempt = 6
	}
	delay := 5 * time.Second * time.Duration(1<<attempt)
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay
}
