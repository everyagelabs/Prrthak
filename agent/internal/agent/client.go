package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	identity       *atomic.Pointer[tls.Certificate]
	renewMu        sync.Mutex
	renewRetry     time.Time
	renewBulkID    string
	renewBulkRetry time.Time
	config         Config
	simulate       bool
	HTTP           *http.Client
	SecurityAcks   []string
	FirewallAcks   []string
}
type HTTPError struct {
	Status int
	Path   string
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("controller %s: HTTP%d: %s", e.Path, e.Status, e.Body)
}
func NewClient(c Config, simulate bool) (*Client, error) {
	return newIdentityClient(c, simulate, true)
}
func newIdentityClient(c Config, simulate, loadIdentity bool) (*Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	identity := &atomic.Pointer[tls.Certificate]{}
	if c.CACert != "" {
		b, e := os.ReadFile(c.CACert)
		if e != nil {
			return nil, e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid controller CA")
		}
		tc.RootCAs = roots
	}
	if !simulate && loadIdentity {
		roots, e := endpointRoots(c, tc.RootCAs)
		if e != nil {
			return nil, e
		}
		if e = recoverPendingIdentity(c, roots); e != nil {
			return nil, e
		}
		if _, e := os.Stat(c.Certificate); e == nil {
			cert, e := verifiedIdentity(c, roots)
			if e != nil {
				return nil, e
			}
			tc.Certificates = []tls.Certificate{cert}
			identity.Store(&cert)
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if certificate := identity.Load(); certificate != nil {
			return certificate, nil
		}
		return &tls.Certificate{}, nil
	}
	tr := &http.Transport{TLSClientConfig: tc, MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	return &Client{config: c, simulate: simulate, identity: identity, HTTP: &http.Client{Transport: tr, Timeout: time.Duration(c.RequestTimeoutSeconds) * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) request(ctx context.Context, method, path string, in any, etag string) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return nil, e
		}
		body = bytes.NewReader(b)
	}
	origin := c.config.ControllerURL
	if path == "/api/v1/agent/enroll" || path == "/api/v1/agent/certificates/recover" || path == "/api/v1/agent/report" || path == "/api/v1/agent/flows" || path == "/api/v1/agent/hits" {
		if c.config.DiscoveryURL != "" {
			origin = c.config.DiscoveryURL
		}
	} else if c.config.ControlURL != "" {
		origin = c.config.ControlURL
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(origin, "/")+path, body)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Prthak-agent/"+Version)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if c.simulate {
		req.Header.Set("X-Agent-ID", c.config.DemoAgentID)
	}
	res, e := c.HTTP.Do(req)
	if e != nil {
		return nil, e
	}
	if res.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		res.Body.Close()
		return nil, &HTTPError{res.StatusCode, path, strings.TrimSpace(string(b))}
	}
	return res, nil
}
func decodeResponse(res *http.Response, out any) error {
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("unexpected HTTP%d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
}
func (c *Client) Report(ctx context.Context, r Report) error {
	c.SecurityAcks = nil
	c.FirewallAcks = nil
	res, e := c.request(ctx, "POST", "/api/v1/agent/report", r, "")
	if e != nil {
		return e
	}
	var reply struct {
		SecurityAcks []string `json:"ack_security_event_ids"`
		FirewallAcks []string `json:"ack_firewall_change_ids"`
	}
	if e = decodeResponse(res, &reply); e != nil {
		return e
	}
	c.SecurityAcks = reply.SecurityAcks
	c.FirewallAcks = reply.FirewallAcks
	return nil
}
func (c *Client) Policy(ctx context.Context, etag string) (*Policy, string, error) {
	res, e := c.request(ctx, "GET", "/api/v1/agent/policy", nil, etag)
	if e != nil {
		return nil, "", e
	}
	if res.StatusCode == 304 {
		res.Body.Close()
		return nil, etag, nil
	}
	var p Policy
	// Signed assignments carry an exact public payload alongside its signature.
	// Only policy responses get this bound; other APIs retain4MiB.
	defer res.Body.Close()
	e = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&p)
	if e != nil {
		return nil, "", e
	}
	if e = ValidatePolicy(&p); e != nil {
		return nil, "", e
	}
	return &p, res.Header.Get("ETag"), nil
}
func (c *Client) Flows(ctx context.Context, b Batch) error {
	res, e := c.request(ctx, "POST", "/api/v1/agent/flows", b, "")
	if e != nil {
		return e
	}
	return decodeResponse(res, &map[string]any{})
}
func (c *Client) Enroll(ctx context.Context) error {
	if c.simulate {
		return nil
	}
	if _, e := os.Stat(c.config.Certificate); e == nil {
		if e := policySigningReadiness(c.config); e != nil {
			return fmt.Errorf("existing identity requires independently pinned assignment trust before bootstrap completes: %w", e)
		}
		return c.reloadIdentity()
	} else if !os.IsNotExist(e) {
		return e
	}
	token, e := EnrollmentToken(c.config)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(c.config.StateDir, 0700); e != nil {
		return e
	}
	key, csrPEM, hostname, e := pendingEnrollment(c.config.StateDir)
	if e != nil {
		return e
	}
	payload := map[string]string{"token": token, "hostname": hostname, "csr": string(csrPEM)}
	res, e := c.request(ctx, "POST", "/api/v1/agent/enroll", payload, "")
	if e != nil {
		return e
	}
	var reply struct {
		ServerID           string          `json:"server_id"`
		Certificate        string          `json:"certificate"`
		CACertificate      string          `json:"ca_certificate"`
		PolicySigningTrust json.RawMessage `json:"policy_signing_trust"`
	}
	if e = decodeResponse(res, &reply); e != nil {
		return e
	}
	block, _ := pem.Decode([]byte(reply.Certificate))
	if block == nil {
		return errors.New("enrollment returned invalid certificate")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return e
	}
	if cert.Subject.CommonName != reply.ServerID || reply.ServerID == "" {
		return errors.New("enrollment certificate identity mismatch")
	}
	der, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		return e
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	// Verify issuer against configured bootstrap CA, never trust replacement CA supplied by server.
	roots := c.HTTP.Transport.(*http.Transport).TLSClientConfig.RootCAs
	roots, e = endpointRoots(c.config, roots)
	if e != nil {
		return e
	}
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return fmt.Errorf("agent certificate verification: %w", e)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("certificate key differs from CSR")
	}
	if e = c.commitEnrollmentArtifacts(keyPEM, []byte(reply.Certificate), reply.PolicySigningTrust); e != nil {
		return e
	}
	// Enrollment is complete only after the committed, verified keypair is loaded into the client.
	return c.reloadIdentity()
}

func (c *Client) commitEnrollmentArtifacts(key, certificate, trust []byte) error {
	// Validate and persist the immutable pin before exposing the certificate
	// which makes future enrollment calls short-circuit after a crash.
	if len(trust) > 0 {
		if e := c.pinEnrollmentSigningTrust(trust); e != nil {
			return e
		}
	}
	// An explicit operator pin is never replaced by the reply, but must itself
	// be present/valid before exposing a completed identity.
	if e := policySigningReadiness(c.config); e != nil {
		return e
	}
	if e := writeOrVerifyPrivate(c.config.PrivateKey, key); e != nil {
		return e
	}
	return writeOrVerifyPrivate(c.config.Certificate, certificate)
}
func (c *Client) reloadIdentity() error {
	fresh, e := NewClient(c.config, false)
	if e != nil {
		return fmt.Errorf("enrolled identity reload failed: %w", e)
	}
	transport, ok := fresh.HTTP.Transport.(*http.Transport)
	if !ok || len(transport.TLSClientConfig.Certificates) == 0 {
		return errors.New("enrollment did not produce a usable mTLS identity")
	}
	c.HTTP = fresh.HTTP
	c.identity = fresh.identity
	_ = os.Remove(filepath.Join(c.config.StateDir, "enrollment-pending.csr"))
	_ = os.Remove(filepath.Join(c.config.StateDir, "enrollment-pending.key"))
	return nil
}
func writePrivate(path string, b []byte) error {
	return createPrivateAtomic(path, b, func(file *os.File, data []byte) (int, error) { return file.Write(data) })
}
func createPrivateAtomic(path string, b []byte, write func(*os.File, []byte) (int, error)) error {
	if len(b) == 0 {
		return errors.New("refusing to create an empty private artifact")
	}
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	file, e := os.CreateTemp(dir, ".seg-private-*")
	if e != nil {
		return e
	}
	temp := file.Name()
	defer os.Remove(temp)
	if e = file.Chmod(0600); e != nil {
		file.Close()
		return e
	}
	n, e := write(file, b)
	if e != nil {
		file.Close()
		return e
	}
	if n != len(b) {
		file.Close()
		return io.ErrShortWrite
	}
	if e = file.Sync(); e != nil {
		file.Close()
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	// Hard-link commit is atomic and refuses to clobber another committed identity.
	// An interrupted/failed write can leave only an ignored private temp file.
	if e = os.Link(temp, path); e != nil {
		return e
	}
	if e = os.Remove(temp); e != nil {
		return e
	}
	directory, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer directory.Close()
	return directory.Sync()
}

func pendingEnrollment(dir string) (*ecdsa.PrivateKey, []byte, string, error) {
	keyPath := filepath.Join(dir, "enrollment-pending.key")
	csrPath := filepath.Join(dir, "enrollment-pending.csr")
	var key *ecdsa.PrivateKey
	if b, e := os.ReadFile(keyPath); e == nil {
		if e = checkPrivateFile(keyPath); e != nil {
			return nil, nil, "", e
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, nil, "", errors.New("invalid pending enrollment key")
		}
		key, e = x509.ParseECPrivateKey(block.Bytes)
		if e != nil {
			return nil, nil, "", e
		}
	} else if os.IsNotExist(e) {
		key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, nil, "", e
		}
		der, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			return nil, nil, "", e
		}
		if e = writePrivate(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); e != nil {
			return nil, nil, "", e
		}
	} else {
		return nil, nil, "", e
	}
	if b, e := os.ReadFile(csrPath); e == nil {
		if e = checkPrivateFile(csrPath); e != nil {
			return nil, nil, "", e
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, nil, "", errors.New("invalid pending CSR")
		}
		csr, e := x509.ParseCertificateRequest(block.Bytes)
		if e != nil {
			return nil, nil, "", e
		}
		if e = csr.CheckSignature(); e != nil {
			return nil, nil, "", e
		}
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok || !pub.Equal(&key.PublicKey) {
			return nil, nil, "", errors.New("pending CSR does not match pending key")
		}
		return key, b, csr.Subject.CommonName, nil
	} else if !os.IsNotExist(e) {
		return nil, nil, "", e
	}
	host, _ := os.Hostname()
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}}, key)
	if e != nil {
		return nil, nil, "", e
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if e = writePrivate(csrPath, csrPEM); e != nil {
		return nil, nil, "", e
	}
	return key, csrPEM, host, nil
}
func writeOrVerifyPrivate(path string, b []byte) error {
	if existing, e := os.ReadFile(path); e == nil {
		if e = checkPrivateFile(path); e != nil {
			return e
		}
		if !bytes.Equal(existing, b) {
			return fmt.Errorf("refusing to overwrite existing identity file %s with different credentials", path)
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	return writePrivate(path, b)
}
