package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const EndpointCertificateRenewalCapability = "endpoint_certificate_renewal_v1"
const certificateRenewalPath = "/api/v1/agent/certificates/renew"

type CertificateRenewalAssignment struct {
	ID             string    `json:"id"`
	ServerID       string    `json:"server_id"`
	OldFingerprint string    `json:"old_fingerprint"`
	NewFingerprint string    `json:"new_fingerprint"`
	NotBefore      time.Time `json:"not_before"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// RenewIdentity keeps a valid current identity during network/controller
// failures. A fresh authenticated handshake is required before issuing a leaf.
// The existing private key is retained; no multi-file keypair swap is needed.
func (c *Client) RenewIdentity(ctx context.Context) error {
	return c.renewIdentity(ctx, nil)
}

func (c *Client) renewIdentity(ctx context.Context, rollout *CertificateRenewalAssignment) error {
	if c.simulate || c.identity == nil || c.identity.Load() == nil {
		return nil
	}
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	pair := c.identity.Load()
	transport, ok := c.HTTP.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return errors.New("verified TLS transport is required for renewal")
	}
	roots, err := endpointRoots(c.config, transport.TLSClientConfig.RootCAs)
	if err != nil {
		return err
	}
	if current, e := os.ReadFile(c.config.Certificate); e == nil {
		if block, _ := pem.Decode(current); block != nil && !bytes.Equal(block.Bytes, pair.Certificate[0]) {
			fresh, e := verifiedIdentity(c.config, roots)
			if e != nil || fresh.Leaf.Subject.CommonName != pair.Leaf.Subject.CommonName {
				return errors.New("external identity replacement is invalid or belongs to another endpoint")
			}
			c.identity.Store(&fresh)
			transport.CloseIdleConnections()
			pair = &fresh
		}
	}
	if pair.Leaf == nil {
		return nil
	}
	at := time.Now()
	if rollout == nil {
		if time.Until(pair.Leaf.NotAfter) > 30*24*time.Hour || at.Before(c.renewRetry) {
			return nil
		}
		c.renewRetry = at.Add(time.Hour)
	} else {
		fingerprint := certificateFingerprint(pair.Certificate[0])
		if len(rollout.ID) != 32 || pair.Leaf.Subject.CommonName != rollout.ServerID ||
			(fingerprint != rollout.OldFingerprint && fingerprint != rollout.NewFingerprint) ||
			at.Add(time.Minute).Before(rollout.NotBefore) || !at.Before(rollout.ExpiresAt) {
			return errors.New("scheduled renewal does not match the current endpoint certificate or time window")
		}
		if c.renewBulkID == rollout.ID && at.Before(c.renewBulkRetry) {
			return nil
		}
		c.renewBulkID, c.renewBulkRetry = rollout.ID, at.Add(time.Minute)
		if fingerprint == rollout.NewFingerprint {
			// A previous attempt installed this leaf but lost its confirmation.
			if err = syncIdentityDirectory(c.config.Certificate); err != nil {
				return err
			}
			return c.proveRenewal(ctx, transport, pair, rollout.ID, "confirm")
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pair.Leaf.Subject}, pair.PrivateKey)
	if err != nil {
		return err
	}
	request := map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	if rollout != nil {
		request["renewal_id"] = rollout.ID
	}
	res, err := c.request(ctx, "POST", certificateRenewalPath, request, "")
	if err != nil {
		return err
	}
	var reply struct {
		Renewed     bool   `json:"renewed"`
		ServerID    string `json:"server_id"`
		Certificate string `json:"certificate"`
	}
	if err = decodeResponse(res, &reply); err != nil {
		return err
	}
	if !reply.Renewed {
		if rollout != nil {
			return errors.New("the controller has not issued the scheduled endpoint certificate")
		}
		return nil
	}
	key, err := os.ReadFile(c.config.PrivateKey)
	if err != nil {
		return err
	}
	candidate, err := tls.X509KeyPair([]byte(reply.Certificate), key)
	if err != nil {
		return errors.New("renewal certificate does not match this endpoint key")
	}
	leaf, err := x509.ParseCertificate(candidate.Certificate[0])
	if err != nil {
		return err
	}
	if reply.ServerID != pair.Leaf.Subject.CommonName || leaf.Subject.CommonName != reply.ServerID || !leaf.NotAfter.After(pair.Leaf.NotAfter) || leaf.IsCA {
		return errors.New("renewed certificate identity or validity differs from the request")
	}
	if rollout != nil && (!bytes.Equal(leaf.RawIssuer, pair.Leaf.RawIssuer) ||
		len(pair.Leaf.AuthorityKeyId) != 0 && !bytes.Equal(leaf.AuthorityKeyId, pair.Leaf.AuthorityKeyId)) {
		return errors.New("scheduled renewal must use the existing certificate issuer")
	}
	intermediates := x509.NewCertPool()
	for _, der := range candidate.Certificate[1:] {
		if issuer, e := x509.ParseCertificate(der); e == nil {
			intermediates.AddCert(issuer)
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("renewal does not match pinned issuing trust: %w", err)
	}
	candidate.Leaf = leaf
	if rollout != nil {
		if rollout.NewFingerprint != "" && rollout.NewFingerprint != certificateFingerprint(candidate.Certificate[0]) {
			return errors.New("the renewed certificate fingerprint differs from the signed assignment")
		}
		if err = c.proveRenewal(ctx, transport, &candidate, rollout.ID, "probe"); err != nil {
			return err
		}
		if c.usesSeparateDiscovery() {
			if err = c.proveRenewal(ctx, transport, &candidate, rollout.ID, "probe-discovery"); err != nil {
				return err
			}
		}
	}
	old, err := os.ReadFile(c.config.Certificate)
	if err != nil {
		return err
	}
	if !bytes.Equal(old, []byte(reply.Certificate)) {
		if err = replacePrivateArtifact(c.config.Certificate+".previous", old); err != nil {
			return err
		}
		if err = replacePrivateArtifact(c.config.Certificate, []byte(reply.Certificate)); err != nil {
			return err
		}
	}
	c.identity.Store(&candidate)
	transport.CloseIdleConnections()
	if rollout != nil {
		return c.proveRenewal(ctx, transport, &candidate, rollout.ID, "confirm")
	}
	return nil
}

func certificateFingerprint(der []byte) string {
	fingerprint := sha256.Sum256(der)
	return hex.EncodeToString(fingerprint[:])
}

func (c *Client) usesSeparateDiscovery() bool {
	control, discovery := c.config.ControlURL, c.config.DiscoveryURL
	if control == "" {
		control = c.config.ControllerURL
	}
	if discovery == "" {
		discovery = c.config.ControllerURL
	}
	return strings.TrimRight(control, "/") != strings.TrimRight(discovery, "/")
}

func (c *Client) proveRenewal(ctx context.Context, transport *http.Transport, candidate *tls.Certificate, rolloutID, action string) error {
	// Use a fresh TLS connection with only the candidate, while ordinary
	// agent traffic continues to use the existing identity and transport.
	proofTransport := transport.Clone()
	defer proofTransport.CloseIdleConnections()
	proofTransport.TLSClientConfig.Certificates = nil
	proofTransport.TLSClientConfig.ClientSessionCache = nil
	proofTransport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return candidate, nil
	}
	proof := &Client{config: c.config, HTTP: &http.Client{
		Transport: proofTransport, Timeout: c.HTTP.Timeout, CheckRedirect: c.HTTP.CheckRedirect,
	}}
	path := certificateRenewalPath
	payload := map[string]string{"action": action, "renewal_id": rolloutID}
	if action == "probe" && c.usesSeparateDiscovery() {
		payload["split_channels"] = "true"
	}
	if action == "probe-discovery" {
		path = "/api/v1/agent/report"
		payload = map[string]string{"certificate_renewal_probe": rolloutID}
	}
	res, err := proof.request(ctx, http.MethodPost, path, payload, "")
	if err != nil {
		return fmt.Errorf("endpoint certificate %s: %w", action, err)
	}
	var reply struct {
		Action      string `json:"action"`
		RenewalID   string `json:"renewal_id"`
		Fingerprint string `json:"fingerprint"`
	}
	if err = decodeResponse(res, &reply); err != nil {
		return err
	}
	if reply.Action != action || reply.RenewalID != rolloutID || reply.Fingerprint != certificateFingerprint(candidate.Certificate[0]) {
		return errors.New("the controller did not acknowledge the exact renewed certificate")
	}
	return nil
}

func replacePrivateArtifact(path string, value []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("private artifact path is unsafe")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	directory := filepath.Dir(path)
	f, err := os.CreateTemp(directory, ".prthak-identity-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(value); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncIdentityDirectory(path)
}

func syncIdentityDirectory(path string) error {
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
