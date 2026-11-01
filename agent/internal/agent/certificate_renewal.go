package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// RenewIdentity keeps a valid current identity during network/controller
// failures. A fresh authenticated handshake is required before issuing a leaf.
// The existing private key is retained; no multi-file keypair swap is needed.
func (c *Client) RenewIdentity(ctx context.Context) error {
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
	if pair.Leaf == nil || time.Until(pair.Leaf.NotAfter) > 30*24*time.Hour || time.Now().Before(c.renewRetry) {
		return nil
	}
	c.renewRetry = time.Now().Add(time.Hour)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pair.Leaf.Subject}, pair.PrivateKey)
	if err != nil {
		return err
	}
	res, err := c.request(ctx, "POST", "/api/v1/agent/certificates/renew", map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}, "")
	if err != nil {
		return err
	}
	var reply struct {
		Renewed     bool   `json:"renewed"`
		ServerID    string `json:"server_id"`
		Certificate string `json:"certificate"`
	}
	if err = decodeResponse(res, &reply); err != nil || !reply.Renewed {
		return err
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
	intermediates := x509.NewCertPool()
	for _, der := range candidate.Certificate[1:] {
		if issuer, e := x509.ParseCertificate(der); e == nil {
			intermediates.AddCert(issuer)
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("renewal does not match pinned issuing trust: %w", err)
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
	candidate.Leaf = leaf
	c.identity.Store(&candidate)
	transport.CloseIdleConnections()
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
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
