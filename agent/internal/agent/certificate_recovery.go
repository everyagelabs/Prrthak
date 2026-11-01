package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
)

func endpointRoots(c Config, fallback *x509.CertPool) (*x509.CertPool, error) {
	if c.EndpointCACert == "" {
		return fallback, nil
	}
	value, err := os.ReadFile(c.EndpointCACert)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(value) {
		return nil, errors.New("endpoint issuing CA trust is invalid")
	}
	return roots, nil
}

type recoveredIdentity struct {
	ServerID    string `json:"server_id"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

func verifyRecoveredIdentity(value recoveredIdentity, roots *x509.CertPool) (tls.Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(value.Certificate), []byte(value.PrivateKey))
	if err != nil {
		return pair, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || value.ServerID == "" || leaf.Subject.CommonName != value.ServerID || leaf.IsCA {
		return pair, errors.New("recovery certificate identity is invalid")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if issuer, e := x509.ParseCertificate(der); e == nil {
			intermediates.AddCert(issuer)
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return pair, err
	}
	pair.Leaf = leaf
	return pair, nil
}

// A crash between the two file replacements is recovered before a TLS client
// is constructed. The durable private journal always contains one valid pair.
func recoverPendingIdentity(c Config, roots *x509.CertPool) error {
	path := filepath.Join(c.StateDir, "certificate-recovery", "commit.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := checkPrivateFile(path); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 65536 {
		return errors.New("certificate recovery journal cannot be read")
	}
	var value recoveredIdentity
	if json.Unmarshal(raw, &value) != nil {
		return errors.New("invalid private recovery journal")
	}
	if _, err = verifyRecoveredIdentity(value, roots); err != nil {
		return err
	}
	if err = replacePrivateArtifact(c.PrivateKey, []byte(value.PrivateKey)); err != nil {
		return err
	}
	if err = replacePrivateArtifact(c.Certificate, []byte(value.Certificate)); err != nil {
		return err
	}
	for _, candidate := range []string{"enrollment-pending.key", "enrollment-pending.csr", "commit.json"} {
		if err = os.Remove(filepath.Join(filepath.Dir(path), candidate)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// RecoverCertificate uses a fresh endpoint key and a short-lived, single-use
// controller recovery token. It never disables server TLS verification.
func RecoverCertificate(ctx context.Context, c Config, tokenFile string) error {
	if err := checkPrivateFile(tokenFile); err != nil {
		return err
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil || len(token) > 257 {
		return errors.New("invalid private recovery token file")
	}
	client, err := newIdentityClient(c, false, false)
	if err != nil {
		return err
	}
	key, csr, hostname, err := pendingEnrollment(filepath.Join(c.StateDir, "certificate-recovery"))
	if err != nil {
		return err
	}
	response, err := client.request(ctx, "POST", "/api/v1/agent/certificates/recover", map[string]string{"token": string(bytes.TrimSpace(token)), "csr": string(csr), "hostname": hostname}, "")
	if err != nil {
		return err
	}
	var value recoveredIdentity
	if err = decodeResponse(response, &value); err != nil {
		return err
	}
	if existing, e := os.ReadFile(c.Certificate); e == nil {
		if block, _ := pem.Decode(existing); block != nil {
			if previous, e := x509.ParseCertificate(block.Bytes); e == nil && previous.Subject.CommonName != value.ServerID {
				return errors.New("recovery token belongs to a different enrolled endpoint")
			}
		}
	}
	encodedKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	value.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encodedKey}))
	roots, err := endpointRoots(c, client.HTTP.Transport.(*http.Transport).TLSClientConfig.RootCAs)
	if err != nil {
		return err
	}
	if _, err = verifyRecoveredIdentity(value, roots); err != nil {
		return err
	}
	if err = atomicJSON(filepath.Join(c.StateDir, "certificate-recovery", "commit.json"), value); err != nil {
		return err
	}
	return recoverPendingIdentity(c, roots)
}
