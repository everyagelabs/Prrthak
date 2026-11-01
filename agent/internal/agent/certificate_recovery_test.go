package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func certificateRecoveryFixture(t *testing.T) (Config, recoveredIdentity, *x509.CertPool) {
	t.Helper()
	c := bootstrapFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "recovery fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err = os.WriteFile(c.CACert, caPEM, 0644); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "recovery-fixture-endpoint"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	value := recoveredIdentity{ServerID: leaf.Subject.CommonName, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))}
	return c, value, roots
}

func TestRecoveryResumesCrashBetweenKeyAndCertificateReplacement(t *testing.T) {
	c, value, roots := certificateRecoveryFixture(t)
	dir := filepath.Join(c.StateDir, "certificate-recovery")
	if err := atomicJSON(filepath.Join(dir, "commit.json"), value); err != nil {
		t.Fatal(err)
	}
	// The key rename completed before a crash; the certificate rename did not.
	for path, data := range map[string]string{c.PrivateKey: value.PrivateKey, c.Certificate: "previous certificate", filepath.Join(dir, "enrollment-pending.key"): "pending key", filepath.Join(dir, "enrollment-pending.csr"): "pending CSR"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := recoverPendingIdentity(c, roots); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(c, false); err != nil {
		t.Fatalf("recovered pair cannot authenticate: %v", err)
	}
	for _, name := range []string{"commit.json", "enrollment-pending.key", "enrollment-pending.csr"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("completed private recovery artifact remains: %s", name)
		}
	}
	if err := recoverPendingIdentity(c, roots); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRejectsUntrustedOrPublicJournalBeforeTouchingIdentity(t *testing.T) {
	for _, invalid := range []string{"untrusted issuer", "different key", "public journal"} {
		t.Run(invalid, func(t *testing.T) {
			c, value, roots := certificateRecoveryFixture(t)
			_, other, otherRoots := certificateRecoveryFixture(t)
			if invalid == "untrusted issuer" {
				roots = otherRoots
			}
			if invalid == "different key" {
				value.PrivateKey = other.PrivateKey
			}
			path := filepath.Join(c.StateDir, "certificate-recovery", "commit.json")
			if err := atomicJSON(path, value); err != nil {
				t.Fatal(err)
			}
			if invalid == "public journal" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			for _, target := range []string{c.PrivateKey, c.Certificate} {
				if err := os.WriteFile(target, []byte("existing identity"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := recoverPendingIdentity(c, roots); err == nil {
				t.Fatal("unsafe journal was admitted")
			}
			for _, target := range []string{c.PrivateKey, c.Certificate} {
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "existing identity" {
					t.Fatal("unsafe recovery changed existing identity")
				}
			}
		})
	}
}
