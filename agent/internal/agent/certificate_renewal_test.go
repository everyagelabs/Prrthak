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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEndpointCertificateRenewalIntentIsBoundToSignedAssignment(t *testing.T) {
	at := time.Now()
	rollout := &CertificateRenewalAssignment{ID: strings.Repeat("c", 32), ServerID: "endpoint", OldFingerprint: strings.Repeat("a", 64),
		NotBefore: at, ExpiresAt: at.Add(time.Hour)}
	config, signed := signPolicyForTest(t, &Policy{ServerID: "endpoint", CertificateRenewal: rollout}, at)
	if err := ValidatePolicySignature(config, signed); err != nil {
		t.Fatal(err)
	}
	replacement := *rollout
	replacement.NewFingerprint = strings.Repeat("b", 64)
	signed.CertificateRenewal = &replacement
	if err := ValidatePolicySignature(config, signed); err == nil {
		t.Fatal("unsigned certificate-renewal change was accepted")
	}
}

func TestScheduledCertificateRenewalUsesLiveTLSAndResumesConfirmation(t *testing.T) {
	at := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "renewal test CA"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(96 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "endpoint-renewal-live"
	makeLeaf := func(serial int64, lifetime time.Duration) ([]byte, []byte) {
		t.Helper()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: endpoint},
			NotBefore: at.Add(-time.Minute), NotAfter: at.Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	oldDER, oldPEM := makeLeaf(2, 48*time.Hour)
	newDER, newPEM := makeLeaf(3, 72*time.Hour)
	key, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg := Config{StateDir: root, CACert: filepath.Join(root, "tls-server.pem"), EndpointCACert: filepath.Join(root, "endpoint-ca.pem"),
		Certificate: filepath.Join(root, "client.pem"), PrivateKey: filepath.Join(root, "client-key.pem"), RequestTimeoutSeconds: 3}
	write := func(path string, value []byte) {
		t.Helper()
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	write(cfg.EndpointCACert, caPEM)
	write(cfg.Certificate, oldPEM)
	write(cfg.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	id := strings.Repeat("c", 32)
	var probes, discoveryProbes, confirms atomic.Int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local mTLS listener unavailable: %v", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("unexpected request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		onDisk, err := os.ReadFile(cfg.Certificate)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		peer := r.TLS.PeerCertificates[0]
		if r.URL.Path == "/api/v1/agent/report" {
			if request["certificate_renewal_probe"] != id || !bytes.Equal(peer.Raw, newDER) || !bytes.Equal(onDisk, oldPEM) {
				t.Error("discovery probe must use the candidate without activating it")
			}
			if discoveryProbes.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"action": "probe-discovery", "renewal_id": id, "fingerprint": certificateFingerprint(peer.Raw)})
			return
		}
		if r.URL.Path != certificateRenewalPath || request["renewal_id"] != id {
			t.Error("unexpected renewal request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		action := request["action"]
		switch action {
		case "":
			block, _ := pem.Decode([]byte(request["csr"]))
			if block == nil || !bytes.Equal(peer.Raw, oldDER) || !bytes.Equal(onDisk, oldPEM) {
				t.Error("issuance did not use the current identity")
			}
			json.NewEncoder(w).Encode(map[string]any{"renewed": true, "server_id": endpoint, "certificate": string(newPEM)})
		case "probe":
			if request["split_channels"] != "true" || !bytes.Equal(peer.Raw, newDER) || !bytes.Equal(onDisk, oldPEM) {
				t.Error("probe must use the candidate without activating it")
			}
			if probes.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			fallthrough
		case "confirm":
			if action == "confirm" {
				if !bytes.Equal(peer.Raw, newDER) || !bytes.Equal(onDisk, newPEM) {
					t.Error("confirmation must use the durably activated candidate")
				}
				if confirms.Add(1) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]string{"action": action, "renewal_id": id, "fingerprint": certificateFingerprint(peer.Raw)})
		default:
			t.Error("unexpected proof action")
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	discovery := httptest.NewUnstartedServer(handler)
	discovery.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	discovery.StartTLS()
	defer discovery.Close()
	write(cfg.CACert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	cfg.ControllerURL = server.URL
	cfg.DiscoveryURL = discovery.URL
	client, err := NewClient(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	rollout := &CertificateRenewalAssignment{ID: id, ServerID: endpoint, OldFingerprint: certificateFingerprint(oldDER), NotBefore: at, ExpiresAt: at.Add(time.Hour)}
	if err = client.renewIdentity(context.Background(), rollout); err == nil || !bytes.Equal(client.identity.Load().Certificate[0], oldDER) {
		t.Fatalf("a failed probe replaced the live identity: %v", err)
	}
	client.renewBulkRetry = time.Time{}
	if err = client.renewIdentity(context.Background(), rollout); err == nil || !bytes.Equal(client.identity.Load().Certificate[0], oldDER) {
		t.Fatalf("a failed discovery probe replaced the live identity: %v", err)
	}
	client.renewBulkRetry = time.Time{}
	if err = client.renewIdentity(context.Background(), rollout); err == nil || !bytes.Equal(client.identity.Load().Certificate[0], newDER) {
		t.Fatalf("lost confirmation did not retain the activated candidate: %v", err)
	}
	restarted, err := NewClient(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	rollout.NewFingerprint = certificateFingerprint(newDER)
	if err = restarted.renewIdentity(context.Background(), rollout); err != nil {
		t.Fatalf("renewal did not resume confirmation after restart: %v", err)
	}
	previous, err := os.ReadFile(cfg.Certificate + ".previous")
	if err != nil || !bytes.Equal(previous, oldPEM) || probes.Load() != 3 || discoveryProbes.Load() != 2 || confirms.Load() != 2 {
		t.Fatalf("unexpected renewal artifacts or retries: %v, %d control probes, %d discovery probes, %d confirmations", err, probes.Load(), discoveryProbes.Load(), confirms.Load())
	}
}
