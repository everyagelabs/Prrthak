package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These vectors come from the real Python Store/PKI/preview/literal-acknowledgement/
// signed assignment/ManagementHealth path. Only the network SSH actuator is a
// deterministic disclosed test stub; no private CA or signing key is exported.
func TestHostDefaultDenyPythonSignedInterop(t *testing.T) {
	raw, err := os.ReadFile("../../../controller/tests/fixtures/host-default-deny.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SchemaVersion int `json:"schema_version"`
		Cases         []struct {
			Name               string                     `json:"name"`
			At                 int64                      `json:"at"`
			Nonce              string                     `json:"nonce"`
			Removal            bool                       `json:"removal"`
			Config             json.RawMessage            `json:"config"`
			ConfigurationState EndpointConfigurationState `json:"configuration_state"`
			Trust              policyTrust                `json:"trust"`
			Protection         Protection                 `json:"protection"`
			Policy             json.RawMessage            `json:"policy"`
			Witness            managedWitness             `json:"witness"`
			Certificate        string                     `json:"certificate_pem"`
			EndpointCA         string                     `json:"endpoint_ca_pem"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &vector) != nil || vector.SchemaVersion != 1 || len(vector.Cases) != 2 {
		t.Fatal("invalid real backend fixture")
	}
	for _, item := range vector.Cases {
		t.Run(item.Name, func(t *testing.T) {
			c := defaultConfig()
			if err := json.Unmarshal(item.Config, &c); err != nil {
				t.Fatal(err)
			}
			c, err = validateConfig(c, false)
			if err != nil {
				t.Fatal(err)
			}
			if c.PolicySigningTrustFile != "" || c.PolicySigningDeploymentID != item.Trust.DeploymentID || !reflect.DeepEqual(c.PolicySigningKeys, item.Trust.Keys) {
				t.Fatal("native config does not pin the actual Python assignment signer")
			}
			if actual := configurationState(c); actual.Digest != item.ConfigurationState.Digest || string(configurationCanonical(actual)) != string(configurationCanonical(item.ConfigurationState)) {
				t.Fatalf("native/Python config receipt mismatch: %+v %+v", actual, item.ConfigurationState)
			}
			var policy Policy
			if json.Unmarshal(item.Policy, &policy) != nil {
				t.Fatal("invalid Python policy")
			}
			at := time.Unix(item.At, 0).UTC()
			if err := validatePolicySignatureAt(c, &policy, at); err != nil {
				t.Fatal("Python assignment signature:", err)
			}
			if digest, err := compiledPolicyDigest(&policy); err != nil || digest != policy.Digest {
				t.Fatalf("Python compiled digest: %s %s %v", digest, policy.Digest, err)
			}
			if protectionDigest(item.Protection) != item.Protection.Digest {
				t.Fatal("Python protection context/profile hash differs")
			}
			if err := validateEnforcement(&policy, item.Protection, at); err != nil {
				t.Fatal("Python authorization:", err)
			}
			block, _ := pem.Decode([]byte(item.Certificate))
			if block == nil {
				t.Fatal("missing public certificate")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(item.EndpointCA)) {
				t.Fatal("missing public endpoint CA")
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatal("Python endpoint identity chain:", err)
			}
			if leaf.Subject.CommonName != policy.ServerID {
				t.Fatal("Python fixture identity is not target-bound")
			}
			var binding struct {
				Enforcement struct {
					IPs []string `json:"approved_ips"`
				} `json:"enforcement"`
			}
			if json.Unmarshal(item.Policy, &binding) != nil || len(binding.Enforcement.IPs) == 0 {
				t.Fatal("missing signed endpoint IPv4/IPv6 binding")
			}
			a := &Agent{Config: c, Client: &Client{}, inventory: &Report{IPs: binding.Enforcement.IPs}}
			a.Client.identity = &atomic.Pointer[tls.Certificate]{}
			a.Client.identity.Store(&tls.Certificate{Leaf: leaf})
			if err := a.validateHostDefaultDeny(&policy, item.Protection, item.Removal); err != nil {
				t.Fatal("Python host acknowledgement:", err)
			}
			if err := a.validateManagedWitness(item.Witness, &policy, item.Protection, item.Nonce, at); err != nil {
				t.Fatal("Python fresh witness:", err)
			}
			if item.Removal && (policy.HostDefaultDeny || c.AllowHostDefaultDeny || len(policy.Services) != 1 || policy.Services[0].Port != 8443) {
				t.Fatal("disable did not retain applied8443 matrix independently of later pending9443")
			}
			for _, kind := range []string{"ack", "kind", "action", "config", "context", "hostflag"} {
				t.Run(kind, func(t *testing.T) {
					var candidate Policy
					json.Unmarshal(item.Policy, &candidate)
					protection := item.Protection
					switch kind {
					case "ack":
						candidate.Enforcement.HostDefaultDenyAck = false
					case "config":
						candidate.Enforcement.HostDefaultDenyConfigurationDigest = strings.Repeat("0", 64)
					case "context":
						protection.HostDefaultDenyContextDigest = strings.Repeat("0", 64)
						protection.Digest = protectionDigest(protection)
					case "hostflag":
						candidate.HostDefaultDeny = !candidate.HostDefaultDeny
					case "kind", "action":
						var proof endpointApprovalProof
						json.Unmarshal(candidate.Enforcement.ApprovalProof, &proof)
						if kind == "kind" {
							proof.Scope["kind"] = json.RawMessage(`"managed_rollout"`)
						} else {
							action := "enable"
							if !item.Removal {
								action = "disable"
							}
							proof.Scope["action"], _ = json.Marshal(action)
						}
						candidate.Enforcement.ApprovalProof = sealDirectApproval(proof)
					}
					if kind == "context" {
						if validateEnforcement(&candidate, protection, at) == nil {
							t.Fatal("changed context reused Python authorization")
						}
						return
					}
					if a.validateHostDefaultDeny(&candidate, protection, item.Removal) == nil {
						t.Fatal("changed Python host authority accepted")
					}
					if kind != "kind" && kind != "action" && validatePolicySignatureAt(c, &candidate, at) == nil {
						t.Fatal("altered Python wire payload retained its signature")
					}
				})
			}
		})
	}
}
