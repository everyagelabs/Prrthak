package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func singleAdminProofFixture() endpointApprovalProof {
	person := configurationPerson{UserID: "tenant:person", TenantID: "tenant"}
	ids, _ := json.Marshal([]string{"host-a"})
	return endpointApprovalProof{Scheme: "prthak-maker-checker-v1", Mode: "single_admin", Stage: "approved", PlanID: "action-id", PlanDigest: strings.Repeat("b", 64), Requester: person, SubmittedBy: person, ApprovedBy: person, ProviderAuthority: map[string]string{"fingerprint": strings.Repeat("a", 64), "epoch": ""}, Scope: map[string]json.RawMessage{"kind": json.RawMessage("\"learning\""), "server_ids": ids}}
}
func sealDirectApproval(proof endpointApprovalProof) json.RawMessage {
	proof.BindingDigest = ""
	raw, _ := json.Marshal(proof)
	var value map[string]any
	json.Unmarshal(raw, &value)
	proof.BindingDigest = directApprovalDigest(value)
	raw, _ = json.Marshal(proof)
	return raw
}
func TestSingleAdminNeedsNoPilotConsentOrSecondPerson(t *testing.T) {
	p := singleAdminProofFixture()
	raw := sealDirectApproval(p)
	c := defaultConfig()
	if err := validateEndpointApproval(c, raw, "host-a", time.Now(), false); err != nil {
		t.Fatal(err)
	}
	c.AllowSingleAdminPilot = true
	c.SingleAdminPilotScope = &SingleAdminPilotScope{Revision: 1, ExpiresAt: time.Now().Add(-time.Hour), ServerIDs: []string{"unrelated"}}
	if err := validateEndpointApproval(c, raw, "host-a", time.Now(), false); err != nil {
		t.Fatal("retired pilot state gated current admin action", err)
	}
	if c.Enforce || c.AllowFirewallChanges || c.LearningAutoAllow {
		t.Fatal("proof elevated local firewall flags")
	}
}

func TestDirectApprovalDigestMatchesPythonUnicodeAndHTMLEscaping(t *testing.T) {
	actual := directApprovalDigest(map[string]any{"name": "Pratik <Admin> पृथक् 😀", "count": 5000, "proof": true})
	if actual != "f490a4886a91f8ab3ab10c68240d0df90d825e136992dd7923ed1423085810f4" {
		t.Fatal("Python/Go proof binding differs", actual)
	}
	if directApprovalDigest(map[string]any{"name": "\x7f"}) != "fa3abebee87dea279e85787c0ac77cdf54380d468d03494b36687037b1fc195a" {
		t.Fatal("Python ASCII DEL escaping differs")
	}
}

func TestLocalAndSAMLActorFieldsRemainBoundInControllerProof(t *testing.T) {
	for _, provider := range []string{"local", "saml"} {
		t.Run(provider, func(t *testing.T) {
			raw, _ := json.Marshal(singleAdminProofFixture())
			var proof map[string]any
			if err := json.Unmarshal(raw, &proof); err != nil {
				t.Fatal(err)
			}
			realm := "11111111-1111-4111-8111-111111111111"
			person := "22222222-2222-4222-8222-222222222222"
			subject := map[string]any{"user_id": realm + ":" + person, "tenant_id": realm,
				"object_id": person, "actor": provider + ":" + realm + ":" + person,
				"auth_provider": provider, "auth_config": strings.Repeat("a", 64), "role": "admin"}
			if provider == "local" {
				subject["credential_version"] = strings.Repeat("c", 32)
			}
			proof["requester"], proof["submitted_by"], proof["approved_by"] = subject, subject, subject
			delete(proof, "binding_digest")
			proof["binding_digest"] = directApprovalDigest(proof)
			raw, _ = json.Marshal(proof)
			if err := validateEndpointApproval(defaultConfig(), raw, "host-a", time.Now(), false, "learning"); err != nil {
				t.Fatal("attributed provider proof was rejected", err)
			}
			// All actor metadata remains covered, even when this endpoint only
			// needs the identity and operation scope from the signed assignment.
			subject["auth_provider"] = "changed"
			raw, _ = json.Marshal(proof)
			if validateEndpointApproval(defaultConfig(), raw, "host-a", time.Now(), false) == nil {
				t.Fatal("changed provider attribution escaped the proof binding")
			}
		})
	}
}
func TestSingleAdminRejectsChangedActorProviderScopeAndRetiredModes(t *testing.T) {
	for _, change := range []func(*endpointApprovalProof){
		func(p *endpointApprovalProof) { p.ApprovedBy.UserID = "another" }, func(p *endpointApprovalProof) { p.SubmittedBy.TenantID = "other" },
		func(p *endpointApprovalProof) { p.ProviderAuthority["fingerprint"] = "" }, func(p *endpointApprovalProof) { p.ProviderAuthority["epoch"] = "bad" },
		func(p *endpointApprovalProof) { p.Scope["server_ids"] = json.RawMessage("[\"other\"]") }, func(p *endpointApprovalProof) { p.Scope["kind"] = json.RawMessage("\"platform\"") },
		func(p *endpointApprovalProof) { p.Mode = "single_admin_pilot" }, func(p *endpointApprovalProof) { p.Mode = "lab_only" },
	} {
		p := singleAdminProofFixture()
		change(&p)
		if validateEndpointApproval(defaultConfig(), sealDirectApproval(p), "host-a", time.Now(), false) == nil {
			t.Fatal("invalid authority accepted")
		}
	}
	p := singleAdminProofFixture()
	raw := sealDirectApproval(p)
	var value map[string]any
	json.Unmarshal(raw, &value)
	value["plan_id"] = "changed"
	raw, _ = json.Marshal(value)
	if validateEndpointApproval(defaultConfig(), raw, "host-a", time.Now(), false) == nil {
		t.Fatal("changed binding accepted")
	}
}
func TestSingleAdminCompactScopeHasNoTwentyHostLimit(t *testing.T) {
	p := singleAdminProofFixture()
	digest, _ := json.Marshal(strings.Repeat("c", 64))
	p.Scope = map[string]json.RawMessage{"kind": json.RawMessage("\"managed_rollout\""), "target_count": json.RawMessage("5000"), "target_digest": digest}
	if err := validateEndpointApproval(defaultConfig(), sealDirectApproval(p), "host-a", time.Now(), false); err != nil {
		t.Fatal(err)
	}
	if validateEndpointApproval(defaultConfig(), sealDirectApproval(p), "host-a", time.Now(), true) == nil {
		t.Fatal("fleet proof used for configuration")
	}
	if validateEndpointApproval(defaultConfig(), sealDirectApproval(p), "host-a", time.Now(), false, "learning") == nil {
		t.Fatal("managed scope used for learned access")
	}
}

func TestManagedSingleAdminAcceptsOneRealSaveAndKeepsDigestGuards(t *testing.T) {
	_, _, protection := managedTestAgent(t)
	p := managedTestPolicy(protection, 1, "10.30.0.0/24")
	proof := singleAdminProofFixture()
	proof.Scope["kind"] = json.RawMessage("\"managed_policy\"")
	ids, _ := json.Marshal([]string{p.ServerID})
	proof.Scope["server_ids"] = ids
	p.Enforcement.ConfirmationCount = 1
	p.Enforcement.ApprovalProof = sealDirectApproval(proof)
	if err := validateEnforcement(p, protection, time.Now()); err != nil {
		t.Fatal(err)
	}
	p.Enforcement.ConfirmationCount = 0
	if validateEnforcement(p, protection, time.Now()) == nil {
		t.Fatal("unsaved action accepted")
	}
	p.Enforcement.ConfirmationCount = 1
	p.Services[0].Sources = []string{"0.0.0.0/0"}
	if validateEnforcement(p, protection, time.Now()) == nil {
		t.Fatal("source expansion escaped exact digest")
	}
}
func TestSingleAdminConfigurationClearsRetiredConsentWithoutElevatingFlags(t *testing.T) {
	c, kit, key, path, now := configurationFixture(t)
	c.AllowSingleAdminPilot = true
	c.SingleAdminPilotScope = &SingleAdminPilotScope{Revision: 1, ExpiresAt: now.Add(-time.Hour), ServerIDs: []string{"old"}}
	kit.Manifest.Scope.ExpectedConfigDigest = configDigest(c)
	kit.Manifest.Scope.Settings.Enforce = false
	setConfigurationProof(t, &kit, "single_admin", "maker", "maker")
	signConfiguration(t, &kit, key, kit.Signature.KeyID)
	writeSetup(t, path, kit)
	parsed, err := readConfigurationKit(path, c, now)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := configurationCandidate(c, parsed.Manifest)
	if err != nil || candidate.AllowSingleAdminPilot || candidate.SingleAdminPilotScope != nil || candidate.Enforce || candidate.AllowFirewallChanges || candidate.LearningAutoAllow {
		t.Fatal("configuration elevated flags or retained retired consent", err)
	}
}
func TestLearningDirectProofChecksOnlyActualDeltaAuthorities(t *testing.T) {
	now := time.Now().UTC()
	a, _, protection, session := learningTestAgent(t)
	old := learningTestAssignment(a, protection, session, 1, "10.20.0.9/32")
	bad := singleAdminProofFixture()
	bad.Mode = "single_admin_pilot"
	inert := sealDirectApproval(bad)
	old.Authorities[0].ApprovalProof = inert
	a.State.LearningAllowBundle = &LearningAllowBundle{Assignment: *old}
	next := learningTestAssignment(a, protection, session, 2, "10.20.0.10/32")
	next.Authorities[0].PolicyID = "learn-new"
	next.Authorities[0].Kind = "reviewed"
	next.Authorities[0].ApprovalProof = sealDirectApproval(singleAdminProofFixture())
	current := next.Authorities[0]
	stale := old.Authorities[0]
	stale.Services = append(append([]Service{}, old.Services...), next.Services...)
	next.Services = append(append([]Service{}, old.Services...), next.Services...)
	next.Authorities = []LearningAuthority{stale, current, {PolicyID: "tombstone", Kind: "reviewed", ApprovalProof: inert, ExpiresAt: now.Add(-time.Hour)}}
	next.PolicyIDs = []string{"learn-a", "learn-new"}
	if err := a.validateLearningDelta(next, now); err != nil {
		t.Fatal(err)
	}
	next.Authorities[1].ApprovalProof = inert
	if a.validateLearningDelta(next, now) == nil {
		t.Fatal("retired proof authorized addition")
	}
	removal := &LearningAllow{ServerID: "host-a", Services: []Service{}, Authorities: []LearningAuthority{{PolicyID: "learn-a", Kind: "reviewed", ExpiresAt: now.Add(time.Hour), ApprovalProof: sealDirectApproval(singleAdminProofFixture())}, {PolicyID: "tombstone", Kind: "reviewed", ApprovalProof: inert, ExpiresAt: now.Add(-time.Hour)}}}
	if err := a.validateLearningDelta(removal, now); err != nil {
		t.Fatal(err)
	}
	removal.Authorities[0].ApprovalProof = inert
	if a.validateLearningDelta(removal, now) == nil {
		t.Fatal("retired owner proof authorized removal")
	}
}
