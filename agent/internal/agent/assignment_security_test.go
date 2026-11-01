package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureAuthenticatedClient(a *Agent, identifier string) {
	a.Client.identity = &atomic.Pointer[tls.Certificate]{}
	a.Client.identity.Store(&tls.Certificate{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: identifier}}})
}

func assignmentHTTP(t *testing.T, p *Policy) *http.Client {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}
}

func TestSignedAssignmentAlwaysMatchesOwnCertificateIncludingFirstAnd304(t *testing.T) {
	c, p := signPolicyForTest(t, &Policy{ServerID: "other-endpoint", Version: 1, Digest: "fixture", Mode: "monitor"}, time.Now())
	c.StateDir = t.TempDir()
	c.ControllerURL = "https://controller.example.internal"
	a := &Agent{Config: c, Client: &Client{config: c, HTTP: assignmentHTTP(t, p)}, State: State{Coverage: map[string]*Coverage{}}}
	fixtureAuthenticatedClient(a, "local-endpoint")
	if err := a.refreshAssignment(context.Background()); err == nil {
		t.Fatal("first cross-endpoint assignment admitted")
	}
	if a.State.Policy != nil || a.State.AssignmentGeneration != 0 {
		t.Fatal("rejected policy changed retained authority")
	}
	if _, err := os.Stat(filepath.Join(c.StateDir, "policy-plan.json")); !os.IsNotExist(err) {
		t.Fatal("rejected policy was cached")
	}
	a.State.Policy = p
	a.Client.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 304, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}}, nil
	})}
	if err := a.refreshAssignment(context.Background()); err == nil {
		t.Fatal("cached304 cross-endpoint assignment admitted")
	}
}

func TestAuxiliaryAssignmentReplayAndSessionStopPersistAcrossRestart(t *testing.T) {
	instant := time.Now().UTC()
	session := Session{ID: "session-replay-123", StartsAt: instant.Add(-time.Minute), ExpiresAt: instant.Add(time.Hour), Status: "active", Ports: []Port{{Port: 443, Protocol: "tcp"}}}
	active := Policy{ServerID: "endpoint", Version: 7, Digest: "same-compiled", Mode: "monitor", AssignmentGeneration: 1, LearningSessions: []Session{session}}
	c, p1 := signPolicyForTest(t, &active, instant)
	c.StateDir = t.TempDir()
	c.ControllerURL = "https://controller.example.internal"
	c.ProbeLogRatePerSecond = 5
	a := &Agent{Config: c, Simulate: true, Client: &Client{config: c, simulate: true}, State: State{Coverage: map[string]*Coverage{}}}
	a.Client.HTTP = assignmentHTTP(t, p1)
	if err := a.refreshAssignment(context.Background()); err != nil {
		t.Fatal(err)
	}
	stop := session
	stop.Status = "stopped"
	stop.StoppedAt = &instant
	stopped := active
	stopped.AssignmentGeneration = 2
	stopped.LearningSessions = nil
	stopped.LearningTombstones = []Session{stop}
	_, p2 := signPolicyForTest(t, &stopped, instant)
	a.Client.HTTP = assignmentHTTP(t, p2)
	if err := a.refreshAssignment(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(c, true, "")
	if err != nil {
		t.Fatal(err)
	}
	restarted.Client.HTTP = assignmentHTTP(t, p1)
	if err = restarted.refreshAssignment(context.Background()); err == nil {
		t.Fatal("older active assignment revived stopped collection")
	}
	if restarted.State.AssignmentGeneration != 2 || len(ActiveSessions(restarted.State.Policy, instant)) != 0 {
		t.Fatal("retained replay floor changed")
	}
	reactivated := active
	reactivated.AssignmentGeneration = 3
	_, p3 := signPolicyForTest(t, &reactivated, instant)
	restarted.Client.HTTP = assignmentHTTP(t, p3)
	if err = restarted.refreshAssignment(context.Background()); err == nil {
		t.Fatal("newer envelope improperly reactivated stopped session ID")
	}
	divergent := *p2
	divergent.AssignmentDigest = shaText("different")
	if restarted.validateAssignmentReplay(&divergent, instant) == nil {
		t.Fatal("same-generation divergence accepted")
	}
}

func TestUnresolvedImportedRecoveryCannotLoseBlockOnRepeatedRestart(t *testing.T) {
	f := newFirewallFake()
	a := firewallAgent(t, f)
	baseline := CollectFirewallSnapshot(context.Background(), f, nil)
	f.set("runtime", "port", "8080/tcp", true)
	journal := &firewallJournal{ID: "uncertain-import", PlanDigest: shaText("plan"), Status: "applying", Before: *baseline, Mutations: []firewallMutation{{Scope: "runtime", Zone: "public", Kind: "port", Value: "8080/tcp", Operation: "add", Completed: false}}}
	if err := a.saveFirewallJournal(journal); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := a.recoverFirewallChanges(context.Background()); err == nil {
			t.Fatal("uncertain recovery block disappeared", attempt)
		}
	}
	f.set("runtime", "port", "8080/tcp", false)
	if err := a.recoverFirewallChanges(context.Background()); err != nil {
		t.Fatal("exact verified original baseline did not resolve recovery", err)
	}
}

func TestUserControlledSSHNamesAreDisplayOnlyAndExplicitPortMustExist(t *testing.T) {
	rows := ParseSockets(`tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("sshd",pid=9999999,fd=3))`)
	rows = EnrichListeners(rows, func(int) (string, error) {
		return "0::/user.slice/user-1000.slice/user@1000.service/app.slice/ssh.service", nil
	}, nil)
	if rows[0].Service != "SSH" || rows[0].ProtectedSSH {
		t.Fatal("display identity incorrectly became trusted protection", rows)
	}
	if protectedSSHListener(rows[0], Config{}) {
		t.Fatal("user comm became management authority")
	}
	if !protectedSSHListener(rows[0], Config{ProtectedSSHPorts: []int{8080}}) {
		t.Fatal("explicit local protected listener missing")
	}
	if protectedSSHListener(Listener{Port: 8080, Protocol: "udp"}, Config{ProtectedSSHPorts: []int{8080}}) {
		t.Fatal("explicit TCP management authority applied to UDP")
	}
}

func TestEnrollmentCannotExposeIdentityBeforeItsImmutableSigningPin(t *testing.T) {
	c, value, _ := certificateRecoveryFixture(t)
	c.Enforce = true
	client, err := NewClient(c, false)
	if err != nil {
		t.Fatal(err)
	}
	// Invalid trust and an unwritable pin target both fail before either
	// identity artifact can turn a retry into apparently completed enrollment.
	if err = client.commitEnrollmentArtifacts([]byte(value.PrivateKey), []byte(value.Certificate), []byte(`{"invalid":true}`)); err == nil {
		t.Fatal("invalid trust accepted")
	}
	for _, path := range []string{c.PrivateKey, c.Certificate} {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("identity exposed before trust", path)
		}
	}
	explicit := c
	explicit.PolicySigningTrustFile = filepath.Join(c.StateDir, "operator-pin-missing.json")
	operatorClient, err := NewClient(explicit, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = operatorClient.commitEnrollmentArtifacts([]byte(value.PrivateKey), []byte(value.Certificate), []byte(`{}`)); err == nil {
		t.Fatal("missing explicit operator pin exposed completed identity")
	}
	if _, err = os.Stat(c.Certificate); !os.IsNotExist(err) {
		t.Fatal("identity committed without explicit pin")
	}
	if err = writePrivate(c.PrivateKey, []byte(value.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	if err = writePrivate(c.Certificate, []byte(value.Certificate)); err != nil {
		t.Fatal(err)
	}
	if err = client.Enroll(context.Background()); err == nil {
		t.Fatal("historical incomplete opt-in identity claimed successful enrollment")
	}
}
