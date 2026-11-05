package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type denyJournalLifecycleRunner struct {
	CommandRunner
	journal *denyJournalRunner
}

func (runner denyJournalLifecycleRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "journalctl" {
		return runner.journal.Run(ctx, name, args...)
	}
	return runner.CommandRunner.Run(ctx, name, args...)
}

func denyJournalLifecycleAgent(t *testing.T, now time.Time) (*Agent, *managedSetFake, captureSidecar, JournalEntry, *denyJournalRunner) {
	t.Helper()
	a, firewall, protection := scaleManagedAgent(t)
	if err := a.applyManaged(context.Background(), managedTestPolicy(protection, 1, "198.51.100.0/24"), protection); err != nil {
		t.Fatal(err)
	}
	session := Session{ID: "deny-log-retry", StartsAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), Ports: []Port{{18080, "tcp"}}, ObservationKinds: []string{captureDenied}, DenyLogCompatibility: true}
	a.State.Policy = &Policy{LearningSessions: []Session{session}}
	a.Config.MaxSpoolBatches = 8
	a.confirmed = true
	a.trafficCapture = &deniedCaptureFixture{}
	journal := &denyJournalRunner{}
	a.Commands = denyJournalLifecycleRunner{
		CommandRunner: oldCaptureLanguageRunner{CommandRunner: &hostDenyFake{CommandRunner: firewall, nft: tailscaleKernelFixture(), forwarding: "0 0"}},
		journal:       journal,
	}
	scopes := a.nativeCaptureScopes(now)
	if err := a.reconcileCaptureSidecars(context.Background(), scopes, now); err != nil {
		t.Fatal(err)
	}
	state, err := readCaptureSidecars(a.Config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range state.Rules {
		if rule.Backend == "journal" && rule.Family == "ipv4" {
			_, _, entry := denyJournalFixture(now)
			entry.Message = strings.ReplaceAll(entry.Message, "PRTN0123456789abcdef:", rule.Prefix)
			entry.Timestamp = strconv.FormatInt(now.Add(time.Second).UnixMicro(), 10)
			journal.outputs = []string{denyJournalJSON(entry), denyJournalJSON(entry)}
			a.captureScopeKey = canonicalCaptureScope(scopes)
			a.nextCaptureCheck = now
			return a, firewall, rule, entry, journal
		}
	}
	t.Fatal("expected an installed journal compatibility sidecar")
	return nil, nil, captureSidecar{}, JournalEntry{}, nil
}

func denyJournalSpoolEvent(t *testing.T, a *Agent, expectedID string) {
	t.Helper()
	files, err := spoolFiles(filepath.Join(a.Config.StateDir, "spool"))
	if err != nil || len(files) != 1 {
		t.Fatal("expected one durable compatibility batch", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var batch Batch
	if err := json.Unmarshal(raw, &batch); err != nil || len(batch.Events) != 1 || batch.Events[0].EventID != expectedID || batch.Events[0].CaptureKind != captureDeniedLog || batch.Events[0].CountUnit != "log_records" {
		t.Fatalf("durable compatibility evidence changed on retry: %s, %v", raw, err)
	}
}

func denyJournalLearningEventID(entry JournalEntry) string {
	return shaText("prthak-learning-capture-v1\x00deny-log-retry\x00" + shaText("prthak-deny-journal-v1\x00"+entry.Cursor))
}

func TestDenyJournalFailedSpoolRetainsWindowUntilRetryBeforeRenewal(t *testing.T) {
	now := time.Now().UTC()
	a, firewall, original, entry, _ := denyJournalLifecycleAgent(t, now)
	spool := filepath.Join(a.Config.StateDir, "spool")
	if err := os.WriteFile(spool, []byte("injected unavailable spool"), 0600); err != nil {
		t.Fatal(err)
	}
	writes := len(firewall.writes)
	if err := a.tickTrafficCapture(context.Background(), now.Add(2*time.Second)); err == nil {
		t.Fatal("unavailable spool incorrectly succeeded")
	}
	state, err := readCaptureSidecars(a.Config.StateDir)
	if err != nil || len(state.Rules) == 0 || !state.Rules[0].StartedAt.Equal(original.StartedAt) || len(firewall.writes) != writes {
		t.Fatal("failed durable capture changed its rule window", state, err)
	}
	positionPath := filepath.Join(a.Config.StateDir, "traffic-capture", "deny-journal.json")
	if _, err := os.Stat(positionPath); !os.IsNotExist(err) {
		t.Fatal("failed spool advanced the journal cursor")
	}
	if err := os.Remove(spool); err != nil {
		t.Fatal(err)
	}
	if err := a.tickTrafficCapture(context.Background(), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	denyJournalSpoolEvent(t, a, denyJournalLearningEventID(entry))
	state, err = readCaptureSidecars(a.Config.StateDir)
	if err != nil || len(state.Rules) == 0 || !state.Rules[0].StartedAt.Equal(now.Add(3*time.Second)) || len(firewall.writes) <= writes {
		t.Fatal("successful durable retry did not renew observation rules", state, err)
	}
	position, err := readPrivateSetupBound(positionPath, 8192)
	if err != nil || !strings.Contains(string(position), entry.Cursor) {
		t.Fatal("successful retry did not commit its journal cursor", err)
	}
}

func TestDenyJournalRestartDrainsStoppedScopeWithoutExistingNativeCollector(t *testing.T) {
	now := time.Now().UTC()
	a, firewall, original, entry, journal := denyJournalLifecycleAgent(t, now)
	stop := now.Add(2 * time.Second)
	session := a.State.Policy.LearningSessions[0]
	session.StoppedAt, session.Status = &stop, "stopped"
	a.State.Policy = &Policy{LearningTombstones: []Session{session}}
	a.trafficCapture = nil
	a.confirmed = false
	err := a.tickTrafficCapture(context.Background(), now.Add(3*time.Second))
	if err != nil && (runtime.GOOS == "linux" || !strings.Contains(err.Error(), "requires Linux")) {
		t.Fatal(err)
	}
	if len(journal.args) != 1 || a.trafficCapture != nil {
		t.Fatal("stopped scope did not drain exactly once and close its temporary collector")
	}
	denyJournalSpoolEvent(t, a, denyJournalLearningEventID(entry))
	state, err := readCaptureSidecars(a.Config.StateDir)
	if err != nil || len(state.Rules) != 0 || firewall.has("runtime", "rich_rule", original.text()) {
		t.Fatal("stopped scope retained its observation rules", state, err)
	}
}

func TestDenyJournalShutdownSpoolsFinalPageBeforeRemovingSidecars(t *testing.T) {
	now := time.Now().UTC().Add(-3 * time.Second)
	a, firewall, original, entry, journal := denyJournalLifecycleAgent(t, now)
	closed := a.trafficCapture.(*deniedCaptureFixture)
	firewall.beforeWrite = func() {
		if len(journal.args) == 0 {
			t.Fatal("shutdown removed a sidecar before reading the final kernel records")
		}
		denyJournalSpoolEvent(t, a, denyJournalLearningEventID(entry))
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	denyJournalSpoolEvent(t, a, denyJournalLearningEventID(entry))
	if !closed.closed || a.trafficCapture != nil || firewall.has("runtime", "rich_rule", original.text()) {
		t.Fatal("shutdown did not close the native reader and remove the journal sidecar")
	}
}
