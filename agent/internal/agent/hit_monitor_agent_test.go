package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestHitAgentFreshSignedPolicyPersistsFloorAnd304CannotRenewLease(t *testing.T) {
	base := time.Now().UTC()
	item := HitMonitorAssignment{ID: "hit-signed", ServerID: "endpoint-one", StartsAt: base.Add(-time.Second), ExpiresAt: base.Add(119 * time.Second), Ports: []Port{{22, "tcp"}, {2022, "tcp"}}}
	c, p := signPolicyForTest(t, &Policy{ServerID: item.ServerID, Version: 1, Digest: "hit-policy", Mode: "monitor", HitMonitors: []HitMonitorAssignment{item}}, base)
	c.StateDir = t.TempDir()
	c.ControllerURL = "https://management.invalid"
	commands := &hitLifecycleCommands{rules: map[string]bool{}}
	a := &Agent{Config: c, Client: &Client{config: c, HTTP: assignmentHTTP(t, p)}, Commands: commands, State: State{Coverage: map[string]*Coverage{}}}
	fixtureAuthenticatedClient(a, item.ServerID)
	if err := a.refreshAssignment(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.State.AssignmentGeneration != p.AssignmentGeneration || a.hitMonitor == nil || len(a.hitMonitor.active) != 1 {
		t.Fatal("fresh signed monitor/floor was not accepted")
	}
	wall, mono := base, base
	a.hitMonitor.clock = func() time.Time { return wall }
	a.hitMonitor.monotonic = func() time.Time { return mono }
	deadline := a.hitMonitor.deadlines[hitLeaseKey(item)]
	if err := a.hitMonitor.Tick(context.Background(), wall); err != nil {
		t.Fatal(err)
	}
	if len(commands.adds) != 2 {
		t.Fatal("explicit SSH observation rules missing")
	}
	a.Client.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 304, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})}
	if err := a.refreshAssignment(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.hitMonitor.deadlines[hitLeaseKey(item)].Equal(deadline) {
		t.Fatal("304 extended hit authority")
	}
	wall = base.Add(-time.Minute)
	mono = base.Add(121 * time.Second)
	if err := a.hitMonitor.Tick(context.Background(), wall); err != nil {
		t.Fatal(err)
	}
	if len(commands.adds) != 2 || len(commands.rules) != 0 || len(a.hitMonitor.active) != 0 {
		t.Fatal("cached304 or wall rollback prolonged LOG capture")
	}
	if len(a.State.Rules) != 0 || len(a.State.Coverage) != 0 || len(a.State.LearningEvidence) != 0 {
		t.Fatal("hit capture contaminated learning state")
	}
}

func TestHitAgentUnsignedMonitoringCompatibilityCannotStartHitCapture(t *testing.T) {
	base := time.Now().UTC()
	item := HitMonitorAssignment{ID: "hit-unsigned", ServerID: "endpoint-one", StartsAt: base, ExpiresAt: base.Add(time.Minute), Ports: []Port{{22, "tcp"}}}
	a := &Agent{Config: Config{StateDir: t.TempDir()}}
	if err := a.acceptHitAssignments(&Policy{ServerID: item.ServerID, HitMonitors: []HitMonitorAssignment{item}}, base); err == nil {
		t.Fatal("unsigned legacy monitoring activated privileged hit capture")
	}
	if a.hitMonitor != nil {
		t.Fatal("rejected hit request created active collector")
	}
}

func TestHitStatusOnlyAcknowledgesStopAfterVerifiedRuleAbsence(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	item := h.assignment("status-hit", Port{8443, "tcp"})
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	statuses := h.monitor.Statuses()
	if len(statuses) != 1 || statuses[0].Status != "observing" {
		t.Fatalf("readback not reflected %+v", statuses)
	}
	h.advance(5)
	h.set(t)
	h.commands.removeErr = errors.New("disposable removal failure")
	if err := h.monitor.Tick(context.Background(), h.wall); err == nil {
		t.Fatal("cleanup failure missing")
	}
	if statuses = h.monitor.Statuses(); statuses[0].Status != "error" {
		t.Fatalf("stop falsely acknowledged %+v", statuses)
	}
	h.advance(7)
	h.commands.removeErr = nil
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if statuses = h.monitor.Statuses(); statuses[0].Status != "off" || !statuses[0].CheckedAt.Equal(h.wall) {
		t.Fatalf("verified stop receipt absent %+v", statuses)
	}
}

func TestHitStatusMonotonicExpiryAndSimulationStateRemainTruthful(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	h.set(t, h.assignment("expiry-hit"))
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.wall = h.base.Add(-time.Minute)
	h.mono = h.base.Add(121 * time.Second)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if statuses := h.monitor.Statuses(); len(statuses) != 1 || statuses[0].Status != "expired" {
		t.Fatalf("monotonic expiry not reported %+v", statuses)
	}
	if _, err := NewHitMonitor(h.dir, "public", 8, h.commands, true); err == nil {
		t.Fatal("simulation adopted real observation/spool state")
	}
}

func TestHitOutcomeReceiptsReportChangesWithoutTerminalHeartbeatStorm(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	h.set(t, h.assignment("outcome-hit"))
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if !h.monitor.ShouldReport(h.wall) || h.monitor.ShouldReport(h.wall) {
		t.Fatal("initial outcome was lost or repeated")
	}
	h.monitor.Reported()
	h.advance(11)
	h.set(t)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if !h.monitor.ShouldReport(h.wall) {
		t.Fatal("verified stop did not request immediate outcome report")
	}
	h.monitor.Reported()
	checked := h.monitor.Statuses()[0].CheckedAt
	h.advance(40)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if !h.monitor.Statuses()[0].CheckedAt.Equal(checked) || h.monitor.ShouldReport(h.wall) {
		t.Fatal("terminal outcome invented a fresh kernel check/report")
	}
}

func TestHitJournalVacuumRebasesCursorWithExplicitCoverageLoss(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	item := h.assignment("vacuum-hit")
	h.set(t, item)
	h.monitor.state.Cursor = "vacuumed-cursor"
	h.commands.journalErr = errors.New("failed to seek cursor")
	if err := h.monitor.Tick(context.Background(), h.wall); err == nil {
		t.Fatal("missing journal cursor was not diagnosed")
	}
	if h.monitor.state.Cursor != "" || !h.monitor.state.Limited {
		t.Fatal("lost journal cursor cannot recover with explicit coverage limit")
	}
	h.advance(1)
	h.commands.journalErr = nil
	h.commands.entries = []JournalEntry{hitLifecycleEntry(item, "fresh-cursor", "192.0.2.2", h.wall)}
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if h.monitor.state.Cursor != "fresh-cursor" || len(hitLifecycleBatches(t, h.monitor)) != 1 {
		t.Fatal("fresh authorized observations did not resume after cursor vacuum")
	}
}

func TestHitRejectedAuthorityReportsErrorUntilExplicitStop(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	item := h.assignment("rejected-hit")
	a := &Agent{Config: Config{StateDir: h.dir}, hitMonitor: h.monitor, Commands: h.commands}
	if err := a.acceptHitAssignments(&Policy{ServerID: item.ServerID, HitMonitors: []HitMonitorAssignment{item}}, h.wall); err == nil {
		t.Fatal("untrusted monitor accepted")
	}
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if statuses := h.monitor.Statuses(); len(statuses) != 1 || statuses[0].Status != "error" {
		t.Fatalf("rejected authority became silent pending/off %+v", statuses)
	}
	if len(h.commands.adds) != 0 {
		t.Fatal("rejected authority installed a LOG rule")
	}
	h.advance(1)
	if err := a.acceptHitAssignments(&Policy{ServerID: item.ServerID}, h.wall); err != nil {
		t.Fatal(err)
	}
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if statuses := h.monitor.Statuses(); statuses[0].Status != "off" {
		t.Fatalf("explicit stop did not clear rejected request %+v", statuses)
	}
}

func TestHitLaterCentralStopRefreshesExpiredReceiptOnlyAfterNativeAbsence(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	item := h.assignment("late-stop-hit")
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.advance(121)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	old := h.monitor.Statuses()[0].CheckedAt
	h.advance(200)
	h.set(t)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	status := h.monitor.Statuses()[0]
	if status.Status != "off" || !status.CheckedAt.Equal(h.wall) || !status.CheckedAt.After(old) {
		t.Fatalf("late stop has no fresh native proof %+v", status)
	}
	queries := 0
	for _, call := range h.commands.calls {
		for _, arg := range call.args {
			if arg == "--list-all-zones" {
				queries++
			}
		}
	}
	if queries != 1 {
		t.Fatalf("stop must use one bounded native read, got%d", queries)
	}
	h.advance(210)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if !h.monitor.Statuses()[0].CheckedAt.Equal(status.CheckedAt) {
		t.Fatal("terminal check timestamp invented another native observation")
	}
}

func TestHitLaterStopRefusesFreshOffForReappearingUnownedPrefix(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	item := h.assignment("unowned-stop-hit")
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.advance(121)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	h.commands.rules[HitObservationRule(item.ID, item.Ports[0])] = true
	h.advance(200)
	h.set(t)
	if err := h.monitor.Tick(context.Background(), h.wall); err == nil {
		t.Fatal("reappearing unowned prefix was falsely absent")
	}
	if status := h.monitor.Statuses()[0]; status.Status != "error" {
		t.Fatalf("unverified stop got false success %+v", status)
	}
	if !h.commands.rules[HitObservationRule(item.ID, item.Ports[0])] {
		t.Fatal("absence check removed unowned instrumentation")
	}
}

func TestHitReceiptCapacityKeepsNewErrorsAheadOfOldTerminalRows(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	for index := 0; index < 16; index++ {
		h.monitor.state.Statuses = append(h.monitor.state.Statuses, HitMonitorStatus{ID: fmt.Sprintf("old-%d", index), Status: "off", CheckedAt: h.base.Add(-time.Hour)})
	}
	h.monitor.state.Rejections = map[string]string{"new-error": "independent trust unavailable"}
	h.monitor.updateStatuses(h.wall, nil)
	statuses := h.monitor.Statuses()
	if len(statuses) != 16 || statuses[0].ID != "new-error" || statuses[0].Status != "error" {
		t.Fatalf("new relevant failure was evicted by stale terminal rows %+v", statuses)
	}
}

func TestHitNativeTimeoutNeverRoundsBeyondFractionalLease(t *testing.T) {
	h := newHitLifecycleHarness(t, 8, time.Now().UTC())
	item := h.assignment("fractional-hit")
	item.ExpiresAt = h.base.Add(119*time.Second + 500*time.Millisecond)
	h.set(t, item)
	if err := h.monitor.Tick(context.Background(), h.wall); err != nil {
		t.Fatal(err)
	}
	if len(h.commands.addTimeouts) != 1 || h.commands.addTimeouts[0] != 119 {
		t.Fatalf("native timeout exceeded remaining signed authority %v", h.commands.addTimeouts)
	}
}
