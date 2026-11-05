package agent

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTypedCaptureCoverageStaysOpenUntilSessionEnds(t *testing.T) {
	now := time.Now().UTC()
	for _, kinds := range [][]string{{captureAccepted}, {captureDenied}, {captureAccepted, captureDenied}} {
		t.Run(strings.Join(kinds, "+"), func(t *testing.T) {
			session := Session{ID: "typed-coverage", StartsAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Status: "active", Ports: []Port{{8443, "tcp"}}, ObservationKinds: kinds}
			a := &Agent{Config: Config{StateDir: t.TempDir()}, State: State{Policy: &Policy{LearningSessions: []Session{session}}}, Simulate: true, confirmed: true,
				captureCoverage: TrafficCaptureCoverage{Backends: []CaptureBackendReport{{Backend: "conntrack", Status: "active"}, {Backend: "nflog", Status: "active"}}}}
			a.updateCaptureReceipts(now, nil)
			coverage := a.State.Coverage[session.ID]
			for _, at := range []time.Time{now, now.Add(2 * time.Second)} {
				if err := a.LearningTick(context.Background(), at); err != nil {
					t.Fatal(err)
				}
				if coverage.EndedAt != nil || !coverage.StartedAt.Equal(now) {
					t.Fatalf("active typed receipt was ended or restarted: %+v", coverage)
				}
			}
			if err := a.LearningTick(context.Background(), session.ExpiresAt.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if coverage.EndedAt == nil || !coverage.EndedAt.Equal(session.ExpiresAt) {
				t.Fatalf("expired receipt did not end at its signed cutoff: %+v", coverage)
			}
		})
	}
}

func TestTypedCaptureReceiptReopensSavedReceiptAndClearsOldBackendError(t *testing.T) {
	now := time.Now().UTC()
	start := now.Add(-time.Minute)
	oldEnd := start
	session := Session{ID: "resumed-typed-coverage", StartsAt: start, ExpiresAt: now.Add(time.Minute), Status: "active", Ports: []Port{{8443, "tcp"}}, ObservationKinds: []string{captureAccepted}}
	coverage := &Coverage{SessionID: session.ID, StartedAt: start, EndedAt: &oldEnd, DroppedEvents: 3, Error: "old kernel journal error"}
	a := &Agent{State: State{Policy: &Policy{LearningSessions: []Session{session}}, Coverage: map[string]*Coverage{session.ID: coverage}}, captureCoverage: TrafficCaptureCoverage{Backends: []CaptureBackendReport{{Backend: "conntrack", Status: "active"}}}}
	a.updateCaptureReceipts(now, nil)
	if coverage.EndedAt != nil || !coverage.StartedAt.Equal(start) || coverage.Error != "" || coverage.DroppedEvents != 3 {
		t.Fatalf("fresh active receipt retained stale termination/error or lost history: %+v", coverage)
	}
	stopped := now.Add(-time.Second)
	a.State.Policy.LearningSessions[0].StoppedAt = &stopped
	a.State.Policy.LearningSessions[0].Status = "stopped"
	coverage.EndedAt = &stopped
	a.updateCaptureReceipts(now, nil)
	if coverage.EndedAt == nil || !coverage.EndedAt.Equal(stopped) {
		t.Fatal("stopped receipt was reopened")
	}
}
