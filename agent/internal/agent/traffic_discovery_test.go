package agent

import (
	"testing"
	"time"
)

func TestTrafficDiscoveryThirtyDayAssignmentRemainsObserveOnly(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Second)
	session := Session{
		ID: "traffic-session-123", Purpose: "traffic", PolicyAction: "observe",
		ObservationKinds: []string{"accepted_connection"}, Ports: []Port{{443, "tcp"}},
		StartsAt: start, ExpiresAt: start.Add(30 * 24 * time.Hour), Status: "active",
	}
	assignment := Policy{Version: 1, Digest: "example", Mode: "monitor", LearningSessions: []Session{session}}
	if err := ValidatePolicy(&assignment); err != nil {
		t.Fatalf("30-day typed traffic assignment was refused: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*Session)
	}{
		{"legacy purpose", func(s *Session) { s.Purpose = "" }},
		{"policy purpose", func(s *Session) { s.Purpose = "policy" }},
		{"unknown purpose", func(s *Session) { s.Purpose = "unknown" }},
		{"auto allow", func(s *Session) { s.PolicyAction = "auto_allow" }},
		{"legacy capture", func(s *Session) { s.ObservationKinds = nil }},
		{"over maximum", func(s *Session) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			modified := session
			test.edit(&modified)
			assignment.LearningSessions = []Session{modified}
			if err := ValidatePolicy(&assignment); err == nil {
				t.Fatal("unexpectedly accepted modified traffic assignment")
			}
		})
	}
}
