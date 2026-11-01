package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSyncWireSteady304UsesOneReportAndChangesAcknowledgeImmediately(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	scans := 0
	a.Commands = inventoryCommands(&scans, nil)
	clock := time.Now().UTC()
	a.clock = func() time.Time { return clock }
	requests := []string{}
	reports := []Report{}
	fixtureAuthenticatedClient(a, "wire-test")
	gets := 0
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		status, body := 200, []byte(`{}`)
		headers := http.Header{}
		if strings.HasSuffix(request.URL.Path, "/policy") {
			requests = append(requests, "policy")
			gets++
			if gets == 2 || gets == 4 {
				if request.Header.Get("If-None-Match") == "" {
					t.Fatal("steady assignment check lost its ETag")
				}
				status, body = 304, nil
			} else {
				settings := pollingFixture(1, 60, 900)
				if gets == 3 {
					settings = pollingFixture(2, 30, 900)
				}
				body, _ = json.Marshal(Policy{ServerID: "wire-test", Version: 1, Digest: "safe-preview", Mode: "monitor", Services: []Service{}, LearningSessions: []Session{}, PollingSettings: settings})
				headers.Set("ETag", "fixture-"+settings.Digest)
			}
		} else {
			requests = append(requests, "report")
			var report Report
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
				t.Fatal(err)
			}
			reports = append(reports, report)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(body))), Header: headers}, nil
	})
	for cycle := 0; cycle < 4; cycle++ {
		before := len(requests)
		if cycle == 3 {
			clock = clock.Add(901 * time.Second)
		} else if cycle > 0 {
			clock = clock.Add(time.Minute)
		}
		if err := a.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		expected := []string{"report", "policy"}
		if cycle == 0 || cycle == 2 {
			expected = append(expected, "report")
		}
		if !reflect.DeepEqual(requests[before:], expected) {
			t.Fatalf("cycle%d HTTP cadence %v want %v", cycle+1, requests[before:], expected)
		}
	}
	if scans != 2 || len(reports) != 6 {
		t.Fatalf("scans=%d reports=%d", scans, len(reports))
	}
	if reports[4].ControlIntervalSeconds != 30 || reports[4].PollingSettings.Version != 2 {
		t.Fatal("changed polling settings lacked same-cycle outcome receipt")
	}
	if !reports[5].DiscoveryPerformed || reports[5].DiscoveredAt == nil {
		t.Fatal("scheduled full discovery was not acknowledged by its immediate first report")
	}
}

func TestSyncReceiptIgnoresRoutineTimesButPreservesMutationAndFailureOutcomes(t *testing.T) {
	a := &Agent{State: State{ManagedEnforcement: &ManagedEnforcement{Status: "enforced", Version: 7, UpdatedAt: time.Now()}, LearningAllowOutcome: &LearningAllowOutcome{Generation: 2, Status: "applied", UpdatedAt: time.Now()}, FirewallChangeResults: []FirewallChangeResult{{ID: "imported-a", Status: "applied"}}}}
	before := a.syncReceipt()
	a.State.ManagedEnforcement.UpdatedAt = time.Now().Add(time.Minute)
	a.State.LearningAllowOutcome.UpdatedAt = time.Now().Add(time.Minute)
	a.State.FirewallChangeResults[0].Acknowledged = true
	if a.receiptChanged(before) {
		t.Fatal("routine timestamps or a locally persisted acknowledgement created another HTTP write")
	}
	a.State.ManagedEnforcement.Status = "rolled_back"
	a.State.ManagedEnforcement.RollbackReason = "fresh authority revoked"
	if !a.receiptChanged(before) {
		t.Fatal("rollback outcome was suppressed")
	}
	before = a.syncReceipt()
	a.State.FirewallChangeResults = append(a.State.FirewallChangeResults, FirewallChangeResult{ID: "imported-b", Status: "failed", Message: "fresh authorization denied"})
	if !a.receiptChanged(before) {
		t.Fatal("new imported-firewall failure receipt was suppressed")
	}
}
