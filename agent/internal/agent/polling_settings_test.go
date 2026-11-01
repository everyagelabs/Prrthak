package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func pollingFixture(version, control, discovery int) *PollingSettings {
	return &PollingSettings{Version: version, Digest: pollingDigest(control, discovery), ControlIntervalSeconds: control, DiscoveryIntervalSeconds: discovery, MatchedRuleIDs: []string{"billing"}}
}
func TestRemotePollingAppliesThroughAssignmentAndReportsActualTiming(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 300, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5}
	a, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	scans := 0
	a.Commands = inventoryCommands(&scans, nil)
	now := time.Now().UTC()
	a.clock = func() time.Time { return now }
	fixtureAuthenticatedClient(a, "polling-test")
	expected := pollingFixture(2, 5, 60)
	reports := []Report{}
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := []byte(`{}`)
		if strings.HasSuffix(request.URL.Path, "/policy") {
			body, _ = json.Marshal(Policy{ServerID: "polling-test", Version: 1, Digest: "safe-policy", Mode: "monitor", Services: []Service{}, LearningSessions: []Session{}, PollingSettings: expected})
		} else {
			var report Report
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
				t.Fatal(err)
			}
			reports = append(reports, report)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})
	if err = a.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reports[0].ControlIntervalSeconds != 300 || reports[1].ControlIntervalSeconds != 5 || reports[1].DiscoveryIntervalSeconds != 60 {
		t.Fatalf("actual runtime intervals missing: %+v", reports)
	}
	if reports[1].PollingSettings == nil || reports[1].PollingSettings.Status != "applied" || reports[1].PollingSettings.Version != 2 || reports[1].PollingSettings.Digest != expected.Digest {
		t.Fatal("missing exact applied receipt")
	}
	if a.Config.IntervalSeconds != 300 || a.Config.DiscoveryIntervalSeconds != 900 || a.Config.Enforce {
		t.Fatal("immutable local/security configuration changed")
	}
	now = now.Add(70 * time.Second)
	if err = a.report(context.Background()); err != nil {
		t.Fatal(err)
	}
	if scans != 2 {
		t.Fatalf("discovery cadence not updated: %d", scans)
	}
	a.Client.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("controller unavailable") })
	if a.Sync(context.Background()) == nil {
		t.Fatal("outage not surfaced")
	}
	if a.controlIntervalSeconds() != 5 || a.discoveryIntervalSeconds() != 60 {
		t.Fatal("outage erased retained timing")
	}
	restarted, err := New(c, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if restarted.controlIntervalSeconds() != 5 || restarted.discoveryIntervalSeconds() != 60 {
		t.Fatal("restart lost valid remote timing")
	}
}
func TestInvalidOrOlderPollingNeverReplacesLastValidSettings(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900}}
	good := pollingFixture(3, 30, 120)
	if err := a.applyPollingSettings(good); err != nil {
		t.Fatal(err)
	}
	cases := []*PollingSettings{pollingFixture(4, 4, 120), pollingFixture(4, 3601, 120), pollingFixture(4, 30, 59), pollingFixture(4, 30, 86401), pollingFixture(2, 10, 90)}
	bad := pollingFixture(4, 10, 90)
	bad.Digest = strings.Repeat("a", 64)
	cases = append(cases, bad)
	for _, candidate := range cases {
		if a.applyPollingSettings(candidate) == nil {
			t.Fatalf("invalid timing accepted: %+v", candidate)
		}
		if a.controlIntervalSeconds() != 30 || a.discoveryIntervalSeconds() != 120 {
			t.Fatal("invalid assignment changed runtime")
		}
	}
	if err := a.applyPollingSettings(nil); err != nil {
		t.Fatal(err)
	}
	if a.controlIntervalSeconds() != 30 {
		t.Fatal("missing assignment cleared cached timing")
	}
	if err := a.applyPollingSettings(good); err != nil {
		t.Fatal(err)
	}
	if a.pollingSettingsReport().Status != "applied" {
		t.Fatal("valid assignment did not clear error")
	}
	path := filepath.Join(a.Config.StateDir, "polling-settings.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if a.applyPollingSettings(pollingFixture(4, 15, 60)) == nil {
		t.Fatal("unpersistable timing activated")
	}
	if a.controlIntervalSeconds() != 30 || a.pollingSettingsReport().Status != "error" {
		t.Fatal("persistence failure did not retain timing and report failure")
	}
}
func TestPollingTimingSnapshotIsRaceSafe(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900}}
	var wait sync.WaitGroup
	for reader := 0; reader < 4; reader++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < 500; index++ {
				_ = a.controlIntervalSeconds()
				_ = a.discoveryIntervalSeconds()
				_ = a.pollingSettingsReport()
			}
		}()
	}
	for version := 1; version <= 20; version++ {
		if err := a.applyPollingSettings(pollingFixture(version, version+5, version+60)); err != nil {
			t.Fatal(err)
		}
	}
	wait.Wait()
	if a.Config.IntervalSeconds != 60 || a.Config.DiscoveryIntervalSeconds != 900 {
		t.Fatal("local config mutated")
	}
}
func TestRunningAgentUsesNewControlTimerWithoutRestart(t *testing.T) {
	c := Config{ControllerURL: "http://127.0.0.1", StateDir: t.TempDir(), IntervalSeconds: 300, DiscoveryIntervalSeconds: 900, RequestTimeoutSeconds: 1, MaxSpoolBatches: 5, DemoAgentID: "runtime-polling"}
	a, err := New(c, true, "runtime-polling")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	gets := 0
	a.Client.HTTP.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := []byte(`{}`)
		if strings.HasSuffix(request.URL.Path, "/policy") {
			gets++
			body, _ = json.Marshal(Policy{ServerID: "runtime-polling", Version: 1, Digest: "safe-policy", Mode: "monitor", Services: []Service{}, LearningSessions: []Session{}, PollingSettings: pollingFixture(1, 5, 60)})
			if gets >= 2 {
				cancel()
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})
	if err = a.Run(ctx, false); err != nil {
		t.Fatal(err)
	}
	if gets < 2 {
		t.Fatal("running timer retained 300-second local delay instead of new 5-second interval")
	}
}

func TestSameRevisionMembershipChangeUpdatesExactRuntimeTiming(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir(), IntervalSeconds: 60, DiscoveryIntervalSeconds: 900}}
	initial := pollingFixture(2, 60, 900)
	changed := pollingFixture(2, 15, 120)
	if err := a.applyPollingSettings(initial); err != nil {
		t.Fatal(err)
	}
	if err := a.applyPollingSettings(changed); err != nil {
		t.Fatalf("fresh assignment after tag/group membership change rejected at same settings revision: %v", err)
	}
	if a.controlIntervalSeconds() != 15 || a.discoveryIntervalSeconds() != 120 {
		t.Fatal("membership-driven timing was not applied")
	}
	receipt := a.pollingSettingsReport()
	if receipt.Version != 2 || receipt.Digest != changed.Digest || receipt.Status != "applied" {
		t.Fatalf("wrong membership receipt: %+v", receipt)
	}
	restarted := &Agent{Config: a.Config}
	restarted.loadPollingSettings()
	if restarted.controlIntervalSeconds() != 15 || restarted.pollingSettingsReport().Digest != changed.Digest {
		t.Fatal("membership update was not persisted")
	}
}
