package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeRunner struct {
	calls [][]string
	fn    func(string, []string) (string, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fn != nil {
		return f.fn(name, args)
	}
	return "", nil
}
func sessionAt(now time.Time) Session {
	return Session{ID: "learning-test-123", Ports: []Port{{80, "tcp"}, {53, "udp"}}, StartsAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Status: "active"}
}
func TestParseSocketsIPv4IPv6AndUDP(t *testing.T) {
	text := `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp LISTEN 0 128 [::]:80 [::]:* users:(("nginx",pid=2,fd=4))
udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:*
tcp LISTEN 0 128 [::]:80 [::]:* users:(("nginx",pid=2,fd=4))
invalid line`
	ls := ParseSockets(text)
	if len(ls) != 3 {
		t.Fatalf("listeners=%+v", ls)
	}
	if ls[0].Process != "sshd" || ls[1].Protocol != "udp" || ls[2].Address != "::" {
		t.Fatalf("unexpected listeners=%+v", ls)
	}
}
func TestLogParsingDoesNotClaimAccept(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	for _, src := range []string{"10.2.3.4", "2001:db8::42"} {
		msg := RulePrefix(s.ID) + " IN=eth0 OUT= SRC=" + src + " DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80"
		flow, ok := ParseKernelLog(msg, now, s)
		if !ok || flow.SourceIP != src || flow.Verdict != "observed" || flow.Count != 1 {
			t.Fatalf("parse %q: %+v %v", msg, flow, ok)
		}
	}
	for _, msg := range []string{RulePrefix(s.ID) + " IN=eth0 OUT= SRC=invalid PROTO=TCP DPT=80", RulePrefix(s.ID) + " IN=eth0 OUT= SRC=10.0.0.1 PROTO=TCP DPT=22", "UNOWNED SRC=10.0.0.1 PROTO=TCP DPT=80"} {
		if _, ok := ParseKernelLog(msg, now, s); ok {
			t.Fatalf("accepted invalid/unassigned log: %s", msg)
		}
	}
	if _, ok := ParseKernelLog(RulePrefix(s.ID)+" IN=eth0 OUT= SRC=10.0.0.1 PROTO=TCP DPT=80", s.ExpiresAt, s); ok {
		t.Fatal("accepted event at/after expiry")
	}
}
func TestLearningExpiryNeverExpiresAccessPolicy(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	p := &Policy{Version: 42, Digest: "digest", Mode: "monitor", LearningSessions: []Session{s}}
	if len(ActiveSessions(p, now)) != 1 || len(ActiveSessions(p, s.ExpiresAt)) != 0 {
		t.Fatal("invalid expiry boundary")
	}
	if p.Version != 42 {
		t.Fatal("learning expiry changed policy")
	}
	s.Status = "stopped"
	p.LearningSessions = []Session{s}
	if len(ActiveSessions(p, now)) != 0 {
		t.Fatal("stopped session remains active")
	}
}
func TestObservationRuleCannotChangeAccess(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	f := &fakeRunner{}
	owned, e := AddObservation(context.Background(), f, "public", s, Port{80, "tcp"}, now)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(owned.Rule, " accept") || strings.Contains(owned.Rule, " drop") || strings.Contains(owned.Rule, " reject") {
		t.Fatal("learning changed access")
	}
	args := f.calls[0]
	if args[0] != "firewall-cmd" || args[len(args)-1] != "--timeout=3600s" || len(args) != 4 {
		t.Fatalf("bad command arguments: %#v", args)
	}
	if e = RemoveObservation(context.Background(), f, OwnedRule{SessionID: s.ID, Zone: "public", Rule: `rule source address="0.0.0.0/0" accept`}); e == nil {
		t.Fatal("removed unowned rule")
	}
	if len(f.calls) != 1 {
		t.Fatal("unowned removal invoked firewall command")
	}
}
func TestValidationAndPerServicePreview(t *testing.T) {
	p := &Policy{Version: 1, Digest: "abc", Mode: "enforce", Services: []Service{{Port: 80, Protocol: "tcp", Mode: "monitor", Sources: []string{"10.0.0.0/24"}}, {Port: 22, Protocol: "tcp", Mode: "enforce", Sources: []string{}}}}
	if e := ValidatePolicy(p); e != nil {
		t.Fatal(e)
	}
	plan := BuildPlan(p, Config{})
	if plan.Capability != "preview-only" || plan.Rules[0].Mode != "monitor" || len(plan.Warnings) == 0 {
		t.Fatalf("invalid preview %+v", plan)
	}
	p.Services[0].Sources = []string{"not-an-address"}
	if ValidatePolicy(p) == nil {
		t.Fatal("invalid CIDR accepted")
	}
}
func TestSimulationMakesNoOSCommandsAndExpires(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	tmp := t.TempDir()
	c := Config{StateDir: tmp, ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 1, MaxSpoolBatches: 2}
	a, e := New(c, true, "sim-host")
	if e != nil {
		t.Fatal(e)
	}
	f := &fakeRunner{fn: func(_ string, _ []string) (string, error) {
		t.Fatal("simulation invoked external command")
		return "", nil
	}}
	a.Commands = f
	a.confirmed = true
	a.State.Policy = &Policy{Version: 9, Digest: "abc", Mode: "monitor", LearningSessions: []Session{s}}
	if e = a.LearningTick(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	if len(a.State.Rules) != 2 {
		t.Fatalf("sim rules=%+v", a.State.Rules)
	}
	if e = a.LearningTick(context.Background(), s.ExpiresAt); e != nil {
		t.Fatal(e)
	}
	if len(a.State.Rules) != 0 || a.State.Coverage[s.ID].EndedAt == nil || a.State.Policy.Version != 9 {
		t.Fatal("expiry did not clean learning only")
	}
	if files, _ := spoolFiles(filepath.Join(tmp, "spool")); len(files) != 0 {
		t.Fatal("simulation fabricated traffic")
	}
}
func TestFailedCleanupRetainsOwnedRuleForRetry(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	r := OwnedRule{s.ID, "public", ObservationRule(s, Port{80, "tcp"}), s.ExpiresAt}
	a := &Agent{Config: Config{StateDir: t.TempDir()}, State: State{Rules: []OwnedRule{r}, Coverage: map[string]*Coverage{}}, Commands: &fakeRunner{fn: func(string, []string) (string, error) { return "", errors.New("daemon down") }}}
	if e := a.Shutdown(context.Background()); e == nil {
		t.Fatal("cleanup failure hidden")
	}
	if len(a.State.Rules) != 1 {
		t.Fatal("failed cleanup intent lost")
	}
}
func TestMissingObservationAfterReloadIsReinstalled(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	r := OwnedRule{s.ID, "public", ObservationRule(s, Port{80, "tcp"}), s.ExpiresAt}
	s.Ports = []Port{{80, "tcp"}}
	commands := &fakeRunner{fn: func(name string, args []string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "ufw":
			return "Status: inactive", nil
		case strings.Contains(joined, "--query-rich-rule"):
			return "no", errors.New("not enabled")
		case joined == "--state":
			return "running", nil
		case joined == "--get-active-zones":
			return "public\n  interfaces: eth0\n", nil
		default:
			return "", nil
		}
	}}
	a := &Agent{Config: Config{StateDir: t.TempDir(), MaxSpoolBatches: 2}, State: State{Policy: &Policy{LearningSessions: []Session{s}}, Rules: []OwnedRule{r}, Coverage: map[string]*Coverage{s.ID: {SessionID: s.ID, StartedAt: now}}}, Commands: commands, confirmed: true}
	if e := a.LearningTick(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	added := false
	for _, call := range commands.calls {
		if strings.Contains(strings.Join(call, " "), "--add-rich-rule=") {
			added = true
		}
	}
	if !added || !strings.Contains(a.State.Coverage[s.ID].Error, "gap") {
		t.Fatal("reload loss not reinstalled/reported")
	}
}
func TestSpoolCapacityReportsLossAndAdvancesCursor(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	dir := t.TempDir()
	state := State{Coverage: map[string]*Coverage{s.ID: {SessionID: s.ID, StartedAt: now}}, JournalSince: now}
	if e := SpoolBatch(dir, 1, Batch{BatchID: "existing", SessionID: s.ID, Events: []Flow{{Count: 1}}}); e != nil {
		t.Fatal(e)
	}
	entry := JournalEntry{Message: RulePrefix(s.ID) + " IN=eth0 OUT= SRC=10.0.0.1 PROTO=TCP DPT=80", Cursor: "cursor-new", Timestamp: fmt.Sprint(now.UnixMicro())}
	b, _ := json.Marshal(entry)
	f := &fakeRunner{fn: func(string, []string) (string, error) { return string(b), nil }}
	if e := CollectJournal(context.Background(), f, &state, []Session{s}, dir, 1, now); e == nil {
		t.Fatal("full spool did not report error")
	}
	if state.Cursor != "cursor-new" || state.Coverage[s.ID].DroppedEvents != 1 {
		t.Fatalf("loss metadata incorrect %+v", state)
	}
}
func TestExpiredBatchDoesNotBlockQueue(t *testing.T) {
	c, e := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 1}, true)
	if e != nil {
		t.Fatal(e)
	}
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 410, Body: io.NopCloser(strings.NewReader(`{"error":"learning upload grace expired"}`)), Header: http.Header{}}, nil
	})
	dir := t.TempDir()
	now := time.Now().UTC()
	b := Batch{BatchID: "one", SessionID: "learning-test-123", Events: []Flow{{LastSeen: now, Count: 1}}}
	if e = SpoolBatch(dir, 2, b); e != nil {
		t.Fatal(e)
	}
	_, e = FlushSpool(context.Background(), c, dir, now)
	var discarded *DiscardedBatchError
	if !errors.As(e, &discarded) || discarded.Count != 1 {
		t.Fatalf("missing discard error %v", e)
	}
	if files, _ := spoolFiles(dir); len(files) != 0 {
		t.Fatal("expired batch remains blocking queue")
	}
}
func TestCachedFilesPrivateAndPolicyETag(t *testing.T) {
	c, e := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 1}, true)
	if e != nil {
		t.Fatal(e)
	}
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") != `"unchanged"` {
			t.Error("ETag not sent")
		}
		return &http.Response{StatusCode: 304, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})
	p, etag, e := c.Policy(context.Background(), `"unchanged"`)
	if e != nil || p != nil || etag != `"unchanged"` {
		t.Fatal("304 handling invalid")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if e = atomicJSON(path, map[string]int{"x": 1}); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("state permissions are not0600")
	}
}

func TestPermanentRejectedBatchDoesNotBlockLaterSession(t *testing.T) {
	for _, status := range []int{400, 403, 404, 410} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, e := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 1}, true)
			if e != nil {
				t.Fatal(e)
			}
			uploaded := []string{}
			c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var batch Batch
				if e := json.NewDecoder(r.Body).Decode(&batch); e != nil {
					t.Fatal(e)
				}
				code := 202
				if batch.SessionID == "old-session" {
					code = status
				} else {
					uploaded = append(uploaded, batch.SessionID)
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(`{"accepted":1}`)), Header: http.Header{}}, nil
			})
			dir := t.TempDir()
			now := time.Now().UTC()
			if e = SpoolBatch(dir, 5, Batch{BatchID: "01-rejected", SessionID: "old-session", Events: []Flow{{Count: 2, LastSeen: now}, {Count: 3, LastSeen: now}}}); e != nil {
				t.Fatal(e)
			}
			if e = SpoolBatch(dir, 5, Batch{BatchID: "02-current", SessionID: "current-session", Events: []Flow{{Count: 1, LastSeen: now}}}); e != nil {
				t.Fatal(e)
			}
			sent, e := FlushSpool(context.Background(), c, dir, now)
			var discarded *DiscardedBatchError
			if sent != 1 || !errors.As(e, &discarded) || discarded.Count != 5 || len(discarded.Losses) != 1 || discarded.Losses[0].SessionID != "old-session" {
				t.Fatalf("sent=%d error=%+v", sent, e)
			}
			if len(uploaded) != 1 || uploaded[0] != "current-session" {
				t.Fatal("later valid session did not upload in same flush")
			}
			if files, _ := spoolFiles(dir); len(files) != 0 {
				t.Fatal("permanent rejection still in active queue")
			}
			retained, _ := os.ReadDir(filepath.Join(dir, "quarantine"))
			if len(retained) != 1 {
				t.Fatal("rejected payload not retained for diagnosis")
			}
		})
	}
}
func TestCorruptSpoolIsQuarantinedAndLaterBatchUploads(t *testing.T) {
	c, _ := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 1}, true)
	uploads := 0
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		uploads++
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"accepted":1}`)), Header: http.Header{}}, nil
	})
	dir := t.TempDir()
	now := time.Now().UTC()
	if e := os.WriteFile(filepath.Join(dir, "00-corrupt.json"), []byte(`{"incomplete":`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := SpoolBatch(dir, 5, Batch{BatchID: "01-good", SessionID: "valid-session", Events: []Flow{{Count: 1, LastSeen: now}}}); e != nil {
		t.Fatal(e)
	}
	sent, e := FlushSpool(context.Background(), c, dir, now)
	var discarded *DiscardedBatchError
	if sent != 1 || uploads != 1 || !errors.As(e, &discarded) || !strings.Contains(discarded.Reason, "count unknown") {
		t.Fatalf("sent=%d uploads=%d error=%v", sent, uploads, e)
	}
	if files, _ := spoolFiles(dir); len(files) != 0 {
		t.Fatal("corrupt file still blocks active spool")
	}
}
func TestTransientDeliveryFailureRetainsPayload(t *testing.T) {
	for _, status := range []int{429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, _ := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 1}, true)
			c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"error":"retry"}`)), Header: http.Header{}}, nil
			})
			dir := t.TempDir()
			now := time.Now().UTC()
			if e := SpoolBatch(dir, 2, Batch{BatchID: "retry", SessionID: "learning-session", Events: []Flow{{Count: 1, LastSeen: now}}}); e != nil {
				t.Fatal(e)
			}
			sent, e := FlushSpool(context.Background(), c, dir, now)
			var response *HTTPError
			if sent != 0 || !errors.As(e, &response) || response.Status != status {
				t.Fatalf("unexpected result %d %v", sent, e)
			}
			if files, _ := spoolFiles(dir); len(files) != 1 {
				t.Fatal("retryable payload was discarded")
			}
		})
	}
}
func tailRunner(s Session, when time.Time) *fakeRunner {
	delivered := false
	return &fakeRunner{fn: func(name string, args []string) (string, error) {
		if name != "journalctl" {
			return "", nil
		}
		if delivered {
			return "", nil
		}
		delivered = true
		entry := JournalEntry{Message: RulePrefix(s.ID) + " IN=eth0 OUT= SRC=10.0.0.8 PROTO=TCP DPT=80", Cursor: "tail-cursor", Timestamp: fmt.Sprint(when.UnixMicro())}
		b, _ := json.Marshal(entry)
		return string(b), nil
	}}
}
func TestExpiryDrainsLastJournalTailOnce(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	s.ExpiresAt = now
	s.StartsAt = now.Add(-time.Hour)
	s.Ports = []Port{{80, "tcp"}}
	dir := t.TempDir()
	a := &Agent{Config: Config{StateDir: dir, MaxSpoolBatches: 5}, State: State{Policy: &Policy{LearningSessions: []Session{s}}, Rules: []OwnedRule{{s.ID, "public", ObservationRule(s, Port{80, "tcp"}), s.ExpiresAt}}, Coverage: map[string]*Coverage{s.ID: {SessionID: s.ID, StartedAt: s.StartsAt}}, JournalSince: s.StartsAt}, Commands: tailRunner(s, now.Add(-time.Millisecond)), confirmed: true}
	if e := a.LearningTick(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	if e := a.LearningTick(context.Background(), now.Add(6*time.Second)); e != nil {
		t.Fatal(e)
	}
	files, _ := spoolFiles(filepath.Join(dir, "spool"))
	if len(files) != 1 {
		t.Fatalf("last pre-expiry event not spooled exactly once: files=%v", files)
	}
	if len(a.State.Rules) != 0 || len(a.State.PendingDrains) != 0 || a.State.Coverage[s.ID].EndedAt == nil {
		t.Fatal("expired learning cleanup incomplete")
	}
}
func TestShutdownDrainsLastJournalTail(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	s.Ports = []Port{{80, "tcp"}}
	dir := t.TempDir()
	a := &Agent{Config: Config{StateDir: dir, MaxSpoolBatches: 5}, State: State{Policy: &Policy{LearningSessions: []Session{s}}, Rules: []OwnedRule{{s.ID, "public", ObservationRule(s, Port{80, "tcp"}), s.ExpiresAt}}, Coverage: map[string]*Coverage{s.ID: {SessionID: s.ID, StartedAt: s.StartsAt}}, JournalSince: s.StartsAt}, Commands: tailRunner(s, now.Add(-time.Millisecond))}
	if e := a.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
	files, _ := spoolFiles(filepath.Join(dir, "spool"))
	if len(files) != 1 || len(a.State.Rules) != 0 {
		t.Fatalf("shutdown lost final events: files=%v rules=%v", files, a.State.Rules)
	}
}
func TestStoppedAssignmentCutoffExcludesPostStopTail(t *testing.T) {
	now := time.Now().UTC()
	s := sessionAt(now)
	s.Ports = []Port{{80, "tcp"}}
	cut := now.Add(-time.Second)
	stopped := s
	stopped.Status = "stopped"
	stopped.StoppedAt = &cut
	a := &Agent{State: State{Policy: &Policy{LearningSessions: []Session{s}}, Rules: []OwnedRule{{s.ID, "public", ObservationRule(s, Port{80, "tcp"}), s.ExpiresAt}}, Coverage: map[string]*Coverage{s.ID: {SessionID: s.ID, StartedAt: s.StartsAt}}}}
	a.rememberLearningTransition(&Policy{LearningTombstones: []Session{stopped}}, now)
	drain, ok := a.State.PendingDrains[s.ID]
	if !ok || !SessionCutoff(drain).Equal(cut) {
		t.Fatal("controller stop cutoff not retained")
	}
	msg := RulePrefix(s.ID) + " IN=eth0 OUT= SRC=10.0.0.8 PROTO=TCP DPT=80"
	if _, ok := ParseKernelLog(msg, cut.Add(-time.Millisecond), drain); !ok {
		t.Fatal("valid pre-stop tail rejected")
	}
	if _, ok := ParseKernelLog(msg, cut, drain); ok {
		t.Fatal("post-stop tail accepted")
	}
}
