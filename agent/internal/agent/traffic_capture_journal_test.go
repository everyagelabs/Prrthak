package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func denyJournalFixture(now time.Time) (captureSidecar, capturePortScope, JournalEntry) {
	rule := captureSidecar{Zone: "public", Family: "ipv4", Port: Port{18080, "tcp"}, Group: 49001, Prefix: "PRTN0123456789abcdef:", Priority: managedCaptureReject, Backend: "journal", StartedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	scope := capturePortScope{Port: rule.Port, Kind: captureDenied, AllowDenyLogs: true, StartsAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(2 * time.Minute)}
	entry := JournalEntry{Message: rule.Prefix + "IN=lo OUT= SRC=192.0.2.44 DST=127.0.0.1 PROTO=TCP SPT=44000 DPT=18080", Cursor: "s=cursor1;i=1;b=boot;m=123;t=456;x=abc", Timestamp: strconv.FormatInt(now.Add(-time.Second).UnixMicro(), 10)}
	return rule, scope, entry
}

func TestDenyJournalEntryRequiresExactOwnedScopeAndLocalDestination(t *testing.T) {
	now := time.Now().UTC()
	rule, scope, entry := denyJournalFixture(now)
	local := map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true}
	flow, ok := parseDenyJournalEntry(entry, "kernel", []captureSidecar{rule}, []capturePortScope{scope}, local, now)
	if !ok || flow.CaptureKind != captureDeniedLog || flow.CaptureBackend != "journal" || flow.CountUnit != "log_records" || flow.Verdict != "denied" || flow.Count != 1 || flow.SourceIP != "192.0.2.44" || flow.DestinationIP != "127.0.0.1" || flow.VerificationOnly {
		t.Fatal("scoped deny log lost its evidence identity", flow, ok)
	}
	for _, change := range []struct {
		name      string
		modify    func(*JournalEntry, *captureSidecar, *capturePortScope)
		transport string
	}{
		{"untrusted journal transport", func(*JournalEntry, *captureSidecar, *capturePortScope) {}, "syslog"},
		{"missing journal cursor", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) { e.Cursor = "" }, "kernel"},
		{"invalid journal cursor", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) { e.Cursor = "cursor\n--bad" }, "kernel"},
		{"future timestamp", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) {
			e.Timestamp = strconv.FormatInt(now.Add(2*time.Minute).UnixMicro(), 10)
		}, "kernel"},
		{"old instrumentation", func(_ *JournalEntry, r *captureSidecar, _ *capturePortScope) { r.StartedAt = now }, "kernel"},
		{"after rule expiry", func(_ *JournalEntry, r *captureSidecar, _ *capturePortScope) { r.ExpiresAt = now.Add(-2 * time.Second) }, "kernel"},
		{"packet verification prefix", func(e *JournalEntry, r *captureSidecar, _ *capturePortScope) {
			r.Prefix = "PRTV0123456789abcdef:"
			e.Message = strings.ReplaceAll(e.Message, "PRTN", "PRTV")
		}, "kernel"},
		{"native backend", func(_ *JournalEntry, r *captureSidecar, _ *capturePortScope) { r.Backend = "nflog" }, "kernel"},
		{"unsigned compatibility", func(_ *JournalEntry, _ *captureSidecar, s *capturePortScope) { s.AllowDenyLogs = false }, "kernel"},
		{"accepted only scope", func(_ *JournalEntry, _ *captureSidecar, s *capturePortScope) { s.Kind = captureAccepted }, "kernel"},
		{"wrong signed port", func(_ *JournalEntry, _ *captureSidecar, s *capturePortScope) { s.Port.Port = 22 }, "kernel"},
		{"expired signed scope", func(_ *JournalEntry, _ *captureSidecar, s *capturePortScope) { s.ExpiresAt = now.Add(-2 * time.Second) }, "kernel"},
		{"nonlocal destination", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) {
			e.Message = strings.ReplaceAll(e.Message, "127.0.0.1", "198.51.100.1")
		}, "kernel"},
		{"forwarded record", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) {
			e.Message = strings.ReplaceAll(e.Message, "OUT= ", "OUT=eth1 ")
		}, "kernel"},
		{"missing input", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) {
			e.Message = strings.ReplaceAll(e.Message, "IN=lo ", "")
		}, "kernel"},
		{"missing output marker", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) {
			e.Message = strings.ReplaceAll(e.Message, "OUT= ", "")
		}, "kernel"},
		{"embedded prefix", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) { e.Message = "user message " + e.Message }, "kernel"},
		{"wrong actual port", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) {
			e.Message = strings.ReplaceAll(e.Message, "DPT=18080", "DPT=22")
		}, "kernel"},
		{"wrong actual protocol", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) {
			e.Message = strings.ReplaceAll(e.Message, "PROTO=TCP", "PROTO=UDP")
		}, "kernel"},
		{"repeated source", func(e *JournalEntry, _ *captureSidecar, _ *capturePortScope) { e.Message += " SRC=192.0.2.55" }, "kernel"},
		{"wrong address family", func(_ *JournalEntry, r *captureSidecar, _ *capturePortScope) { r.Family = "ipv6" }, "kernel"},
	} {
		t.Run(change.name, func(t *testing.T) {
			changedEntry, changedRule, changedScope := entry, rule, scope
			change.modify(&changedEntry, &changedRule, &changedScope)
			if _, accepted := parseDenyJournalEntry(changedEntry, change.transport, []captureSidecar{changedRule}, []capturePortScope{changedScope}, local, now); accepted {
				t.Fatal("unreviewed or ambiguous log became denied evidence")
			}
		})
	}
}

func TestDenyJournalUDPAllowsRepeatedLengthButRejectsAmbiguousIdentity(t *testing.T) {
	now := time.Date(2026, 11, 5, 6, 40, 0, 0, time.UTC)
	rule, scope, entry := denyJournalFixture(now)
	rule.Port.Protocol, scope.Port.Protocol = "udp", "udp"
	entry.Message = rule.Prefix + "IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.0.2.44 DST=127.0.0.1 LEN=45 TOS=0x00 PREC=0x00 TTL=64 ID=47280 DF PROTO=UDP SPT=41374 DPT=18080 LEN=25"
	local := map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true}
	flow, ok := parseDenyJournalEntry(entry, "kernel", []captureSidecar{rule}, []capturePortScope{scope}, local, now)
	if !ok || flow.Protocol != "udp" || flow.CaptureKind != captureDeniedLog || flow.CountUnit != "log_records" || flow.Count != 1 {
		t.Fatalf("normal UDP IP/transport length fields lost sampled evidence: %+v, %v", flow, ok)
	}
	for _, repeated := range []string{"IN=eth1", "OUT=eth1", "SRC=192.0.2.44", "DST=127.0.0.1", "PROTO=UDP", "SPT=41374", "DPT=18080"} {
		changed := entry
		changed.Message += " " + repeated
		if _, ok := parseDenyJournalEntry(changed, "kernel", []captureSidecar{rule}, []capturePortScope{scope}, local, now); ok {
			t.Fatalf("repeated identity/routing field accepted: %s", repeated)
		}
	}
}

func TestDenyJournalNativeIPv6AndStableReplayIdentity(t *testing.T) {
	now := time.Now().UTC()
	rule, scope, entry := denyJournalFixture(now)
	rule.Family = "ipv6"
	entry.Message = rule.Prefix + "IN=lo OUT= SRC=2001:db8::44 DST=::1 PROTO=TCP SPT=44000 DPT=18080"
	local := map[netip.Addr]bool{netip.MustParseAddr("::1"): true}
	first, ok := parseDenyJournalEntry(entry, "kernel", []captureSidecar{rule}, []capturePortScope{scope}, local, now)
	if !ok || first.AddressFamily != "ipv6" {
		t.Fatal("native IPv6 deny log rejected")
	}
	retry, ok := parseDenyJournalEntry(entry, "kernel", []captureSidecar{rule}, []capturePortScope{scope}, local, now.Add(time.Second))
	if !ok || retry.EventID != first.EventID {
		t.Fatal("journal replay changed event identity")
	}
	entry.Cursor += "1"
	next, ok := parseDenyJournalEntry(entry, "kernel", []captureSidecar{rule}, []capturePortScope{scope}, local, now)
	if !ok || next.EventID == first.EventID {
		t.Fatal("different journal records were merged")
	}
	entry.Message = strings.ReplaceAll(entry.Message, "2001:db8::44", "::ffff:192.0.2.44")
	if _, ok := parseDenyJournalEntry(entry, "kernel", []captureSidecar{rule}, []capturePortScope{scope}, local, now); ok {
		t.Fatal("mapped IPv6 address admitted as native IPv6")
	}
}

type denyJournalRunner struct {
	outputs []string
	errors  []error
	args    [][]string
}

func (runner *denyJournalRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != "journalctl" {
		return "", errors.New("unexpected compatibility collector command")
	}
	runner.args = append(runner.args, append([]string{}, args...))
	index := len(runner.args) - 1
	var err error
	if index < len(runner.errors) {
		err = runner.errors[index]
	}
	if index >= len(runner.outputs) {
		return "", err
	}
	return runner.outputs[index], err
}

func denyJournalTestAgent(t *testing.T, now time.Time, output string) (*Agent, captureSidecar, capturePortScope, *denyJournalRunner) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rule, scope, _ := denyJournalFixture(now)
	if err := atomicJSON(captureSidecarPath(directory), captureSidecarState{Version: 1, Rules: []captureSidecar{rule}}); err != nil {
		t.Fatal(err)
	}
	runner := &denyJournalRunner{outputs: []string{output}}
	return &Agent{Config: Config{StateDir: directory}, Commands: runner}, rule, scope, runner
}

func denyJournalJSON(entry JournalEntry) string {
	value := map[string]string{"MESSAGE": entry.Message, "__CURSOR": entry.Cursor, "__REALTIME_TIMESTAMP": entry.Timestamp, "_TRANSPORT": "kernel"}
	raw, _ := json.Marshal(value)
	return string(raw) + "\n"
}

func TestDenyJournalCursorCommitsOnlyAfterDurableSpoolAndHandlesRotation(t *testing.T) {
	now := time.Now().UTC()
	_, _, entry := denyJournalFixture(now)
	text := denyJournalJSON(entry)
	a, _, scope, runner := denyJournalTestAgent(t, now, text+text)
	page, err := a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now)
	if err != nil || len(page.Flows) != 1 || page.Coverage.Status != "active" || page.Coverage.LostEvents != nil || !page.Coverage.IPv4 || len(page.Gaps) == 0 {
		t.Fatal("bounded sampled evidence or honest coverage lost", page, err)
	}
	if _, err := os.Stat(page.path); !os.IsNotExist(err) {
		t.Fatal("read advanced cursor before spooling")
	}
	if err := page.Commit(); err != nil {
		t.Fatal(err)
	}
	saved, err := readPrivateSetupBound(page.path, 8192)
	if err != nil || !strings.Contains(string(saved), entry.Cursor) {
		t.Fatal("journal cursor was not durably committed", err)
	}
	runner.outputs = append(runner.outputs, "Failed to seek to cursor", text)
	runner.errors = []error{nil, errors.New("invalid cursor"), nil}
	replayed, err := a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now)
	if err != nil || len(replayed.Flows) != 1 || replayed.Flows[0].EventID != page.Flows[0].EventID || len(replayed.Gaps) < 2 {
		t.Fatal("rotation recovery lost stable identity or gap", replayed, err)
	}
	if !strings.Contains(strings.Join(runner.args[1], " "), "--after-cursor="+entry.Cursor) || strings.Contains(strings.Join(runner.args[2], " "), "--after-cursor=") {
		t.Fatal("rotation did not retry within the active rule window", runner.args)
	}
}

func TestDenyJournalDrainsFinalAuthorizedRecordsAfterLeaseExpires(t *testing.T) {
	now := time.Now().UTC()
	_, _, entry := denyJournalFixture(now)
	a, rule, scope, _ := denyJournalTestAgent(t, now, denyJournalJSON(entry))
	rule.ExpiresAt = now
	scope.ExpiresAt = now
	if err := atomicJSON(captureSidecarPath(a.Config.StateDir), captureSidecarState{Version: 1, Rules: []captureSidecar{rule}}); err != nil {
		t.Fatal(err)
	}
	page, err := a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now.Add(time.Second))
	if err != nil || len(page.Flows) != 1 {
		t.Fatal("final authorized log lost at collection expiry", page, err)
	}
}

func TestDenyJournalBinaryKernelMessageDoesNotDiscardOwnedObservations(t *testing.T) {
	now := time.Now().UTC()
	_, _, first := denyJournalFixture(now)
	last := first
	last.Cursor = "s=cursor1;i=3;b=boot;m=125;t=458;x=abe"
	last.Message = strings.ReplaceAll(last.Message, "192.0.2.44", "192.0.2.55")
	binary, err := json.Marshal(map[string]any{
		"MESSAGE":              []int{255, 254},
		"__CURSOR":             "s=cursor1;i=2;b=boot;m=124;t=457;x=abd",
		"__REALTIME_TIMESTAMP": first.Timestamp,
		"_TRANSPORT":           "kernel",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := denyJournalJSON(first) + string(binary) + "\n" + denyJournalJSON(last)
	a, _, scope, runner := denyJournalTestAgent(t, now, text)
	page, err := a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now)
	if err != nil || page.Coverage.Status != "active" || len(page.Flows) != 2 {
		t.Fatal("unrelated binary message discarded valid deny observations", page, err)
	}
	for index, entry := range []JournalEntry{first, last} {
		flow := page.Flows[index]
		if flow.EventID != shaText("prthak-deny-journal-v1\x00"+entry.Cursor) || flow.CaptureKind != captureDeniedLog || flow.CountUnit != "log_records" || flow.CaptureBackend != "journal" || flow.VerificationOnly {
			t.Fatal("binary record changed scoped log evidence", flow)
		}
	}
	if err := page.Commit(); err != nil {
		t.Fatal(err)
	}
	saved, err := readPrivateSetupBound(page.path, 8192)
	if err != nil || !strings.Contains(string(saved), last.Cursor) {
		t.Fatal("cursor did not advance past the binary message", err)
	}
	runner.outputs = append(runner.outputs, text)
	replayed, err := a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now.Add(time.Second))
	if err != nil || len(replayed.Flows) != 2 || replayed.Flows[0].EventID != page.Flows[0].EventID || replayed.Flows[1].EventID != page.Flows[1].EventID {
		t.Fatal("replayed page changed stable log identities", replayed, err)
	}
}

func TestDenyJournalBoundsPagesAndNeverRunsWithoutCompatibilityScope(t *testing.T) {
	now := time.Now().UTC()
	_, _, entry := denyJournalFixture(now)
	text := denyJournalJSON(entry)
	a, _, scope, runner := denyJournalTestAgent(t, now, text)
	scope.AllowDenyLogs = false
	page, err := a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now)
	if err != nil || len(runner.args) != 0 || len(page.Flows) != 0 || page.Coverage.Status != "off" {
		t.Fatal("journal read ran without signed compatibility scope")
	}
	scope.AllowDenyLogs = true
	runner.outputs[0] = strings.Repeat(text, denyJournalPageLimit)
	page, err = a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now)
	if err != nil || len(page.Flows) != 1 || !strings.Contains(strings.Join(page.Gaps, " "), "record bound") {
		t.Fatal("record limit did not disclose omissions", err)
	}
	runner.outputs = append(runner.outputs, strings.Repeat("x", denyJournalByteLimit+1))
	page, err = a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now)
	if err == nil || page.Coverage.Status != "error" || page.Commit() == nil {
		t.Fatal("oversized/unsuccessful page could advance cursor")
	}
	if !strings.Contains(strings.Join(runner.args[0], " "), fmt.Sprintf("-n %d", denyJournalPageLimit)) {
		t.Fatal("journal command lacks native page bound", runner.args[0])
	}
	if !strings.Contains(strings.Join(runner.args[0], " "), "--since="+now.Add(-time.Minute).UTC().Format("2006-01-02 15:04:05 UTC")) {
		t.Fatal("journal start time is incompatible with systemd 239", runner.args[0])
	}
	for _, invalid := range []string{strings.Repeat(text, denyJournalPageLimit+1), text + "{invalid JSON}\n", text + strings.Repeat("x", 65*1024)} {
		runner.outputs = append(runner.outputs, invalid)
		page, err = a.collectDenyJournal(context.Background(), []capturePortScope{scope}, now)
		if err == nil || page.Coverage.Status != "error" || len(page.Flows) != 0 || page.Commit() == nil {
			t.Fatal("invalid page could publish partial records or advance cursor", err)
		}
	}
}
