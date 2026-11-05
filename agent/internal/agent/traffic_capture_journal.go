package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const denyJournalPageLimit = 512
const denyJournalByteLimit = 2 * 1024 * 1024

type denyJournalPosition struct {
	Version int       `json:"version"`
	Cursor  string    `json:"cursor"`
	Since   time.Time `json:"since"`
}

type denyJournalPage struct {
	Flows    []capturedFlow
	Coverage CaptureBackendReport
	Gaps     []string
	path     string
	position denyJournalPosition
}

// Commit follows durable spooling. A failed spool leaves the cursor unchanged,
// and stable journal identities let the controller deduplicate a retried page.
func (page *denyJournalPage) Commit() error {
	if page.path == "" {
		return nil
	}
	if page.Coverage.Status != "active" || page.position.Version != 1 || page.position.Since.IsZero() {
		return errors.New("cannot commit an unsuccessful deny-log journal page")
	}
	if _, err := setupPath(filepath.Dir(page.path), true); err != nil {
		return err
	}
	return atomicJSON(page.path, page.position)
}

func validDenyJournalCursor(cursor string) bool {
	if cursor == "" || len(cursor) > 4096 {
		return false
	}
	for _, character := range cursor {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func parseDenyJournalEntry(entry JournalEntry, transport string, rules []captureSidecar, scopes []capturePortScope, local map[netip.Addr]bool, now time.Time) (capturedFlow, bool) {
	if transport != "kernel" || !validDenyJournalCursor(entry.Cursor) {
		return capturedFlow{}, false
	}
	micros, err := strconv.ParseInt(entry.Timestamp, 10, 64)
	if err != nil || micros <= 0 {
		return capturedFlow{}, false
	}
	when := time.UnixMicro(micros).UTC()
	if when.After(now.Add(time.Minute)) {
		return capturedFlow{}, false
	}
	for _, rule := range rules {
		if rule.Backend != "journal" || !strings.HasPrefix(rule.Prefix, "PRTN") || rule.StartedAt.IsZero() || !strings.HasPrefix(entry.Message, rule.Prefix) || when.Before(rule.StartedAt) || !when.Before(rule.ExpiresAt) {
			continue
		}
		fields := map[string]string{}
		for _, field := range strings.Fields(strings.TrimPrefix(entry.Message, rule.Prefix)) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			if _, duplicate := fields[key]; duplicate {
				return capturedFlow{}, false
			}
			fields[key] = value
		}
		out, hasOut := fields["OUT"]
		if fields["IN"] == "" || !hasOut || out != "" {
			return capturedFlow{}, false
		}
		source, err := netip.ParseAddr(fields["SRC"])
		if err != nil || source.Zone() != "" || source.Is4In6() || source.IsUnspecified() || source.IsMulticast() || captureFamily(source) != rule.Family {
			return capturedFlow{}, false
		}
		destination, err := netip.ParseAddr(fields["DST"])
		if err != nil || destination.Zone() != "" || destination.Is4In6() || captureFamily(destination) != rule.Family || !local[destination] {
			return capturedFlow{}, false
		}
		port, err := strconv.Atoi(fields["DPT"])
		if err != nil || port != rule.Port.Port || strings.ToLower(fields["PROTO"]) != rule.Port.Protocol {
			return capturedFlow{}, false
		}
		for _, scope := range scopes {
			if !scope.AllowDenyLogs || scope.Kind != captureDenied || scope.Port != rule.Port || when.Before(scope.StartsAt) || !when.Before(scope.ExpiresAt) {
				continue
			}
			return capturedFlow{
				Flow:          Flow{EventID: shaText("prthak-deny-journal-v1\x00" + entry.Cursor), CaptureKind: captureDeniedLog, CaptureBackend: "journal", CountUnit: "log_records", AddressFamily: rule.Family, SourceIP: source.String(), Port: port, Protocol: rule.Port.Protocol, Verdict: "denied", Count: 1, FirstSeen: when, LastSeen: when},
				DestinationIP: destination.String(), ReceivedAt: now, RulePrefix: rule.Prefix,
			}, true
		}
	}
	return capturedFlow{}, false
}

// collectDenyJournal reads only currently owned compatibility sidecars. Kernel
// records remain sampled log observations and never enter packet verification.
func (a *Agent) collectDenyJournal(ctx context.Context, scopes []capturePortScope, now time.Time) (*denyJournalPage, error) {
	page := &denyJournalPage{Coverage: CaptureBackendReport{Backend: "journal", Status: "off"}}
	state, err := readCaptureSidecars(a.Config.StateDir)
	if err != nil {
		page.Coverage.Status, page.Coverage.Error = "error", err.Error()
		return page, err
	}
	rules := []captureSidecar{}
	for _, rule := range state.Rules {
		if rule.Backend != "journal" || !strings.HasPrefix(rule.Prefix, "PRTN") || rule.StartedAt.IsZero() || !rule.StartedAt.Before(rule.ExpiresAt) || rule.StartedAt.After(now.Add(time.Minute)) {
			continue
		}
		for _, scope := range scopes {
			if scope.AllowDenyLogs && scope.Kind == captureDenied && scope.Port == rule.Port && scope.StartsAt.Before(rule.ExpiresAt) && rule.StartedAt.Before(scope.ExpiresAt) {
				rules = append(rules, rule)
				break
			}
		}
	}
	if len(rules) == 0 {
		return page, nil
	}
	page.Coverage.Status = "active"
	page.Gaps = []string{"Deny logs are sampled and rate limited; kernel/journal suppression or rotation can omit records. Counts are log records."}
	for _, rule := range rules {
		page.Coverage.IPv4 = page.Coverage.IPv4 || rule.Family == "ipv4"
		page.Coverage.IPv6 = page.Coverage.IPv6 || rule.Family == "ipv6"
	}
	page.path = filepath.Join(a.Config.StateDir, "traffic-capture", "deny-journal.json")
	position := denyJournalPosition{Version: 1, Since: now}
	for _, rule := range rules {
		if rule.StartedAt.Before(position.Since) {
			position.Since = rule.StartedAt
		}
	}
	data, err := readPrivateSetupBound(page.path, 8192)
	if err == nil {
		var saved denyJournalPosition
		if json.Unmarshal(data, &saved) != nil || saved.Version != 1 || saved.Since.IsZero() || saved.Since.After(now.Add(time.Minute)) || saved.Cursor != "" && !validDenyJournalCursor(saved.Cursor) {
			err = errors.New("invalid private deny-log journal position")
		} else {
			position = saved
		}
	} else if _, statErr := os.Lstat(page.path); os.IsNotExist(statErr) {
		err = nil
	}
	if err != nil {
		page.Coverage.Status, page.Coverage.Error = "error", err.Error()
		return page, err
	}
	read := func(cursor string) (string, error) {
		args := []string{"-k", "-o", "json", "--no-pager", "-n", strconv.Itoa(denyJournalPageLimit), "--output-fields=MESSAGE,__CURSOR,__REALTIME_TIMESTAMP,_TRANSPORT"}
		if cursor != "" {
			args = append(args, "--after-cursor="+cursor)
		} else {
			args = append(args, "--since="+position.Since.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		return a.Commands.Run(ctx, "journalctl", args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	text, err := read(position.Cursor)
	if err != nil && position.Cursor != "" && strings.Contains(strings.ToLower(text+err.Error()), "cursor") {
		position.Cursor = ""
		position.Since = rules[0].StartedAt
		for _, rule := range rules[1:] {
			if rule.StartedAt.Before(position.Since) {
				position.Since = rule.StartedAt
			}
		}
		page.Gaps = append(page.Gaps, "Deny-log journal cursor was unavailable; resumed within the current rule window. Older records may be missing.")
		text, err = read("")
	}
	if err != nil || len(text) > denyJournalByteLimit {
		if err == nil {
			err = errors.New("deny-log journal output exceeds its byte bound")
		}
		err = fmt.Errorf("deny-log kernel journal read: %w", err)
		page.Coverage.Status, page.Coverage.Error = "error", err.Error()
		return page, err
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		page.Coverage.Status, page.Coverage.Error = "error", err.Error()
		return page, err
	}
	local := map[netip.Addr]bool{}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	lines := 0
	seen := map[string]bool{}
	for scanner.Scan() {
		lines++
		if lines > denyJournalPageLimit {
			err := errors.New("deny-log journal page exceeds its record bound")
			page.Coverage.Status, page.Coverage.Error = "error", err.Error()
			page.Flows = nil
			return page, err
		}
		var record struct {
			Message   json.RawMessage `json:"MESSAGE"`
			Cursor    string          `json:"__CURSOR"`
			Timestamp string          `json:"__REALTIME_TIMESTAMP"`
			Transport string          `json:"_TRANSPORT"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil || !validDenyJournalCursor(record.Cursor) {
			err := errors.New("deny-log journal page contains an invalid record")
			page.Coverage.Status, page.Coverage.Error = "error", err.Error()
			page.Flows = nil
			return page, err
		}
		position.Cursor = record.Cursor
		var message string
		if json.Unmarshal(record.Message, &message) != nil {
			// Journal JSON represents binary or repeated field values as
			// arrays. Such unrelated kernel records carry no owned log prefix.
			continue
		}
		entry := JournalEntry{Message: message, Cursor: record.Cursor, Timestamp: record.Timestamp}
		flow, ok := parseDenyJournalEntry(entry, record.Transport, rules, scopes, local, now)
		if ok && !seen[flow.EventID] {
			page.Flows = append(page.Flows, flow)
			seen[flow.EventID] = true
		}
	}
	if err := scanner.Err(); err != nil {
		page.Coverage.Status, page.Coverage.Error = "error", err.Error()
		page.Flows = nil
		return page, err
	}
	if lines == denyJournalPageLimit {
		page.Gaps = append(page.Gaps, "Deny-log journal page reached its record bound; older records may be missing.")
	}
	page.position = position
	return page, nil
}
