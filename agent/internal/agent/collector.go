package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type JournalEntry struct {
	Message   string `json:"MESSAGE"`
	Cursor    string `json:"__CURSOR"`
	Timestamp string `json:"__REALTIME_TIMESTAMP"`
}
type BatchLoss struct {
	SessionID string
	Count     int
	Reason    string
}
type DiscardedBatchError struct {
	SessionID string // first affected session; retained for callers of the initial agent API
	Count     int    // total observed events dropped across all sessions
	Reason    string
	Losses    []BatchLoss
	Retryable error
}

func (e *DiscardedBatchError) Error() string {
	msg := fmt.Sprintf("quarantined/discarded %d undeliverable observed events across %d batch/session diagnostics: %s", e.Count, len(e.Losses), e.Reason)
	if e.Retryable != nil {
		msg += "; remaining delivery retryable: " + e.Retryable.Error()
	}
	return msg
}
func (e *DiscardedBatchError) Unwrap() error { return e.Retryable }
func batchEventCount(batch Batch) int {
	n := 0
	for _, f := range batch.Events {
		if f.Count > 0 {
			n += f.Count
		} else {
			n++
		}
	}
	return n
}
func quarantineBatch(path string) error {
	dir := filepath.Join(filepath.Dir(path), "quarantine")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	// Bound diagnostic disk usage: keep only the newest20 rejected payloads.
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	type retained struct {
		name string
		when time.Time
	}
	files := []retained{}
	for _, entry := range entries {
		if !entry.IsDir() {
			info, e := entry.Info()
			if e != nil {
				return e
			}
			files = append(files, retained{entry.Name(), info.ModTime()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].when.Before(files[j].when) })
	for len(files) >= 20 {
		if e = os.Remove(filepath.Join(dir, files[0].name)); e != nil {
			return e
		}
		files = files[1:]
	}
	return os.Rename(path, filepath.Join(dir, filepath.Base(path)+".rejected"))
}
func ParseKernelLog(message string, when time.Time, s Session) (Flow, bool) {
	prefixPosition := strings.Index(message, RulePrefix(s.ID))
	if prefixPosition < 0 {
		return Flow{}, false
	}
	message = message[prefixPosition+len(RulePrefix(s.ID)):]
	if when.Before(s.StartsAt) || !when.Before(SessionCutoff(s)) {
		return Flow{}, false
	}
	fields := map[string]string{}
	for _, f := range strings.Fields(message) {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) == 2 {
			fields[kv[0]] = kv[1]
		}
	}
	if fields["IN"] == "" || fields["OUT"] != "" {
		return Flow{}, false
	}
	if _, present := fields["OUT"]; !present {
		return Flow{}, false
	}
	src, e := netip.ParseAddr(fields["SRC"])
	if e != nil {
		return Flow{}, false
	}
	port, e := strconv.Atoi(fields["DPT"])
	if e != nil {
		return Flow{}, false
	}
	proto := strings.ToLower(fields["PROTO"])
	for _, p := range s.Ports {
		if p.Port == port && p.Protocol == proto {
			return Flow{src.String(), port, proto, "observed", 1, when, when}, true
		}
	}
	return Flow{}, false
}
func batchID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return fmt.Sprintf("local-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
func spoolFiles(dir string) ([]string, error) {
	entries, e := os.ReadDir(dir)
	if os.IsNotExist(e) {
		return []string{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, ent := range entries {
		if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".json") {
			out = append(out, filepath.Join(dir, ent.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}
func SpoolBatch(dir string, max int, b Batch) error {
	if len(b.Events) == 0 {
		return nil
	}
	files, e := spoolFiles(dir)
	if e != nil {
		return e
	}
	if len(files) >= max {
		return errors.New("traffic spool full; observation events dropped")
	}
	return atomicJSON(filepath.Join(dir, b.BatchID+".json"), b)
}
func FlushSpool(ctx context.Context, c *Client, dir string, now time.Time) (int, error) {
	files, e := spoolFiles(dir)
	if e != nil {
		return 0, e
	}
	sent := 0
	losses := []BatchLoss{}
	finish := func(retry error) (int, error) {
		if len(losses) == 0 {
			return sent, retry
		}
		dropped := &DiscardedBatchError{SessionID: losses[0].SessionID, Reason: losses[0].Reason, Losses: losses, Retryable: retry}
		for _, loss := range losses {
			dropped.Count += loss.Count
		}
		return sent, dropped
	}
	for _, path := range files {
		data, e := os.ReadFile(path)
		if e != nil {
			return finish(e)
		}
		var batch Batch
		if e = json.Unmarshal(data, &batch); e != nil {
			if e = quarantineBatch(path); e != nil {
				return finish(e)
			}
			losses = append(losses, BatchLoss{Reason: "corrupt spool JSON quarantined (" + filepath.Base(path) + "); session and event count unknown"})
			continue
		}
		count := batchEventCount(batch)
		tooOld := len(batch.Events) > 0 && now.Sub(batch.Events[len(batch.Events)-1].LastSeen) > 24*time.Hour
		if tooOld {
			if e = os.Remove(path); e != nil {
				return finish(e)
			}
			losses = append(losses, BatchLoss{batch.SessionID, count, "older than local24h delivery retention"})
			continue
		}
		if e = c.Flows(ctx, batch); e != nil {
			var status *HTTPError
			if errors.As(e, &status) && (status.Status == 400 || status.Status == 403 || status.Status == 404 || status.Status == 410) {
				if e = quarantineBatch(path); e != nil {
					return finish(e)
				}
				losses = append(losses, BatchLoss{batch.SessionID, count, fmt.Sprintf("permanent controller rejection HTTP%d; batch quarantined", status.Status)})
				continue
			}
			return finish(e) // network, rate limiting and server errors retain their payload for retry.
		}
		if e = os.Remove(path); e != nil {
			return finish(e)
		}
		sent += len(batch.Events)
	}
	return finish(nil)
}
func CollectJournal(ctx context.Context, r CommandRunner, state *State, sessions []Session, spoolDir string, maxSpool int, now time.Time) error {
	if len(sessions) == 0 {
		return nil
	}
	args := []string{"-k", "-o", "json", "--no-pager", "-n", "5000"}
	if state.Cursor != "" {
		args = append(args, "--after-cursor="+state.Cursor)
	} else {
		since := state.JournalSince
		if since.IsZero() {
			since = now
		}
		args = append(args, "--since="+since.Format(time.RFC3339Nano))
	}
	text, e := r.Run(ctx, "journalctl", args...)
	if e != nil {
		if strings.Contains(strings.ToLower(text+e.Error()), "cursor") {
			state.Cursor = ""
			state.JournalSince = now
		}
		return fmt.Errorf("kernel journal read: %w", e)
	}
	events := map[string][]Flow{}
	newCursor := state.Cursor
	lines := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var entry JournalEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue
		}
		lines++
		if entry.Cursor != "" {
			newCursor = entry.Cursor
		}
		micro, e := strconv.ParseInt(entry.Timestamp, 10, 64)
		if e != nil {
			continue
		}
		when := time.UnixMicro(micro).UTC()
		for _, s := range sessions {
			if f, ok := ParseKernelLog(entry.Message, when, s); ok {
				events[s.ID] = append(events[s.ID], f)
				rememberLearningEvidence(state, s, f)
			}
		}
	}
	if e = scanner.Err(); e != nil {
		return e
	}
	// Cursor advances only after batches are persisted. A process crash can replay records; batch delivery itself is idempotent.
	var spoolError error
	for session, items := range events {
		for len(items) > 0 {
			n := len(items)
			if n > 2000 {
				n = 2000
			}
			batch := Batch{batchID(), session, items[:n]}
			if e = SpoolBatch(spoolDir, maxSpool, batch); e != nil {
				if cov := state.Coverage[session]; cov != nil {
					cov.DroppedEvents += len(items)
					cov.Error = e.Error()
				}
				spoolError = e
				break
			}
			items = items[n:]
		}
	}
	state.Cursor = newCursor
	if lines >= 5000 {
		for _, s := range sessions {
			if cov := state.Coverage[s.ID]; cov != nil {
				cov.Error = "journal page limit reached; earlier events may be missing"
			}
		}
	}
	return spoolError
}
