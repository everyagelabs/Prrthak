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

func sparseTrafficFile(t *testing.T, path string, size int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(file.Truncate(size), file.Close()); err != nil {
		t.Fatal(err)
	}
}

func TestLearningSpoolByteQuotaRetainsReplayAndDiscardsOversizedFiles(t *testing.T) {
	dir, now := t.TempDir(), time.Now().UTC()
	batch := Batch{BatchID: "01-pending", SessionID: "session", Events: []Flow{{LastSeen: now, Count: 1}}}
	if err := SpoolBatch(dir, 20, batch); err != nil {
		t.Fatal(err)
	}
	sparseTrafficFile(t, filepath.Join(dir, "00-oversized.json"), maxLearningSpoolBytes)
	rejected := filepath.Join(dir, "quarantine")
	if err := os.Mkdir(rejected, 0700); err != nil {
		t.Fatal(err)
	}
	sparseTrafficFile(t, filepath.Join(rejected, "legacy.json.rejected"), maxLearningBatchBytes+1)
	if err := SpoolBatch(dir, 20, batch); err != nil {
		t.Fatalf("exact replay must remain valid while full: %v", err)
	}
	newBatch := batch
	newBatch.BatchID = "02-new"
	if err := SpoolBatch(dir, 20, newBatch); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("byte quota did not report loss: %v", err)
	}
	client, err := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})
	sent, err := FlushSpool(context.Background(), client, dir, now)
	var dropped *DiscardedBatchError
	if sent != 1 || !errors.As(err, &dropped) || len(dropped.Losses) != 1 {
		t.Fatalf("expected valid replay and one oversized discard: sent=%d err=%v", sent, err)
	}
	files, err := os.ReadDir(rejected)
	if err != nil || len(files) != 0 {
		t.Fatalf("oversized files must not remain in quarantine: files=%v err=%v", files, err)
	}
}

func TestHitSpoolByteQuotaKeepsReplayAndUsesControllerUploadGrace(t *testing.T) {
	h := newHitLifecycleHarness(t, 20, time.Now().UTC())
	lease := h.assignment("quota")
	first := hitLifecycleBatch(t, lease, "first", "192.0.2.1", h.base.Add(time.Second))
	second := hitLifecycleBatch(t, lease, "second", "192.0.2.2", h.base.Add(time.Second))
	if err := h.monitor.spool(first); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(h.monitor.dir, "spool")
	sparseTrafficFile(t, filepath.Join(dir, "00-oversized.json"), maxHitSpoolBytes)
	if err := h.monitor.spool(first); err != nil {
		t.Fatalf("exact replay must remain valid while full: %v", err)
	}
	if err := h.monitor.spool(second); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("byte quota did not preserve retry cursor: %v", err)
	}
	var received []HitBatch
	status := 200
	client := hitLifecycleClient(t, lease.ServerID, &status, &received)
	sent, err := h.monitor.Flush(context.Background(), client, lease.ExpiresAt.Add(hitUploadGrace))
	if sent != 1 || err == nil || len(received) != 1 {
		t.Fatalf("inclusive grace boundary or oversized cleanup failed: sent=%d err=%v received=%d", sent, err, len(received))
	}
	if err := h.monitor.spool(second); err != nil {
		t.Fatal(err)
	}
	sent, err = h.monitor.Flush(context.Background(), client, lease.ExpiresAt.Add(hitUploadGrace+time.Second))
	if sent != 0 || err == nil || len(received) != 1 || h.monitor.coverage.DroppedEvents != 2 || h.monitor.coverage.PendingBatches != 0 {
		t.Fatalf("expired hits must be discarded before uploading: sent=%d err=%v received=%d coverage=%+v", sent, err, len(received), h.monitor.coverage)
	}
}

func TestTrafficFlushGivesBothStreamsADeadlineAndCapsEachCycle(t *testing.T) {
	now := time.Now().UTC()
	h := newHitLifecycleHarness(t, 20, now)
	lease := h.assignment("flush-quota")
	learnDir := filepath.Join(h.dir, "spool")
	for index := range trafficFlushBatchLimit + 1 {
		id := fmt.Sprintf("batch-%d", index)
		hit := hitLifecycleBatch(t, lease, id, "192.0.2.1", now.Add(time.Second))
		if err := h.monitor.spool(hit); err != nil {
			t.Fatal(err)
		}
		batch := Batch{BatchID: id, SessionID: "learning", Events: []Flow{{LastSeen: now, Count: 1}}}
		if err := SpoolBatch(learnDir, 20, batch); err != nil {
			t.Fatal(err)
		}
	}
	oldestID := fmt.Sprintf("batch-%d", trafficFlushBatchLimit)
	oldest := now.Add(-time.Minute)
	if err := os.Chtimes(filepath.Join(learnDir, oldestID+".json"), oldest, oldest); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{ControllerURL: "http://127.0.0.1", RequestTimeoutSeconds: 15}, true)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]int{}
	failHit := true
	client.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > trafficUploadBudget || r.Context().Err() != nil {
			t.Fatalf("missing usable per-stream deadline for %s", r.URL.Path)
		}
		paths[r.URL.Path]++
		if failHit && strings.HasSuffix(r.URL.Path, "/hits") {
			return nil, context.DeadlineExceeded
		}
		if r.URL.Path == "/api/v1/agent/flows" && paths[r.URL.Path] == 1 {
			var batch Batch
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil || batch.BatchID != oldestID {
				t.Fatalf("oldest queued batch was not uploaded first: batch=%s err=%v", batch.BatchID, err)
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})
	a := Agent{Config: Config{StateDir: h.dir}, Client: client, hitMonitor: h.monitor}
	a.flushTrafficSpools(context.Background(), now.Add(2*time.Second))
	if paths["/api/v1/agent/hits"] != 1 || paths["/api/v1/agent/flows"] != trafficFlushBatchLimit ||
		h.monitor.coverage.PendingBatches != trafficFlushBatchLimit+1 {
		t.Fatalf("failed hit upload blocked or consumed learning budget: paths=%v pending hits=%d", paths, h.monitor.coverage.PendingBatches)
	}
	failHit = false
	a.flushTrafficSpools(context.Background(), now.Add(3*time.Second))
	if paths["/api/v1/agent/hits"] != trafficFlushBatchLimit+1 ||
		paths["/api/v1/agent/flows"] != trafficFlushBatchLimit+1 || h.monitor.coverage.PendingBatches != 1 {
		t.Fatalf("a flush must retain bounded overflow for the next cycle: paths=%v pending hits=%d", paths, h.monitor.coverage.PendingBatches)
	}
}
