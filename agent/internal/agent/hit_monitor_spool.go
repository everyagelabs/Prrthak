package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

const (
	maxHitSpoolBytes = 16 * 1024 * 1024
	hitUploadGrace   = 5 * time.Minute // controller/hit_monitoring.py UPLOAD_GRACE_SECONDS
)

func hitBatchDigest(batch HitBatch) string {
	batch.BatchID = ""
	raw, _ := json.Marshal(batch)
	return shaText("prthak-hit-batch-v1\x00" + string(raw))
}
func validateHitBatch(batch HitBatch) error {
	if !validDigest(batch.BatchID) || batch.BatchID != hitBatchDigest(batch) || !hitID.MatchString(batch.MonitorID) || !batch.LeaseExpiresAt.After(batch.LeaseStartsAt) || batch.LeaseExpiresAt.Sub(batch.LeaseStartsAt) > hitLeaseLifetime || len(batch.Events) < 1 || len(batch.Events) > maxHitEvents {
		return errors.New("invalid private hit batch")
	}
	seen := map[string]bool{}
	for _, event := range batch.Events {
		address, err := netip.ParseAddr(event.SourceIP)
		legacy := event.CaptureKind == "" && event.CaptureBackend == "" && event.CountUnit == "" && event.AddressFamily == "" && event.Verdict == "observed"
		if err != nil || address.Zone() != "" || !validDigest(event.EventID) || seen[event.EventID] || event.Port < 1 || event.Port > 65535 || (event.Protocol != "tcp" && event.Protocol != "udp") || (!legacy && !validTypedCapture(event.Flow, event.EventID)) || event.Count != 1 || !event.FirstSeen.Equal(event.LastSeen) || event.FirstSeen.Before(batch.LeaseStartsAt) || !event.LastSeen.Before(batch.LeaseExpiresAt) {
			return errors.New("invalid private hit event")
		}
		seen[event.EventID] = true
	}
	return nil
}
func (m *HitMonitor) spool(batch HitBatch) error {
	if err := validateHitBatch(batch); err != nil {
		return err
	}
	raw, err := json.Marshal(batch)
	if err != nil || len(raw) > maxHitBatchBytes {
		return errors.New("hit batch exceeds byte limit")
	}
	dir, err := trafficSpoolDir(filepath.Join(m.dir, "spool"), true)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, batch.BatchID+".json")
	if _, err = os.Lstat(path); err == nil {
		stored, err := readPrivateSetupBound(path, maxHitBatchBytes)
		if err != nil {
			return err
		}
		var old HitBatch
		if json.Unmarshal(stored, &old) != nil || validateHitBatch(old) != nil || hitBatchDigest(old) != hitBatchDigest(batch) {
			return errors.New("hit batch ID was reused with different content")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	allowed, err := spoolCanAppend(dir, m.maxSpool, maxHitSpoolBytes, len(raw))
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("hit spool full; durable cursor retained for retry")
	}
	return atomicPrivateFile(path, raw)
}
func (client *Client) Hits(ctx context.Context, batch HitBatch) error {
	if err := validateHitBatch(batch); err != nil {
		return err
	}
	response, err := client.request(ctx, "POST", "/api/v1/agent/hits", batch, "")
	if err != nil {
		return err
	}
	return decodeResponse(response, &map[string]any{})
}
func (m *HitMonitor) Flush(ctx context.Context, client *Client, now time.Time) (int, error) {
	dir, err := trafficSpoolDir(filepath.Join(m.dir, "spool"), false)
	if os.IsNotExist(err) {
		m.coverage.PendingBatches = 0
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	files, err := trafficSpoolFiles(dir)
	if err != nil {
		return 0, err
	}
	m.coverage.PendingBatches = len(files)
	if m.simulate {
		return 0, nil
	}
	if client == nil {
		return 0, errors.New("hit upload client unavailable")
	}
	if identity := client.identity; identity != nil {
		if certificate := identity.Load(); certificate != nil && certificate.Leaf != nil && m.state.ServerID != "" && certificate.Leaf.Subject.CommonName != m.state.ServerID {
			return 0, errors.New("hit spool belongs to another endpoint identity")
		}
	}
	if err := pruneTrafficQuarantine(filepath.Join(dir, "quarantine"), maxHitBatchBytes, rejectedSpoolLimit); err != nil {
		return 0, err
	}
	sent := 0
	var discarded error
	finish := func(retry error) (int, error) {
		result := errors.Join(discarded, retry, m.save())
		if discarded != nil {
			m.coverage.Status = "degraded"
		}
		if result != nil {
			m.coverage.Error = result.Error()
		}
		return sent, result
	}
	for _, path := range files[:min(len(files), trafficFlushBatchLimit)] {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		raw, readErr := readPrivateSetupBound(path, maxHitBatchBytes)
		var batch HitBatch
		if readErr != nil || json.Unmarshal(raw, &batch) != nil || validateHitBatch(batch) != nil {
			if err = quarantineTrafficBatch(path, maxHitBatchBytes); err != nil {
				return finish(err)
			}
			m.drop(max(1, len(batch.Events)))
			m.coverage.PendingBatches--
			discarded = errors.New("invalid hit spool discarded; observed packets omitted")
			continue
		}
		if now.After(batch.LeaseExpiresAt.Add(hitUploadGrace)) {
			if err = os.Remove(path); err != nil {
				return finish(err)
			}
			m.drop(len(batch.Events))
			m.coverage.PendingBatches--
			discarded = errors.New("expired hit delivery window; observed packets omitted")
			continue
		}
		if err = client.Hits(ctx, batch); err != nil {
			var status *HTTPError
			if errors.As(err, &status) && (status.Status == 400 || status.Status == 403 || status.Status == 404 || status.Status == 409 || status.Status == 410 || status.Status == 422) {
				if err = quarantineTrafficBatch(path, maxHitBatchBytes); err != nil {
					return finish(err)
				}
				m.drop(len(batch.Events))
				m.coverage.PendingBatches--
				discarded = errors.New("hit controller permanently rejected private batch; quarantined")
				continue
			}
			return finish(err)
		}
		if err = os.Remove(path); err != nil {
			return finish(err)
		}
		m.coverage.PendingBatches--
		sent += len(batch.Events)
	}
	return finish(nil)
}
