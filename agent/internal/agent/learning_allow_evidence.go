package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// A crash after a flow batch was fsynced but before state.json was saved must
// not turn that legitimate observation into an unprovable automatic grant.
func (a *Agent) restoreLearningEvidenceFromSpool() error {
	sessions := map[string]Session{}
	if a.State.Policy != nil {
		for _, session := range append(append([]Session{}, a.State.Policy.LearningSessions...), a.State.Policy.LearningTombstones...) {
			sessions[session.ID] = session
		}
	}
	for id, session := range a.State.PendingDrains {
		sessions[id] = session
	}
	dir, e := trafficSpoolDir(filepath.Join(a.Config.StateDir, "spool"), false)
	if os.IsNotExist(e) {
		return a.save()
	}
	if e != nil {
		return e
	}
	files, e := spoolFiles(dir)
	if e != nil {
		return e
	}
	for _, path := range files {
		raw, e := readPrivateSetupBound(path, maxLearningBatchBytes)
		if e != nil {
			continue // FlushSpool discards malformed/unsafe payloads and reports the loss.
		}
		var batch Batch
		if json.Unmarshal(raw, &batch) != nil {
			continue
		}
		session, ok := sessions[batch.SessionID]
		if !ok || session.PolicyAction != "auto_allow" {
			continue
		}
		for _, flow := range batch.Events {
			if flow.FirstSeen.Before(session.StartsAt) || !flow.LastSeen.Before(SessionCutoff(session)) {
				continue
			}
			selected := false
			for _, port := range session.Ports {
				if flow.Port == port.Port && flow.Protocol == port.Protocol {
					selected = true
				}
			}
			if selected {
				rememberLearningEvidence(&a.State, session, flow)
			}
		}
	}
	return a.save()
}
