package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const PollingSettingsCapability = "agent_polling_config_v1"

type PollingSettings struct {
	Version                  int      `json:"version"`
	Digest                   string   `json:"digest"`
	ControlIntervalSeconds   int      `json:"control_interval_seconds"`
	DiscoveryIntervalSeconds int      `json:"discovery_interval_seconds"`
	MatchedRuleIDs           []string `json:"matched_rule_ids,omitempty"`
}

type PollingSettingsReport struct {
	Version int    `json:"version"`
	Digest  string `json:"digest"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

func pollingDigest(control, discovery int) string {
	body, _ := json.Marshal(map[string]int{"control_interval_seconds": control, "discovery_interval_seconds": discovery})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func ValidatePollingSettings(settings *PollingSettings) error {
	if settings == nil {
		return nil
	}
	if settings.Version < 0 || settings.ControlIntervalSeconds < 5 || settings.ControlIntervalSeconds > 3600 || settings.DiscoveryIntervalSeconds < 60 || settings.DiscoveryIntervalSeconds > 86400 {
		return errors.New("remote polling intervals require control 5..3600 and discovery 60..86400 seconds")
	}
	if settings.Digest != pollingDigest(settings.ControlIntervalSeconds, settings.DiscoveryIntervalSeconds) {
		return errors.New("remote polling settings digest does not match the exact intervals")
	}
	return nil
}

func (a *Agent) loadPollingSettings() {
	data, err := os.ReadFile(filepath.Join(a.Config.StateDir, "polling-settings.json"))
	if os.IsNotExist(err) {
		return
	}
	var settings PollingSettings
	if err != nil || json.Unmarshal(data, &settings) != nil || ValidatePollingSettings(&settings) != nil {
		a.pollingError = "Cached polling settings are invalid; using local timing until a valid controller assignment arrives"
		return
	}
	a.remotePolling = &settings
}

func (a *Agent) applyPollingSettings(settings *PollingSettings) error {
	if settings == nil {
		return nil
	} // A controller outage/older response never erases the last valid timing.
	a.timingMu.Lock()
	defer a.timingMu.Unlock()
	fail := func(err error) error { a.pollingError = err.Error(); return err }
	if err := ValidatePollingSettings(settings); err != nil {
		return fail(err)
	}
	if current := a.remotePolling; current != nil {
		if settings.Version < current.Version {
			return fail(errors.New("remote polling revision is older than the retained valid revision"))
		}
	}
	snapshot := *settings
	snapshot.MatchedRuleIDs = append([]string(nil), settings.MatchedRuleIDs...)
	if err := atomicJSON(filepath.Join(a.Config.StateDir, "polling-settings.json"), snapshot); err != nil {
		return fail(fmt.Errorf("cannot persist remote polling settings; previous timing retained"))
	}
	a.remotePolling = &snapshot
	a.pollingError = ""
	return nil
}

func (a *Agent) controlIntervalSeconds() int {
	a.timingMu.RLock()
	defer a.timingMu.RUnlock()
	if a.remotePolling != nil {
		return a.remotePolling.ControlIntervalSeconds
	}
	if a.Config.IntervalSeconds > 0 {
		return a.Config.IntervalSeconds
	}
	return 60
}
func (a *Agent) discoveryIntervalSeconds() int {
	a.timingMu.RLock()
	defer a.timingMu.RUnlock()
	if a.remotePolling != nil {
		return a.remotePolling.DiscoveryIntervalSeconds
	}
	if a.Config.DiscoveryIntervalSeconds > 0 {
		return a.Config.DiscoveryIntervalSeconds
	}
	return 900
}
func (a *Agent) pollingSettingsReport() *PollingSettingsReport {
	a.timingMu.RLock()
	defer a.timingMu.RUnlock()
	if a.remotePolling == nil {
		return nil
	}
	status := "applied"
	if a.pollingError != "" {
		status = "error"
	}
	return &PollingSettingsReport{Version: a.remotePolling.Version, Digest: a.remotePolling.Digest, Status: status, Error: a.pollingError}
}
