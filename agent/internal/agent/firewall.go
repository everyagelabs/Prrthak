package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Plan describes intended source restrictions; only the guarded managed engine applies them.
type Plan struct {
	Version    int              `json:"version"`
	Digest     string           `json:"digest"`
	Capability string           `json:"capability"`
	Rules      []PlannedService `json:"services"`
	Warnings   []string         `json:"warnings"`
}
type PlannedService struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Mode     string   `json:"mode"`
	Sources  []string `json:"sources"`
}

func BuildPlan(p *Policy, c Config) Plan {
	plan := Plan{Version: p.Version, Digest: p.Digest, Capability: "preview-only", Rules: []PlannedService{}, Warnings: []string{}}
	for _, svc := range p.Services {
		mode := svc.Mode
		if mode == "" {
			mode = p.Mode
		}
		sources := append([]string{}, svc.Sources...)

		plan.Rules = append(plan.Rules, PlannedService{svc.Port, svc.Protocol, mode, sources})
	}
	plan.Warnings = append(plan.Warnings, "Management exceptions use actual SSH listeners and the reviewed endpoint protection digest")
	if c.Enforce {
		plan.Capability = "managed-enforcement-opt-in"
		plan.Warnings = append(plan.Warnings, "Applying requires exact two-confirmation approval, fresh SSH witness and independent systemd rollback; a plan is not proof of application")
	}
	return plan
}
func RulePrefix(id string) string {
	h := sha256.Sum256([]byte(id))
	return "SEG" + hex.EncodeToString(h[:6]) + ":"
}
func ObservationRule(s Session, p Port) string {
	return fmt.Sprintf(`rule priority="-32760" port port="%d" protocol="%s" log prefix="%s" level="info" limit value="20/s"`, p.Port, p.Protocol, RulePrefix(s.ID))
}
func ActiveSessions(p *Policy, now time.Time) []Session {
	result := []Session{}
	if p == nil {
		return result
	}
	for _, s := range p.LearningSessions {
		if !s.DiscoveryPending && len(s.Ports) > 0 && s.Status != "stopped" && s.Status != "expired" && !now.Before(s.StartsAt) && now.Before(SessionCutoff(s)) {
			result = append(result, s)
		}
	}
	return result
}
func LearningZone(ctx context.Context, c Config, r CommandRunner) (string, error) {
	if out, e := r.Run(ctx, "ufw", "status"); e == nil && strings.Contains(strings.ToLower(out), "status: active") {
		return "", errors.New("UFW is active; automatic migration is disabled")
	}
	if out, e := r.Run(ctx, "firewall-cmd", "--state"); e != nil || strings.TrimSpace(out) != "running" {
		return "", errors.New("firewalld is not running")
	}
	out, e := r.Run(ctx, "firewall-cmd", "--get-active-zones")
	if e != nil {
		return "", e
	}
	zones := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			zones = append(zones, strings.Fields(line)[0])
		}
	}
	if c.Zone != "" {
		for _, z := range zones {
			if z == c.Zone {
				return z, nil
			}
		}
		return "", fmt.Errorf("configured zone %q is not active", c.Zone)
	}
	if len(zones) != 1 {
		return "", errors.New("temporary learning requires exactly one active zone, or explicit zone in config")
	}
	return zones[0], nil
}
func AddObservation(ctx context.Context, r CommandRunner, zone string, s Session, p Port, now time.Time) (OwnedRule, error) {
	rule := ObservationRule(s, p)
	seconds := int(math.Ceil(s.ExpiresAt.Sub(now).Seconds()))
	if seconds < 1 {
		return OwnedRule{}, errors.New("learning session expired")
	}
	_, e := r.Run(ctx, "firewall-cmd", "--zone="+zone, "--add-rich-rule="+rule, fmt.Sprintf("--timeout=%ds", seconds))
	return OwnedRule{s.ID, zone, rule, s.ExpiresAt}, e
}
func RemoveObservation(ctx context.Context, r CommandRunner, rule OwnedRule) error {
	// Only remove exact rules saved by this agent and bearing the expected session prefix.
	if !strings.Contains(rule.Rule, `prefix="`+RulePrefix(rule.SessionID)+`"`) || !strings.HasPrefix(rule.Rule, `rule priority="-32760" `) {
		return errors.New("refusing to remove unowned firewall rule")
	}
	out, e := r.Run(ctx, "firewall-cmd", "--zone="+rule.Zone, "--remove-rich-rule="+rule.Rule)
	if strings.Contains(out, "NOT_ENABLED") {
		return nil
	}
	return e
}
func ObservationExists(ctx context.Context, r CommandRunner, rule OwnedRule) (bool, error) {
	out, e := r.Run(ctx, "firewall-cmd", "--zone="+rule.Zone, "--query-rich-rule="+rule.Rule)
	if strings.TrimSpace(out) == "yes" && e == nil {
		return true, nil
	}
	if strings.TrimSpace(out) == "no" {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return false, errors.New("unexpected firewalld rich-rule query response")
}
