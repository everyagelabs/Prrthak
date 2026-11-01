package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func (a *Agent) managedHealth(ctx context.Context, p *Policy, protection Protection, nonce string) error {
	freshNonce := make([]byte, 16)
	if _, err := rand.Read(freshNonce); err != nil {
		return err
	}
	nonce = hex.EncodeToString(freshNonce)
	if a.checkManagedHealth != nil {
		return a.checkManagedHealth(ctx, p, protection, nonce)
	}
	if a.Client == nil || a.Client.simulate {
		return errors.New("fresh mTLS management witness unavailable")
	}
	// A newly constructed transport prevents a pre-existing TLS connection from
	// masking a broken outbound controller route after staged restrictions.
	fresh, e := NewClient(a.Config, false)
	if e != nil {
		return e
	}
	transport := fresh.HTTP.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	request := map[string]any{"approval_id": p.Enforcement.ApprovalID, "version": p.Version, "digest": p.Digest, "protection_digest": protection.Digest, "binding_digest": p.Enforcement.BindingDigest, "nonce": nonce, "ssh_ports": protection.SSHPorts}
	response, e := fresh.request(ctx, "POST", "/api/v1/agent/enforcement/check", request, "")
	if e != nil {
		return e
	}
	var witness managedWitness
	if e = decodeResponse(response, &witness); e != nil {
		return e
	}
	return a.validateManagedWitness(witness, p, protection, nonce, time.Now())
}
func (a *Agent) validateManagedWitness(witness managedWitness, p *Policy, protection Protection, nonce string, now time.Time) error {
	if err := a.validateAssignmentIdentity(p); err != nil {
		return err
	}
	if witness.Nonce != nonce || witness.ServerID != p.ServerID || witness.Version != p.Version || witness.Digest != p.Digest || witness.ProtectionDigest != protection.Digest || witness.BindingDigest != p.Enforcement.BindingDigest || witness.Status != "healthy" || !witness.ControllerOK {
		return errors.New("management witness identity/approval binding mismatch")
	}
	if witness.CheckedAt.Before(now.Add(-30*time.Second)) || witness.CheckedAt.After(now.Add(5*time.Second)) {
		return errors.New("management witness is stale or from the future")
	}
	allowedTargets := map[string]bool{}
	if a.inventory != nil {
		for _, ip := range a.inventory.IPs {
			allowedTargets[ip] = true
		}
	}
	if len(allowedTargets) == 0 {
		return errors.New("local addresses unavailable for management witness verification")
	}
	verified := map[int]bool{}
	for _, check := range witness.SSHChecks {
		source, err := netip.ParseAddr(check.SourceIP)
		if err != nil || !check.SSHBannerVerified || !allowedTargets[check.TargetIP] {
			continue
		}
		approved := false
		for _, cidr := range protection.ManagementSources {
			prefix, _ := netip.ParsePrefix(cidr)
			if prefix.Contains(source) {
				approved = true
				break
			}
		}
		if approved {
			verified[check.Port] = true
		}
	}
	for _, port := range protection.SSHPorts {
		if !verified[port] {
			return errors.New("fresh SSH-banner witness missing for an actual SSH port from approved management source")
		}
	}
	return nil
}
func configuredManagedProbe(c Config) string {
	origin := c.ControllerURL
	if c.ControlURL != "" {
		origin = c.ControlURL
	}
	return strings.TrimRight(origin, "/") + "/api/v1/agent/enforcement/check"
}

type managedWitness struct {
	Generation       int       `json:"generation"`
	TargetIPsDigest  string    `json:"target_ips_digest"`
	Nonce            string    `json:"nonce"`
	ServerID         string    `json:"server_id"`
	Version          int       `json:"version"`
	Digest           string    `json:"digest"`
	ProtectionDigest string    `json:"protection_digest"`
	BindingDigest    string    `json:"binding_digest"`
	CheckedAt        time.Time `json:"checked_at"`
	ControllerOK     bool      `json:"controller_ok"`
	Status           string    `json:"status"`
	SSHChecks        []struct {
		TargetIP          string `json:"target_ip"`
		Port              int    `json:"port"`
		SourceIP          string `json:"source_ip"`
		SSHBannerVerified bool   `json:"ssh_banner_verified"`
	} `json:"ssh_checks"`
}
