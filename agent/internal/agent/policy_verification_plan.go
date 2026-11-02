package agent

import (
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

func (a *Agent) validatePolicyVerification(p *Policy, item *PolicyVerificationAssignment, now time.Time) error {
	if item == nil || item.SchemaVersion != 1 || !changeIDValid(item.ID) || !changeIDValid(item.DeploymentID) || item.Version < 1 || !validDigest(item.Digest) || !validDigest(item.ProtectionDigest) || !validDigest(item.TargetIPsDigest) || item.WindowSeconds != 600 || item.ExpiresAt.Sub(item.StartsAt) != 600*time.Second || item.StartsAt.After(now.Add(time.Minute)) || item.ExpiresAt.After(now.Add(10*time.Minute)) || !now.Before(item.ExpiresAt) || len(item.Ports) == 0 || len(item.Ports) > 64 {
		return errors.New("invalid or expired bounded policy-verification lease")
	}
	strict := a.Config
	strict.Enforce = true
	if err := ValidatePolicySignature(strict, p); err != nil {
		return err
	}
	if err := a.validateAssignmentIdentity(p); err != nil {
		return err
	}
	// deployment_id identifies the bulk rollout. Controller identity remains
	// independently pinned by the signed-policy envelope verified above.
	if item.ServerID != p.ServerID || item.Version != p.Version || item.Digest != p.Digest || p.Enforcement == nil || item.ApprovalID != p.Enforcement.ApprovalID || item.ProtectionDigest != p.Enforcement.ProtectionDigest || !changeIDValid(item.ApprovalID) {
		return errors.New("verification lease lost its exact signed policy/approval binding")
	}
	if a.inventory == nil || item.TargetIPsDigest != targetIPsDigest(a.inventory.IPs) {
		return errors.New("verification target addresses changed")
	}
	seen := map[Port]bool{}
	for _, port := range item.Ports {
		if port.Port < 1 || port.Port > 65535 || port.Protocol != "tcp" && port.Protocol != "udp" || seen[port] {
			return errors.New("verification needs at most64 unique exact TCP/UDP ports")
		}
		seen[port] = true
		found := false
		for _, service := range p.Services {
			mode := service.Mode
			if mode == "" {
				mode = p.Mode
			}
			if service.Port == port.Port && service.Protocol == port.Protocol && mode == "enforce" {
				found = true
			}
		}
		if !found {
			return errors.New("verification port is outside the exact enforced service matrix")
		}
	}
	return nil
}

func verificationPrefixEnd(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		bytes := prefix.Addr().As4()
		for bit := prefix.Bits(); bit < 32; bit++ {
			bytes[bit/8] |= 1 << uint(7-bit%8)
		}
		return netip.AddrFrom4(bytes)
	}
	bytes := prefix.Addr().As16()
	for bit := prefix.Bits(); bit < 128; bit++ {
		bytes[bit/8] |= 1 << uint(7-bit%8)
	}
	return netip.AddrFrom16(bytes)
}

// Union coverage, including adjacent prefixes such as the two /1 halves.
func verificationFamilyCovered(sources []string, ipv4 bool) bool {
	prefixes := []netip.Prefix{}
	for _, value := range sources {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Addr().Is4() == ipv4 {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].Addr().Less(prefixes[j].Addr()) })
	cursor := netip.IPv6Unspecified()
	if ipv4 {
		cursor = netip.IPv4Unspecified()
	}
	for _, prefix := range prefixes {
		if cursor.Less(prefix.Addr()) {
			return false
		}
		last := verificationPrefixEnd(prefix)
		if !last.Less(cursor) {
			cursor = last.Next()
			if !cursor.IsValid() {
				return true
			}
		}
	}
	return false
}

func verificationSourceMatches(sources []string, address netip.Addr) bool {
	for _, value := range sources {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func verificationPortSources(p *Policy, protection Protection, port Port) ([]string, []string) {
	business := []string{}
	for _, service := range p.Services {
		mode := service.Mode
		if mode == "" {
			mode = p.Mode
		}
		if service.Port == port.Port && service.Protocol == port.Protocol && mode == "enforce" {
			business = append(business, service.Sources...)
		}
	}
	effective := append([]string{}, business...)
	if port.Protocol == "tcp" {
		for _, ssh := range protection.SSHPorts {
			if ssh == port.Port {
				effective = append(effective, protection.ManagementSources...)
			}
		}
	}
	business, _ = canonicalSources(business, false)
	effective, _ = canonicalSources(effective, false)
	return business, effective
}

func verificationCases(p *Policy, protection Protection, ports []Port, ips []string) ([]PolicyVerificationPort, map[string][]string) {
	families := map[bool]bool{}
	for _, value := range ips {
		if address, err := netip.ParseAddr(value); err == nil && !address.Is4In6() && !address.IsLoopback() && !address.IsUnspecified() {
			families[address.Is4()] = true
		}
	}
	result := []PolicyVerificationPort{}
	sources := map[string][]string{}
	for _, port := range ports {
		business, effective := verificationPortSources(p, protection, port)
		sources[capturePortKey(port)] = effective
		sources["business/"+capturePortKey(port)] = business
		allow, deny := false, false
		for ipv4 := range families {
			for _, value := range business {
				prefix, _ := netip.ParsePrefix(value)
				allow = allow || prefix.IsValid() && prefix.Addr().Is4() == ipv4
			}
			deny = deny || !verificationFamilyCovered(effective, ipv4)
		}
		row := PolicyVerificationPort{Port: port.Port, Protocol: port.Protocol, Allow: PolicyVerificationCase{Status: "awaiting", Reason: "Awaiting one matching post-arm accepted connection."}, Deny: PolicyVerificationCase{Status: "awaiting", Reason: "Awaiting one matching post-arm denied packet."}}
		if !allow {
			row.Allow = PolicyVerificationCase{Status: "not_applicable", Reason: "No business-approved source exists in the endpoint address families; protected SSH exceptions do not prove this case."}
		}
		if !deny {
			row.Deny = PolicyVerificationCase{Status: "not_applicable", Reason: "Approved sources and protected SSH exceptions cover all endpoint address families."}
		}
		result = append(result, row)
	}
	return result, sources
}

func verificationDeniedPrefix(id, generation, epoch, protocol string, port int, family string) string {
	return "PRTV" + shaText("prthak-policy-verification-deny-v1\x00" + id + "\x00" + generation + "\x00" + epoch + "\x00" + protocol + "\x00" + strconv.Itoa(port) + "\x00" + family)[:16] + ":"
}
