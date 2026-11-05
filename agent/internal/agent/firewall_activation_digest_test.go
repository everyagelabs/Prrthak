package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func cloneActivationBaseline(t *testing.T, baseline firewallActivationBaseline) firewallActivationBaseline {
	t.Helper()
	raw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	var copy firewallActivationBaseline
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestFirewallActivationDigestIgnoresInformationalPortsButBindsProtection(t *testing.T) {
	_, _, original, _ := activationFixture(t, "deactivate_existing")
	changed := cloneActivationBaseline(t, original)
	changed.Assessment.DiscoveredPorts = append(changed.Assessment.DiscoveredPorts, FirewallActivationPort{53781, "udp"}, FirewallActivationPort{54660, "udp"})
	if activationDigest(changed) != original.Digest {
		t.Fatal("transient UDP discovery invalidated unchanged firewall review")
	}
	for _, test := range []struct {
		name   string
		mutate func(*firewallActivationBaseline)
	}{
		{"SSH listener", func(value *firewallActivationBaseline) { value.Assessment.SSHPorts = []int{2222} }},
		{"endpoint address", func(value *firewallActivationBaseline) { value.Assessment.IPs = []string{"10.0.0.2"} }},
		{"management source", func(value *firewallActivationBaseline) { value.Assessment.ManagementSources = []string{"192.0.2.1/32"} }},
		{"native topology", func(value *firewallActivationBaseline) { value.NativeTopology = shaText("changed topology") }},
		{"firewall file", func(value *firewallActivationBaseline) {
			value.Files["/etc/firewalld/firewalld.conf"] = "0640:" + shaText("changed configuration")
		}},
		{"service state", func(value *firewallActivationBaseline) { value.Assessment.FirewalldActive = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneActivationBaseline(t, original)
			test.mutate(&changed)
			if activationDigest(changed) == original.Digest {
				t.Fatal("safety-relevant change did not invalidate review")
			}
		})
	}
}

func TestFirewallActivationStopSurvivesTransientPortDiscovery(t *testing.T) {
	a, commands, reviewed, protection := activationFixture(t, "deactivate_existing")
	policy := activationPolicy(t, a, "deactivate_existing", reviewed, protection)
	a.firewallActivation.Baseline = func() (firewallActivationBaseline, Protection, error) {
		current := cloneActivationBaseline(t, reviewed)
		current.Assessment.DiscoveredPorts = append(current.Assessment.DiscoveredPorts, FirewallActivationPort{53781, "udp"}, FirewallActivationPort{54660, "udp"})
		current.Digest = activationDigest(current)
		return current, protection, nil
	}
	handled, err := a.processFirewallActivation(context.Background(), policy)
	receipt := ReadFirewallActivationStatus(a.Config.StateDir)
	if err != nil || !handled || commands.active || commands.enabled || receipt == nil || receipt.Status != "completed" {
		t.Fatal("unchanged reviewed stop failed on incidental discovery", handled, err, receipt)
	}
}

func TestFirewallActivationRecoveryRetainsLegacyExactDigest(t *testing.T) {
	a, _, baseline, protection := activationFixture(t, "deactivate_existing")
	baseline.Digest = activationFullDigest(baseline)
	if !activationRecordedDigestValid(baseline) {
		t.Fatal("pre-upgrade exact rollback baseline was refused")
	}
	request := activationPolicy(t, a, "deactivate_existing", baseline, protection).FirewallActivation
	journal := &managedJournal{Nonce: strings.Repeat("a", 32), Phase: "prepared", PID: os.Getpid(), FirewallActivation: &firewallActivationJournal{Assignment: *request, Baseline: baseline, ChangedFiles: map[string]firewallActivationFile{}, Report: activationReceipt(request)}}
	if err := validateFirewallActivationJournal(journal); err != nil {
		t.Fatal("pre-upgrade rollback journal could not be recovered", err)
	}
	baseline.Assessment.DiscoveredPorts = append(baseline.Assessment.DiscoveredPorts, FirewallActivationPort{53781, "udp"})
	if activationRecordedDigestValid(baseline) {
		t.Fatal("legacy rollback baseline no longer binds its exact recorded facts")
	}
}
