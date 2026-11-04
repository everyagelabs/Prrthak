package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	activationDefaultAllowName = "prt-allow-inbound"
	activationDefaultAllowPath = "/etc/firewalld/policies/" + activationDefaultAllowName + ".xml"
	activationDefaultAllowXML  = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<policy target=\"ACCEPT\" priority=\"32767\"><short>Prrthak default inbound allow</short>" +
		"<ingress-zone name=\"ANY\"/><egress-zone name=\"HOST\"/></policy>\n"
)

func activationDefaultAllowPreflight(ctx context.Context, commands CommandRunner, root, version string) error {
	major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if err != nil || major < 1 {
		return errors.New("the default inbound allow requires firewalld 1 or newer")
	}
	if _, err := setupPath(root+filepath.Dir(activationDefaultAllowPath), true); err != nil {
		return errors.New("the protected firewalld policy directory is unavailable")
	}
	for _, path := range []string{activationDefaultAllowPath, "/usr/lib/firewalld/policies/" + activationDefaultAllowName + ".xml"} {
		if _, err := os.Lstat(root + path); !os.IsNotExist(err) {
			return errors.New("the default inbound policy name already exists or cannot be inspected; use Start with existing rules if it is already configured")
		}
	}
	for _, option := range []string{"--get-all-rules", "--get-all-passthroughs", "--get-all-chains"} {
		text, err := commands.Run(ctx, "firewall-offline-cmd", "--direct", option)
		if err != nil || strings.TrimSpace(text) != "" {
			return errors.New("direct firewall rules, chains or passthroughs prevent the default inbound allow")
		}
	}
	policies, err := commands.Run(ctx, "firewall-offline-cmd", "--get-policies")
	if err != nil {
		return errors.New("the permanent policy inventory is unavailable")
	}
	for _, name := range strings.Fields(policies) {
		if name != "allow-host-ipv6" {
			return errors.New("existing custom policies require separate review before adding the default inbound allow")
		}
		details, err := commands.Run(ctx, "firewall-offline-cmd", "--policy="+name, "--list-all")
		if err != nil || !safeHostIPv6Policy(details) {
			return errors.New("the native IPv6 control policy could not be verified")
		}
	}
	return nil
}

func activationDefaultAllowPolicyMatches(ctx context.Context, commands CommandRunner) error {
	activeText, err := commands.Run(ctx, "firewall-cmd", "--get-active-policies")
	active, valid := activePolicyNames(activeText)
	if err != nil || !valid || !slices.Contains(active, activationDefaultAllowName) {
		return errors.New("the reviewed default inbound allow policy is not active")
	}
	expected := map[string]string{
		"priority": "32767", "ingress-zones": "ANY", "egress-zones": "HOST",
		"services": "", "ports": "", "protocols": "", "source-ports": "",
		"forward-ports": "", "icmp-blocks": "", "masquerade": "no",
	}
	for _, scope := range []string{"runtime", "permanent"} {
		text, err := commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+activationDefaultAllowName, "--list-all")...)
		policies, parseErr := parseFirewallZones(text)
		if err != nil || parseErr != nil || len(policies) != 1 || policies[0].Name != activationDefaultAllowName ||
			policies[0].Target != "ACCEPT" || len(policies[0].Rich) != 0 || len(policies[0].Fields) != len(expected) {
			return errors.New("runtime or permanent inbound policy differs from the exact reviewed default allow")
		}
		for key, want := range expected {
			values, exists := policies[0].Fields[key]
			if !exists || strings.Join(values, " ") != want {
				return errors.New("runtime or permanent inbound policy differs from the exact reviewed default allow")
			}
		}
	}
	return nil
}

func activationDefaultAllowReadback(ctx context.Context, commands CommandRunner, zone string) error {
	for _, scope := range []string{"runtime", "permanent"} {
		text, err := commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--zone="+zone, "--list-all")...)
		zones, parseErr := parseFirewallZones(text)
		if err != nil || parseErr != nil || len(zones) != 1 || zones[0].Name != zone || zones[0].Target != "default" {
			return errors.New("the reviewed zone default target changed during startup")
		}
	}
	return activationDefaultAllowPolicyMatches(ctx, commands)
}

func firewallDeactivationCommands(ctx context.Context, commands CommandRunner, files map[string]string) (CommandRunner, error) {
	fingerprint, exists := files[activationDefaultAllowPath]
	if !exists {
		return commands, nil
	}
	if fingerprint != activationFileFingerprint([]byte(activationDefaultAllowXML), 0644) {
		return nil, errors.New("the default inbound policy differs from the supported rollback scope")
	}
	if err := activationDefaultAllowPolicyMatches(ctx, commands); err != nil {
		return nil, err
	}
	return activationFilteredRunner{CommandRunner: commands, ignorePolicy: activationDefaultAllowName}, nil
}
