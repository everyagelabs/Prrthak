package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const activationEgressPolicy = "prt-egress"
const activationEgressDescription = "Prrthak owned outbound policy v1"

func activationEgressShort(nonce string) string { return "Prrthak egress template owner:" + nonce }
func activationEgressPath(stateDir string) string {
	return filepath.Join(managedDirectory(stateDir), "network-control", "egress-template.json")
}

func activationEgressAbsent(ctx context.Context, commands CommandRunner) error {
	for _, scope := range []string{"runtime", "permanent"} {
		text, err := commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-policies")...)
		if err != nil {
			return errors.New("the installed firewalld does not support policy-object preparation")
		}
		for _, name := range strings.Fields(text) {
			if name == activationEgressPolicy {
				return errors.New("prt-egress already exists; existing unmarked policies are never adopted or overwritten")
			}
		}
	}
	return nil
}

func activationEgressPresent(ctx context.Context, commands CommandRunner, scope string) (bool, error) {
	text, err := commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--get-policies")...)
	if err != nil {
		return false, errors.New("cannot inspect exact policy-object inventory")
	}
	for _, name := range strings.Fields(text) {
		if name == activationEgressPolicy {
			return true, nil
		}
	}
	return false, nil
}

func activationEgressOwnedEmpty(ctx context.Context, commands CommandRunner, scope, nonce string) error {
	if !validManagedNonce(nonce) {
		return errors.New("invalid egress policy ownership nonce")
	}
	queries := map[string]string{"--get-short": activationEgressShort(nonce), "--get-description": activationEgressDescription, "--get-target": "CONTINUE", "--get-priority": "-30000", "--list-ingress-zones": "HOST", "--list-egress-zones": "ANY", "--list-services": "", "--list-ports": "", "--list-protocols": "", "--list-source-ports": "", "--list-rich-rules": "", "--list-forward-ports": "", "--query-masquerade": "no"}
	for query, expected := range queries {
		text, err := commands.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+activationEgressPolicy, query)...)
		if strings.TrimSpace(text) != expected || err != nil && !(query == "--query-masquerade" && strings.TrimSpace(text) == "no") {
			return errors.New("egress policy ownership, exact empty bindings or target changed; no overwrite or deletion permitted")
		}
	}
	return nil
}

func activationEgressXML(nonce string) ([]byte, error) {
	if !validManagedNonce(nonce) {
		return nil, errors.New("invalid egress policy owner")
	}
	return []byte(fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<policy target=\"CONTINUE\" priority=\"-30000\"><short>%s</short><description>%s</description><ingress-zone name=\"HOST\"/><egress-zone name=\"ANY\"/></policy>\n", activationEgressShort(nonce), activationEgressDescription)), nil
}

func activationEgressMarker(stateDir, nonce string) error {
	path := activationEgressPath(stateDir)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return errors.New("an egress ownership marker already exists or cannot be inspected")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return atomicJSON(path, canonicalEgressTemplate(nonce))
}

type activationFilteredRunner struct{ CommandRunner }

func (runner activationFilteredRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	text, err := runner.CommandRunner.Run(ctx, name, args...)
	if err != nil || name != "firewall-cmd" {
		return text, err
	}
	for _, arg := range args {
		if arg == "--get-policies" {
			names := []string{}
			for _, entry := range strings.Fields(text) {
				if entry != activationEgressPolicy {
					names = append(names, entry)
				}
			}
			return strings.Join(names, " "), nil
		}
	}
	return text, err
}

// This wrapper is used only after exact nonce/empty-policy validation above.
// It lets the pre-existing parity checker compare every unrelated rule/zone
// without treating our newly reviewed inert template as a foreign policy.
func activationOriginalPolicyBaseline(ctx context.Context, commands CommandRunner, stateDir string, original sourceBankBaseline, global string, created bool) (sourceBankBaseline, error) {
	if created {
		commands = activationFilteredRunner{commands}
	}
	inspection := &Agent{Config: Config{StateDir: stateDir}, Commands: commands, sourceBankOwnedRulesOverride: original.OwnedRules, sourceBankConfigDigest: func() (string, error) { return global, nil }}
	return inspection.sourceBankBaseline(ctx)
}

func activationCounterConfig(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, errors.New("protected global configuration is unavailable or oversized")
	}
	lines := strings.Split(string(raw), "\n")
	found := 0
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			return nil, errors.New("malformed firewalld global configuration")
		}
		if strings.TrimSpace(key) == "NftablesCounters" {
			found++
			value = strings.TrimSpace(value)
			if value != "no" && value != "yes" {
				return nil, errors.New("NftablesCounters has an unsupported value")
			}
			lines[index] = "NftablesCounters=yes"
		}
	}
	if found != 1 {
		return nil, errors.New("an unambiguous installed NftablesCounters option is required; missing or duplicate options are not guessed")
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func activationCounterRuntime(ctx context.Context, commands CommandRunner, enabled bool) error {
	text, err := commands.Run(ctx, "busctl", "--system", "get-property", "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1/config", "org.fedoraproject.FirewallD1.config", "NftablesCounters")
	wanted := "no"
	if enabled {
		wanted = "yes"
	}
	if err != nil || strings.TrimSpace(text) != "s "+strconv.Quote(wanted) {
		return errors.New("the running daemon cannot prove the exact supported native-counter option")
	}
	return nil
}

type activationCounterAttestation struct {
	SchemaVersion  int    `json:"schema_version"`
	DaemonIdentity string `json:"daemon_identity"`
	ConfigHash     string `json:"config_hash"`
	GlobalDigest   string `json:"global_digest"`
	Enabled        bool   `json:"enabled"`
}

func activationCounterAttestationPath(stateDir string) string {
	return filepath.Join(managedDirectory(stateDir), "native-counter-config.json")
}

func activationGlobalBytes(root string) (string, string, error) {
	values := map[string]string{}
	primary := ""
	for _, name := range []string{"/etc/firewalld/firewalld.conf", "/usr/lib/firewalld/firewalld.conf"} {
		raw, err := readPreparationSystemFile(root, name, 65536)
		if err != nil {
			if name == "/usr/lib/firewalld/firewalld.conf" {
				if _, e := os.Lstat(root + name); os.IsNotExist(e) {
					values[name] = "absent"
					continue
				}
			}
			return "", "", err
		}
		values[name] = shaText(string(raw))
		if name == "/etc/firewalld/firewalld.conf" {
			primary = values[name]
		}
	}
	raw, _ := json.Marshal(values)
	return primary, shaText(string(raw)), nil
}

func activationDaemonIdentity(ctx context.Context, commands CommandRunner) (string, error) {
	text, err := commands.Run(ctx, "busctl", "--system", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/firewalld_2eservice", "org.freedesktop.systemd1.Service", "MainPID")
	fields := strings.Fields(text)
	if err != nil || len(fields) != 2 || fields[0] != "u" {
		return "", errors.New("firewalld process identity is unavailable")
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil || pid < 2 || pid == os.Getpid() {
		return "", errors.New("firewalld process identity is invalid")
	}
	identity := processIdentity(pid)
	if identity == "" {
		return "", errors.New("firewalld boot/process identity is unavailable")
	}
	return identity, nil
}

func recordActivationCounterAttestation(ctx context.Context, stateDir, root string, commands CommandRunner, enabled bool) error {
	if err := activationCounterRuntime(ctx, commands, enabled); err != nil {
		return err
	}
	identity, err := activationDaemonIdentity(ctx, commands)
	if err != nil {
		return err
	}
	hash, global, err := activationGlobalBytes(root)
	if err != nil {
		return err
	}
	return atomicJSON(activationCounterAttestationPath(stateDir), activationCounterAttestation{1, identity, hash, global, enabled})
}

// Only a successfully reviewed exact option transition may account for a
// newer config ctime on an unchanged daemon. Arbitrary edits still fail closed.
func firewallActivationGlobalConfigDigest(ctx context.Context, stateDir, root string, commands CommandRunner) (string, error) {
	if root == "" {
		if value, err := sourceBankGlobalConfigDigest(ctx, commands); err == nil {
			return value, nil
		}
	}
	raw, err := readPrivateSetupBound(activationCounterAttestationPath(stateDir), 4096)
	if err != nil {
		return "", errors.New("global configuration changed without an exact reviewed native-counter attestation")
	}
	var proof activationCounterAttestation
	if json.Unmarshal(raw, &proof) != nil || proof.SchemaVersion != 1 || !validDigest(proof.ConfigHash) || !validDigest(proof.GlobalDigest) {
		return "", errors.New("native-counter configuration attestation is invalid")
	}
	identity, err := activationDaemonIdentity(ctx, commands)
	if err != nil || identity != proof.DaemonIdentity {
		return "", errors.New("native-counter attestation belongs to another daemon generation")
	}
	hash, global, err := activationGlobalBytes(root)
	if err != nil || hash != proof.ConfigHash || global != proof.GlobalDigest {
		return "", errors.New("global configuration differs from the reviewed counter-only transition")
	}
	if err := activationCounterRuntime(ctx, commands, proof.Enabled); err != nil {
		return "", err
	}
	return global, nil
}
