package agent

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var activationZoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,30}$`)

func activationUFWEnabled(raw []byte, enabled bool) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, errors.New("UFW enablement configuration is unavailable")
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
			return nil, errors.New("malformed UFW enablement configuration")
		}
		if strings.TrimSpace(key) == "ENABLED" {
			found++
			value = strings.TrimSpace(value)
			if value != "yes" && value != "no" {
				return nil, errors.New("unsupported UFW enablement value")
			}
			value = "no"
			if enabled {
				value = "yes"
			}
			lines[index] = "ENABLED=" + value
		}
	}
	if found != 1 {
		return nil, errors.New("UFW enablement must be one explicit setting")
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func activationMigrationZoneXML(nonce string, facts FirewallActivationAssessment) ([]byte, error) {
	if !validManagedNonce(nonce) || !activationZoneName.MatchString(facts.Zone) || len(facts.TranslatedRules) > 128 || len(facts.SSHPorts) == 0 || len(facts.SSHPorts) > 8 {
		return nil, errors.New("invalid reviewed migration zone scope")
	}
	buffer := new(bytes.Buffer)
	buffer.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<zone target=\"DROP\"><short>Prrthak UFW migration owner:")
	buffer.WriteString(nonce)
	buffer.WriteString("</short><description>Explicitly reviewed numeric UFW ingress migration</description>")
	writeRule := func(rule FirewallActivationRule) error {
		if err := validateActivationRule(rule); err != nil {
			return err
		}
		fmt.Fprintf(buffer, `<rule family="%s" priority="%d"><source address="`, rule.Family, rule.Priority)
		if err := xml.EscapeText(buffer, []byte(rule.Source)); err != nil {
			return err
		}
		fmt.Fprintf(buffer, `"/><port port="%d" protocol="%s"/><%s/></rule>`, rule.Port, rule.Protocol, rule.Action)
		return nil
	}
	for _, source := range facts.ManagementSources {
		prefix, err := parsePrefix(source)
		if err != nil || prefix.Bits() == 0 {
			return nil, errors.New("restricted native management sources are required")
		}
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		for _, port := range facts.SSHPorts {
			if err := writeRule(FirewallActivationRule{Family: family, Source: prefix.Masked().String(), Port: port, Protocol: "tcp", Action: "accept", Priority: -30000}); err != nil {
				return nil, err
			}
		}
	}
	for _, rule := range facts.TranslatedRules {
		if err := writeRule(rule); err != nil {
			return nil, err
		}
	}
	buffer.WriteString("</zone>\n")
	return buffer.Bytes(), nil
}

func (a *Agent) prepareActivationFiles(ctx context.Context, journal *managedJournal) error {
	value := journal.FirewallActivation
	root := a.activationRoot()
	if value.Assignment.Operation == "activate_allow_all" {
		if _, err := os.Lstat(root + activationDefaultAllowPath); !os.IsNotExist(err) {
			return errors.New("the default inbound allow policy path already exists or cannot be inspected")
		}
		value.ChangedFiles[activationDefaultAllowPath] = firewallActivationFile{After: []byte(activationDefaultAllowXML), Mode: 0644, Absent: true}
	}
	if value.Assignment.Operation == "enable_native_counters" {
		name := "/etc/firewalld/firewalld.conf"
		raw, err := readPreparationSystemFile(root, name, 65536)
		if err != nil {
			return err
		}
		after, err := activationCounterConfig(raw)
		if err != nil {
			return err
		}
		info, err := os.Lstat(root + name)
		if err != nil {
			return err
		}
		value.ChangedFiles[name] = firewallActivationFile{Before: raw, After: after, Mode: info.Mode().Perm()}
	}
	if value.Assignment.Operation == "migrate_ufw" {
		name := "/etc/firewalld/zones/" + value.Baseline.Assessment.Zone + ".xml"
		if _, err := os.Lstat(root + name); !os.IsNotExist(err) {
			return errors.New("an existing system zone override is not overwritten by automatic UFW conversion")
		}
		after, err := activationMigrationZoneXML(journal.Nonce, value.Baseline.Assessment)
		if err != nil {
			return err
		}
		value.ChangedFiles[name] = firewallActivationFile{After: after, Mode: 0644, Absent: true}
		name = "/etc/ufw/ufw.conf"
		raw, err := readPreparationSystemFile(root, name, 65536)
		if err != nil {
			return err
		}
		after, err = activationUFWEnabled(raw, false)
		if err != nil {
			return err
		}
		info, err := os.Lstat(root + name)
		if err != nil {
			return err
		}
		value.ChangedFiles[name] = firewallActivationFile{Before: raw, After: after, Mode: info.Mode().Perm()}
	}
	return nil
}

// Only journal-validated fixed paths reach this primitive. Existing bytes must
// still be exactly before/after; a foreign edit is an error, never overwritten.
func writeActivationFile(root, name string, change firewallActivationFile, forward bool) error {
	path := root + name
	if _, err := setupPath(filepath.Dir(path), true); err != nil {
		return err
	}
	current, err := readPreparationSystemFile(root, name, 2<<20)
	missing := os.IsNotExist(func() error { _, e := os.Lstat(path); return e }())
	wanted, previous := change.Before, change.After
	if forward {
		wanted, previous = change.After, change.Before
	}
	if forward && change.Absent {
		if !missing {
			return errors.New("a new firewall configuration path appeared; no overwrite permitted")
		}
	} else if !forward && change.Absent && missing {
		return nil
	} else if err != nil {
		return err
	} else if bytes.Equal(current, wanted) {
		return nil
	} else if !bytes.Equal(current, previous) {
		return errors.New("firewall configuration bytes changed outside this transaction")
	}
	if !forward && change.Absent {
		if err := os.Remove(path); err != nil {
			return err
		}
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".prthak-maintenance-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(change.Mode.Perm()); err == nil {
		_, err = file.Write(wanted)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if forward && change.Absent {
		// Link publishes a complete file atomically and refuses an existing path.
		if err = os.Link(temporary, path); err != nil {
			return errors.New("atomic firewall configuration creation refused an existing path")
		}
		if err = os.Remove(temporary); err != nil {
			return err
		}
	} else {
		fresh, err := readPreparationSystemFile(root, name, 2<<20)
		if err != nil || !bytes.Equal(fresh, previous) {
			return errors.New("firewall configuration changed before atomic replacement")
		}
		if err = os.Rename(temporary, path); err != nil {
			return err
		}
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
