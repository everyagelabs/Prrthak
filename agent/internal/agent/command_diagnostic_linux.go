//go:build linux

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const commandUncertaintyHistoryFilename = "command-uncertainty-last.json"

// Diagnostics describe the command which reserved the fence, never commands
// attempted later. They are evidence only: no stage, PID or empty cgroup can
// authorize clearing a same-boot fence. Raw argv, environment, paths, command
// output and error strings are deliberately never persisted here.
type commandDiagnostic struct {
	Executable         string                    `json:"executable"`
	Operation          string                    `json:"operation"`
	Flags              []string                  `json:"flags,omitempty"`
	ArgumentCount      int                       `json:"argument_count"`
	StartedAt          string                    `json:"started_at"`
	UpdatedAt          string                    `json:"updated_at"`
	Stage              string                    `json:"stage"`
	OwnerCgroupDigest  string                    `json:"owner_cgroup_sha256,omitempty"`
	Supervisor         *commandProcessDiagnostic `json:"supervisor,omitempty"`
	Worker             *commandProcessDiagnostic `json:"worker,omitempty"`
	DrainStartedAt     string                    `json:"drain_started_at,omitempty"`
	DrainReason        string                    `json:"drain_reason,omitempty"`
	LastEvidence       string                    `json:"last_evidence,omitempty"`
	SupervisorExitCode *int                      `json:"supervisor_exit_code,omitempty"`
}

type commandProcessDiagnostic struct {
	PID          int    `json:"pid"`
	Identity     string `json:"identity,omitempty"`
	CgroupDigest string `json:"cgroup_sha256,omitempty"`
}

var diagnosticCommandFlags = map[string]bool{
	"--permanent": true, "--state": true, "--get-active-zones": true,
	"--list-all-zones": true, "--list-all": true, "--list-rich-rules": true,
	"--get-ipsets": true, "--info-ipset": true, "--get-entries": true,
	"--query-rich-rule": true, "--add-rich-rule": true, "--remove-rich-rule": true,
	"--new-ipset": true, "--delete-ipset": true, "--add-entry": true,
	"--remove-entry": true, "--add-entries-from-file": true, "--remove-entries-from-file": true,
	"--query-entry": true, "--get-target": true, "--set-target": true,
	"--get-default-zone": true, "--set-default-zone": true, "--zone": true,
	"--ipset": true, "--direct": true, "--reload": true, "--runtime-to-permanent": true,
	"--get-policies": true, "--info-policy": true, "--policy": true,
	"--new-policy": true, "--delete-policy": true, "--set-priority": true,
	"--add-ingress-zone": true, "--add-egress-zone": true,
}

// Classification uses exact executable/flag allowlists. Even unknown flags and
// positional arguments are omitted: credentials can be in either position, or
// embedded in a URL, rich rule, file name or shell program.
func classifyDiagnosticCommand(name string, args []string) (string, string, []string) {
	base := filepath.Base(name)
	switch base {
	case "firewall-cmd", "firewall-offline-cmd", "nft", "iptables", "ip6tables", "systemctl", "ip", "ss", "conntrack", "journalctl":
	default:
		return "other", "unclassified", nil
	}
	operation := "unclassified"
	var flags []string
	seen := map[string]bool{}
	for _, argument := range args {
		flag, _, _ := strings.Cut(argument, "=")
		if diagnosticCommandFlags[flag] && !seen[flag] && len(flags) < 8 {
			flags, seen[flag] = append(flags, flag), true
		}
	}
	if base == "firewall-cmd" || base == "firewall-offline-cmd" {
		for _, argument := range args {
			flag, _, _ := strings.Cut(argument, "=")
			if strings.HasPrefix(flag, "--add-") || strings.HasPrefix(flag, "--remove-") || strings.HasPrefix(flag, "--new-") || strings.HasPrefix(flag, "--delete-") || strings.HasPrefix(flag, "--set-") || strings.HasPrefix(flag, "--change-") || flag == "--reload" || flag == "--runtime-to-permanent" {
				return base, "firewall-mutation", flags
			}
			if strings.HasPrefix(flag, "--get-") || strings.HasPrefix(flag, "--list-") || strings.HasPrefix(flag, "--query-") || strings.HasPrefix(flag, "--info-") || flag == "--state" || flag == "--version" || flag == "--check-config" {
				operation = "firewall-readback"
			}
		}
	} else if base == "systemctl" {
		for _, argument := range args {
			switch argument {
			case "start", "stop", "restart", "reload", "enable", "disable", "daemon-reload":
				return base, "service-mutation", flags
			case "show", "is-active", "is-enabled", "status":
				operation = "service-readback"
			}
		}
	} else if base == "nft" {
		for _, argument := range args {
			switch argument {
			case "-f", "--file", "add", "delete", "replace", "insert", "flush":
				return base, "nft-mutation-or-check", flags
			case "list":
				operation = "nft-readback"
			}
		}
	} else if base == "ip" {
		for _, argument := range args {
			switch argument {
			case "add", "del", "delete", "replace", "set", "flush":
				return base, "network-mutation", flags
			case "show", "list":
				operation = "network-observation"
			}
		}
	} else if base == "ss" || base == "conntrack" || base == "journalctl" {
		operation = "network-observation"
	}
	return base, operation, flags
}

func newCommandDiagnostic(name string, args []string) *commandDiagnostic {
	executable, operation, flags := classifyDiagnosticCommand(name, args)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return &commandDiagnostic{Executable: executable, Operation: operation, Flags: flags, ArgumentCount: len(args), StartedAt: now, UpdatedAt: now, Stage: "reserved", OwnerCgroupDigest: commandCgroupDigest(os.Getpid())}
}

func commandCgroupDigest(pid int) string {
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func commandProcessIdentity(pid int) *commandProcessDiagnostic {
	identity := processIdentity(pid)
	cgroup := commandCgroupDigest(pid)
	if processIdentity(pid) != identity {
		identity, cgroup = "", ""
	}
	return &commandProcessDiagnostic{PID: pid, Identity: identity, CgroupDigest: cgroup}
}

func validCommandDiagnostic(d *commandDiagnostic, boot string) bool {
	executable, _, _ := classifyDiagnosticCommand(d.Executable, nil)
	if executable != d.Executable || d.ArgumentCount < 0 || d.ArgumentCount > 1048576 || len(d.Flags) > 8 {
		return false
	}
	switch d.Operation {
	case "unclassified", "firewall-readback", "firewall-mutation", "service-mutation", "service-readback", "nft-mutation-or-check", "nft-readback", "network-observation", "network-mutation":
	default:
		return false
	}
	for _, flag := range d.Flags {
		if !diagnosticCommandFlags[flag] {
			return false
		}
	}
	switch d.Stage {
	case "reserved", "supervisor-started", "worker-running", "draining", "drain-unproven", "supervisor-exited-unproven":
	default:
		return false
	}
	for _, value := range []string{d.StartedAt, d.UpdatedAt, d.DrainStartedAt} {
		if value == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return false
		}
	}
	for _, value := range []string{d.OwnerCgroupDigest} {
		if value != "" && !validDigest(value) {
			return false
		}
	}
	for _, process := range []*commandProcessDiagnostic{d.Supervisor, d.Worker} {
		if process == nil {
			continue
		}
		if process.PID < 1 || process.PID > 2147483647 || process.CgroupDigest != "" && !validDigest(process.CgroupDigest) {
			return false
		}
		if process.Identity != "" {
			if !strings.HasPrefix(process.Identity, boot+":") {
				return false
			}
			if _, err := strconv.ParseUint(strings.TrimPrefix(process.Identity, boot+":"), 10, 64); err != nil {
				return false
			}
		}
	}
	for _, value := range []string{d.DrainReason, d.LastEvidence} {
		switch value {
		case "", "worker-exited", "owner-canceled", "deadline-expired", "wait-failed", "children-signal-failed", "diagnostic-write-failed", "worker-started", "kernel-echild-unproven", "supervisor-exit-without-drain-receipt":
		default:
			return false
		}
	}
	return true
}

func updateCommandDiagnostic(path, nonce string, change func(*commandDiagnostic)) error {
	record, err := readCommandFence(path)
	if err != nil || record.Nonce != nonce || record.Diagnostic == nil {
		return errUncertainCommand
	}
	original := *record.Diagnostic
	originalFlags := strings.Join(original.Flags, "\x00")
	var supervisor, worker commandProcessDiagnostic
	if original.Supervisor != nil {
		supervisor = *original.Supervisor
	}
	if original.Worker != nil {
		worker = *original.Worker
	}
	change(record.Diagnostic)
	current := record.Diagnostic
	// Later retries, failures and retirement may annotate the original command,
	// never relabel it as a newer operation or a reused process identity.
	if current.Executable != original.Executable || current.Operation != original.Operation || current.ArgumentCount != original.ArgumentCount || current.StartedAt != original.StartedAt || current.OwnerCgroupDigest != original.OwnerCgroupDigest || strings.Join(current.Flags, "\x00") != originalFlags ||
		original.Supervisor != nil && (current.Supervisor == nil || *current.Supervisor != supervisor) || original.Worker != nil && (current.Worker == nil || *current.Worker != worker) ||
		original.DrainStartedAt != "" && (current.DrainStartedAt != original.DrainStartedAt || current.DrainReason != original.DrainReason) {
		return errUncertainCommand
	}
	record.Diagnostic.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if !validCommandDiagnostic(record.Diagnostic, record.BootID) {
		return errUncertainCommand
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil || len(raw) > 2048 {
		return errors.New("command diagnostic exceeds its durable bound")
	}
	return atomicJSON(path, record)
}

func archivePreviousBootCommandFence(path string, record *commandFence, boot string) error {
	historyPath := filepath.Join(filepath.Dir(path), commandUncertaintyHistoryFilename)
	if _, err := os.Lstat(historyPath); err == nil {
		if _, err = readPrivateSetupBound(historyPath, 4096); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	// A single bounded private record is replaced only on verified new boot.
	// Existing managed transaction journals are not changed or pruned.
	history := struct {
		Fence         *commandFence `json:"fence"`
		RetiredAt     string        `json:"retired_at"`
		RetiredByBoot string        `json:"retired_by_boot"`
		Reason        string        `json:"reason"`
	}{record, time.Now().UTC().Format(time.RFC3339Nano), boot, "verified-new-kernel-boot"}
	raw, err := json.MarshalIndent(history, "", "  ")
	if err != nil || len(raw) > 4096 {
		return errors.New("prior command diagnostic exceeds its history bound")
	}
	return atomicJSON(historyPath, history)
}
