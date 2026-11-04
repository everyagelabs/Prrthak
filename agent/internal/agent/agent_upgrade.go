package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const AgentUpgradeCapability = "agent_pull_upgrade_v1"

const (
	upgradeConfig         = "/etc/seg-agent/config.json"
	upgradeTrust          = "/etc/seg-agent/release-public-trust.json"
	upgradeBinary         = "/usr/local/bin/seg-agent"
	upgradeUnit           = "/etc/systemd/system/seg-agent.service"
	upgradeManifest       = "/usr/share/seg-agent/runtime-integrity.json"
	upgradeHelper         = "/usr/share/seg-agent/upgrade-helper"
	upgradeHelperManifest = "/usr/share/seg-agent/upgrade-helper-integrity.json"
	upgradeUnitName       = "seg-agent.service"
	upgradeArchiveLimit   = 16 << 20
	upgradeRuntimeLimit   = 64 << 20
)

var upgradeID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var upgradeVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

type AgentUpgradeAssignment struct {
	ID           string    `json:"id"`
	Version      string    `json:"version"`
	Architecture string    `json:"architecture"`
	SHA256       string    `json:"sha256"`
	Bytes        int64     `json:"bytes"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type AgentUpgradeReport struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

type agentUpgradeJournal struct {
	Assignment       AgentUpgradeAssignment `json:"assignment"`
	ServerID         string                 `json:"server_id"`
	PreviousVersion  string                 `json:"previous_version"`
	Generation       int                    `json:"assignment_generation"`
	AssignmentDigest string                 `json:"assignment_digest"`
	Phase            string                 `json:"phase"`
	Error            string                 `json:"error,omitempty"`
}

type agentUpgradeRuntime struct {
	Binary   []byte
	Manifest []byte
}

func agentUpgradeNewer(version, previous string) bool {
	if !upgradeVersionPattern.MatchString(version) || !upgradeVersionPattern.MatchString(previous) {
		return false
	}
	target, current := strings.Split(version, "."), strings.Split(previous, ".")
	for index := range target {
		a, _ := strconv.Atoi(target[index])
		b, _ := strconv.Atoi(current[index])
		if a != b {
			return a > b
		}
	}
	return false
}

func (item AgentUpgradeAssignment) valid(previous, architecture string) bool {
	return upgradeID.MatchString(item.ID) && agentUpgradeNewer(item.Version, previous) &&
		(item.Architecture == "amd64" || item.Architecture == "arm64") && item.Architecture == architecture &&
		validDigest(item.SHA256) && item.Bytes > 0 && item.Bytes <= upgradeArchiveLimit && !item.ExpiresAt.IsZero()
}

func (item AgentUpgradeAssignment) stem() string {
	return "prthak-agent-" + item.Version + "-linux-" + item.Architecture
}

func verifyAgentUpgradeArchive(item AgentUpgradeAssignment, archive, signature, trust []byte) error {
	var envelope PolicySignature
	var pinned policyTrust
	if len(signature) > 16384 || len(trust) > 16384 || json.Unmarshal(signature, &envelope) != nil ||
		json.Unmarshal(trust, &pinned) != nil || envelope.Algorithm != "Ed25519" || len(pinned.Keys) < 1 || len(pinned.Keys) > 16 {
		return errors.New("invalid detached release signature")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(pinned.Keys[envelope.KeyID])
	keyDigest := sha256.Sum256(key)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(keyDigest[:])[:32] != envelope.KeyID {
		return errors.New("release signer is not pinned on this endpoint")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return errors.New("invalid signed release payload")
	}
	signed, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), payload, signed) {
		return errors.New("detached release signature did not verify")
	}
	var document struct {
		Domain   string `json:"domain"`
		Manifest struct {
			Filename string `json:"filename"`
			Bytes    int64  `json:"bytes"`
			SHA256   string `json:"sha256"`
		} `json:"manifest"`
	}
	digest := sha256.Sum256(archive)
	if json.Unmarshal(payload, &document) != nil || document.Domain != "prthak-package-manifest-v1" ||
		document.Manifest.Filename != item.stem()+".tar.gz" || document.Manifest.Bytes != item.Bytes ||
		document.Manifest.SHA256 != item.SHA256 || item.Bytes != int64(len(archive)) || hex.EncodeToString(digest[:]) != item.SHA256 {
		return errors.New("download does not match the exact signed agent release")
	}
	return nil
}

func extractAgentUpgrade(item AgentUpgradeAssignment, archive, trust, installedUnit []byte) (agentUpgradeRuntime, error) {
	var result agentUpgradeRuntime
	var packagedUnit []byte
	compressed, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return result, errors.New("invalid agent release gzip stream")
	}
	defer compressed.Close()
	// Only three fixed regular files are read. Never write archive-supplied paths.
	reader := tar.NewReader(io.LimitReader(compressed, 72<<20))
	seen := map[string]bool{}
	prefix := item.stem() + "/"
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(seen) >= 128 || !strings.HasPrefix(entry.Name, prefix) || path.Clean(entry.Name) != entry.Name ||
			seen[entry.Name] || (entry.Typeflag != tar.TypeReg && entry.Typeflag != tar.TypeRegA) {
			return result, errors.New("agent release contains invalid or unexpected archive entries")
		}
		seen[entry.Name] = true
		var target *[]byte
		limit := int64(upgradeRuntimeLimit)
		switch strings.TrimPrefix(entry.Name, prefix) {
		case "seg-agent":
			target = &result.Binary
		case "runtime-integrity.json":
			target, limit = &result.Manifest, 65536
		case "deploy/systemd/seg-agent.service":
			target, limit = &packagedUnit, 65536
		}
		if target != nil {
			if entry.Size <= 0 || entry.Size > limit {
				return result, errors.New("signed agent release file exceeds its size limit")
			}
			*target, err = io.ReadAll(reader)
			if err != nil {
				return result, err
			}
		}
	}
	if len(packagedUnit) == 0 || !bytes.Equal(packagedUnit, installedUnit) {
		return result, errors.New("this release changes the systemd unit and requires the local installer")
	}
	return result, result.verify(item.Version, trust, installedUnit)
}

func (files agentUpgradeRuntime) verify(version string, trust, unit []byte) error {
	return verifyRuntimeReleaseVersion(files.Manifest, trust, version, func(name string) ([]byte, error) {
		switch name {
		case upgradeBinary:
			return files.Binary, nil
		case upgradeUnit:
			return unit, nil
		default:
			return nil, errors.New("unknown agent runtime file")
		}
	})
}

func (c *Client) agentUpgradeAsset(ctx context.Context, item AgentUpgradeAssignment, asset string, limit int64) ([]byte, error) {
	response, err := c.request(ctx, http.MethodGet, "/api/v1/agent/upgrade/"+item.ID+"/"+asset, nil, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/octet-stream" ||
		response.ContentLength > limit || response.ContentLength == 0 {
		return nil, errors.New("controller did not return a bounded signed upgrade asset")
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(value) == 0 || int64(len(value)) > limit {
		return nil, errors.New("agent upgrade download exceeds its size limit")
	}
	return value, nil
}

func agentUpgradeDirectory(c Config) string {
	return filepath.Join(c.StateDir, "agent-upgrade")
}

func readAgentUpgrade(c Config) (agentUpgradeJournal, error) {
	var journal agentUpgradeJournal
	location := filepath.Join(agentUpgradeDirectory(c), "transaction.json")
	if _, err := os.Lstat(location); err != nil {
		return journal, err
	}
	raw, err := readPrivateSetupBound(location, 8192)
	if err != nil || json.Unmarshal(raw, &journal) != nil || journal.ServerID == "" || len(journal.ServerID) > 128 ||
		journal.Generation < 1 || !validDigest(journal.AssignmentDigest) ||
		!journal.Assignment.valid(journal.PreviousVersion, runtime.GOARCH) {
		return journal, errors.New("agent upgrade journal is not trustworthy")
	}
	switch journal.Phase {
	case "staging", "staged", "stopping", "replacing", "starting", "rollback_replacing", "restoring", "applied", "blocked", "rolled_back", "error":
		return journal, nil
	default:
		return journal, errors.New("agent upgrade journal has an invalid phase")
	}
}

func (j agentUpgradeJournal) fencing() bool {
	switch j.Phase {
	case "stopping", "replacing", "starting", "rollback_replacing", "restoring":
		return true
	default:
		return false
	}
}

func (j *agentUpgradeJournal) save(c Config, phase, detail string) error {
	if chars := []rune(detail); len(chars) > 200 {
		detail = string(chars[:200])
	}
	next := *j
	next.Phase, next.Error = phase, detail
	raw, err := json.Marshal(next)
	if err == nil {
		err = atomicPrivateFile(filepath.Join(agentUpgradeDirectory(c), "transaction.json"), raw)
	}
	if err == nil {
		*j = next
	}
	return err
}

func agentUpgradeLock(c Config) (*os.File, error) {
	directory := agentUpgradeDirectory(c)
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := setupPath(directory, true)
	if err != nil || info.Mode().Perm() != 0700 {
		return nil, errors.New("agent upgrade requires a private canonical state directory")
	}
	filename := filepath.Join(directory, "lock")
	fd, err := syscall.Open(filename, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filename)
	info, err = file.Stat()
	if err != nil || validatePrivateFileInfo(filename, info, os.Geteuid()) != nil {
		file.Close()
		return nil, errors.New("agent upgrade lock ownership is unsafe")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func agentUpgradeAvailable(c Config, simulate bool) bool {
	if simulate || runtime.GOOS != "linux" || os.Geteuid() != 0 || ValidateInstallConfig(c) != nil ||
		(runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || !policySigningRequired(c) || policySigningReadiness(c) != nil {
		return false
	}
	executable, err := os.Executable()
	if err != nil || executable != upgradeBinary {
		return false
	}
	info, err := setupPath(upgradeHelper, false)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || info.Size() < 1 || info.Size() > upgradeRuntimeLimit {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Nlink != 1 {
		return false
	}
	_, err = runtimeRead(upgradeHelperManifest, 65536, 0)
	return err == nil
}

func (a *Agent) agentUpgradeFenced() bool {
	if a.Simulate || a.Config.StateDir != "/var/lib/seg-agent" {
		return false
	}
	journal, err := readAgentUpgrade(a.Config)
	return err == nil && journal.fencing() || err != nil && !os.IsNotExist(err)
}

func (a *Agent) awaitAgentUpgradeCommit(ctx context.Context) bool {
	if !a.agentUpgradeFenced() {
		return true
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	reported := false
	for a.agentUpgradeFenced() {
		journal, err := readAgentUpgrade(a.Config)
		if !reported && err == nil && journal.Phase == "starting" && Version == journal.Assignment.Version {
			if err = a.report(ctx); err == nil {
				reported = a.writeReadyStatus("ready", nil) == nil
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
	return true
}

func checkAgentUpgradeIdle(c Config) error {
	if c.StateDir != "/var/lib/seg-agent" {
		return nil
	}
	return checkAgentUpgradeJournalIdle(c, time.Now())
}

func checkAgentUpgradeJournalIdle(c Config, now time.Time) error {
	journal, err := readAgentUpgrade(c)
	if os.IsNotExist(err) {
		return nil
	}
	staged := journal.Phase == "staging" || journal.Phase == "staged"
	if err != nil || journal.fencing() || staged && now.Before(journal.Assignment.ExpiresAt) {
		return errors.New("a managed agent upgrade is active or its journal is unavailable")
	}
	return nil
}

func agentUpgradeOutcome(c Config) *AgentUpgradeReport {
	journal, err := readAgentUpgrade(c)
	if err != nil {
		return nil
	}
	status := journal.Phase
	switch {
	case journal.fencing():
		status = "upgrading"
	case status == "staged":
		status = "staging"
	}
	return &AgentUpgradeReport{ID: journal.Assignment.ID, Version: journal.Assignment.Version, Status: status, Error: journal.Error}
}

func (a *Agent) processAgentUpgrade(ctx context.Context, p *Policy) (bool, error) {
	item := p.AgentUpgrade
	if item == nil || !agentUpgradeAvailable(a.Config, a.Simulate) {
		return false, nil
	}
	if !policySigningRequired(a.Config) || p.Signature == nil || p.AssignmentGeneration < 1 ||
		!validDigest(p.AssignmentDigest) || !item.valid(Version, runtime.GOARCH) || !a.currentTime().Before(item.ExpiresAt) {
		return false, nil
	}
	lock, err := agentUpgradeLock(a.Config)
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return true, nil
		}
		return false, err
	}
	journal, err := readAgentUpgrade(a.Config)
	if err != nil && !os.IsNotExist(err) {
		lock.Close()
		return true, err
	}
	if journal.fencing() || journal.Assignment.ID == item.ID && journal.Phase != "staging" && journal.Phase != "staged" {
		lock.Close()
		return journal.fencing(), nil
	}
	if journal.Assignment.ID != item.ID || journal.Phase == "staging" {
		journal = agentUpgradeJournal{Assignment: *item, ServerID: p.ServerID, PreviousVersion: Version,
			Generation: p.AssignmentGeneration, AssignmentDigest: p.AssignmentDigest}
		if err = journal.save(a.Config, "staging", ""); err == nil {
			err = a.stageAgentUpgrade(ctx, *item)
		}
		if err != nil {
			saveErr := journal.save(a.Config, "error", "Signed agent release could not be staged: "+err.Error())
			lock.Close()
			return true, errors.Join(err, saveErr)
		}
		if err = journal.save(a.Config, "staged", ""); err != nil {
			lock.Close()
			return true, err
		}
	}
	lock.Close()
	_, err = a.Commands.Run(ctx, "systemd-run", "--quiet", "--no-block", "--collect", "--unit=seg-agent-upgrade",
		"--property=Type=oneshot", "--property=TimeoutStartSec=240s", "--property=UMask=0077",
		"--property=Restart=on-failure", "--property=RestartSec=5s", "--property=StartLimitBurst=3",
		upgradeHelper, "--run-agent-upgrade")
	if err != nil {
		// Leave the stage intact. A disconnected response can race a live worker.
		return true, fmt.Errorf("could not start independent agent upgrade worker: %w", err)
	}
	return true, nil
}

func (a *Agent) stageAgentUpgrade(ctx context.Context, item AgentUpgradeAssignment) error {
	trust, err := runtimeRead(upgradeTrust, 16384, 0)
	if err != nil {
		return err
	}
	unit, err := runtimeRead(upgradeUnit, 65536, 0)
	if err != nil {
		return err
	}
	signature, err := a.Client.agentUpgradeAsset(ctx, item, "signature", 16384)
	if err != nil {
		return err
	}
	archive, err := a.Client.agentUpgradeAsset(ctx, item, "archive", item.Bytes)
	if err != nil {
		return err
	}
	if err = verifyAgentUpgradeArchive(item, archive, signature, trust); err != nil {
		return err
	}
	files, err := extractAgentUpgrade(item, archive, trust, unit)
	if err != nil {
		return err
	}
	return files.stage(a.Config, "candidate")
}

func (files agentUpgradeRuntime) stage(c Config, prefix string) error {
	directory := agentUpgradeDirectory(c)
	if err := atomicPrivateFile(filepath.Join(directory, prefix+"-binary"), files.Binary); err != nil {
		return err
	}
	return atomicPrivateFile(filepath.Join(directory, prefix+"-manifest"), files.Manifest)
}

func readAgentUpgradeRuntime(c Config, prefix string) (agentUpgradeRuntime, error) {
	binary, manifest := upgradeBinary, upgradeManifest
	if prefix != "" {
		directory := agentUpgradeDirectory(c)
		binary, manifest = filepath.Join(directory, prefix+"-binary"), filepath.Join(directory, prefix+"-manifest")
	}
	var result agentUpgradeRuntime
	var err error
	if result.Binary, err = runtimeRead(binary, upgradeRuntimeLimit, 0); err != nil {
		return result, err
	}
	result.Manifest, err = runtimeRead(manifest, 65536, 0)
	return result, err
}

func (files agentUpgradeRuntime) install() error {
	if err := atomicProtectedFile(upgradeBinary, files.Binary, 0755); err != nil {
		return err
	}
	return atomicProtectedFile(upgradeManifest, files.Manifest, 0644)
}
