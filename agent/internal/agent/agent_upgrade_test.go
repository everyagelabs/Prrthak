package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func agentUpgradeTestSigner(t *testing.T) ([]byte, func(any) []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(public)
	keyID := hex.EncodeToString(hash[:])[:32]
	trust, err := json.Marshal(policyTrust{Keys: map[string]string{keyID: base64.StdEncoding.EncodeToString(public)}})
	if err != nil {
		t.Fatal(err)
	}
	return trust, func(manifest any) []byte {
		raw, err := json.Marshal(map[string]any{"domain": "prthak-package-manifest-v1", "manifest": manifest})
		if err != nil {
			t.Fatal(err)
		}
		result, err := json.Marshal(PolicySignature{
			Algorithm: "Ed25519", KeyID: keyID, Payload: base64.StdEncoding.EncodeToString(raw),
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
}

func agentUpgradeTestRuntime(version string, sign func(any) []byte, unit []byte) agentUpgradeRuntime {
	binary := []byte("agent binary " + version)
	records := map[string]runtimeFile{}
	for name, content := range map[string][]byte{upgradeBinary: binary, upgradeUnit: unit} {
		hash := sha256.Sum256(content)
		records[name] = runtimeFile{Bytes: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}
	}
	manifest := sign(map[string]any{"kind": "prthak-agent-runtime-v1", "version": version, "files": records})
	return agentUpgradeRuntime{Binary: binary, Manifest: manifest}
}

func agentUpgradeTestArchive(t *testing.T, stem string, files agentUpgradeRuntime, unit []byte, unsafePath bool) []byte {
	t.Helper()
	var raw bytes.Buffer
	compressed := gzip.NewWriter(&raw)
	writer := tar.NewWriter(compressed)
	entries := map[string][]byte{"seg-agent": files.Binary, "runtime-integrity.json": files.Manifest, "deploy/systemd/seg-agent.service": unit}
	if unsafePath {
		entries["../config.json"] = []byte("unexpected data")
	}
	for name, value := range entries {
		if err := writer.WriteHeader(&tar.Header{Name: stem + "/" + name, Mode: 0644, Size: int64(len(value)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func TestAgentUpgradeRequiresExactSignedArchiveAndFixedUnit(t *testing.T) {
	item := AgentUpgradeAssignment{ID: strings.Repeat("a", 32), Version: "1.2.3", Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	trust, sign := agentUpgradeTestSigner(t)
	unit := []byte("fixed signed unit")
	files := agentUpgradeTestRuntime(item.Version, sign, unit)
	archive := agentUpgradeTestArchive(t, item.stem(), files, unit, false)
	digest := sha256.Sum256(archive)
	item.SHA256, item.Bytes = hex.EncodeToString(digest[:]), int64(len(archive))
	signature := sign(map[string]any{"filename": item.stem() + ".tar.gz", "bytes": item.Bytes, "sha256": item.SHA256})
	if !item.valid("1.2.2", runtime.GOARCH) || item.valid("1.2.3", runtime.GOARCH) || item.valid("1.3.0", runtime.GOARCH) {
		t.Fatal("incorrect version ordering")
	}
	if err := verifyAgentUpgradeArchive(item, archive, signature, trust); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(archive)
	changed[0] ^= 1
	if err := verifyAgentUpgradeArchive(item, changed, signature, trust); err == nil {
		t.Fatal("archive different from the reviewed signed release was accepted")
	}
	if err := verifyAgentUpgradeArchive(item, archive, signature, []byte(`{"keys":{}}`)); err == nil {
		t.Fatal("unknown release signer was accepted")
	}
	extracted, err := extractAgentUpgrade(item, archive, trust, unit)
	if err != nil || !bytes.Equal(extracted.Binary, files.Binary) || !bytes.Equal(extracted.Manifest, files.Manifest) {
		t.Fatalf("unexpected extraction: %v", err)
	}
	if _, err := extractAgentUpgrade(item, archive, trust, []byte("changed installed unit")); err == nil {
		t.Fatal("managed upgrade could change the signed systemd unit")
	}
	unsafe := agentUpgradeTestArchive(t, item.stem(), files, unit, true)
	if _, err := extractAgentUpgrade(item, unsafe, trust, unit); err == nil {
		t.Fatal("archive traversal entry was accepted")
	}
}

func TestAgentUpgradePackageAvailabilityWithoutAssignmentHasNoAction(t *testing.T) {
	a := Agent{Client: nil, Commands: nil}
	if handled, err := a.processAgentUpgrade(context.Background(), &Policy{}); err != nil || handled {
		t.Fatalf("availability without a signed assignment triggered an upgrade: %v", err)
	}
}

func TestAgentUpgradeRequiresLoadedStockSystemdUnit(t *testing.T) {
	stock := "NeedDaemonReload=no\nDropInPaths=\nFragmentPath=" + upgradeUnit + "\n"
	if err := checkAgentUpgradeUnitProperties(stock); err != nil {
		t.Fatalf("loaded stock unit was rejected: %v", err)
	}
	for _, unsafe := range []string{
		strings.Replace(stock, upgradeUnit, "/run/systemd/system/seg-agent.service", 1),
		strings.Replace(stock, "DropInPaths=", "DropInPaths=/etc/systemd/system/seg-agent.service.d/override.conf", 1),
		strings.Replace(stock, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1),
		strings.Replace(stock, "DropInPaths=\n", "", 1),
		stock + "DropInPaths=\n",
	} {
		if err := checkAgentUpgradeUnitProperties(unsafe); err == nil {
			t.Fatalf("unverified effective unit was accepted: %q", unsafe)
		}
	}
}

func TestAgentUpgradeRollbackKeepsDurableFenceAfterInterruptedWrite(t *testing.T) {
	c := Config{StateDir: t.TempDir()}
	if err := os.Mkdir(agentUpgradeDirectory(c), 0700); err != nil {
		t.Fatal(err)
	}
	journal := agentUpgradeJournal{Assignment: AgentUpgradeAssignment{ID: strings.Repeat("1", 32), Version: "1.2.3", Architecture: runtime.GOARCH, SHA256: strings.Repeat("a", 64), Bytes: 123, ExpiresAt: time.Now().Add(time.Hour)}, ServerID: "test-endpoint", PreviousVersion: "1.2.2", Generation: 1, AssignmentDigest: strings.Repeat("b", 64)}
	if err := journal.save(c, "replacing", "interrupted candidate"); err != nil {
		t.Fatal(err)
	}
	if err := checkAgentUpgradeJournalIdle(c, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("an interrupted replacement ceased blocking the local installer at lease expiry")
	}
	trust, sign := agentUpgradeTestSigner(t)
	unit := []byte("fixed signed unit")
	previous := agentUpgradeTestRuntime(journal.PreviousVersion, sign, unit)
	path := filepath.Join(c.StateDir, "restored-binary")
	interrupted := errors.New("interrupted after first atomic replacement")
	if err := journal.restoreRuntime(c, previous, trust, unit, func() error {
		if err := atomicPrivateFile(path, previous.Binary); err != nil {
			t.Fatal(err)
		}
		return interrupted
	}); !errors.Is(err, interrupted) {
		t.Fatalf("expected injected interruption, got %v", err)
	}
	resumed, err := readAgentUpgrade(c)
	if err != nil || resumed.Phase != "rollback_replacing" || !resumed.fencing() {
		t.Fatalf("interrupted replacement escaped its recovery fence: %#v %v", resumed, err)
	}
	if err := resumed.restoreRuntime(c, previous, trust, unit, func() error {
		return atomicPrivateFile(filepath.Join(c.StateDir, "restored-manifest"), previous.Manifest)
	}); err != nil {
		t.Fatal(err)
	}
	if resumed.Phase != "restoring" || !resumed.fencing() {
		t.Fatalf("previous files were restored without maintaining the restart fence: %#v", resumed)
	}
	if err := resumed.save(c, "rolled_back", ""); err != nil {
		t.Fatal(err)
	}
	if resumed.fencing() || agentUpgradeOutcome(c).Status != "rolled_back" {
		t.Fatal("terminal rollback did not remove the firewall mutation fence")
	}
	if err := checkAgentUpgradeJournalIdle(c, time.Now()); err != nil {
		t.Fatalf("verified rollback should release the local installer: %v", err)
	}
}
