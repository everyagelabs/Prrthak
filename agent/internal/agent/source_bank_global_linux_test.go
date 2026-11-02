//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func sourceBankGlobalFilesFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"etc/firewalld", "usr/lib/firewalld"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/firewalld/firewalld.conf"), []byte("FirewallBackend=nftables\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestSourceBankGlobalConfigurationRequiresExistingPrimaryEvenIfDeletedBeforeAssessment(t *testing.T) {
	root := sourceBankGlobalFilesFixture(t)
	started := time.Now().Add(time.Minute)
	if digest, err := sourceBankGlobalFilesDigest(root, started); err != nil || !validDigest(digest) {
		t.Fatal("unchanged global configuration failed", digest, err)
	}
	if err := os.Remove(filepath.Join(root, "etc/firewalld/firewalld.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceBankGlobalFilesDigest(root, started); err == nil || !strings.Contains(err.Error(), "primary") {
		t.Fatal("missing/deleted primary global configuration permitted a reload", err)
	}
}

func TestSourceBankGlobalConfigurationRejectsStagedFutureMTime(t *testing.T) {
	root := sourceBankGlobalFilesFixture(t)
	started := time.Now().Add(time.Minute)
	path := filepath.Join(root, "etc/firewalld/firewalld.conf")
	if err := os.Chtimes(path, started.Add(time.Minute), started.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceBankGlobalFilesDigest(root, started); err == nil {
		t.Fatal("post-initialization global configuration modification permitted a reload")
	}
}

func TestSourceBankGlobalConfigurationChecksCTimeWhenMTimeWasRestored(t *testing.T) {
	root := sourceBankGlobalFilesFixture(t)
	path := filepath.Join(root, "etc/firewalld/firewalld.conf")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	// Choose a boundary using observed nanoseconds, avoiding sleeps/timing races.
	started := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).Add(-time.Nanosecond)
	if !info.ModTime().Before(started) {
		t.Fatal("fixture does not model a restored modification time")
	}
	if err := sourceBankGlobalMetadataUnchanged(info, started); err == nil {
		t.Fatal("restoring mtime hid a post-startup configuration change")
	}
}
