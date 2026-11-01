package agent

// Installed release integrity is separate from mutable endpoint configuration.
// An administrator controlling the host's root trust can still replace both.
import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type runtimeFile struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func runtimeRead(path string, limit int64, owner uint32) ([]byte, error) {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return nil, err
		}
		meta, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || meta.Uid != owner || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("runtime integrity requires protected owned directories")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	meta, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || meta.Uid != owner || meta.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
		return nil, errors.New("invalid protected runtime release file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("runtime release exceeds byte limit")
	}
	return raw, nil
}

func verifyRuntimeRelease(manifestRaw, trustRaw []byte, read func(string) ([]byte, error)) error {
	var signed struct {
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"key_id"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	var trust struct {
		Keys map[string]string `json:"keys"`
	}
	if len(manifestRaw) > 65536 || len(trustRaw) > 16384 || json.Unmarshal(manifestRaw, &signed) != nil || json.Unmarshal(trustRaw, &trust) != nil || signed.Algorithm != "Ed25519" || len(trust.Keys) < 1 || len(trust.Keys) > 16 {
		return errors.New("invalid runtime signature envelope")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(trust.Keys[signed.KeyID])
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("untrusted runtime signer")
	}
	keyHash := sha256.Sum256(key)
	if hex.EncodeToString(keyHash[:])[:32] != signed.KeyID {
		return errors.New("runtime signer fingerprint differs")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(signed.Payload)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), payload, signature) {
		return errors.New("runtime signature did not verify")
	}
	var document struct {
		Domain   string `json:"domain"`
		Manifest struct {
			Kind    string                 `json:"kind"`
			Version string                 `json:"version"`
			Files   map[string]runtimeFile `json:"files"`
		} `json:"manifest"`
	}
	if json.Unmarshal(payload, &document) != nil || document.Domain != "prthak-package-manifest-v1" || document.Manifest.Kind != "prthak-agent-runtime-v1" || document.Manifest.Version != Version || len(document.Manifest.Files) != 2 {
		return errors.New("runtime manifest has another domain, version or file scope")
	}
	for _, path := range []string{"/usr/local/bin/seg-agent", "/etc/systemd/system/seg-agent.service"} {
		expected, ok := document.Manifest.Files[path]
		if !ok || expected.Bytes <= 0 || expected.Bytes > 64<<20 {
			return errors.New("runtime manifest omits a fixed installed file")
		}
		raw, err := read(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		if int64(len(raw)) != expected.Bytes || hex.EncodeToString(digest[:]) != expected.SHA256 {
			return fmt.Errorf("installed release bytes changed: %s", path)
		}
	}
	return nil
}

// VerifyInstalledRuntime fails closed for the canonical installed daemon. Local
// source/test executables and independent rollback entrypoints remain separate.
func VerifyInstalledRuntime() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if filepath.Clean(executable) != "/usr/local/bin/seg-agent" {
		return nil
	}
	manifest, err := runtimeRead("/usr/share/seg-agent/runtime-integrity.json", 65536, 0)
	if err != nil {
		return fmt.Errorf("installed runtime manifest unavailable: %w", err)
	}
	trust, err := runtimeRead("/etc/seg-agent/release-public-trust.json", 16384, 0)
	if err != nil {
		return fmt.Errorf("installed runtime signer trust unavailable: %w", err)
	}
	return verifyRuntimeRelease(manifest, trust, func(path string) ([]byte, error) { return runtimeRead(path, 64<<20, 0) })
}

// VerifyReleaseFiles checks exact candidate bytes before an installer changes
// protected files. Archive trust is independently established before execution.
func VerifyReleaseFiles(manifestPath, trustPath, binaryPath, unitPath string) error {
	readCandidate := func(path string, maximum int64) ([]byte, error) {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), path)
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > maximum {
			return nil, errors.New("invalid public release candidate file")
		}
		value, err := io.ReadAll(io.LimitReader(file, maximum+1))
		if int64(len(value)) > maximum {
			return nil, errors.New("release candidate exceeds byte limit")
		}
		return value, err
	}
	manifest, err := readCandidate(manifestPath, 65536)
	if err != nil {
		return err
	}
	trust, err := readCandidate(trustPath, 16384)
	if err != nil {
		return err
	}
	return verifyRuntimeRelease(manifest, trust, func(path string) ([]byte, error) {
		if path == "/usr/local/bin/seg-agent" {
			return readCandidate(binaryPath, 64<<20)
		}
		if path == "/etc/systemd/system/seg-agent.service" {
			return readCandidate(unitPath, 1024<<10)
		}
		return nil, errors.New("release path outside the fixed runtime")
	})
}
