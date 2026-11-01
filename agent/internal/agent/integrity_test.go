package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func TestRuntimeReleaseExactBytesAndScope(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	keyHash := sha256.Sum256(public)
	keyID := hex.EncodeToString(keyHash[:])[:32]
	files := map[string][]byte{"/usr/local/bin/seg-agent": []byte("compiled-agent"), "/etc/systemd/system/seg-agent.service": []byte("fixed-service")}
	records := map[string]runtimeFile{}
	for name, raw := range files {
		h := sha256.Sum256(raw)
		records[name] = runtimeFile{int64(len(raw)), hex.EncodeToString(h[:])}
	}
	sign := func(kind, version string, scope map[string]runtimeFile) []byte {
		payload, _ := json.Marshal(map[string]any{"domain": "prthak-package-manifest-v1", "manifest": map[string]any{"kind": kind, "version": version, "files": scope}})
		raw, _ := json.Marshal(map[string]string{"algorithm": "Ed25519", "key_id": keyID, "payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
		return raw
	}
	trust, _ := json.Marshal(map[string]any{"keys": map[string]string{keyID: base64.StdEncoding.EncodeToString(public)}})
	manifest := sign("prthak-agent-runtime-v1", Version, records)
	read := func(name string) ([]byte, error) {
		raw, ok := files[name]
		if !ok {
			return nil, errors.New("missing")
		}
		return raw, nil
	}
	if err := verifyRuntimeRelease(manifest, trust, read); err != nil {
		t.Fatal(err)
	}
	files["/usr/local/bin/seg-agent"][0] = 'X'
	if err := verifyRuntimeRelease(manifest, trust, read); err == nil {
		t.Fatal("accepted modified binary")
	}
	files["/usr/local/bin/seg-agent"][0] = 'c'
	for _, bad := range [][]byte{sign("another-domain", Version, records), sign("prthak-agent-runtime-v1", "old-version", records), append([]byte(nil), manifest...)} {
		if string(bad) == string(manifest) {
			bad[len(bad)/2] ^= 1
		}
		if err := verifyRuntimeRelease(bad, trust, read); err == nil {
			t.Fatal("accepted tampered or wrongly scoped release")
		}
	}
	delete(records, "/etc/systemd/system/seg-agent.service")
	records["/etc/seg-agent/config.json"] = runtimeFile{1, "x"}
	if err := verifyRuntimeRelease(sign("prthak-agent-runtime-v1", Version, records), trust, read); err == nil {
		t.Fatal("accepted mutable configuration in signed code scope")
	}
	if err := verifyRuntimeRelease(manifest, []byte(`{"keys":{}}`), read); err == nil {
		t.Fatal("accepted unknown signer")
	}
}
