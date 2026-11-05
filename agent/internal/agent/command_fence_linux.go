//go:build linux

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type commandFence struct {
	SchemaVersion int                `json:"schema_version"`
	Nonce         string             `json:"nonce"`
	BootID        string             `json:"boot_id"`
	OwnerPID      int                `json:"owner_pid"`
	OwnerIdentity string             `json:"owner_identity"`
	Diagnostic    *commandDiagnostic `json:"diagnostic,omitempty"`
}

func kernelBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	value := strings.TrimSpace(string(raw))
	if err != nil || !validCommandBootID(value) {
		return "", errors.New("kernel boot identity is unavailable")
	}
	return value, nil
}

func validCommandBootID(value string) bool {
	return len(value) == 36 && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-' && validDigest(strings.ReplaceAll(value, "-", "")+strings.ReplaceAll(value, "-", ""))
}

func commandFencePath(leasePath string) (string, error) {
	if !filepath.IsAbs(leasePath) || filepath.Clean(leasePath) != leasePath || filepath.Base(leasePath) != "lock" || filepath.Base(filepath.Dir(leasePath)) != "managed" {
		return "", errors.New("command lease is not an exact managed lock path")
	}
	return filepath.Join(filepath.Dir(leasePath), commandFenceFilename), nil
}

func readCommandFence(path string) (*commandFence, error) {
	raw, err := readPrivateSetupBound(path, 2048)
	if err != nil || strictSetupJSON(raw) != nil {
		return nil, errUncertainCommand
	}
	var record commandFence
	if json.Unmarshal(raw, &record) != nil || record.SchemaVersion != 1 || !validManagedNonce(record.Nonce) || record.OwnerPID < 1 || record.OwnerPID > 2147483647 || !validCommandBootID(record.BootID) || !strings.HasPrefix(record.OwnerIdentity, record.BootID+":") {
		return nil, errUncertainCommand
	}
	if _, err := strconv.ParseUint(strings.TrimPrefix(record.OwnerIdentity, record.BootID+":"), 10, 64); err != nil {
		return nil, errUncertainCommand
	}
	if record.Diagnostic != nil && !validCommandDiagnostic(record.Diagnostic, record.BootID) {
		return nil, errUncertainCommand
	}
	return &record, nil
}

func syncCommandFenceDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// checkCommandFence never uses PID death or an unlocked descriptor as proof of
// drainage. A different kernel boot is the only automatic orphan-clear proof.
// The caller owns the managed lease when retirePreviousBoot is true.
func checkCommandFence(leasePath string, retirePreviousBoot bool) error {
	path, err := commandFencePath(leasePath)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return errUncertainCommand
	}
	record, err := readCommandFence(path)
	if err != nil {
		return err
	}
	boot, err := kernelBootID()
	if err != nil || record.BootID == boot {
		return errUncertainCommand
	}
	if retirePreviousBoot {
		// Keep the last unresolved operation for RCA. A different boot proves
		// the old process tree cannot survive; empty current process lists do not.
		if err := archivePreviousBootCommandFence(path, record, boot); err != nil {
			return fmt.Errorf("%w: cannot preserve previous-boot command diagnostic", errUncertainCommand)
		}
		return clearCommandFence(path, record.Nonce)
	}
	return nil
}

func createCommandFence(leasePath string) (*commandFence, string, error) {
	return createCommandFenceForCommand(leasePath, "", nil)
}

func createCommandFenceForCommand(leasePath, name string, args []string) (*commandFence, string, error) {
	path, err := commandFencePath(leasePath)
	if err != nil {
		return nil, "", err
	}
	if err = checkCommandFence(leasePath, true); err != nil {
		return nil, "", err
	}
	boot, err := kernelBootID()
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return nil, "", err
	}
	record := &commandFence{SchemaVersion: 1, Nonce: hex.EncodeToString(nonce), BootID: boot, OwnerPID: os.Getpid(), OwnerIdentity: processIdentity(os.Getpid()), Diagnostic: newCommandDiagnostic(name, args)}
	if record.OwnerIdentity == "" {
		return nil, "", errors.New("command owner identity is unavailable")
	}
	// O_EXCL both serializes commands sharing one lease and prevents a new
	// command from overwriting an uncertain predecessor. A partial crash write
	// remains an unreadable fence and therefore fails closed.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("%w: cannot reserve durable command fence", errUncertainCommand)
	}
	raw, err := json.Marshal(record)
	if err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncCommandFenceDirectory(path)
	}
	if err != nil {
		return nil, "", fmt.Errorf("%w: command fence could not be persisted", errUncertainCommand)
	}
	return record, path, nil
}

func clearCommandFence(path, nonce string) error {
	record, err := readCommandFence(path)
	if err != nil || record.Nonce != nonce {
		return errUncertainCommand
	}
	if err = os.Remove(path); err != nil {
		return errUncertainCommand
	}
	if err = syncCommandFenceDirectory(path); err != nil {
		return fmt.Errorf("%w: drain receipt could not be persisted", errUncertainCommand)
	}
	return nil
}

func commandTreeProvenDrained() bool {
	for {
		var status syscall.WaitStatus
		_, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		return err == syscall.ECHILD
	}
}
