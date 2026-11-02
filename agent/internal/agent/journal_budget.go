package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const enforcementHistoryMaxEntries = 8192
const enforcementHistoryMaxBytes int64 = 1 << 30
const enforcementJournalReserveBytes int64 = 2 * 16 * 1024 * 1024

var errEnforcementHistoryCapacity = errors.New("enforcement history capacity unavailable: new access transaction refused; retained replay/rollback history is preserved and recovery remains allowed")

// Admission is read-only and applies only to new transactions, never recovery
// or updates to an existing journal. Do not prune terminal records: they still
// carry replay, failed-approval and committed-successor fences.
func checkNewEnforcementJournalBudget(stateDir, area string) error {
	var path string
	switch area {
	case "managed", "learning-allow":
		path = filepath.Join(stateDir, area, "transactions")
	case "firewall-changes":
		path = filepath.Join(stateDir, area)
	case "source-banks":
		path = sourceBankDirectory(stateDir)
	default:
		return errEnforcementHistoryCapacity
	}
	ancestor := path
	for {
		if _, err := os.Lstat(ancestor); os.IsNotExist(err) {
			parent := filepath.Dir(ancestor)
			if parent == ancestor {
				return errEnforcementHistoryCapacity
			}
			ancestor = parent
			continue
		} else if err != nil {
			return errEnforcementHistoryCapacity
		}
		break
	}
	if _, err := setupPath(ancestor, true); err != nil {
		return errEnforcementHistoryCapacity
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(ancestor, &stat); err != nil || stat.Bsize <= 0 || uint64(stat.Bavail) < uint64(enforcementJournalReserveBytes)/uint64(stat.Bsize)+1 {
		return errEnforcementHistoryCapacity
	}
	if ancestor != path {
		return nil
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errEnforcementHistoryCapacity
	}
	directory := os.NewFile(uintptr(descriptor), path)
	defer directory.Close()
	count, retained := 0, int64(0)
	for {
		entries, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return errEnforcementHistoryCapacity
		}
		for _, entry := range entries {
			info, entryErr := entry.Info()
			if entryErr != nil || entry.Type()&os.ModeSymlink != 0 || validatePrivateFileInfo("enforcement history", info, os.Geteuid()) != nil {
				return errEnforcementHistoryCapacity
			}
			if file, ok := info.Sys().(*syscall.Stat_t); !ok || file.Nlink != 1 {
				return errEnforcementHistoryCapacity
			}
			count++
			if info.Size() < 0 || info.Size() > enforcementHistoryMaxBytes-enforcementJournalReserveBytes-retained || count >= enforcementHistoryMaxEntries {
				return errEnforcementHistoryCapacity
			}
			retained += info.Size()
		}
		if err == io.EOF {
			return nil
		}
	}
}
