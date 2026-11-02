//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A pending global configuration can change backend/rpfilter on reload even
// when zone/service parity holds. The public config D-Bus properties reflect
// disk settings, not every loaded daemon setting. Therefore require unchanged
// protected config metadata since this exact daemon process initialized.
func sourceBankGlobalConfigDigest(ctx context.Context, commands CommandRunner) (string, error) {
	property := func(name, kind string) (uint64, error) {
		text, err := commands.Run(ctx, "busctl", "--system", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/firewalld_2eservice", "org.freedesktop.systemd1.Service", name)
		fields := strings.Fields(text)
		if err != nil || len(fields) != 2 || fields[0] != kind {
			return 0, errors.New("cannot prove when the running firewalld daemon loaded its global configuration")
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value == 0 {
			return 0, errors.New("invalid firewalld initialization metadata")
		}
		return value, nil
	}
	pid, err := property("MainPID", "u")
	if err != nil {
		return "", err
	}
	if pid > 2147483647 || pid < 2 || int(pid) == os.Getpid() {
		return "", errors.New("invalid firewalld process identity")
	}
	identity := processIdentity(int(pid))
	if identity == "" {
		return "", errors.New("firewalld process cannot be bound to this boot")
	}
	started, err := property("ExecMainStartTimestamp", "t")
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if started > uint64(now.Add(5*time.Second).UnixMicro()) || bootElapsedSeconds() <= 0 || float64(now.UnixMicro()-int64(started)) > (bootElapsedSeconds()+60)*1e6 {
		return "", errors.New("firewalld initialization clock metadata is inconsistent")
	}
	digest, err := sourceBankGlobalFilesDigest("", time.UnixMicro(int64(started)))
	if err != nil {
		return "", err
	}
	if processIdentity(int(pid)) != identity {
		return "", errors.New("firewalld restarted during configuration inspection")
	}
	return digest, nil
}

func sourceBankGlobalMetadataUnchanged(info os.FileInfo, started time.Time) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("global firewalld change time is unavailable")
	}
	changed := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
	if info.ModTime().After(started) || changed.After(started) {
		return errors.New("global firewalld configuration changed after daemon initialization; reload safety is unproven")
	}
	return nil
}

func sourceBankGlobalFilesDigest(root string, started time.Time) (string, error) {
	values := map[string]string{}
	for _, name := range []string{"/etc/firewalld/firewalld.conf", "/usr/lib/firewalld/firewalld.conf"} {
		// Inspect absence before setupPath intentionally wraps inaccessible or
		// missing path components into its generic safe-path error.
		_, err := os.Lstat(root + name)
		if os.IsNotExist(err) {
			// A deleted primary configuration may still be loaded in memory.
			// Absence alone cannot prove that an ordinary reload is harmless.
			if name == "/etc/firewalld/firewalld.conf" {
				return "", errors.New("primary firewalld configuration is missing; reload safety is unproven")
			}
			parent := root + "/usr/lib/firewalld"
			if _, err := setupPath(parent, false); err != nil {
				return "", errors.New("vendor firewalld configuration absence cannot be verified")
			}
			info, err := os.Lstat(parent)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
				return "", errors.New("vendor firewalld configuration directory is unsafe")
			}
			if err := sourceBankGlobalMetadataUnchanged(info, started); err != nil {
				return "", err
			}
			values[name] = "absent"
			continue
		}
		if err != nil {
			return "", errors.New("global firewalld configuration cannot be inspected safely")
		}
		raw, err := readPreparationSystemFile(root, name, 65536)
		if err != nil {
			return "", errors.New("global firewalld configuration cannot be inspected safely")
		}
		info, err := os.Lstat(root + name)
		if err != nil {
			return "", err
		}
		if err := sourceBankGlobalMetadataUnchanged(info, started); err != nil {
			return "", err
		}
		values[name] = shaText(string(raw))
	}
	raw, _ := json.Marshal(values)
	return shaText(string(raw)), nil
}
