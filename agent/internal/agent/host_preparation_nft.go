package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const nftPreparationUnit = "nftables.service"

func nftPreparationEnabled(ctx context.Context, runner CommandRunner) (string, error) {
	load, _ := runner.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", nftPreparationUnit)
	switch strings.TrimSpace(load) {
	case "not-found":
		return "not-found", nil
	case "loaded", "masked":
	default:
		return "", errors.New("cannot verify the nftables unit before preparing dependencies")
	}
	out, _ := runner.Run(ctx, "/usr/bin/systemctl", "is-enabled", nftPreparationUnit)
	switch v := strings.TrimSpace(out); v {
	case "enabled", "enabled-runtime", "disabled", "masked", "masked-runtime", "static", "indirect":
		return v, nil
	default:
		return "", errors.New("cannot verify original nftables enablement")
	}
}

// Installing the read-only nft utility must not activate a second firewall
// manager. A separate protected journal and exact owned runtime mask cover RPM
// scripts as well as Debian packages. Existing custom units are left intact.
func suppressNFTPreparationStartup(ctx context.Context, root, directory string, runner CommandRunner, lease *os.File) (func(context.Context) error, error) {
	original, err := nftPreparationEnabled(ctx, runner)
	if err != nil {
		return nil, err
	}
	if active := preparationActive(ctx, runner, nftPreparationUnit); active == nil || *active {
		return nil, errors.New("existing nftables service activity is active or unknown; dependency preparation refused to preserve its rules")
	}
	for _, base := range []string{"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached"} {
		path := root + base + "/" + nftPreparationUnit
		if info, e := os.Lstat(path); e == nil {
			link, readErr := os.Readlink(path)
			if info.Mode()&os.ModeSymlink == 0 || readErr != nil || link != "/dev/null" {
				return nil, errors.New("existing higher-precedence nftables unit override prevents safe package preparation")
			}
		} else if !os.IsNotExist(e) {
			return nil, errors.New("cannot inspect higher-precedence nftables unit configuration")
		}
	}
	mask := root + "/run/systemd/system/" + nftPreparationUnit
	if _, err := setupPath(filepath.Dir(mask), true); err != nil {
		return nil, errors.New("protected systemd runtime directory is required for the nftables startup fence")
	}
	initial, err := os.Lstat(mask)
	owned := os.IsNotExist(err)
	if !owned {
		link, readErr := os.Readlink(mask)
		if err != nil || initial.Mode()&os.ModeSymlink == 0 || readErr != nil || link != "/dev/null" {
			return nil, errors.New("existing runtime nftables override prevents safe package preparation")
		}
	}
	journal := filepath.Join(directory, "nftables-suppression.json")
	if err := atomicJSON(journal, map[string]any{"schema_version": 1, "phase": "armed", "runtime_mask_owned": owned, "original_enabled": original}); err != nil {
		return nil, err
	}
	var created os.FileInfo
	removed := false
	cleanup := func(cleanCtx context.Context) (cleanErr error) {
		defer func() {
			if cleanErr != nil && owned && removed {
				if _, e := os.Lstat(mask); os.IsNotExist(e) {
					_ = os.Symlink("/dev/null", mask)
				}
			}
		}()
		if err := checkCommandFence(lease.Name(), false); err != nil {
			return errors.New("package descendants are not proven stopped; nftables startup suppression retained")
		}
		if active := preparationActive(cleanCtx, runner, nftPreparationUnit); active == nil || *active {
			return errors.New("nftables service activity changed or cannot be verified; startup suppression retained")
		}
		if owned && created != nil {
			info, e := os.Lstat(mask)
			link, readErr := os.Readlink(mask)
			if e != nil || readErr != nil || link != "/dev/null" || !os.SameFile(created, info) {
				return errors.New("nftables temporary mask ownership changed; refusing removal")
			}
			if err := os.Remove(mask); err != nil {
				return err
			}
			removed = true
		}
		if _, err := runner.Run(cleanCtx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return errors.New("restored nftables service metadata cannot be verified")
		}
		current, err := nftPreparationEnabled(cleanCtx, runner)
		for attempt := 0; err == nil && attempt < 2 && (original == "not-found" || original == "disabled") && (current == "enabled" || current == "enabled-runtime"); attempt++ {
			args := []string{"disable", nftPreparationUnit}
			if current == "enabled-runtime" {
				args = []string{"disable", "--runtime", nftPreparationUnit}
			}
			if _, err := runner.Run(cleanCtx, "/usr/bin/systemctl", args...); err != nil {
				return errors.New("cannot undo unexpected package enablement of nftables")
			}
			current, err = nftPreparationEnabled(cleanCtx, runner)
		}
		if err != nil || current != original && !(original == "not-found" && current == "disabled") {
			return errors.New("original nftables enablement is not verified; startup suppression retained")
		}
		if active := preparationActive(cleanCtx, runner, nftPreparationUnit); active == nil || *active {
			return errors.New("nftables service activity changed after dependency preparation")
		}
		return os.Remove(journal)
	}
	if owned {
		if err := os.Symlink("/dev/null", mask); err != nil {
			return nil, errors.New("could not arm the journaled nftables startup fence")
		}
		created, err = os.Lstat(mask)
		if err != nil {
			return nil, errors.New("cannot identify the owned nftables mask; startup suppression retained")
		}
	}
	if _, err := runner.Run(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return nil, errors.New("could not load the nftables startup mask; no packages were changed")
	}
	load, err := runner.Run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", nftPreparationUnit)
	if err != nil || strings.TrimSpace(load) != "masked" {
		return nil, errors.New("effective nftables startup mask is unverified; no packages were changed")
	}
	return cleanup, nil
}
