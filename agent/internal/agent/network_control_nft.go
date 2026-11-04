package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func quarantineObjectModel(objects []map[string]any, expiresAt time.Time, now time.Time, expired bool) (map[string]any, error) {
	model := map[string]any{"chains": map[string]any{}, "sets": map[string]any{}, "rules": map[string][]any{}}
	chains := model["chains"].(map[string]any)
	sets := model["sets"].(map[string]any)
	rules := model["rules"].(map[string][]any)
	tableSeen := false
	for _, object := range objects {
		if len(object) != 1 {
			return nil, errors.New("invalid quarantine native object")
		}
		for kind, raw := range object {
			value, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid quarantine native object data")
			}
			if kind == "metainfo" {
				continue
			}
			if kind == "table" {
				if tableSeen || value["family"] != "inet" || value["name"] != quarantineTableName {
					return nil, errors.New("foreign quarantine table")
				}
				tableSeen = true
				comment, ok := value["comment"].(string)
				if !ok || !strings.HasPrefix(comment, "Prrthak emergency quarantine owner:") {
					return nil, errors.New("quarantine table lacks exact ownership metadata")
				}
				model["table"] = map[string]any{"family": "inet", "name": quarantineTableName, "comment": comment}
				continue
			}
			if value["family"] != "inet" || value["table"] != quarantineTableName {
				return nil, errors.New("foreign objects in quarantine table")
			}
			switch kind {
			case "chain":
				name, ok := value["name"].(string)
				if !ok || chains[name] != nil {
					return nil, errors.New("duplicate quarantine chain")
				}
				copy := map[string]any{}
				for _, key := range []string{"name", "type", "hook", "prio", "policy"} {
					copy[key] = value[key]
				}
				for key := range value {
					if key != "name" && key != "type" && key != "hook" && key != "prio" && key != "policy" && key != "handle" && key != "family" && key != "table" {
						return nil, errors.New("unexpected quarantine chain property")
					}
				}
				chains[name] = copy
			case "set":
				name, ok := value["name"].(string)
				if !ok || sets[name] != nil {
					return nil, errors.New("duplicate quarantine lease set")
				}
				flags, ok := value["flags"].([]any)
				if !ok {
					return nil, errors.New("quarantine lease flags unavailable")
				}
				flagStrings := []string{}
				for _, flag := range flags {
					s, ok := flag.(string)
					if !ok {
						return nil, errors.New("invalid lease flag")
					}
					flagStrings = append(flagStrings, s)
				}
				sort.Strings(flagStrings)
				timeout, ok := counterDecimal(value["timeout"])
				if !ok {
					return nil, errors.New("quarantine lease timeout unavailable")
				}
				elements, ok := value["elem"].([]any)
				if !ok {
					if value["elem"] == nil && expired {
						elements = []any{}
					} else {
						return nil, errors.New("quarantine lease membership unavailable")
					}
				}
				if len(elements) > 1 || len(elements) == 0 && !expired {
					return nil, errors.New("unexpected quarantine lease coverage")
				}
				for _, element := range elements {
					item := element
					if wrapper, ok := element.(map[string]any); ok && wrapper["elem"] != nil {
						data, ok := wrapper["elem"].(map[string]any)
						if !ok {
							return nil, errors.New("invalid lease element")
						}
						item = data["val"]
						if seconds, exists := data["timeout"]; exists {
							actual, ok := counterDecimal(seconds)
							if !ok || actual != timeout {
								return nil, errors.New("lease element timeout changed")
							}
						}
						if remaining, exists := data["expires"]; exists {
							seconds, ok := counterDecimal(remaining)
							if !ok {
								return nil, errors.New("invalid lease expiration")
							}
							maximum := int64(expiresAt.Sub(now)/time.Second) + 2
							if maximum < 0 {
								maximum = 2
							}
							number := json.Number(seconds)
							n, _ := number.Int64()
							if n > maximum {
								return nil, errors.New("native quarantine expiration would extend the original lease")
							}
						}
					}
					prefix, ok := item.(map[string]any)
					if !ok {
						return nil, errors.New("invalid lease interval")
					}
					network, ok := prefix["prefix"].(map[string]any)
					if !ok || fmt.Sprint(network["len"]) != "0" || (name == "lease4" && network["addr"] != "0.0.0.0") || (name == "lease6" && network["addr"] != "::") {
						return nil, errors.New("lease no longer covers the exact IPv4/IPv6 address space")
					}
				}
				sets[name] = map[string]any{"type": value["type"], "flags": flagStrings, "timeout": timeout}
			case "rule":
				chain, ok := value["chain"].(string)
				if !ok {
					return nil, errors.New("invalid quarantine rule chain")
				}
				expressions, ok := value["expr"].([]any)
				if !ok || len(expressions) == 0 || len(expressions) > 12 {
					return nil, errors.New("invalid quarantine rule expressions")
				}
				rules[chain] = append(rules[chain], expressions)
			default:
				return nil, errors.New("unexpected object in owned quarantine table")
			}
		}
	}
	if !tableSeen {
		return nil, errors.New("owned quarantine table missing")
	}
	return model, nil
}

func normalizeQuarantineObjects(objects []map[string]any) ([]map[string]any, error) {
	raw, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		return nil, err
	}
	document, err := counterJSON(string(raw))
	if err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for _, item := range document["nftables"].([]any) {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid typed quarantine object")
		}
		result = append(result, object)
	}
	return result, nil
}

func readQuarantineTable(ctx context.Context, commands CommandRunner) ([]map[string]any, string, error) {
	text, err := commands.Run(ctx, "nft", "-j", "-a", "list", "table", "inet", quarantineTableName)
	if err != nil {
		if strings.Contains(strings.ToLower(text), "no such file or directory") {
			return nil, "", nil
		}
		return nil, "", errors.New("native quarantine table ownership could not be read")
	}
	document, err := counterJSON(text)
	if err != nil {
		return nil, "", err
	}
	items, ok := document["nftables"].([]any)
	if !ok || len(items) > 512 {
		return nil, "", errors.New("invalid quarantine native inventory")
	}
	result := []map[string]any{}
	handle := ""
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, "", errors.New("invalid quarantine object")
		}
		result = append(result, object)
		if table, ok := object["table"].(map[string]any); ok {
			if table["family"] != "inet" || table["name"] != quarantineTableName || handle != "" {
				return nil, "", errors.New("foreign or duplicate quarantine table")
			}
			handle, ok = counterDecimal(table["handle"])
			if !ok || handle == "0" {
				return nil, "", errors.New("quarantine table handle is unavailable")
			}
		}
	}
	if handle == "" {
		return nil, "", errors.New("quarantine native table header missing")
	}
	return result, handle, nil
}

func verifyQuarantineTable(ctx context.Context, commands CommandRunner, plan *quarantinePlan, now time.Time, allowExpired bool) (string, error) {
	actual, handle, err := readQuarantineTable(ctx, commands)
	if err != nil {
		return "", err
	}
	if plan == nil {
		if handle != "" {
			return "", errors.New("unowned quarantine table already exists")
		}
		return "", nil
	}
	if handle == "" {
		return "", errors.New("committed quarantine table disappeared")
	}
	expected, err := quarantineNFTObjects(*plan, time.Duration(plan.LeaseSeconds)*time.Second)
	if err != nil {
		return "", err
	}
	expected, err = normalizeQuarantineObjects(expected)
	if err != nil {
		return "", err
	}
	want, err := quarantineObjectModel(expected, plan.ExpiresAt, now, false)
	if err != nil {
		return "", err
	}
	got, err := quarantineObjectModel(actual, plan.ExpiresAt, now, allowExpired)
	if err != nil {
		return "", err
	}
	if directApprovalDigest(want) != directApprovalDigest(got) {
		return "", errors.New("owned quarantine rules or ownership changed; refusing to overwrite them")
	}
	return handle, nil
}

func runQuarantineBatch(ctx context.Context, commands CommandRunner, stateDir, nonce string, objects []map[string]any, handle string, check bool) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if !validManagedNonce(nonce) {
		return errors.New("invalid quarantine transaction nonce")
	}
	raw, err := quarantineNFTBatch(objects, handle)
	if err != nil {
		return err
	}
	if _, err = setupPath(stateDir, true); err != nil {
		return err
	}
	directory := filepath.Join(networkDirectory(stateDir), "batches")
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	path := filepath.Join(directory, nonce+".json")
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return errors.New("invalid generated quarantine batch")
	}
	if err = atomicJSON(path, value); err != nil {
		return err
	}
	defer os.Remove(path)
	args := []string{"-j", "-f", path}
	if check {
		args = append([]string{"-c"}, args...)
	}
	if _, err = commands.Run(ctx, "nft", args...); err != nil {
		if check {
			return errors.New("native kernel rejected the typed quarantine transaction; no access change was made")
		}
		return errors.New("native quarantine transaction failed")
	}
	return nil
}
