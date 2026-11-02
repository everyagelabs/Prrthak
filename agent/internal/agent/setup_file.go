package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const maxSetupFileBytes = 512 * 1024
const maxSetupCABytes = 128 * 1024
const maxFleetSetupLifetime = 30 * 24 * time.Hour

type setupFile struct {
	SchemaVersion       int                     `json:"schema_version"`
	IssuedAt            string                  `json:"issued_at"`
	ExpiresAt           string                  `json:"expires_at"`
	ExpectedHostname    string                  `json:"expected_hostname,omitempty"`
	EnrollmentProfileID string                  `json:"enrollment_profile_id,omitempty"`
	Config              json.RawMessage         `json:"config"`
	ControllerCA        string                  `json:"controller_ca_pem"`
	EndpointCA          string                  `json:"endpoint_ca_pem,omitempty"`
	EnrollmentToken     string                  `json:"enrollment_token"`
	InstallationOptions *HostPreparationOptions `json:"installation_options,omitempty"`
}

// setupPath rejects aliases and writable non-sticky ancestors before touching
// private input/output. The helper accepts only explicit absolute clean paths.
func setupPath(path string, wantDirectory bool) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errors.New("setup paths must be explicit absolute clean paths")
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator))
	var final os.FileInfo
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("setup paths must exist without symlink components")
		}
		last := index == len(parts)-1
		if !last || wantDirectory {
			if !info.IsDir() {
				return nil, errors.New("setup path ancestor is not a directory")
			}
			if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return nil, errors.New("setup path ancestors must not be writable by other users")
			}
			if status, ok := info.Sys().(*syscall.Stat_t); ok && status.Uid != 0 && status.Uid != uint32(os.Geteuid()) {
				return nil, errors.New("setup path ancestors must be owned by root or the installer user")
			}
		}
		final = info
	}
	return final, nil
}

func readSetupFile(path string) ([]byte, error) {
	return readPrivateSetupBound(path, maxSetupFileBytes)
}
func readPrivateSetupBound(path string, limit int64) ([]byte, error) {
	if _, err := setupPath(path, false); err != nil {
		return nil, err
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open private setup file safely")
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || validatePrivateFileInfo(path, info, os.Geteuid()) != nil {
		return nil, errors.New("setup file must be a private owned regular file (0600 or 0400)")
	}
	if status, ok := info.Sys().(*syscall.Stat_t); ok && status.Nlink != 1 {
		return nil, errors.New("setup file must not have hard-link aliases")
	}
	if info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("setup file exceeds its byte bound")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("setup file cannot be read within its byte bound")
	}
	return data, nil
}

// strictSetupJSON refuses duplicate object names, nulls and excessive nesting.
// JSON is data only: unknown fields are separately rejected by typed decoding.
func strictSetupJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var readValue func(int) error
	readValue = func(depth int) error {
		if depth > 16 {
			return errors.New("setup JSON nesting exceeds its bound")
		}
		token, err := decoder.Token()
		if err != nil || token == nil {
			return errors.New("setup JSON must contain non-null typed values")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, err := decoder.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return errors.New("setup JSON object names must be unique")
					}
					seen[name] = true
					if err = readValue(depth + 1); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return errors.New("invalid setup JSON object")
				}
			case '[':
				for decoder.More() {
					if err := readValue(depth + 1); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return errors.New("invalid setup JSON array")
				}
			default:
				return errors.New("invalid setup JSON delimiter")
			}
		}
		return nil
	}
	if err := readValue(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("setup file must contain exactly one JSON document")
	}
	return nil
}

func validSetupCA(value string, until, now time.Time) bool {
	data := bytes.TrimSpace([]byte(value))
	if len(data) == 0 || len(data) > maxSetupCABytes {
		return false
	}
	count := 0
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || now.Before(certificate.NotBefore) || !until.Before(certificate.NotAfter) {
			return false
		}
		count++
		if count > 16 {
			return false
		}
		data = bytes.TrimSpace(rest)
	}
	return true
}

func parseSetup(data []byte, hostname string, now time.Time) (Config, setupFile, error) {
	var value setupFile
	if err := strictSetupJSON(data); err != nil {
		return Config{}, value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || (value.SchemaVersion != 1 && value.SchemaVersion != 2 && value.SchemaVersion != 3) || len(value.Config) == 0 {
		return Config{}, value, errors.New("setup file has an unsupported schema or field")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return Config{}, value, errors.New("setup file has an unsupported schema or field")
	}
	_, hasProfile := fields["enrollment_profile_id"]
	fleet := value.SchemaVersion == 2 || value.SchemaVersion == 3 && hasProfile
	if value.SchemaVersion != 3 {
		if _, present := fields["installation_options"]; present {
			return Config{}, value, errors.New("host preparation requires setup schema 3")
		}
	} else if value.InstallationOptions == nil || validateHostPreparationOptions(*value.InstallationOptions, fields["installation_options"]) != nil {
		return Config{}, value, errors.New("setup preparation options must explicitly select supported preparation")
	}
	if !fleet {
		// A profile is a new explicit contract, never a way to reinterpret a
		// historical one-use token as reusable fleet authority.
		if _, present := fields["enrollment_profile_id"]; present {
			return Config{}, value, errors.New("one-use setup cannot contain a fleet enrollment profile")
		}
	} else if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(value.EnrollmentProfileID) || value.EnrollmentProfileID == "00000000-0000-0000-0000-000000000000" || value.ExpectedHostname != "" {
		return Config{}, value, errors.New("fleet setup requires its canonical enrollment profile and no hostname binding")
	}
	issued, err := time.Parse(time.RFC3339Nano, value.IssuedAt)
	if err != nil {
		return Config{}, value, errors.New("setup issued_at must be an ISO timestamp")
	}
	expires, err := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	if err != nil || !expires.After(now) || !expires.After(issued) || issued.After(now.Add(2*time.Minute)) {
		if !fleet {
			return Config{}, value, errors.New("setup file has expired or exceeds its 15-minute validity")
		}
		return Config{}, value, errors.New("setup file has expired or has invalid validity timestamps")
	}
	lifetime := expires.Sub(issued)
	if !fleet && lifetime > 15*time.Minute {
		return Config{}, value, errors.New("setup file has expired or exceeds its 15-minute validity")
	}
	if fleet && (lifetime < time.Hour || lifetime > maxFleetSetupLifetime) {
		return Config{}, value, errors.New("fleet setup validity must be between one hour and 30 days")
	}
	if value.ExpectedHostname != "" && (!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`).MatchString(value.ExpectedHostname) || value.ExpectedHostname != hostname) {
		return Config{}, value, errors.New("setup file belongs to another hostname")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`).MatchString(value.EnrollmentToken) {
		return Config{}, value, errors.New("setup file has an invalid enrollment token")
	}
	if fleet && len(value.EnrollmentToken) != 64 {
		return Config{}, value, errors.New("fleet setup has an invalid enrollment credential")
	}
	c := defaultConfig()
	var configFields map[string]json.RawMessage
	if json.Unmarshal(value.Config, &configFields) != nil || len(configFields["controller_url"]) == 0 {
		return Config{}, value, errors.New("setup config must explicitly provide its trusted controller origin")
	}
	configDecoder := json.NewDecoder(bytes.NewReader(value.Config))
	configDecoder.DisallowUnknownFields()
	if configDecoder.Decode(&c) != nil {
		return Config{}, value, errors.New("setup config has an unsupported field or value")
	}
	c, err = validateConfig(c, false)
	if err != nil || ValidateInstallConfig(c) != nil || c.EnrollmentTokenFile != "/etc/seg-agent/enrollment-token" || c.Enforce || c.AllowHostDefaultDeny || c.AllowFirewallChanges || c.LearningAutoAllow || c.UnexpectedPortMonitorEnabled || c.AllowSingleAdminPilot || c.SingleAdminPilotScope != nil || c.DemoAgentID != "" || c.PolicySigningTrustFile != "" || len(c.PolicySigningKeys) != 0 || c.PolicySigningDeploymentID != "" || c.ManagementProbeURL != "" || c.ManagementProbeCACert != "" {
		return Config{}, value, errors.New("setup config must use canonical monitor-only paths and valid intervals")
	}
	if !validSetupCA(value.ControllerCA, expires, now) || (value.EndpointCA != "" && !validSetupCA(value.EndpointCA, expires, now)) || (value.EndpointCA == "") != (c.EndpointCACert == "") {
		return Config{}, value, errors.New("setup requires valid public CA certificates matching its config")
	}
	if c.ManagementSources == nil {
		c.ManagementSources = []string{}
	}
	return c, value, nil
}

// PrepareSetupFile materializes only fixed private data files in an empty
// private directory. It never enrolls, changes firewall rules or reads identity.
func PrepareSetupFile(path, output, hostname string, now time.Time) error {
	data, err := readSetupFile(path)
	if err != nil {
		return err
	}
	config, value, err := parseSetup(data, hostname, now)
	if err != nil {
		return err
	}
	info, err := setupPath(output, true)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 || validateSetupDirectoryOwner(info) != nil {
		return errors.New("setup output must be an owned private 0700 directory")
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 0 {
		return errors.New("setup output directory must be empty")
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return errors.New("setup config cannot be encoded")
	}
	files := map[string][]byte{"agent.json": append(encoded, '\n'), "controller-ca.crt": []byte(value.ControllerCA), "enrollment-token": []byte(value.EnrollmentToken)}
	if value.EndpointCA != "" {
		files["endpoint-ca.crt"] = []byte(value.EndpointCA)
	}
	if value.InstallationOptions != nil {
		files["preparation-options.json"], err = json.Marshal(value.InstallationOptions)
		if err != nil {
			return errors.New("setup preparation options cannot be encoded")
		}
	}
	created := []string{}
	for _, name := range []string{"agent.json", "controller-ca.crt", "endpoint-ca.crt", "enrollment-token", "preparation-options.json"} {
		content, present := files[name]
		if !present {
			continue
		}
		current, currentErr := os.Lstat(output)
		if currentErr != nil || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 {
			err = errors.New("setup output directory changed")
			break
		}
		destination := filepath.Join(output, name)
		file, writeErr := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if writeErr != nil {
			err = errors.New("setup data file could not be created safely")
			break
		}
		created = append(created, destination)
		_, writeErr = file.Write(content)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			err = errors.New("setup data file could not be committed")
			break
		}
	}
	if err != nil {
		for _, name := range created {
			_ = os.Remove(name)
		}
		return err
	}
	return nil
}

func validateSetupDirectoryOwner(info os.FileInfo) error {
	if status, ok := info.Sys().(*syscall.Stat_t); !ok || status.Uid != uint32(os.Geteuid()) {
		return errors.New("setup directory must be owned by the installer user")
	}
	return nil
}
