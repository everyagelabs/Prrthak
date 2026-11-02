//go:build linux

package agent

// Disposable Docker namespace adapter test only. Real firewall-cmd performs
// definition creation, reload, readback and inverse removal. Controller/SSH
// authorization, daemon-start metadata and systemd watchdog are explicit stubs;
// native OS, actual mTLS/SSH witness and systemd acceptance remain separate.
import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestRealPrivateSourceBankPreparationLinux(t *testing.T) {
	if os.Getenv("PRTHAK_PRIVATE_SOURCE_BANK_LINUX") != "1" {
		t.Skip("explicit isolated Docker firewalld namespace only")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("the opted-in real adapter fixture must run inside its disposable Docker container")
	}
	ctx := context.Background()
	newEndpoint := func() *Agent {
		a := &Agent{Config: Config{StateDir: t.TempDir(), Zone: "public", ControllerURL: "https://127.0.0.1:8787", ManagementSources: []string{"127.0.0.1/32"}}, Commands: ExecRunner{}, Client: &Client{}, State: State{Coverage: map[string]*Coverage{}}}
		fixturePolicyTrust(t, a)
		fixtureAuthenticatedClient(a, "host-a")
		a.sourceBankConfigDigest = func() (string, error) { return shaText("explicit-private-lab-daemon-metadata-stub"), nil }
		a.sourceBankConfigurationLease = func() (*os.File, error) { return os.CreateTemp(t.TempDir(), "private-config-lease-") }
		a.armManaged = func(_ context.Context, path string, journal *managedJournal) error {
			loaded, err := readManagedJournal(path, journal.Nonce)
			if err != nil || loaded.SourceBankPreparation == nil || loaded.Phase != "prepared" {
				return errors.New("private adapter transaction was not durably armed")
			}
			return nil
		}
		return a
	}
	for _, failHealth := range []bool{true, false} {
		name := "successful-activation"
		if failHealth {
			name = "failed-health-compensation"
		}
		t.Run(name, func(t *testing.T) {
			a := newEndpoint()
			baseline, err := a.sourceBankBaseline(ctx)
			if err != nil || len(baseline.Runtime) != 0 || len(baseline.Permanent) != 0 {
				t.Fatal("private fixture must start without any source-bank definitions", err)
			}
			protection := a.sourceBankProtection(ctx)
			if !protection.Ready {
				t.Fatal("private protected SSH2022 preflight failed", protection.Blockers)
			}
			witnesses := 0
			a.checkSourceBankHealth = func(context.Context, *Policy, *SourceBankPreparationAssignment, Protection) error {
				witnesses++
				active, err := readBankSetNames(ctx, a.Commands, "runtime")
				if err != nil {
					return err
				}
				if failHealth && len(active) > 0 {
					return errors.New("explicit private failed post-reload management witness")
				}
				return nil
			}
			p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
			handled, err := a.processSourceBankPreparation(ctx, p)
			if !handled || (err != nil) != failHealth || witnesses < 4 {
				t.Fatalf("private real adapter completion handled=%v witnesses=%d error=%v", handled, witnesses, err)
			}
			status := ReadSourceBankPreparationStatus(a.Config.StateDir)
			verified, verifyErr := a.sourceBankBaseline(ctx)
			if status == nil || verifyErr != nil {
				t.Fatal("private outcome did not verify", status, verifyErr)
			}
			if failHealth {
				if status.Status != "rolled_back" || verified.Digest != baseline.Digest {
					t.Fatal("real failed-health compensation did not restore the exact firewall baseline", status)
				}
			} else if status.Status != "prepared" || status.ActiveBanks != 256 || status.PermanentBanks != 256 || status.MissingBanks != 0 || status.CreatedBanks != 256 || status.ActivationRequired {
				t.Fatal("real reviewed source-bank activation did not report all256 runtime/permanent banks", status)
			}
			if a.Config.Enforce || a.Config.AllowFirewallChanges || a.Config.LearningAutoAllow {
				t.Fatal("maintenance silently enabled access-policy enforcement")
			}
			t.Logf("real firewall-cmd result: %s; health callbacks=%d; active=%d permanent=%d", status.Status, witnesses, len(verified.Runtime), len(verified.Permanent))
		})
		if t.Failed() {
			break // Preserve a failed fixture instead of starting another mutation.
		}
	}
}
