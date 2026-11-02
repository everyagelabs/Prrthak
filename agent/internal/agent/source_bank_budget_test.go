package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSourceBankPreparationFreshBatchFitsExplicitVirtualCommandBudget(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	virtualStart := time.Now().UTC()
	virtualNow := virtualStart
	f.onCommand = func() { virtualNow = virtualNow.Add(100 * time.Millisecond) }
	start := time.Now()
	calls := f.commands
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	count := f.commands - calls
	estimate := virtualNow.Sub(virtualStart) + time.Since(start)
	if count > 1600 || estimate >= 9*time.Minute {
		t.Fatalf("fresh256-bank command workload exceeds the maintenance budget: %d calls, %s", count, estimate)
	}
	t.Logf("256-bank maintenance: %d commands; virtual time at100ms/command %s plus real journal I/O; estimate %s within9-minute operation/10-minute watchdog", count, virtualNow.Sub(virtualStart), estimate)
}

func TestSourceBankPreparationExpiredPendingOperationRecoversBeforeReportingBlocked(t *testing.T) {
	a, f, protection := sourceBankFixture(t)
	baseline, _ := a.sourceBankBaseline(context.Background())
	p := sourceBankRequest(t, a, "prepare_activate", baseline, protection)
	result := sourceBankReceipt(p.SourceBankPreparation)
	if err := a.applySourceBanks(context.Background(), p, p.SourceBankPreparation, protection, baseline, &result); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(sourceBankDirectory(a.Config.StateDir), "*.json"))
	path := paths[0]
	nonce := strings.TrimSuffix(filepath.Base(path), ".json")
	j, err := readManagedJournal(path, nonce)
	if err != nil {
		t.Fatal(err)
	}
	j.Phase = "activating"
	j.SourceBankPreparation.Report.Status = "preparing"
	if err := saveManagedJournal(path, j); err != nil {
		t.Fatal(err)
	}
	if err := a.sourceBankStatus(j.SourceBankPreparation.Report); err != nil {
		t.Fatal(err)
	}
	p.SourceBankPreparation.ExpiresAt = time.Now().Add(-time.Minute)
	if handled, err := a.processSourceBankPreparation(context.Background(), p); !handled || err != nil {
		t.Fatal(handled, err)
	}
	if status := ReadSourceBankPreparationStatus(a.Config.StateDir); status == nil || status.Status != "rolled_back" || len(f.sets) != 0 {
		t.Fatal("expired pending mutation falsely reported pre-write blocked", status, len(f.sets))
	}
}
