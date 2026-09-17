package worm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jampanikomal/tracestate/pkg/scanner"
)

// withTestLedger points the package-level ledgerPath at a fresh temp file
// for the duration of the test, restoring the original afterward.
func withTestLedger(t *testing.T) {
	t.Helper()
	previous := ledgerPath
	ledgerPath = filepath.Join(t.TempDir(), "audit_ledger.db")
	t.Cleanup(func() { ledgerPath = previous })
}

func TestInitDB(t *testing.T) {
	withTestLedger(t)

	if err := InitializeLedger(); err != nil {
		t.Fatalf("failed to initialize ledger: %v", err)
	}

	db, err := openLedger()
	if err != nil {
		t.Fatalf("failed to open WORM database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("failed to connect to WORM database: %v", err)
	}

	if _, err := os.Stat(ledgerPath); err != nil {
		t.Fatalf("expected test ledger file to exist: %v", err)
	}
}

func TestHashChainLinksSequentialEntries(t *testing.T) {
	withTestLedger(t)
	if err := InitializeLedger(); err != nil {
		t.Fatalf("InitializeLedger: %v", err)
	}

	findings := []scanner.Finding{
		{File: "docker-compose.yml", Category: "infrastructure", Framework: "ISO-27001", Message: "first finding"},
		{File: "src/api.py", Category: "code", Framework: "ISO-27001", Message: "second finding"},
		{File: "logs/app_audit.log", Category: "telemetry", Framework: "DPDPA", Message: "third finding"},
	}
	for _, f := range findings {
		if err := LogViolation(f); err != nil {
			t.Fatalf("LogViolation(%v): %v", f, err)
		}
	}

	db, err := openLedger()
	if err != nil {
		t.Fatalf("openLedger: %v", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT prev_hash, row_hash FROM audit_logs ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var prevRowHash string
	i := 0
	for rows.Next() {
		var prevHash, rowHash string
		if err := rows.Scan(&prevHash, &rowHash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if i == 0 {
			if prevHash != "GENESIS" {
				t.Errorf("expected first row's prev_hash to be GENESIS, got %q", prevHash)
			}
		} else if prevHash != prevRowHash {
			t.Errorf("row %d: prev_hash %q does not match previous row's row_hash %q", i, prevHash, prevRowHash)
		}
		prevRowHash = rowHash
		i++
	}
	if i != len(findings) {
		t.Fatalf("expected %d rows, found %d", len(findings), i)
	}
}

func TestVerifyLedgerPassesForIntactChain(t *testing.T) {
	withTestLedger(t)
	if err := InitializeLedger(); err != nil {
		t.Fatalf("InitializeLedger: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := LogViolation(scanner.Finding{File: "f", Category: "c", Framework: "ISO-27001", Message: "m"}); err != nil {
			t.Fatalf("LogViolation: %v", err)
		}
	}

	ok, err := VerifyLedger()
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if !ok {
		t.Fatal("expected an untampered ledger to verify as intact")
	}
}

func TestAuditLogsCannotBeUpdated(t *testing.T) {
	withTestLedger(t)
	if err := InitializeLedger(); err != nil {
		t.Fatalf("InitializeLedger: %v", err)
	}
	if err := LogViolation(scanner.Finding{File: "f", Category: "c", Framework: "ISO-27001", Message: "original"}); err != nil {
		t.Fatalf("LogViolation: %v", err)
	}

	db, err := openLedger()
	if err != nil {
		t.Fatalf("openLedger: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE audit_logs SET message = 'tampered' WHERE id = 1`)
	if err == nil {
		t.Fatal("expected UPDATE against the WORM table to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), "write-once") {
		t.Fatalf("expected a write-once trigger error, got: %v", err)
	}
}

func TestAuditLogsCannotBeDeleted(t *testing.T) {
	withTestLedger(t)
	if err := InitializeLedger(); err != nil {
		t.Fatalf("InitializeLedger: %v", err)
	}
	if err := LogViolation(scanner.Finding{File: "f", Category: "c", Framework: "ISO-27001", Message: "original"}); err != nil {
		t.Fatalf("LogViolation: %v", err)
	}

	db, err := openLedger()
	if err != nil {
		t.Fatalf("openLedger: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`DELETE FROM audit_logs WHERE id = 1`)
	if err == nil {
		t.Fatal("expected DELETE against the WORM table to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), "write-once") {
		t.Fatalf("expected a write-once trigger error, got: %v", err)
	}
}

// TestVerifyLedgerDetectsTrustedPathTampering models an attacker with
// direct file-level access to the SQLite database: the WORM triggers
// only stop ordinary UPDATE/DELETE statements (proven by the two tests
// above), but a trigger is just metadata in the same file, not something
// a file-level attacker is bound by. This confirms the hash chain itself
// - not just the trigger - is what actually catches tampering, by
// dropping the trigger, editing a row directly, and checking that
// VerifyLedger still flags it.
func TestVerifyLedgerDetectsTrustedPathTampering(t *testing.T) {
	withTestLedger(t)
	if err := InitializeLedger(); err != nil {
		t.Fatalf("InitializeLedger: %v", err)
	}
	if err := LogViolation(scanner.Finding{File: "f", Category: "c", Framework: "ISO-27001", Message: "original"}); err != nil {
		t.Fatalf("LogViolation: %v", err)
	}
	if err := LogViolation(scanner.Finding{File: "f2", Category: "c", Framework: "ISO-27001", Message: "second"}); err != nil {
		t.Fatalf("LogViolation: %v", err)
	}

	db, err := openLedger()
	if err != nil {
		t.Fatalf("openLedger: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`DROP TRIGGER audit_logs_no_update`); err != nil {
		t.Fatalf("failed to drop trigger for test setup: %v", err)
	}
	if _, err := db.Exec(`UPDATE audit_logs SET message = 'tampered' WHERE id = 1`); err != nil {
		t.Fatalf("failed to simulate a direct file-level tamper: %v", err)
	}
	db.Close()

	ok, err := VerifyLedger()
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if ok {
		t.Fatal("expected VerifyLedger to detect a tampered row via the hash chain, but it reported the ledger as intact")
	}
}

func TestExportLedgerJSON(t *testing.T) {
	withTestLedger(t)
	if err := InitializeLedger(); err != nil {
		t.Fatalf("InitializeLedger: %v", err)
	}
	want := scanner.Finding{File: "docker-compose.yml", Category: "infrastructure", Framework: "ISO-27001", Message: "containers must not run as root"}
	if err := LogViolation(want); err != nil {
		t.Fatalf("LogViolation: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "report.json")
	if err := ExportLedgerJSON(outputPath); err != nil {
		t.Fatalf("ExportLedgerJSON: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading exported report: %v", err)
	}

	var records []struct {
		File      string `json:"file"`
		Category  string `json:"category"`
		Framework string `json:"framework"`
		Message   string `json:"message"`
		PrevHash  string `json:"prev_hash"`
		RowHash   string `json:"row_hash"`
	}
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatalf("unmarshaling exported report: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 exported record, got %d", len(records))
	}
	r := records[0]
	if r.File != want.File || r.Category != want.Category || r.Framework != want.Framework || r.Message != want.Message {
		t.Errorf("exported record %+v does not match logged finding %+v", r, want)
	}
	if r.PrevHash != "GENESIS" || r.RowHash == "" {
		t.Errorf("expected a GENESIS prev_hash and a non-empty row_hash, got prev=%q row=%q", r.PrevHash, r.RowHash)
	}
}
