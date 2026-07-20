package worm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitDB(t *testing.T) {
	previousLedgerPath := ledgerPath
	ledgerPath = filepath.Join(t.TempDir(), "audit_ledger.db")
	defer func() { ledgerPath = previousLedgerPath }()

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
