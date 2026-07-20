package worm

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jampanikomal/tracestate/pkg/scanner"
	_ "github.com/mattn/go-sqlite3"
)

const ledgerPath = "audit_ledger.db"

func InitializeLedger() error {
	db, err := openLedger()
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  file TEXT NOT NULL,
  category TEXT NOT NULL,
  framework TEXT NOT NULL,
  message TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  row_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs table is write-once');
END;
CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs table is write-once');
END;
`)

	return err
}

func LogViolation(finding scanner.Finding) error {
	db, err := openLedger()
	if err != nil {
		return err
	}
	defer db.Close()

	prevHash, err := lastHash(db)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(finding)
	if err != nil {
		return err
	}

	rowHash := sha256.Sum256(append([]byte(prevHash), payload...))
	_, err = db.Exec(`INSERT INTO audit_logs(created_at, file, category, framework, message, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), finding.File, finding.Category, finding.Framework, finding.Message, prevHash, hex.EncodeToString(rowHash[:]))
	if err != nil {
		return err
	}

	fmt.Printf("[+] Ledgered: %s\n", finding.Message)
	return nil
}

func VerifyLedger() (bool, error) {
	db, err := openLedger()
	if err != nil {
		return false, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, file, category, framework, message, prev_hash, row_hash FROM audit_logs ORDER BY id ASC`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	prevHash := "GENESIS"
	for rows.Next() {
		var id int
		var file, category, framework, message, storedPrevHash, storedRowHash string
		if err := rows.Scan(&id, &file, &category, &framework, &message, &storedPrevHash, &storedRowHash); err != nil {
			return false, err
		}
		if storedPrevHash != prevHash {
			return false, nil
		}
		finding := scanner.Finding{File: file, Category: category, Framework: framework, Message: message}
		payload, err := json.Marshal(finding)
		if err != nil {
			return false, err
		}
		computed := sha256.Sum256(append([]byte(prevHash), payload...))
		if hex.EncodeToString(computed[:]) != storedRowHash {
			return false, nil
		}
		prevHash = storedRowHash
	}
	return true, rows.Err()
}

func openLedger() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ledgerPath)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func lastHash(db *sql.DB) (string, error) {
	var hash sql.NullString
	err := db.QueryRow(`SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "GENESIS", nil
	}
	if err != nil {
		return "", err
	}
	if !hash.Valid {
		return "GENESIS", nil
	}
	return hash.String, nil
}
