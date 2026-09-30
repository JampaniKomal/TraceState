// Package ledger is TraceState's tamper-evident audit trail: an append-only
// SQLite log in which every entry commits to the hash of the one before it.
//
// Three independent layers protect it:
//
//  1. SQLite triggers reject UPDATE and DELETE statements, so ordinary tools
//     and honest mistakes can't rewrite history.
//  2. A SHA-256 hash chain over every field of every entry (sequence number,
//     kind, timestamp, scan ID, payload, previous hash) means any edit made by
//     someone who bypasses the triggers is detected by Verify.
//  3. Ed25519 seals: `Seal` signs the current head. Someone with write access
//     to the file can recompute the whole chain, but can't forge a seal
//     without the private key, so verifying against a pinned public key
//     detects even a complete rewrite up to the last seal.
//
// Truncation after the last seal is only detectable against an external
// anchor (a head hash recorded elsewhere); see Verify's ExpectHead option.
package ledger

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver ("sqlite")
)

// SchemaVersion is stored in the meta table and checked on open.
const SchemaVersion = "2"

// Entry kinds.
const (
	KindScanStarted   = "scan_started"
	KindFinding       = "finding"
	KindScanCompleted = "scan_completed"
	KindSeal          = "seal"
)

// ErrLegacyLedger is returned when the file is a TraceState v1 ledger.
var ErrLegacyLedger = errors.New("this is a TraceState v1 ledger (audit_logs table); v2 uses a new format, so start a new ledger file (the old one remains readable with sqlite3)")

// Entry is one row of the chain.
type Entry struct {
	Seq       int64  `json:"seq"`
	Kind      string `json:"kind"`
	CreatedAt string `json:"created_at"`
	ScanID    string `json:"scan_id,omitempty"`
	Payload   string `json:"payload"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// Ledger is an open ledger file.
type Ledger struct {
	db   *sql.DB
	path string
	id   string
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
  seq        INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  scan_id    TEXT NOT NULL,
  payload    TEXT NOT NULL,
  prev_hash  TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_scan ON entries(scan_id);
CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries
BEGIN SELECT RAISE(ABORT, 'ledger entries are write-once'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
BEGIN SELECT RAISE(ABORT, 'ledger entries are write-once'); END;
CREATE TRIGGER IF NOT EXISTS meta_no_update BEFORE UPDATE ON meta
BEGIN SELECT RAISE(ABORT, 'ledger metadata is write-once'); END;
CREATE TRIGGER IF NOT EXISTS meta_no_delete BEFORE DELETE ON meta
BEGIN SELECT RAISE(ABORT, 'ledger metadata is write-once'); END;
`

// Open opens the ledger at path, creating and initialising it if it doesn't
// exist yet. Use it for commands that append (scan, seal).
func Open(ctx context.Context, path string) (*Ledger, error) {
	return open(ctx, path, true)
}

// OpenExisting opens a ledger that must already exist and never changes its
// schema. Read-only commands (verify, scans, show, export, head) use it so
// that inspecting a ledger can't create one, or silently restore write-once
// triggers that someone removed.
func OpenExisting(ctx context.Context, path string) (*Ledger, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no ledger at %s (run a scan or `tracestate ledger init` first)", path)
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a ledger file", path)
	}
	return open(ctx, path, false)
}

func open(ctx context.Context, path string, create bool) (*Ledger, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	l := &Ledger{db: db, path: path}
	if err := l.init(ctx, create); err != nil {
		_ = db.Close()
		return nil, err
	}
	return l, nil
}

func (l *Ledger) init(ctx context.Context, create bool) error {
	tables := map[string]bool{}
	rows, err := l.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return fmt.Errorf("opening ledger %s: %w", l.path, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		tables[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if tables["audit_logs"] && !tables["entries"] {
		return ErrLegacyLedger
	}
	if !tables["entries"] {
		if !create {
			return fmt.Errorf("%s is not a TraceState ledger", l.path)
		}
		return l.create(ctx)
	}
	// An existing ledger's schema is never touched again: re-running the
	// CREATE statements would quietly restore triggers an attacker dropped.
	meta := map[string]string{}
	rows, err = l.db.QueryContext(ctx, `SELECT key, value FROM meta`)
	if err != nil {
		return fmt.Errorf("reading ledger metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		meta[k] = v
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if meta["ledger_id"] == "" {
		return fmt.Errorf("ledger %s has no ledger_id (metadata was modified outside TraceState)", l.path)
	}
	if meta["schema_version"] != SchemaVersion {
		return fmt.Errorf("ledger schema version %q is not supported (want %s)", meta["schema_version"], SchemaVersion)
	}
	l.id = meta["ledger_id"]
	return nil
}

func (l *Ledger) create(ctx context.Context) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("creating ledger schema: %w", err)
	}
	id := newID()
	for _, kv := range [][2]string{
		{"ledger_id", id},
		{"schema_version", SchemaVersion},
		{"created_at", now()},
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?, ?)`, kv[0], kv[1]); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	l.id = id
	return nil
}

// Close closes the underlying database.
func (l *Ledger) Close() error { return l.db.Close() }

// ID is the random identifier assigned when the ledger was created. It is
// bound into the genesis hash, so entries can't be spliced between ledgers.
func (l *Ledger) ID() string { return l.id }

// Path returns the file the ledger was opened from.
func (l *Ledger) Path() string { return l.path }

// genesisHash is the prev_hash of entry 1.
func genesisHash(ledgerID string) string {
	sum := sha256.Sum256([]byte("tracestate-ledger-v2 genesis\n" + ledgerID))
	return hex.EncodeToString(sum[:])
}

// HashEntry computes an entry's hash. Every field is length-prefixed, so no
// two different entries can serialise to the same bytes.
func HashEntry(e Entry) string {
	h := sha256.New()
	for _, part := range []string{
		"tracestate-ledger-v2",
		strconv.FormatInt(e.Seq, 10),
		e.Kind,
		e.CreatedAt,
		e.ScanID,
		e.Payload,
		e.PrevHash,
	} {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// head returns the last entry's sequence number and hash (0 and the genesis
// hash for an empty ledger).
func (l *Ledger) head(ctx context.Context, q queryer) (int64, string, error) {
	var seq int64
	var hash string
	err := q.QueryRowContext(ctx, `SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, genesisHash(l.id), nil
	}
	return seq, hash, err
}

// Head returns the current head, suitable for anchoring outside the ledger.
func (l *Ledger) Head(ctx context.Context) (int64, string, error) { return l.head(ctx, l.db) }

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// appender adds chained entries inside one transaction.
type appender struct {
	tx   *sql.Tx
	seq  int64
	prev string
}

func (a *appender) add(ctx context.Context, kind, scanID, payload string) (Entry, error) {
	a.seq++
	e := Entry{Seq: a.seq, Kind: kind, CreatedAt: now(), ScanID: scanID, Payload: payload, PrevHash: a.prev}
	e.Hash = HashEntry(e)
	_, err := a.tx.ExecContext(ctx,
		`INSERT INTO entries(seq, kind, created_at, scan_id, payload, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Seq, e.Kind, e.CreatedAt, e.ScanID, e.Payload, e.PrevHash, e.Hash)
	if err != nil {
		return Entry{}, err
	}
	a.prev = e.Hash
	return e, nil
}

// begin starts a write transaction positioned at the current head.
func (l *Ledger) begin(ctx context.Context) (*appender, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	seq, prev, err := l.head(ctx, tx)
	if err != nil {
		rollback(tx)
		return nil, err
	}
	return &appender{tx: tx, seq: seq, prev: prev}, nil
}

// Entries returns every entry in sequence order.
func (l *Ledger) Entries(ctx context.Context) ([]Entry, error) {
	return l.query(ctx, `SELECT seq, kind, created_at, scan_id, payload, prev_hash, entry_hash FROM entries ORDER BY seq`)
}

func (l *Ledger) query(ctx context.Context, q string, args ...any) ([]Entry, error) {
	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Seq, &e.Kind, &e.CreatedAt, &e.ScanID, &e.Payload, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}

// rollback ends a transaction that may already be committed. After a commit
// it returns sql.ErrTxDone, and otherwise there is nothing useful to do with
// the error, so it is dropped.
func rollback(tx *sql.Tx) { _ = tx.Rollback() }
