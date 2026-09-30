package ledger

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/report"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

var ctx = context.Background()

func sampleReport(target string, n int) *report.Report {
	r := &report.Report{
		Tool: report.ToolName, Version: "test", Target: target, StartedAt: time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC),
		DurationMS: 12, FilesIndexed: 3, RuleSetSHA256: "abc", RuleSources: []string{policy.DefaultRulesName},
		Findings: []finding.Finding{},
		Rules: []report.RuleOutcome{
			{ID: "TS-CTR-001", Title: "Container runs as root", Severity: policy.High, Check: "compose.user_root",
				Status: scanner.Failed, FilesMatched: 1, Findings: n},
			{ID: "TS-CTR-002", Title: "Privileged container", Severity: policy.Critical, Check: "compose.privileged",
				Status: scanner.Passed, FilesMatched: 1},
		},
	}
	for i := 0; i < n; i++ {
		r.Findings = append(r.Findings, finding.Finding{
			RuleID: "TS-CTR-001", Title: "Container runs as root", Severity: policy.High, Wire: "compose",
			File: "docker-compose.yml", Line: 3 + i, Message: "service runs as root", Evidence: "user: root",
			Fingerprint: strings.Repeat("f", 31) + string(rune('0'+i)),
		})
	}
	return r
}

// newLedger returns a ledger of 11 entries: scan A (entries 1-4, two
// findings), scan B (5-7, one finding), a seal by the returned key (8,
// covering 1-7) and scan C (9-11), recorded after the seal.
func newLedger(t *testing.T) (*Ledger, ed25519.PrivateKey) {
	t.Helper()
	l, err := Open(ctx, filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if _, err := l.RecordScan(ctx, sampleReport("/a", 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.RecordScan(ctx, sampleReport("/b", 1)); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := l.Seal(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := l.RecordScan(ctx, sampleReport("/c", 1)); err != nil {
		t.Fatal(err)
	}
	return l, key
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func mustVerify(t *testing.T, l *Ledger, opts VerifyOptions) *VerifyReport {
	t.Helper()
	rep, err := l.Verify(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func problems(rep *VerifyReport) string {
	var s []string
	for _, p := range rep.Problems {
		s = append(s, p.Reason)
	}
	return strings.Join(s, "\n")
}

func TestRecordVerifyAndReload(t *testing.T) {
	l, key := newLedger(t)
	rep := mustVerify(t, l, VerifyOptions{TrustedKey: pub(key)})
	if !rep.OK() {
		t.Fatalf("fresh ledger fails verification:\n%s", problems(rep))
	}
	if rep.Entries != 11 || rep.Scans != 3 || rep.Findings != 4 || rep.Seals != 1 || rep.SealsVerified != 1 ||
		rep.SealedThrough != 7 || rep.HeadSeq != 11 || !rep.TriggersIntact {
		t.Errorf("unexpected report: %+v", rep)
	}

	scans, err := l.Scans(ctx)
	if err != nil || len(scans) != 3 {
		t.Fatalf("scans = %v, %v", scans, err)
	}
	if s := scans[0]; s.Target != "/a" || s.Findings != 2 || s.FirstSeq != 1 || s.LastSeq != 4 || !s.Complete {
		t.Errorf("scan A = %+v", s)
	}
	latest, err := l.ResolveScan(ctx, "latest")
	if err != nil || latest != scans[2].ID {
		t.Errorf("latest = %s, %v", latest, err)
	}
	if id, err := l.ResolveScan(ctx, scans[0].ID[:8]); err != nil || id != scans[0].ID {
		t.Errorf("prefix lookup = %s, %v", id, err)
	}
	if _, err := l.ResolveScan(ctx, "abc"); err == nil {
		t.Error("short prefix accepted")
	}

	got, err := l.LoadScan(ctx, scans[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	want := sampleReport("/a", 2)
	if got.Target != want.Target || len(got.Findings) != 2 || got.Findings[1].Line != 4 ||
		got.Findings[0].Fingerprint != want.Findings[0].Fingerprint || len(got.Rules) != 2 ||
		got.Rules[0].Status != scanner.Failed || !got.StartedAt.Equal(want.StartedAt) {
		t.Errorf("reloaded report differs: %+v", got)
	}
}

func TestTriggersRejectRewrites(t *testing.T) {
	l, _ := newLedger(t)
	for _, q := range []string{
		`UPDATE entries SET payload = '{}' WHERE seq = 2`,
		`DELETE FROM entries WHERE seq = 11`,
		`UPDATE meta SET value = 'x' WHERE key = 'ledger_id'`,
		`DELETE FROM meta`,
	} {
		if _, err := l.db.Exec(q); err == nil || !strings.Contains(err.Error(), "write-once") {
			t.Errorf("%s: err = %v", q, err)
		}
	}
}

// raw runs statements with the write-once triggers removed and then puts
// them back, as an attacker covering their tracks would.
func raw(t *testing.T, l *Ledger, stmts ...string) {
	t.Helper()
	for _, q := range append(append([]string{
		`DROP TRIGGER entries_no_update`, `DROP TRIGGER entries_no_delete`,
		`DROP TRIGGER meta_no_update`, `DROP TRIGGER meta_no_delete`,
	}, stmts...), schemaTriggers...) {
		if _, err := l.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

var schemaTriggers = []string{
	`CREATE TRIGGER entries_no_update BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'ledger entries are write-once'); END`,
	`CREATE TRIGGER entries_no_delete BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT, 'ledger entries are write-once'); END`,
	`CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'ledger metadata is write-once'); END`,
	`CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta BEGIN SELECT RAISE(ABORT, 'ledger metadata is write-once'); END`,
}

func TestTamperDetection(t *testing.T) {
	cases := []struct {
		name  string
		stmts []string
		want  []string
	}{
		{"downgraded finding severity", []string{
			`UPDATE entries SET payload = replace(payload, '"high"', '"low"') WHERE seq = 2`},
			[]string{"content modified"}},
		{"backdated timestamp", []string{
			`UPDATE entries SET created_at = '2020-01-01T00:00:00Z' WHERE seq = 6`},
			[]string{"content modified"}},
		{"moved finding to another scan", []string{
			`UPDATE entries SET scan_id = (SELECT scan_id FROM entries WHERE seq = 5) WHERE seq = 3`},
			[]string{"content modified"}},
		{"deleted finding", []string{`DELETE FROM entries WHERE seq = 3`},
			[]string{"sequence gap", "broken chain"}},
		{"reordered entries", []string{
			`UPDATE entries SET seq = 100 WHERE seq = 2`,
			`UPDATE entries SET seq = 2 WHERE seq = 3`,
			`UPDATE entries SET seq = 3 WHERE seq = 100`},
			[]string{"broken chain", "content modified"}},
		{"inserted forged entry", []string{
			`INSERT INTO entries(seq, kind, created_at, scan_id, payload, prev_hash, entry_hash)
			 SELECT 12, 'finding', created_at, scan_id, '{}', entry_hash, 'forged' FROM entries WHERE seq = 11`},
			[]string{"content modified"}},
		{"swapped ledger id", []string{`UPDATE meta SET value = 'someone-else' WHERE key = 'ledger_id'`},
			[]string{"broken chain"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, key := newLedger(t)
			raw(t, l, c.stmts...)
			if c.name == "swapped ledger id" { // the ID is read at open time
				l2, err := OpenExisting(ctx, l.Path())
				if err != nil {
					t.Fatal(err)
				}
				defer l2.Close()
				l = l2
			}
			rep := mustVerify(t, l, VerifyOptions{TrustedKey: pub(key)})
			if rep.OK() {
				t.Fatal("tampering went undetected")
			}
			for _, w := range c.want {
				if !strings.Contains(problems(rep), w) {
					t.Errorf("problems lack %q:\n%s", w, problems(rep))
				}
			}
		})
	}
}

func TestDroppedTriggersAreReportedAndNotRepaired(t *testing.T) {
	l, _ := newLedger(t)
	if _, err := l.db.Exec(`DROP TRIGGER entries_no_delete`); err != nil {
		t.Fatal(err)
	}
	path := l.Path()
	l.Close()
	// Reopening, even for writing, must not quietly recreate the trigger.
	for _, open := range []func(context.Context, string) (*Ledger, error){Open, OpenExisting} {
		l2, err := open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		rep := mustVerify(t, l2, VerifyOptions{})
		l2.Close()
		if rep.TriggersIntact || !strings.Contains(problems(rep), "1 of 4 write-once triggers are missing") {
			t.Errorf("missing trigger not reported: %+v", rep)
		}
	}
}

// rewrite replaces the whole chain with a consistent one built from entries
// (after mutate), re-signing any seal with signer (or dropping seals when
// signer is nil). This is what an attacker with write access to the file can
// do; only a pinned key or an external anchor can catch it.
func rewrite(t *testing.T, l *Ledger, signer ed25519.PrivateKey, mutate func([]Entry) []Entry) {
	t.Helper()
	entries, err := l.Entries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entries = mutate(entries)
	var stmts []string
	stmts = append(stmts, `DELETE FROM entries`)
	prev, seq := genesisHash(l.id), int64(0)
	for _, e := range entries {
		if e.Kind == KindSeal {
			if signer == nil {
				continue
			}
			p := sealPayload{HeadSeq: seq, HeadHash: prev, PublicKey: hex.EncodeToString(pub(signer))}
			p.Signature = hex.EncodeToString(ed25519.Sign(signer, sealMessage(l.id, seq, prev)))
			b, _ := json.Marshal(p)
			e.Payload = string(b)
		}
		seq++
		e.Seq, e.PrevHash = seq, prev
		e.Hash = HashEntry(e)
		prev = e.Hash
		stmts = append(stmts, `INSERT INTO entries VALUES (`+
			strings.Join([]string{strconv.FormatInt(e.Seq, 10), q(e.Kind), q(e.CreatedAt), q(e.ScanID), q(e.Payload), q(e.PrevHash), q(e.Hash)}, ",")+`)`)
	}
	raw(t, l, stmts...)
}

func q(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func TestFullRewriteNeedsPinnedKeyOrAnchor(t *testing.T) {
	downgrade := func(es []Entry) []Entry {
		for i := range es {
			es[i].Payload = strings.ReplaceAll(es[i].Payload, `"high"`, `"low"`)
		}
		return es
	}
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("re-signed with the attacker's key", func(t *testing.T) {
		l, key := newLedger(t)
		seq, head, _ := l.Head(ctx)
		rewrite(t, l, attacker, downgrade)
		// Internally consistent: without a pinned key this is undetectable.
		if rep := mustVerify(t, l, VerifyOptions{}); !rep.OK() {
			t.Fatalf("a consistent rewrite should pass unpinned verification:\n%s", problems(rep))
		}
		rep := mustVerify(t, l, VerifyOptions{TrustedKey: pub(key)})
		if !strings.Contains(problems(rep), "isn't the trusted key") {
			t.Errorf("pinned key did not catch the re-signed rewrite:\n%s", problems(rep))
		}
		anchored := mustVerify(t, l, VerifyOptions{ExpectHead: formatAnchor(seq, head)})
		if !strings.Contains(problems(anchored), "different hash") {
			t.Errorf("anchor did not catch the rewrite:\n%s", problems(anchored))
		}
	})

	t.Run("seals dropped", func(t *testing.T) {
		l, key := newLedger(t)
		rewrite(t, l, nil, downgrade)
		rep := mustVerify(t, l, VerifyOptions{TrustedKey: pub(key)})
		if !strings.Contains(problems(rep), "no valid seal by the trusted key") {
			t.Errorf("pinned key did not catch a rewrite without seals:\n%s", problems(rep))
		}
	})

	t.Run("genuine seal kept over rewritten history", func(t *testing.T) {
		l, key := newLedger(t)
		entries, _ := l.Entries(ctx)
		sealPayloadText := entries[7].Payload
		rewrite(t, l, key, func(es []Entry) []Entry { return downgrade(es) })
		// Put the original (now mismatching) seal back in place of the re-signed one.
		raw(t, l, `UPDATE entries SET payload = `+q(sealPayloadText)+` WHERE seq = 8`)
		rep := mustVerify(t, l, VerifyOptions{TrustedKey: pub(key)})
		if !strings.Contains(problems(rep), "doesn't match the chain") {
			t.Errorf("stale seal not detected:\n%s", problems(rep))
		}
	})
}

func TestTruncationNeedsAnchor(t *testing.T) {
	l, key := newLedger(t)
	seq, head, _ := l.Head(ctx)
	raw(t, l, `DELETE FROM entries WHERE seq > 8`) // drop scan C, which came after the seal
	if rep := mustVerify(t, l, VerifyOptions{TrustedKey: pub(key)}); !rep.OK() {
		t.Fatalf("truncating unsealed entries can't be seen without an anchor, got:\n%s", problems(rep))
	}
	rep := mustVerify(t, l, VerifyOptions{TrustedKey: pub(key), ExpectHead: formatAnchor(seq, head)})
	if !strings.Contains(problems(rep), "missing (ledger truncated)") {
		t.Errorf("anchor did not catch truncation:\n%s", problems(rep))
	}
	// A bare hash anchor works too.
	if rep := mustVerify(t, l, VerifyOptions{ExpectHead: head}); !strings.Contains(problems(rep), "not found") {
		t.Errorf("bare-hash anchor did not catch truncation:\n%s", problems(rep))
	}
	if rep := mustVerify(t, l, VerifyOptions{ExpectHead: "nonsense:abc"}); !strings.Contains(problems(rep), "invalid anchor") {
		t.Errorf("bad anchor accepted:\n%s", problems(rep))
	}
}

func formatAnchor(seq int64, hash string) string { return strconv.FormatInt(seq, 10) + ":" + hash }

func TestLegacyAndMissingLedgers(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "audit_ledger.db")
	db, err := sql.Open("sqlite", legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, timestamp TEXT, rule_id TEXT, current_hash TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(ctx, legacy); !errors.Is(err, ErrLegacyLedger) {
		t.Errorf("legacy ledger: err = %v", err)
	}
	missing := filepath.Join(dir, "nope.db")
	if _, err := OpenExisting(ctx, missing); err == nil || !strings.Contains(err.Error(), "no ledger at") {
		t.Errorf("missing ledger: err = %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("OpenExisting created a file")
	}
	other := filepath.Join(dir, "other.db")
	db, _ = sql.Open("sqlite", other)
	if _, err := db.Exec(`CREATE TABLE t (x)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := OpenExisting(ctx, other); err == nil || !strings.Contains(err.Error(), "not a TraceState ledger") {
		t.Errorf("foreign sqlite file: err = %v", err)
	}
}

func TestKeys(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "ci")
	pubPath, keyPath, err := GenerateKeyPair(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateKeyPair(prefix); err == nil {
		t.Error("GenerateKeyPair overwrote an existing key")
	}
	priv, err := ReadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := ParsePublicKey(pubPath)
	if err != nil || !fromFile.Equal(pub(priv)) {
		t.Fatalf("public key from file: %v", err)
	}
	fromHex, err := ParsePublicKey(hex.EncodeToString(pub(priv)))
	if err != nil || !fromHex.Equal(pub(priv)) {
		t.Fatalf("public key from hex: %v", err)
	}
	if _, err := ParsePublicKey("zz"); err == nil {
		t.Error("garbage public key accepted")
	}
	if _, err := ReadPrivateKey(pubPath); err == nil {
		// A .pub file holds 32 bytes, which happens to be a valid seed length;
		// make sure at least a non-hex file is rejected.
		if err := os.WriteFile(pubPath, []byte("not hex"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPrivateKey(pubPath); err == nil {
			t.Error("garbage private key accepted")
		}
	}
}

func TestEmptyLedgerVerifies(t *testing.T) {
	l, err := Open(ctx, filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	rep := mustVerify(t, l, VerifyOptions{})
	if !rep.OK() || rep.Entries != 0 || rep.HeadHash != genesisHash(l.ID()) {
		t.Errorf("empty ledger: %+v", rep)
	}
	if _, err := l.ResolveScan(ctx, "latest"); err == nil {
		t.Error("ResolveScan on an empty ledger should fail")
	}
}
