package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tsledger "github.com/jampanikomal/tracestate/v2/pkg/ledger"
)

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := Execute(context.Background(), "v0.0.0-test", args, &out, &errb)
	return result{code, out.String(), errb.String()}
}

func (r result) expect(t *testing.T, code int, contains ...string) {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, code, r.stdout, r.stderr)
	}
	for _, c := range contains {
		if !strings.Contains(r.stdout+r.stderr, c) {
			t.Errorf("output lacks %q\nstdout:\n%s\nstderr:\n%s", c, r.stdout, r.stderr)
		}
	}
}

// project writes a small target with one high-severity finding (a root
// container) and one medium one (an unpinned dependency is low; CORS is medium).
func project(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"docker-compose.yml": "services:\n  api:\n    image: acme/api:1.0.0\n    user: root\n",
		"api/app.js":         "app.use(cors());\n",
	}
	for name, body := range files {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(name)), body)
	}
	return dir
}

// writeFile writes body to path, creating parent directories.
func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanExitCodesAndLedger(t *testing.T) {
	dir := project(t)
	ledger := filepath.Join(t.TempDir(), "l.db")

	run(t, "scan", dir, "--ledger", ledger).expect(t, ExitFindings,
		"TS-CTR-001", "TS-NET-001", "docker-compose.yml:4", "ledger: scan", "Findings: 2 finding(s) (1 high, 1 medium)")
	run(t, "scan", dir, "--ledger", ledger, "--fail-on", "critical").expect(t, ExitOK)
	run(t, "scan", dir, "--ledger", ledger, "--fail-on", "medium").expect(t, ExitFindings)
	run(t, "scan", dir, "--ledger", ledger, "--fail-on", "none", "-q").expect(t, ExitOK)
	run(t, "scan", dir, "--no-ledger", "--exclude", "docker-compose.yml").expect(t, ExitOK, "excluded 1 file(s)")

	r := run(t, "ledger", "scans", "--ledger", ledger)
	r.expect(t, ExitOK)
	if n := strings.Count(r.stdout, "1H 1M"); n != 4 {
		t.Errorf("expected 4 recorded scans, got %d:\n%s", n, r.stdout)
	}
	run(t, "ledger", "verify", "--ledger", ledger).expect(t, ExitOK, "OK: the chain is intact", "entries   16 (4 scans, 8 findings, 0 seals)")
}

func TestScanErrors(t *testing.T) {
	dir := project(t)
	run(t, "scan", dir, "--no-ledger", "--format", "pdf").expect(t, ExitError, `unknown format "pdf"`)
	run(t, "scan", dir, "--no-ledger", "--fail-on", "severe").expect(t, ExitError, "--fail-on")
	run(t, "scan", filepath.Join(dir, "missing"), "--no-ledger").expect(t, ExitError, "scan target")
	run(t, "scan", dir, "--no-ledger", "--rules", filepath.Join(dir, "nope.yaml")).expect(t, ExitError, "reading rules")
	run(t, "scan", dir, "--no-ledger", "--exclude", "[bad").expect(t, ExitError, "invalid exclude glob")
	run(t, "scan", dir, "extra-arg", "--no-ledger").expect(t, ExitError)
	run(t, "no-such-command").expect(t, ExitError, "unknown command")
}

func TestScanWritesEveryReport(t *testing.T) {
	dir := project(t)
	out := t.TempDir()
	p := func(n string) string { return filepath.Join(out, n) }
	run(t, "scan", dir, "--no-ledger", "-q", "--fail-on", "none", "-f", "json", "-o", p("r.json"),
		"--sarif-output", p("r.sarif"), "--markdown-output", p("r.md"), "--html-output", p("r.html")).expect(t, ExitOK)
	for name, want := range map[string]string{
		"r.json": `"findings"`, "r.sarif": `"version": "2.1.0"`, "r.md": "## Framework coverage", "r.html": "<!doctype html>",
	} {
		b, err := os.ReadFile(p(name))
		if err != nil || !strings.Contains(string(b), want) {
			t.Errorf("%s: %v, missing %q", name, err, want)
		}
	}
}

func TestCustomRulesOverrideDefaults(t *testing.T) {
	dir := project(t)
	rules := filepath.Join(t.TempDir(), "r.yaml")
	writeFile(t, rules, `version: 2
rules:
  - id: TS-CTR-001
    title: Root containers are tolerated here
    severity: low
    check: compose.user_root
    files: ["**/docker-compose.yml"]
`)
	// With the override the root container is only low, so --fail-on high passes... but CORS (medium) stays.
	run(t, "scan", dir, "--no-ledger", "--rules", rules, "--fail-on", "high").expect(t, ExitOK, "LOW       TS-CTR-001")
	run(t, "scan", dir, "--no-ledger", "--no-default-rules", "--rules", rules, "--fail-on", "low").
		expect(t, ExitFindings, "Rules:    1 failed")
}

func TestLedgerWorkflow(t *testing.T) {
	dir := project(t)
	work := t.TempDir()
	ledger := filepath.Join(work, "l.db")
	key := filepath.Join(work, "ci")

	run(t, "ledger", "verify", "--ledger", ledger).expect(t, ExitError, "no ledger at")
	run(t, "ledger", "init", "--ledger", ledger).expect(t, ExitOK, "created ledger")
	run(t, "ledger", "init", "--ledger", ledger).expect(t, ExitOK, "already exists")
	run(t, "scan", dir, "--ledger", ledger, "--fail-on", "none").expect(t, ExitOK)

	run(t, "ledger", "keygen", key).expect(t, ExitOK, "ci.key", "ci.pub")
	run(t, "ledger", "keygen", key).expect(t, ExitError, "refusing to overwrite")
	run(t, "ledger", "seal", "--ledger", ledger).expect(t, ExitError, "--key is required")
	run(t, "ledger", "seal", "--ledger", ledger, "--key", key+".key").expect(t, ExitOK, "sealed entries 1-4")
	run(t, "ledger", "verify", "--ledger", ledger, "--pubkey", key+".pub").expect(t, ExitOK, "1 of 1 valid", "pinned key")

	head := strings.TrimSpace(run(t, "ledger", "head", "--ledger", ledger).stdout)
	if !regexp.MustCompile(`^5:[0-9a-f]{64}$`).MatchString(head) {
		t.Fatalf("head = %q", head)
	}
	run(t, "ledger", "verify", "--ledger", ledger, "--expect-head", head).expect(t, ExitOK)

	show := run(t, "ledger", "show", "--ledger", ledger, "-f", "json")
	show.expect(t, ExitOK)
	var rep struct {
		ScanID   string `json:"scan_id"`
		Findings []any  `json:"findings"`
	}
	if err := json.Unmarshal([]byte(show.stdout), &rep); err != nil || len(rep.ScanID) != 32 || len(rep.Findings) != 2 {
		t.Fatalf("ledger show json: %v %+v", err, rep)
	}
	run(t, "ledger", "show", rep.ScanID[:8], "--ledger", ledger).expect(t, ExitOK, "TS-CTR-001")
	run(t, "ledger", "show", "zzzzzzzz", "--ledger", ledger).expect(t, ExitError, "no scan")

	exp := run(t, "ledger", "export", "--ledger", ledger, "-q")
	exp.expect(t, ExitOK)
	if lines := strings.Count(exp.stdout, "\n"); lines != 5 {
		t.Errorf("export wrote %d lines, want 5", lines)
	}
	// Each line is self-contained: it names its ledger, and its hash can be
	// recomputed from the exported fields alone.
	var first struct {
		LedgerID string `json:"ledger_id"`
		tsledger.Entry
	}
	if err := json.Unmarshal([]byte(strings.SplitN(exp.stdout, "\n", 2)[0]), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.LedgerID) != 32 || first.Seq != 1 || tsledger.HashEntry(first.Entry) != first.Hash {
		t.Errorf("exported entry doesn't verify on its own: %+v", first)
	}

	// Tamper with the file directly: verification must now fail with exit 1.
	db, err := sql.Open("sqlite", ledger)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP TRIGGER entries_no_update`,
		`UPDATE entries SET payload = replace(payload, 'root', 'r00t') WHERE seq = 2`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	run(t, "ledger", "verify", "--ledger", ledger, "--pubkey", key+".pub").
		expect(t, ExitFindings, "TAMPERING DETECTED", "content modified", "triggers  MISSING")
	j := run(t, "ledger", "verify", "--ledger", ledger, "-f", "json")
	if j.code != ExitFindings || !strings.Contains(j.stdout, `"triggers_intact": false`) {
		t.Errorf("json verify: %d\n%s", j.code, j.stdout)
	}
}

func TestLedgerEnvDefault(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "env.db")
	t.Setenv("TRACESTATE_LEDGER", ledger)
	run(t, "scan", project(t), "--fail-on", "none", "-q").expect(t, ExitOK)
	if _, err := os.Stat(ledger); err != nil {
		t.Fatalf("TRACESTATE_LEDGER not honoured: %v", err)
	}
}

func TestRulesCommands(t *testing.T) {
	run(t, "rules", "list").expect(t, ExitOK, "TS-CTR-001", "compose.user_root", "rules from builtin:default_rules.yaml")
	run(t, "rules", "show", "ts-sec-003").expect(t, ExitOK, "TS-SEC-003", "Remediation", "ISO27001")
	run(t, "rules", "show", "NOPE-1").expect(t, ExitError, `no rule "NOPE-1"`)
	run(t, "rules", "validate").expect(t, ExitOK, "ok    builtin:default_rules.yaml")
	run(t, "rules", "checks").expect(t, ExitOK, "compose\n  compose.datastore_bind_mount", "regex.absent")

	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	writeFile(t, good, "version: 2\nrules:\n  - {id: X-1, title: t, severity: low, check: regex.match, files: ['*'], pattern: x}\n")
	writeFile(t, bad, "version: 2\nrules:\n  - {id: X-1, title: t, severity: low, check: regex.match, files: ['*'], pattern: '('}\n")
	run(t, "rules", "validate", good).expect(t, ExitOK, "ok    "+good+" (1 rules)")
	run(t, "rules", "validate", good, bad).expect(t, ExitFindings, "FAIL  "+bad, "invalid pattern")

	export := run(t, "rules", "export")
	export.expect(t, ExitOK, "version: 2")
	exported := filepath.Join(dir, "exported.yaml")
	writeFile(t, exported, export.stdout)
	run(t, "rules", "validate", exported).expect(t, ExitOK)

	var list []map[string]any
	if err := json.Unmarshal([]byte(run(t, "rules", "list", "-f", "json").stdout), &list); err != nil || len(list) < 30 {
		t.Errorf("rules list json: %v (%d rules)", err, len(list))
	}
}

func TestFrameworksCommand(t *testing.T) {
	run(t, "frameworks", "dpdpa").expect(t, ExitOK, "Digital Personal Data Protection Act", "TS-DAT-001")
	run(t, "frameworks", "NOPE").expect(t, ExitError, `unknown framework "NOPE"`)
	md := run(t, "frameworks", "--format", "markdown")
	md.expect(t, ExitOK, "# Framework mapping", "## ISO/IEC 27001:2022 Annex A", "| `A.8.2` |")
}

func TestVersion(t *testing.T) {
	run(t, "version").expect(t, ExitOK, "tracestate v0.0.0-test")
	run(t, "--version").expect(t, ExitOK, "tracestate v0.0.0-test")
}
