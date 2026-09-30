package wires_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jampanikomal/tracestate/v2/pkg/detect"
	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
	_ "github.com/jampanikomal/tracestate/v2/pkg/wires"
)

// scan writes files into a temporary directory and runs the complete default
// rule pack over it. Running every rule (not just the one under test) means
// each fixture also checks that no other rule misfires on it.
func scan(t *testing.T, files map[string]string, opts scanner.Options) []finding.Finding {
	t.Helper()
	root := writeTree(t, files)
	rs, err := policy.DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	tg, err := scanner.NewTarget(root)
	if err != nil {
		t.Fatal(err)
	}
	res, err := scanner.Run(context.Background(), tg, rs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res.Findings
}

// writeTree creates files (slash-separated paths) under a new temp directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// keys renders findings as "RULE file:line", sorted.
func keys(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s %s:%d", f.RuleID, f.File, f.Line))
	}
	sort.Strings(out)
	return out
}

func expect(t *testing.T, got []finding.Finding, want ...string) {
	t.Helper()
	sort.Strings(want)
	g := keys(got)
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings differ\n got:\n  %s\nwant:\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
		for _, f := range got {
			t.Logf("  %s %s:%d %s [%s]", f.RuleID, f.File, f.Line, f.Message, f.Evidence)
		}
	}
}

func find(fs []finding.Finding, rule string) *finding.Finding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}

func lines(ls ...string) string { return strings.Join(ls, "\n") + "\n" }

func TestComposeInsecure(t *testing.T) {
	got := scan(t, map[string]string{"deploy/docker-compose.yml": lines(
		"services:", // 1
		"  api:",
		"    image: acme/api:latest", // 3  TS-CTR-005
		"    user: root",             // 4  TS-CTR-001
		"    privileged: true",       // 5  TS-CTR-002
		"    network_mode: host",     // 6  TS-CTR-004
		"    volumes:",
		"      - /var/run/docker.sock:/var/run/docker.sock", // 8 TS-CTR-003
		"    environment:",
		"      - DB_PASSWORD=hunter2hunter2", // 10 TS-CTR-006
		"      - LOG_LEVEL=debug",
		"      - TOKEN_TYPE=bearer",
		"      - SECRET_KEY=${SECRET_KEY}",
		"  db:",
		"    image: postgres", // 15 TS-CTR-005
		"    ports:",
		`      - "5432:5432"`, // 17 TS-CTR-008
		"    volumes:",
		"      - ./pgdata:/var/lib/postgresql/data", // 19 TS-CTR-007
		"    environment:",
		"      POSTGRES_HOST_AUTH_METHOD: trust", // 21 TS-CTR-009
		"  search:",
		"    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0",
		"    ports:",
		`      - "127.0.0.1:9200:9200"`,
		`      - "[::1]:9300:9300"`,
		"    environment:",
		"      - xpack.security.enabled=false", // 28 TS-CTR-009
	)}, scanner.Options{})
	f := "deploy/docker-compose.yml"
	expect(t, got,
		"TS-CTR-005 "+f+":3", "TS-CTR-001 "+f+":4", "TS-CTR-002 "+f+":5", "TS-CTR-004 "+f+":6",
		"TS-CTR-003 "+f+":8", "TS-CTR-006 "+f+":10", "TS-CTR-005 "+f+":15", "TS-CTR-008 "+f+":17",
		"TS-CTR-007 "+f+":19", "TS-CTR-009 "+f+":21", "TS-CTR-009 "+f+":28",
	)
	if s := find(got, "TS-CTR-006"); s == nil || strings.Contains(s.Evidence, "hunter2hunter2") {
		t.Errorf("secret value leaked into evidence: %+v", s)
	}
}

func TestComposeHardened(t *testing.T) {
	got := scan(t, map[string]string{"compose.yaml": lines(
		"services:",
		"  api:",
		"    image: ghcr.io/acme/api:1.4.2",
		`    user: "10001:10001"`,
		"    read_only: true",
		"    environment:",
		"      DB_PASSWORD_FILE: /run/secrets/db_password",
		"      API_KEY: ${API_KEY}",
		"    secrets: [db_password]",
		"  db:",
		"    image: registry.local:5000/postgres:16.4@sha256:0123456789abcdef",
		"    ports:",
		`      - "127.0.0.1:5432:5432"`,
		"      - target: 5433",
		"        published: 5433",
		"        host_ip: 127.0.0.1",
		"    volumes:",
		"      - pgdata:/var/lib/postgresql/data",
		"volumes:",
		"  pgdata: {}",
	)}, scanner.Options{})
	expect(t, got)
}

func TestDockerfile(t *testing.T) {
	got := scan(t, map[string]string{
		"Dockerfile": lines(
			"FROM python:latest AS build",                              // 1 TS-IMG-002
			"RUN curl -fsSL https://get.example.com/install.sh | bash", // 2 TS-IMG-005
			"FROM build AS test",
			"FROM ubuntu",                       // 4 TS-IMG-002, TS-IMG-001 (final stage, no USER)
			"ENV API_TOKEN=abcd1234efgh5678 \\", // 5 TS-IMG-004
			"    LOG_LEVEL=info",
			"ADD https://example.com/tool.tar.gz /opt/", // 7 TS-IMG-003
		),
		"svc/Dockerfile.prod": lines(
			"FROM golang:1.26 AS build",
			"COPY . .",
			"RUN go build -o /app ./cmd/app",
			"FROM gcr.io/distroless/static-debian12:nonroot",
			"COPY --from=build /app /app",
			"ARG VERSION=dev",
			"ENV TOKEN_ENDPOINT=https://auth.example.com/token",
			"ADD --checksum=sha256:0123 https://example.com/x.tar.gz /x",
			"USER 65532:65532",
			`ENTRYPOINT ["/app"]`,
		),
		"worker.Dockerfile": lines(
			"FROM alpine:3.20",
			"USER root", // 2 TS-IMG-001
		),
	}, scanner.Options{})
	expect(t, got,
		"TS-IMG-002 Dockerfile:1", "TS-IMG-005 Dockerfile:2", "TS-IMG-002 Dockerfile:4", "TS-IMG-001 Dockerfile:4",
		"TS-IMG-004 Dockerfile:5", "TS-IMG-003 Dockerfile:7", "TS-IMG-001 worker.Dockerfile:2",
	)
}

func TestSecrets(t *testing.T) {
	// Token-shaped strings are assembled at run time so the repository never
	// contains anything a secret scanner (including GitHub's) would flag.
	awsKey := "AKIA" + "QWERTYUIOPASDFGH"
	ghToken := "ghp" + "_" + strings.Repeat("a1B2c3", 6)
	pemHeader := "-----BEGIN " + "RSA PRIVATE KEY-----"

	got := scan(t, map[string]string{
		"app/config.py": lines(
			"import os",
			`DB_PASSWORD = os.getenv("DB_PASSWORD", "s3cr3t-pass")`, // 2 TS-SEC-003
			`API_KEY = "sk_test_placeholder"`,
			`password_label = "Enter your password"`,
			`SECRET_KEY = os.environ["SECRET_KEY"]`,
			`AWS_ACCESS_KEY_ID = "`+awsKey+`"`, // 6 TS-SEC-001 (an *_ID name is an identifier, not TS-SEC-003)
			`TOKEN_TYPE = "bearer-token"`,
		),
		"app/server.js": lines(
			`const dbPass = process.env.DB_PASS || 'fallbackpass1';`, // 1 TS-SEC-003
			`const pageSize = process.env.PAGE_SIZE || '50';`,
			`if (req.headers.authorization === 'Bearer abcdef123456') { next(); }`, // 3 TS-SEC-005
			`if (apiKey == "live-key-123456") { next(); }`,                         // 4 TS-SEC-005
			`const header = "Authorization: Bearer " + token;`,
		),
		"public/app.js":       `const API_TOKEN = "abcd1234abcd1234";` + "\n", // 1 TS-SEC-004
		"ci/deploy.sh":        "export GH_TOKEN=" + ghToken + "\n",            // 1 TS-SEC-001
		"keys/id_rsa":         pemHeader + "\nMIIEow...\n",                    // 1 TS-SEC-002
		"tests/test_login.py": `PASSWORD = "only-in-tests"` + "\n",
		".env.example":        "DB_PASSWORD=change-me\n",
	}, scanner.Options{})
	expect(t, got,
		"TS-SEC-003 app/config.py:2", "TS-SEC-001 app/config.py:6",
		"TS-SEC-003 app/server.js:1", "TS-SEC-005 app/server.js:3", "TS-SEC-005 app/server.js:4",
		"TS-SEC-004 public/app.js:1", "TS-SEC-001 ci/deploy.sh:1", "TS-SEC-002 keys/id_rsa:1",
	)
	for _, f := range got {
		for _, secret := range []string{awsKey, ghToken, "s3cr3t-pass", "fallbackpass1", "abcdef123456", "abcd1234abcd1234"} {
			if strings.Contains(f.Evidence, secret) || strings.Contains(f.Message, secret) {
				t.Errorf("%s leaks %q in its output", f.RuleID, secret)
			}
		}
	}
}

func TestPlaintextPasswordStorage(t *testing.T) {
	got := scan(t, map[string]string{
		"db/seed.sql": lines(
			"CREATE TABLE users (id INT, email TEXT, plaintext_password VARCHAR(64));",                  // 1 schema column
			"INSERT INTO users (email, password) VALUES ('a@b.c', 'hunter22'), ('d@e.f', 'swordfish');", // 2
		),
		"app/repo.py": lines(
			`cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hashed))`,
			`log.debug('stored user')`,
			`DEFAULT_ROLE = 'member'`,
		),
		"app/legacy.js": lines(
			"db.query(`INSERT INTO accounts (name, temp_password) VALUES",
			"  ('ops', 'Welcome@123')`);", // literal on the next line, same tuple
		),
	}, scanner.Options{})
	expect(t, got, "TS-SEC-006 db/seed.sql:1", "TS-SEC-006 db/seed.sql:2", "TS-SEC-006 app/legacy.js:1")
}

func TestCORS(t *testing.T) {
	got := scan(t, map[string]string{
		"api/main.py": lines(
			"app.add_middleware(",
			"    CORSMiddleware,",
			`    allow_origins=["*"],`, // 3
			"    allow_credentials=True,",
			")",
		),
		"web/server.js":  "app.use(cors());\n",
		"api/strict.py":  `app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])` + "\n",
		"api/headers.go": `w.Header().Set("Access-Control-Allow-Origin", "*")` + "\n",
		"nginx/site.conf": lines(
			"location /api {",
			`  add_header Access-Control-Allow-Origin "https://app.example.com";`,
			"}",
		),
	}, scanner.Options{})
	expect(t, got, "TS-NET-001 api/main.py:3", "TS-NET-001 web/server.js:1", "TS-NET-001 api/headers.go:1")
	if f := find(got, "TS-NET-001"); f != nil {
		for _, g := range got {
			if g.File == "api/main.py" && (g.Severity != policy.High || !strings.Contains(g.Message, "credentials")) {
				t.Errorf("wildcard + credentials should be high: %+v", g)
			}
			if g.File == "web/server.js" && g.Severity != policy.Medium {
				t.Errorf("wildcard without credentials should stay medium: %+v", g)
			}
		}
	}
}

func TestTLS(t *testing.T) {
	got := scan(t, map[string]string{
		"nginx/nginx.conf": lines(
			"server {",
			"  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;",  // 2 TS-NET-002
			"  ssl_ciphers HIGH:!aNULL:!MD5:RC4-SHA;", // 3 TS-NET-003
			"}",
		),
		"nginx/modern.conf": lines(
			"ssl_protocols TLSv1.2 TLSv1.3;",
			"ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!RC4:!aNULL;",
		),
		"apache/httpd.conf": lines(
			"SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
			"SSLProtocol all -SSLv3", // 2 TS-NET-002: TLS 1.0 and 1.1 still on
		),
		"client/fetch.py": lines(
			"import requests",
			"r = requests.get(url, verify=False)", // 2 TS-NET-004
			"ctx = ssl.create_default_context()",
		),
		"svc/tls.go": "cfg := &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}\n", // TS-NET-002, TS-NET-004
	}, scanner.Options{})
	expect(t, got,
		"TS-NET-002 nginx/nginx.conf:2", "TS-NET-003 nginx/nginx.conf:3", "TS-NET-002 apache/httpd.conf:2",
		"TS-NET-004 client/fetch.py:2", "TS-NET-002 svc/tls.go:1", "TS-NET-004 svc/tls.go:1",
	)
}

func TestPersonalDataInLogs(t *testing.T) {
	base := "98765432101"
	aadhaar := base + string(detect.VerhoeffCheckDigit(base))
	notAadhaar := base + string('0'+(detect.VerhoeffCheckDigit(base)-'0'+1)%10)
	got := scan(t, map[string]string{
		"logs/app.log": lines(
			"2026-01-01 INFO start",
			"2026-01-01 INFO kyc ok aadhaar="+aadhaar,           // 2 TS-DAT-001
			"2026-01-01 INFO pan ABCPD1234E verified",           // 3 TS-DAT-002
			"2026-01-01 INFO charged card 4111 1111 1111 1111",  // 4 TS-DAT-003
			"2026-01-01 INFO receipt sent to ravi.k@example.in", // 5 TS-DAT-004
			"2026-01-01 INFO otp sent to +91 9876543210",        // 6 TS-DAT-005
			"2026-01-01 WARN login failed password=hunter22",    // 7 TS-DAT-006
			"2026-01-01 INFO chart MRN-004521 opened",           // 8 TS-DAT-007
			"2026-01-01 INFO order 123456789012 shipped",        // not Verhoeff-valid: ignored
			"2026-01-01 INFO ref "+notAadhaar+" archived",       // near-miss: ignored
			"2026-01-01 WARN login failed password=***",         // already redacted: ignored
			"2026-01-01 INFO card 4111 1111 1111 1112 declined", // Luhn failure: ignored
		),
		"exports/users.csv": lines(
			"name,email,aadhaar",
			"Ravi,ravi@example.in,"+aadhaar[:4]+" "+aadhaar[4:8]+" "+aadhaar[8:],
			"Asha,asha@example.in,"+aadhaar,
		),
		"src/app.py": "EMAIL_RE = r'[a-z]+@example.com'\n", // source code is not a data file
	}, scanner.Options{})
	expect(t, got,
		"TS-DAT-001 logs/app.log:2", "TS-DAT-002 logs/app.log:3", "TS-DAT-003 logs/app.log:4",
		"TS-DAT-004 logs/app.log:5", "TS-DAT-005 logs/app.log:6", "TS-DAT-006 logs/app.log:7",
		"TS-DAT-007 logs/app.log:8",
		"TS-DAT-001 exports/users.csv:2", "TS-DAT-004 exports/users.csv:2",
	)
	for _, f := range got {
		for _, raw := range []string{aadhaar, "ABCPD1234E", "4111 1111 1111 1111", "ravi.k@", "9876543210", "hunter22", "004521"} {
			if strings.Contains(f.Evidence, raw) || strings.Contains(f.Message, raw) {
				t.Errorf("%s leaks %q: %q", f.RuleID, raw, f.Evidence)
			}
		}
		if f.File == "exports/users.csv" && f.RuleID == "TS-DAT-001" && f.Occurrences != 2 {
			t.Errorf("Aadhaar occurrences in csv = %d, want 2", f.Occurrences)
		}
	}
}

func TestSensitiveLogging(t *testing.T) {
	got := scan(t, map[string]string{
		"svc/auth.py": lines(
			`logger.info(f"login attempt with token {token}")`, // 1
			`logger.info("user %s logged in", username)`,
			`logging.debug("auth header: %s", authorization)`,     // 3
			`record_audit(f"export done: {json.dumps(payload)}")`, // 4
			`logger.info(f"exported {len(rows)} rows")`,
		),
		"svc/api.js": lines(
			"console.log(`request body: ${JSON.stringify(body)}`);", // 1
			"console.log(`served ${count} users`);",
		),
		"svc/log_test.go": `log.Printf("token %s", token)` + "\n", // tests are excluded
	}, scanner.Options{})
	expect(t, got, "TS-LOG-001 svc/auth.py:1", "TS-LOG-001 svc/auth.py:3", "TS-LOG-001 svc/auth.py:4", "TS-LOG-001 svc/api.js:1")
}

func TestUnpinnedDependencies(t *testing.T) {
	got := scan(t, map[string]string{
		"requirements.txt": lines(
			"# runtime",
			"flask==2.0.0",
			"requests>=2.0", // 3
			"numpy",
			"gunicorn==22.0.0 ; sys_platform != 'win32'",
			"-r extra.txt",
			"git+https://github.com/acme/lib.git",
		),
		"web/package.json": `{
  "dependencies": {"express": "4.17.1", "lodash": "^4.17.0", "local": "file:../x"},
  "devDependencies": {"jest": "29.7.0"}
}
`,
		"go.mod": "module x\n\nrequire (\n\tgithub.com/spf13/cobra v1.10.2\n)\n",
	}, scanner.Options{})
	expect(t, got, "TS-DEP-002 requirements.txt:3", "TS-DEP-002 web/package.json:2")
	if f := find(got, "TS-DEP-002"); f != nil && f.File == "requirements.txt" && f.Occurrences != 2 {
		t.Errorf("requirements.txt unpinned count = %d, want 2", f.Occurrences)
	}
}

func TestCustomRegexRules(t *testing.T) {
	root := writeTree(t, map[string]string{
		"web/a.js":        "fetch('https://corp.acme.internal/api')\nfetch('https://corp.acme.internal/v2')\n",
		"web/b.js":        "fetch('/api')\n",
		"svc/main.py":     "# SPDX-License-Identifier: Apache-2.0\nprint('hi')\n",
		"svc/untagged.py": "print('no header')\n",
	})
	rs := &policy.RuleSet{Rules: []policy.Rule{
		{ID: "ACME-001", Title: "Internal hostnames in client code", Severity: policy.Low, Check: "regex.match",
			Files: []string{"web/**/*.js"}, Pattern: `corp\.acme\.internal`},
		{ID: "ACME-002", Title: "Source files carry a licence header", Severity: policy.Info, Check: "regex.absent",
			Files: []string{"**/*.py"}, Pattern: `SPDX-License-Identifier:`},
	}}
	tg, _ := scanner.NewTarget(root)
	res, err := scanner.Run(context.Background(), tg, rs, scanner.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, res.Findings, "ACME-001 web/a.js:1", "ACME-002 svc/untagged.py:0")
	if f := find(res.Findings, "ACME-001"); f.Occurrences != 2 {
		t.Errorf("occurrences = %d, want 2", f.Occurrences)
	}
}

// The Auditable scenarios are TraceState's reference targets; none of the
// hardened fixtures above should be anywhere near as noisy. This guards the
// overall false-positive rate on ordinary, well-written code.
func TestCleanProjectHasNoFindings(t *testing.T) {
	got := scan(t, map[string]string{
		"app/main.py": lines(
			"import logging, os",
			"from fastapi import FastAPI",
			"logger = logging.getLogger(__name__)",
			`DB_URL = os.environ["DATABASE_URL"]`,
			`PASSWORD_MIN_LENGTH = 12`,
			`TOKEN_EXPIRY_SECONDS = 3600`,
			"app = FastAPI()",
			"@app.get('/health')",
			"def health():",
			`    logger.info("health check from %s", request.client.host)`,
			`    return {"status": "ok"}`,
		),
		"app/requirements.txt": "fastapi==0.115.0\nuvicorn==0.30.6\n",
		"Dockerfile": lines(
			"FROM python:3.12-slim",
			"RUN useradd -r app",
			"COPY app /app",
			"USER app",
			`CMD ["uvicorn", "app.main:app"]`,
		),
		"docker-compose.yml": lines(
			"services:",
			"  app:",
			"    build: .",
			`    user: "1000:1000"`,
			"    environment:",
			"      DATABASE_URL: ${DATABASE_URL}",
		),
		"README.md": "Set `DB_PASSWORD` in your environment. See https://example.com/docs.\n",
		// Regressions from scanning public projects (docs/BENCHMARK.md): a
		// locally built image tagged latest, a Docker secret file path, npm
		// ranges pinned by a workspace lockfile, and a minified library.
		"deploy/compose.yaml": lines(
			"services:",
			"  backend:",
			"    image: backend:latest",
			"    build: ./backend",
			"    environment:",
			"      - DATABASE_PASSWORD=/run/secrets/db-password",
		),
		// Found by scanning TraceState itself: a code example in a comment,
		// and a pattern for Express that lives in a Go string literal.
		"internal/audit/audit.go": lines(
			"package audit",
			`// Never logger.info("%s", token): tokens must not reach the log.`,
			"var expressCORS = regexp.MustCompile(`\\bcors\\(\\s*\\)`)",
		),
		"bun.lock":            "{}\n",
		"web/ui/package.json": `{"dependencies": {"react": "^19.2.0"}}` + "\n",
		"web/static/lib/vendor.min.js": "!function(){" +
			strings.Repeat("console.log(`${token}`);var a=1;", 400) + "}();\n",
	}, scanner.Options{})
	expect(t, got)
}

func TestPlaintextIdentifierColumns(t *testing.T) {
	got := scan(t, map[string]string{
		"db/schema.sql": lines(
			"CREATE TABLE IF NOT EXISTS customers (",
			"  id BIGINT PRIMARY KEY,",
			"  full_name VARCHAR(100),",
			"  aadhaar_number VARCHAR(12),", // 4
			`  "pan" CHAR(10),`,             // 5
			"  aadhaar_hash CHAR(64),",
			"  card_last4 CHAR(4),",
			"  note TEXT DEFAULT 'card_number VARCHAR(19)'",
			");",
			"CREATE TABLE payments (id INT, card_number VARCHAR(19), amount NUMERIC(10, 2), card_token TEXT);", // 10
		),
		"app/models.py": lines(
			"cur.execute(\"\"\"",
			"    CREATE TABLE patients (",
			"        id SERIAL PRIMARY KEY,",
			"        mrn VARCHAR(20),", // 4
			"        phone VARCHAR(15)",
			"    )",
			"\"\"\")",
			"account_number = request.form['account_number']", // not a table definition
		),
	}, scanner.Options{})
	expect(t, got,
		"TS-DAT-008 db/schema.sql:4", "TS-DAT-008 db/schema.sql:5", "TS-DAT-008 db/schema.sql:10", "TS-DAT-008 app/models.py:4")
	for _, f := range got {
		if f.File == "db/schema.sql" && f.Line == 10 && !strings.Contains(f.Message, "table payments stores payment card number in plaintext column card_number") {
			t.Errorf("message = %q", f.Message)
		}
	}
}
