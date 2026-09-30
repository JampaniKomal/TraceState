# TraceState

[![CI](https://github.com/JampaniKomal/TraceState/actions/workflows/ci.yml/badge.svg)](https://github.com/JampaniKomal/TraceState/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/JampaniKomal/TraceState)](https://github.com/JampaniKomal/TraceState/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Policy-as-code compliance scanner with a tamper-evident audit ledger.**

TraceState automates the "walk the codebase and write down what's wrong"
part of a security or compliance audit. Point it at a repository and it:

- checks it against 35 generic rules for containers, secrets, network
  configuration, personal data, logging, database schemas and dependencies;
- maps every finding to the controls it is evidence against, across ISO 27001,
  India's DPDP Act, PCI DSS, HIPAA, NIST CSF 2.0, SEBI CSCRF, OWASP Top 10, CWE
  and the CIS Docker Benchmark;
- records each scan in an append-only, hash-chained ledger that can be sealed
  with an Ed25519 key, so a result shown to an auditor months later can be
  proven unaltered, even without trusting TraceState itself.

It is one Go binary with no runtime dependencies. Reports come as a terminal
table, JSON, SARIF (GitHub code scanning), Markdown and a standalone HTML page.

## Manual audit vs. policy-as-code

TraceState was built as a pair with
[Auditable](https://github.com/JampaniKomal/Auditable): three deliberately
non-compliant environments (a fintech startup, a legacy enterprise and a
healthcare data broker), each with a hand-written audit guide. The idea is to
audit Auditable manually first, the way a GRC analyst would, by reading the
code, running the stacks and tracing evidence by hand, and then run TraceState
against the same target to see how much of that ground a policy engine covers.

| | Manual audit | TraceState v2 |
|---|---|---|
| Time | hours | 25 ms for all three scenarios |
| Documented problems found | 21 of 21 | 20 of 21 |
| Other real problems found | – | 27 more, each reviewed (exposed datastore ports, credentials in env fallbacks, a dependency with 2026 advisories...) |
| Judgement ("is this socket actually exploitable?", "does anyone read these alerts?") | yes | no |

The one it misses is a breach-report webhook that points at an unreachable
host: an operational failure no file shows. That split is the honest pitch for
policy-as-code: it covers the repetitive "did anyone check this file for
this" ground on every commit, and leaves the judgement calls to the human.

The rules name nothing in Auditable, so they hold up elsewhere: on two
unrelated public projects (awesome-compose and the FastAPI full-stack
template), every one of 89 findings was checked by hand and all were correct.
Methodology, per-problem results and the false positives fixed along the way
are in [docs/BENCHMARK.md](docs/BENCHMARK.md), and CI re-checks the
ground truth on every push.

## Quick start

Install one of:

```bash
go install github.com/jampanikomal/tracestate/v2/cmd/tracestate@latest   # Go 1.26+
docker build -t tracestate https://github.com/JampaniKomal/TraceState.git
```

or download a binary for Linux, macOS or Windows from
[Releases](https://github.com/JampaniKomal/TraceState/releases). Each archive
has a checksum and a signed build provenance attestation
(`gh attestation verify <file> --repo JampaniKomal/TraceState`).

Scan:

```bash
tracestate scan path/to/repo
tracestate scan . --format html -o report.html      # or json, sarif, markdown
tracestate scan . --online                           # also look up dependency advisories on OSV.dev
docker run --rm -v "$PWD:/src:ro" -v tracestate-ledger:/ledger tracestate scan .
```

```
TraceState v2.0.0 · 8 files in scenarios/01-fintech-startup · 66 ms · rules sha256:75708e779836

CRITICAL  TS-SEC-004  Credential shipped to the browser in client-side code
          frontend/index.html:46
          API_TOKEN is assigned a literal credential
          evidence: API_TOKEN = MA***(24 chars)
          CWE CWE-798 · ISO27001 A.5.17, A.8.26 · OWASP A01, A07

HIGH      TS-CTR-008  Datastore port published on all interfaces
          docker-compose.yml:33
          PostgreSQL service "postgres-db" publishes port 5432:5432 on every host interface
          evidence: ports: 5432:5432
          CIS-Docker bind-host-interface · ISO27001 A.8.20, A.8.22 · NIST-CSF PR.IR-01
...
Findings: 16 finding(s) (1 critical, 14 high, 1 medium) in 4 file(s)
Rules:    11 failed · 18 passed · 5 not applicable · 1 not evaluated (need --online)
Controls: CIS-Docker 3/7 · CWE 6/13 · DPDPA 1/1 · HIPAA 1/3 · ISO27001 11/17 · ...
```

Secrets and personal data are masked in evidence. Exit codes: `0` nothing at
or above `--fail-on` (default `high`), `1` findings at or above it, `2` error.

## Rules and frameworks

```bash
tracestate rules list                 # the 35 built-in rules
tracestate rules show TS-DAT-008      # description, files, controls, remediation
tracestate frameworks ISO27001        # which rules evidence which controls, and the gaps
```

Rules are YAML. Override a built-in rule by ID, or add your own pattern rules
without writing Go:

```yaml
version: 2
rules:
  - id: ACME-LOG-001
    title: Customer IDs must not be logged
    severity: medium
    check: regex.match
    pattern: 'log\w*\.\w+\(.*\bcustomer_id\b'
    files: ["services/**/*.py"]
    frameworks: { DPDPA: [s.8(5)], ISO27001: [A.8.15] }
```

```bash
tracestate scan . --rules acme.yaml
```

Silence a reviewed finding with a `tracestate:ignore TS-SEC-003` comment on
the line or the line above; reports count every suppression. Full reference:
[docs/RULES.md](docs/RULES.md). Control-by-control mapping:
[docs/FRAMEWORKS.md](docs/FRAMEWORKS.md).

A clean scan shows that specific checks passed. It does not certify a
control, which also covers process, people and infrastructure no scanner can
see.

## The ledger

```bash
tracestate ledger scans                          # every recorded scan
tracestate ledger show 3f2a --format html -o old.html
tracestate ledger keygen ci-seal && tracestate ledger seal --key ci-seal.key
tracestate ledger verify --pubkey ci-seal.pub    # exit 1 and "TAMPERING DETECTED" on any change
tracestate ledger export -o ledger.jsonl         # verify independently with scripts/verify-export.py
```

Write-once SQLite triggers stop casual edits; a SHA-256 chain over every field
exposes edits made around them; Ed25519 seals expose a full rewrite; and a
`seq:hash` anchor stored elsewhere exposes truncation. Each layer, what it does
and doesn't stop, and the exact hash format are in
[docs/LEDGER.md](docs/LEDGER.md).

## In CI

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: JampaniKomal/TraceState@v2
    with:
      fail-on: high           # critical, high, medium, low, info or none
      # path: services/api    # rules: policy/extra.yaml   # online: true
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: tracestate.sarif
```

The action installs a verified release binary, writes SARIF for code scanning
and puts the Markdown report in the job summary. TraceState scans itself this
way on every push.

## How it's built

The original design called the core engine the **PSU** and the scanner
modules plugged into it the **wires**, and v2 keeps that shape. The engine
indexes the target once, sends each rule to the wire that implements its
check, applies suppressions, fingerprints findings and computes rule and
control outcomes. It knows nothing about any specific check.

| Wire | Reads | Finds |
|---|---|---|
| `compose` | Compose files, parsed as YAML | root or privileged containers, the Docker socket, host namespaces, unpinned images, literal secrets, datastores on host volumes or open ports, disabled datastore security |
| `dockerfile` | Dockerfiles, with continuations and stages | root final stage, unpinned base images, remote `ADD`, secrets in `ENV`/`ARG`, `curl \| sh` |
| `secrets` | all text files | provider tokens by documented format, private keys, credentials in server and browser code, static token comparisons, plaintext password storage |
| `cors`, `tls` | code and server config | wildcard CORS origins in seven web frameworks and raw headers (worse with credentials), TLS 1.0/1.1, weak ciphers, disabled certificate checks |
| `pii` | logs, exports, CSV | Aadhaar (Verhoeff checksum), PAN, cards (Luhn + issuer ranges), emails, phone numbers, credentials |
| `logging` | source code | log statements that write tokens, passwords or personal data, before any log file exists |
| `schema` | SQL and inline DDL | Aadhaar, PAN, card, account or medical record numbers in plaintext columns |
| `deps` | requirements, package.json, go.mod | unpinned versions (lockfile-aware); known advisories from OSV.dev with `--online` |
| `regex` | anything | your own `regex.match` / `regex.absent` rules |

Adding a wire means one new file and a line in the registry; the engine
doesn't change. See [CONTRIBUTING.md](CONTRIBUTING.md).

```
cmd/tracestate     entry point
internal/cli       commands, flags, exit codes
pkg/scanner        target index, wire registry, engine, suppression
pkg/wires          the built-in wires
pkg/policy         rule model, loader, validator, framework catalogue, default rules
pkg/report         table, JSON, SARIF, Markdown and HTML renderers
pkg/ledger         hash chain, triggers, seals, verification
pkg/detect, osv    checksums and masking; OSV.dev client
```

## Development

```bash
go test -race ./...
go run ./cmd/tracestate scan .
```

The test suite includes fixtures for every rule (and for every false positive
fixed so far), the ledger tamper cases, end-to-end CLI runs and a check that
the generated docs are current. CI runs it on Linux, Windows and macOS, along
with golangci-lint, the Auditable benchmark, the independent ledger verifier
and a self-scan.

## License

MIT. See [LICENSE](LICENSE).
