# TraceState: Policy-as-Code Compliance Engine

A standalone Go CLI that automates the "walk the codebase and note the
findings" step of a compliance audit: point it at a target, and it scans
against a JSON policy ruleset and permanently logs every violation to a
cryptographically tamper-evident SQLite ledger.

## Project Overview

TraceState pairs with [Auditable](https://github.com/JampaniKomal/Auditable),
a deliberately vulnerable practice target mapped to real frameworks
(ISO 27001, DPDPA, SEBI CSCRF, HIPAA, CERT-In). The idea behind the pair:
audit Auditable manually first — the way a GRC analyst actually would,
reading code, running the app, tracing evidence by hand — then run
TraceState against the same target and see how much of that same ground
a policy-as-code engine covers in under two seconds. See "Manual vs.
Automated" below for the real comparison.

TraceState scans any target directory against a Policy-as-Code JSON
ruleset (`ruleset.json`) and writes every violation to a SHA-256
hash-chained, Write-Once-Read-Many (WORM) SQLite database — once a
finding is logged, it cannot be edited or deleted, only appended after.

TraceState is framework-agnostic and modular by design: `ruleset.json`
maps regex patterns to specific files and tags each with a compliance
framework, and the scanner itself is a set of independently pluggable
modules (see "The Wires" below) — adding a check for a new framework or
a new kind of target means writing one new file, not editing the engine.

## The Architecture

### 1. The PSU (Power Supply Unit - Core Engine)

- `cmd/`: The Cobra CLI framework — `tracestate init`, `tracestate scan`,
  `tracestate ledger verify`, `tracestate export`.
- `pkg/worm/`: The cryptographic vault. SHA-256 hash chaining plus SQLite
  `BEFORE UPDATE`/`BEFORE DELETE` triggers that reject any attempt to
  modify a logged row.
- `ruleset.json`: The dynamic "Brain" — the compliance rules themselves.

### 2. The Wires (Scanner Modules) — genuinely pluggable

`pkg/scanner/` holds six built-in scanner modules ("wires"), each
implementing a small `Wire` interface (`pkg/scanner/wire.go`):

```go
type Wire interface {
    Name() string
    Scan(targetDir string, rs rules.RuleSet) ([]Finding, error)
}
```

`ScanTarget` doesn't know about any specific wire — it just iterates a
registry (`RegisterWire`) and calls `.Scan()` on whatever's in it. The
six shipped wires each register themselves:

- **Wire 1 (Infrastructure):** `docker-compose.yml` — privileged
  containers, exposed sockets, unencrypted volumes.
- **Wire 2 (Telemetry):** any `*.log` file under the target — unmasked
  PII (Aadhaar-shaped numbers, emails, password fields, medical record
  numbers).
- **Wire 3 (Source Code):** hardcoded secrets and backdoors in app code.
- **Wire 4 (Network):** CORS misconfiguration and deprecated TLS.
- **Wire 5 (Supply Chain):** known-vulnerable pinned dependency versions.
- **Wire 6 (Database & IAM):** plaintext-credential SQL in database
  initialization code.

Adding your own check for a framework or target type this ruleset
doesn't cover — say, a Kubernetes-manifest wire, or an org-specific IAM
policy check — means writing a new type that implements `Wire` and
calling `scanner.RegisterWire(myWire{})`, typically from that new file's
own `init()`. Nothing in `ScanTarget`, or in any of the six existing
wires, has to change. Each wire also skips gracefully if its target file
doesn't exist in the scan target — a codebase with no
`docker-compose.yml`, for instance, simply has nothing for Wire 1 to
check, and the other five wires still run.

## Quick Start

```bash
go build -o bin/tracestate main.go
./bin/tracestate scan --target /path/to/target
./bin/tracestate ledger verify
./bin/tracestate export --format json
```

Building requires cgo (the SQLite driver links the C SQLite library), so
a C compiler must be on `PATH` — on Windows that means MinGW-w64/GCC; on
Linux/macOS, GCC or Clang is normally already present. Without one,
`go build` still succeeds (the driver has a pure-Go stub), but the
binary fails at runtime the moment it touches the ledger.

## Manual vs. Automated: A Real Comparison

This is the actual point of building these two repos together. The
manual audit of Auditable (documented in its own `audit_guide.md` files)
involved reading every scenario's source, standing up all three Docker
Compose stacks, clicking through each dashboard, inspecting logs and an
Elasticsearch index by hand, and independently verifying two of the
audit guide's own claims were wrong before fixing them — real audit work,
on the order of hours.

Running TraceState against the same three scenarios:

```bash
./bin/tracestate scan --target ../Auditable/scenarios/01-fintech-startup
./bin/tracestate scan --target ../Auditable/scenarios/02-legacy-enterprise
./bin/tracestate scan --target ../Auditable/scenarios/03-healthcare-data-broker
./bin/tracestate ledger verify
./bin/tracestate export --format json
```

...found **30 violations across all three scenarios in 1.8 seconds**,
each one already tagged with its file, category, and compliance
framework, and permanently logged to a verifiable ledger. That's the
pitch for policy-as-code in one number: it doesn't replace the manual
audit (it can't tell you the Docker socket is *exploitable*, only that
it's *mounted* — that judgment call is still the point of the manual
audit), but it covers the repetitive, "did anyone check this file for
this exact pattern" ground instantly, every time, on every commit — see
the CI workflow (`.github/workflows/scan.yml`) for running it on every
push.

Each scan appends its findings to the same ledger, so `ledger verify`
checks the whole accumulated hash chain across all three runs, and
`export` produces one combined, chronologically ordered report.

## Testing

```bash
make test
# or directly:
go test ./... -v
```

The suite covers the WORM ledger's actual claims, not just that the
database file gets created: hash-chain linkage across sequential
entries, that `ledger verify` passes on an intact chain, that a direct
SQL `UPDATE`/`DELETE` against a logged row fails with the write-once
trigger error, and — the more interesting case — that `ledger verify`
still detects tampering via its hash chain even if the trigger itself
were bypassed (simulated by dropping the trigger directly and editing a
row, modeling an attacker with raw file-level database access rather
than one going through the CLI). It also covers the scanner's rule
matching and its graceful handling of missing target files.

## License
MIT License. See [LICENSE](LICENSE) for more information.
