# Benchmark

How well does TraceState find what an auditor would find, and how much noise
does it make on code it was never written for? This page answers both with
numbers you can reproduce.

- **Recall** is measured against [Auditable](https://github.com/JampaniKomal/Auditable),
  three deliberately non-compliant environments whose problems are documented
  in audit guides and `INTENTIONAL FLAW` markers.
- **Precision** is measured by reviewing every finding, one by one, against
  its source line, on Auditable and on two unrelated public projects.

## Setup

| | |
|---|---|
| TraceState | v2.0.0 (default rule pack, 35 rules) |
| Runtime | Go 1.26, `golang:1.26` container, 16 vCPU, targets on the container's own filesystem |
| Auditable | commit `146213b` |
| docker/awesome-compose | commit `30f4b7f` (2026-06-15), 502 files |
| fastapi/full-stack-fastapi-template | commit `cb740b6` (2026-09-01), 250 files |
| Command | `tracestate scan <target> --no-ledger --format json` (plus `--online` for the dependency rule on Auditable) |

## Results at a glance

| Target | Files | Findings | False positives after review | Scan time |
|---|---:|---:|---:|---:|
| Auditable (3 scenarios) | 36 | 53 | 0 | 25 ms |
| full-stack-fastapi-template | 250 | 7 | 0 | 89 ms |
| awesome-compose | 502 | 82 | 0 | 1.0 s |

**Recall on Auditable:** 20 of the 20 documented problems that are visible in
files (21 in total; the remaining one is an operational failure that no file
shows). TraceState v1 found 15 of the 21.

The zero false-positive figures are after fixing four false-positive patterns
this benchmark uncovered (details [below](#precision-on-projects-traceState-was-not-written-for)).
Before those fixes, 17 of 106 findings on the two public projects were noise.

## Recall on Auditable

Ground truth is every problem named in the three audit guides and every
`INTENTIONAL FLAW` comment, de-duplicated. Locations are relative to
`scenarios/`.

| # | Problem (source) | TraceState v2 | v1 |
|---|---|---|:-:|
| **01** | **Fintech startup** | | |
| G01 | App container runs as root (guide 3, flaw 1) | TS-CTR-001 `docker-compose.yml:6` | ✓ |
| G02 | Plaintext secrets in the compose file (flaw 2) | TS-CTR-006 `docker-compose.yml:15, :31` | ✗ |
| G03 | Database on an unencrypted host volume (flaw 3) | TS-CTR-007 `docker-compose.yml:35` | ✓ |
| G04 | Passwords stored in plaintext (flaw 5) | TS-SEC-006 `src/api.py:60, :68` | ✓ |
| G05 | Aadhaar numbers stored in plaintext (flaw 5) | TS-DAT-008 `src/api.py:59` | ✗ |
| G06 | API token in browser JavaScript (guide 4, flaw 6) | TS-SEC-004 `frontend/index.html:46` | ✓ |
| G07 | Authorization against a static bearer token (guide 2) | TS-SEC-005 `src/api.py:82` | ✓ |
| G08 | Aadhaar numbers and auth tokens written to logs (guide 1) | TS-LOG-001 `src/api.py:83, :95` | ✓ |
| **02** | **Legacy enterprise** | | |
| G09 | Database container runs as root (flaw 1) | TS-CTR-001 `docker-compose.yml:6` | ✓ |
| G10 | MySQL data on an unencrypted host volume (flaw 2, guide 4) | TS-CTR-007 `docker-compose.yml:15` | ✗ |
| G11 | App container runs as root (flaw 3) | TS-CTR-001 `docker-compose.yml:26` | ✗ |
| G12 | Override token in browser JavaScript (guide 3, flaw 4) | TS-SEC-004 `frontend/index.html:185` | ✓ |
| G13 | TLS 1.0 and 1.1 enabled in nginx (guide 1) | TS-NET-002 `nginx/default.conf:28` | ✗ |
| G14 | `mysql2@3.11.2` with GHSA-3f6p-5ww8-9rcr (guide 2) | TS-DEP-001 `src/package.json:12` (`--online`) | ✓ |
| G15 | Card numbers and passwords written to the audit log (guide 4) | TS-LOG-001 `src/server.js:91` | ✓ |
| G16 | Card PANs, account numbers and passwords stored in cleartext (guide 4) | TS-DAT-008 `src/server.js:49, :50`; TS-SEC-006 `src/server.js:60` | ✓ |
| **03** | **Healthcare data broker** | | |
| G17 | Public-facing app runs as root (flaw 1) | TS-CTR-001 `docker-compose.yml:28` | ✓ |
| G18 | Docker socket mounted into the app (guide 1, flaw 2) | TS-CTR-003 `docker-compose.yml:32` | ✓ |
| G19 | Master bypass token in browser JavaScript (guide 3, flaw 3) | TS-SEC-004 `dashboard/index.html:118` | ✓ |
| G20 | Patient data flows into an unauthenticated Elasticsearch (guide 4) | TS-CTR-009 `docker-compose.yml:7`; TS-LOG-001 `src/app.py:85` | ✓ |
| G21 | Breach-report webhook unreachable, no alerting (guide 2) | not detected | ✗ |
| | **Total** | **20 / 21** | **15 / 21** |

**About G21.** A breach-reporting webhook pointing at an unreachable host,
with failures only logged at INFO level, is an operational control failure.
Nothing in the files is wrong in isolation, so no static scanner should
claim to find it. It is listed so the denominator stays honest.

**About G05.** The first run of this benchmark missed G05, which is how the
`schema.plaintext_identifier` check (rule TS-DAT-008) came to exist. It is a
general check: it reads any `CREATE TABLE` and flags columns named for Aadhaar,
PAN, card, bank account, passport or medical record numbers, unless the name
says the value is hashed, encrypted, tokenised or masked. Without it, recall
was 19 / 20 on the file-visible problems.

**Runtime evidence.** Several guides also point at log files
(`logs/app_audit.log` and others) that only exist after the stacks have run.
When those files are present, TraceState's personal-data rules (TS-DAT-001 to
007) scan them. This benchmark deliberately did not start the stacks, because
they publish root containers, the Docker socket and unauthenticated
datastores on every interface. The source-level cause of each log leak is
detected (G08, G15, G20).

### Found beyond the ground truth

The ground-truth rows above account for 26 of the 53 findings. The other 27
were reviewed too, and each is a real problem the guides don't mention:

| Finding | Count |
|---|---:|
| Datastore ports published on all interfaces (5432, 3306, 9200) | 3 |
| CORS wildcard; with credentials in the two FastAPI apps | 3 |
| Credentials hard-coded as environment fallbacks (`os.getenv("DB_PASS", "...")`) | 4 |
| Bearer tokens written to the log on every rejected request | 4 |
| Simulator scripts hard-coding and logging the bypass tokens | 5 |
| More plaintext secrets in compose files | 5 |
| Elasticsearch data on a host directory | 1 |
| nginx image with no `USER` | 1 |
| `requests==2.32.3` in scenario 03, with 4 advisories published in 2026 (fixed in 2.33.0) | 1 |

The last one is a current vulnerability in the benchmark target itself.

## Precision on projects TraceState was not written for

TraceState v1's rules matched Auditable's literal strings, so they found
nothing anywhere else. v2's rules name no target. To check that they hold
up, every finding on two popular public projects was reviewed against its
source line.

**First pass: 106 findings, 17 of them false positives, in four patterns.**
Each was fixed in the wire and has a regression fixture in
`pkg/wires/wires_test.go`:

| Pattern | Findings | Fix |
|---|---:|---|
| npm version ranges flagged although a lockfile pins them (including a workspace lockfile at the repository root) | 12 | `deps.unpinned` looks for `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` or `bun.lock` beside the manifest and in its parent directories |
| `image: backend:latest` on a service that also has `build:` | 3 | the check skips services that build their own image, since nothing is pulled |
| `DATABASE_PASSWORD=/run/secrets/db-password` | 1 | paths to mounted secret files count as references, not values |
| The logging rule firing inside `jquery.min.js` | 1 | statement-level checks skip minified bundles (average line longer than 400 characters) |

**Second pass: 89 findings, all correct.**

| Rule | awesome-compose | fastapi template | Verdict |
|---|---:|---:|---|
| TS-IMG-001 image runs as root | 33 | 2 | correct: final stage has no `USER` (checked mechanically for all 35) |
| TS-CTR-005 image not pinned | 20 | 2 | correct: untagged or `:latest` pulls |
| TS-CTR-006 secret in compose environment | 15 | 0 | correct: demo passwords such as `MYSQL_ROOT_PASSWORD=somewordpress` |
| TS-CTR-008 datastore port on all interfaces | 4 | 0 | correct |
| TS-DEP-002 unpinned Python requirements | 4 | 0 | correct: no version, no lockfile |
| TS-CTR-003 Docker socket mounted | 2 | 1 | correct (Portainer, Traefik, Traefik) |
| TS-IMG-005 `curl … \| bash` in a Dockerfile | 2 | 1 | correct |
| TS-CTR-004 host namespace | 1 | 1 | correct (`network_mode: host`, `ipc: host`) |
| TS-NET-001 CORS wildcard | 1 | 0 | correct (`app.use(cors())`) |

Two caveats:
- The reviewer is TraceState's author.
- "Correct" means the file does what the rule describes. A demo project may
  run as root on purpose; whether that matters is a policy decision. That's
  why any rule can be overridden in a rule file (`--rules`), and any
  location can be exempted with a `tracestate:ignore` comment.

## Speed

A CPU profile showed 92% of scan time in regular-expression matching, mostly
patterns that could never match the line in hand. Each check now tests for a
cheap literal first (`AKIA`/`ASIA` before the AWS key pattern, a digit count
before the Aadhaar pattern, and so on) and runs the regex only on lines that
pass.

| Target | Before | After | Speed-up |
|---|---:|---:|---:|
| full-stack-fastapi-template (250 files) | 550 ms | 89 ms | 6.2× |
| awesome-compose (502 files) | 2,750 ms | 1,015 ms | 2.7× |
| Auditable (36 files) | 59 ms | 25 ms | 2.4× |

Findings before and after are identical, fingerprints included. Most of the
remaining second on awesome-compose is spent checking a 1.9 MB, 8,130-line
`nginx.log` for personal data, which is exactly the file those rules exist
for.

## Compared with TraceState v1

| | v1 | v2 |
|---|---|---|
| Recall on Auditable | 15 / 21 | 20 / 21 |
| Findings on Auditable | 26 | 53 |
| Rules | tied to Auditable's literal strings (`MASTER_BACKDOOR_KEY_2026`, `"mysql2": "3.11.2"`) | generic; no rule names a target |
| Dependency vulnerabilities | a hard-coded list; flagged `psycopg2-binary==2.9.7`, which has no advisory in OSV | queried from OSV.dev with `--online` |
| Location | file only | file and line, redacted evidence, stable fingerprint |
| Framework mapping | every finding labelled "ISO-27001" | per rule, across 9 frameworks, with a control coverage matrix |
| Two violations of one rule in one file | reported once | reported separately |

## Reproduce

```bash
git clone https://github.com/JampaniKomal/Auditable
tracestate scan Auditable --online --format markdown
```

CI scans Auditable (pinned to the commit above) on every push, and fails if
any detection in [`benchmark/auditable-expected.txt`](benchmark/auditable-expected.txt),
the ground-truth rows in the table above, stops being reported.
