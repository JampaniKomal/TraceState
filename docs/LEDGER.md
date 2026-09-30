# The audit ledger

Every scan is recorded in a ledger: an append-only SQLite file in which each
entry commits to the hash of the entry before it. The point is that a scan
result can be shown to an auditor later, and the auditor can check that
nobody has quietly removed a finding, changed a severity, or re-run the scan
until it came out clean.

```bash
tracestate scan .                          # records the scan in tracestate-ledger.db
tracestate ledger scans                    # what was scanned, when, with which rules
tracestate ledger show 3f2a                # re-render a recorded scan in any format
tracestate ledger verify                   # check the whole chain
tracestate ledger keygen ci-seal           # Ed25519 key pair: ci-seal.key, ci-seal.pub
tracestate ledger seal --key ci-seal.key   # sign the current head
tracestate ledger verify --pubkey ci-seal.pub --expect-head 77:e899...
tracestate ledger export -o ledger.jsonl   # for archiving or independent checking
```

The ledger path defaults to `tracestate-ledger.db` in the working directory;
set `--ledger` or `TRACESTATE_LEDGER` to keep it elsewhere.

## What a scan writes

One transaction per scan, so a scan is recorded completely or not at all:

| Entry | Payload |
|---|---|
| `scan_started` | target, tool version, time, SHA-256 and sources of the rule set, files indexed and skipped, whether `--online` was used |
| `finding` (one per finding) | rule, severity, file, line, message, redacted evidence, controls, fingerprint |
| `scan_completed` | duration, suppressed count, summary, the outcome of every rule |
| `seal` | written by `ledger seal`, see below |

Evidence is redacted before it is written (secrets are masked, Aadhaar and
card numbers keep only their last digits), so the ledger never becomes a
second copy of the data it reports on.

## Four layers, and what each one stops

| Layer | Stops | Doesn't stop |
|---|---|---|
| **Write-once triggers.** SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers abort any change to `entries` or `meta`. | Honest mistakes and ordinary tools: `UPDATE entries ...` fails. | Anyone who drops the triggers first. `verify` reports missing triggers, and read-only commands never re-create them, so dropping them leaves a trace. |
| **Hash chain.** Each entry's hash covers every field, including the previous entry's hash; the first entry links to a genesis hash bound to the ledger's random ID. | Editing, deleting, reordering or inserting entries, moving entries between ledgers. `verify` names the entry. | Someone who rewrites the file and recomputes every hash after their change. |
| **Ed25519 seals.** `ledger seal` signs the ledger ID and the current head. | A full rewrite up to the last seal, when you verify with `--pubkey`: the attacker can't sign the new head without the private key, and dropping the seals fails too, because a pinned key requires at least one valid seal. | Removing entries appended after the last seal. |
| **Anchors.** `ledger head` prints `seq:hash`; store it somewhere the ledger's owner can't edit (a CI log, a ticket, an email to the auditor). | Truncation and rewrites after the last seal: `verify --expect-head seq:hash` fails if that entry is gone or different. | Nothing further; this is the outer layer. |

In short: verify with `--pubkey` against a key that was never on the machine
holding the ledger, and anchor the head after important scans.

### Key handling

- `ledger keygen` writes the private key with mode 0600 and refuses to
  overwrite an existing key.
- Keep the private key where the scans run (for example a CI secret passed
  as `TRACESTATE_SEAL_KEY`), and give auditors only the `.pub` file.
- Without `--pubkey`, `verify` still checks that every seal is internally
  consistent, but it can't distinguish your seal from one made by whoever
  rewrote the file with their own key. The output says `not pinned` in that
  case.

## Verifying without TraceState

An auditor shouldn't have to trust the tool whose output they are checking.
`ledger export` writes one JSON object per line:

```json
{"ledger_id":"1f99c5ca...","seq":1,"kind":"scan_started","created_at":"2026-09-30T04:12:09.51Z","scan_id":"9c1e...","payload":"{...}","prev_hash":"8a3f...","hash":"d41c..."}
```

and [`scripts/verify-export.py`](../scripts/verify-export.py) checks it using
only the Python standard library (plus `cryptography` for seal signatures):

```bash
python3 scripts/verify-export.py ledger.jsonl --pubkey ci-seal.pub --expect-head 77:e899...
```

CI runs it on every push, including against a deliberately tampered export.
The format, for anyone writing their own verifier:

**Genesis.** Entry 1's `prev_hash` is
`SHA-256("tracestate-ledger-v2 genesis\n" + ledger_id)`, hex encoded.

**Entry hash.** SHA-256 over these seven fields, in order, each written as
its length in bytes (decimal), a colon, the UTF-8 bytes, and a newline:

```
"tracestate-ledger-v2", seq (decimal), kind, created_at, scan_id, payload, prev_hash
```

For example, the kind `seal` contributes the bytes `4:seal\n`. The length
prefix means no two different entries can produce the same byte stream.
`scan_id` is empty for seals.

**Chain.** `seq` starts at 1 and increases by one. Each entry's `prev_hash`
equals the previous entry's `hash`.

**Seals.** A `seal` entry's payload is
`{"head_seq":N,"head_hash":"...","public_key":"<hex>","signature":"<hex>"}`.
`head_seq` must be lower than the seal's own `seq`, and `head_hash` must equal
the hash of entry `head_seq` (or the genesis hash when it is 0). The signature
is Ed25519 over:

```
"tracestate-seal-v1\n" + ledger_id + "\n" + head_seq (decimal) + "\n" + head_hash
```

## `verify` output

```
Ledger 1f99c5ca1029b677a6125d2a2b4a5cb1 (l.db)
  entries   77 (2 scans, 72 findings, 1 seals)
  head      77:e899b1208ba568c9d54bf6cabd03d1135f313531ff7b940d86b7dd3737eeabbc
  triggers  intact
  seals     1 of 1 valid, latest covers entries 1-53, key 5ed0b67fd251, pinned key
            23 later entries are chained but not yet sealed

OK: the chain is intact.
```

On a problem it lists each one with the entry number, prints `TAMPERING
DETECTED`, and exits 1. `--format json` gives the same report for scripts.

The tamper cases above are all covered by tests in
`pkg/ledger/ledger_test.go`: content and timestamp edits, moved scan IDs,
deletions, reorders, forged inserts, swapped ledger IDs, dropped triggers,
full rewrites with and without the attacker's own seals, stale seals, and
truncation against an anchor.

## Upgrading from v1

TraceState v1 wrote an `audit_logs` table. v2 detects such a file and refuses
to append to it; start a new ledger file. The old one remains readable with
`sqlite3`.
