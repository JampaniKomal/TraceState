#!/usr/bin/env python3
"""Verify a TraceState ledger export without TraceState.

    tracestate ledger export -o ledger.jsonl
    python3 scripts/verify-export.py ledger.jsonl [--pubkey seal.pub] [--expect-head SEQ:HASH]

Recomputes every entry hash and chain link from the format in
docs/LEDGER.md, and checks seal signatures when the `cryptography` package
is installed. Uses nothing from TraceState. Exits 0 if the export is intact,
1 if it is not, 2 on usage errors.
"""
import argparse
import hashlib
import json
import sys

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # seals are then reported as unchecked
    Ed25519PublicKey = None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def genesis_hash(ledger_id: str) -> str:
    return sha256_hex(("tracestate-ledger-v2 genesis\n" + ledger_id).encode())


def entry_hash(e: dict) -> str:
    """Each field is written as '<byte length>:<bytes>\n', in this order."""
    h = hashlib.sha256()
    for part in ("tracestate-ledger-v2", str(e["seq"]), e["kind"], e["created_at"],
                 e.get("scan_id", ""), e["payload"], e["prev_hash"]):
        b = part.encode()
        h.update(str(len(b)).encode() + b":" + b + b"\n")
    return h.hexdigest()


def seal_message(ledger_id: str, seq: int, head_hash: str) -> bytes:
    return f"tracestate-seal-v1\n{ledger_id}\n{seq}\n{head_hash}".encode()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("export", help="JSON Lines file from `tracestate ledger export`")
    ap.add_argument("--pubkey", help="trusted seal public key (.pub file or hex)")
    ap.add_argument("--expect-head", help="anchor recorded earlier with `tracestate ledger head` (SEQ:HASH)")
    args = ap.parse_args()

    trusted = None
    if args.pubkey:
        if Ed25519PublicKey is None:
            print("--pubkey needs the cryptography package: pip install cryptography", file=sys.stderr)
            return 2
        try:
            with open(args.pubkey) as f:
                trusted = f.read().strip()
        except OSError:
            trusted = args.pubkey.strip()

    with open(args.export, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    if not entries:
        print("empty export", file=sys.stderr)
        return 1

    problems = []
    ledger_id = entries[0]["ledger_id"]
    prev, want = genesis_hash(ledger_id), 1
    hash_at = {0: prev}
    seals = sealed_ok = 0
    for e in entries:
        seq = e["seq"]
        if e["ledger_id"] != ledger_id:
            problems.append((seq, "entry belongs to a different ledger"))
        if seq != want:
            problems.append((seq, f"sequence gap: expected entry {want}"))
        if e["prev_hash"] != prev:
            problems.append((seq, "broken chain: prev_hash doesn't match the preceding entry"))
        if entry_hash(e) != e["hash"]:
            problems.append((seq, "content modified: entry no longer matches its hash"))
        if e["kind"] == "seal":
            seals += 1
            p = json.loads(e["payload"])
            if p["head_seq"] >= seq or hash_at.get(p["head_seq"]) != p["head_hash"]:
                problems.append((seq, "seal: signed head doesn't match the chain"))
            elif Ed25519PublicKey is not None:
                try:
                    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(p["public_key"]))
                    key.verify(bytes.fromhex(p["signature"]), seal_message(ledger_id, p["head_seq"], p["head_hash"]))
                    if trusted is None or p["public_key"] == trusted:
                        sealed_ok += 1
                    else:
                        problems.append((seq, "seal: signed by a key that isn't the trusted key"))
                except (InvalidSignature, ValueError):
                    problems.append((seq, "seal: signature does not verify"))
        hash_at[seq] = e["hash"]
        prev, want = e["hash"], seq + 1

    if trusted is not None and sealed_ok == 0:
        problems.append((0, "no valid seal by the trusted key"))
    if args.expect_head:
        a_seq, _, a_hash = args.expect_head.partition(":")
        if hash_at.get(int(a_seq)) != a_hash:
            problems.append((int(a_seq), "anchor doesn't match (history rewritten or truncated)"))

    print(f"ledger   {ledger_id}")
    print(f"entries  {len(entries)}, head {entries[-1]['seq']}:{entries[-1]['hash']}")
    if Ed25519PublicKey is None:
        print(f"seals    {seals} (signatures not checked: pip install cryptography)")
    else:
        print(f"seals    {sealed_ok} of {seals} valid" + (", pinned key" if trusted else ""))
    for seq, reason in problems:
        print(f"  entry {seq}: {reason}" if seq else f"  {reason}")
    print("OK: the export is intact." if not problems else f"TAMPERING DETECTED: {len(problems)} problem(s)")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
