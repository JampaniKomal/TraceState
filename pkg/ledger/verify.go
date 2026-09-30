package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Problem is one integrity violation found by Verify.
type Problem struct {
	Seq    int64  `json:"seq,omitempty"`
	Reason string `json:"reason"`
}

// VerifyOptions tunes Verify.
type VerifyOptions struct {
	// TrustedKey pins the Ed25519 public key seals must be signed with.
	// Without it, Verify checks that each seal is internally consistent but
	// can't tell a genuine seal from one forged by whoever rewrote the file.
	TrustedKey ed25519.PublicKey
	// ExpectHead is an externally recorded anchor, "seq:hash" as printed by
	// `tracestate ledger head`. It detects entries removed from the end.
	ExpectHead string
}

// VerifyReport is the outcome of Verify.
type VerifyReport struct {
	LedgerID      string `json:"ledger_id"`
	Entries       int    `json:"entries"`
	Scans         int    `json:"scans"`
	Findings      int    `json:"findings"`
	Seals         int    `json:"seals"`
	SealsVerified int    `json:"seals_verified"`
	LastSealSeq   int64  `json:"last_seal_seq,omitempty"`
	// SealedThrough is the last entry covered by a valid seal; entries after
	// it are protected only by the hash chain (and an external anchor).
	SealedThrough  int64     `json:"sealed_through"`
	SealKeys       []string  `json:"seal_keys,omitempty"`
	HeadSeq        int64     `json:"head_seq"`
	HeadHash       string    `json:"head_hash"`
	TriggersIntact bool      `json:"triggers_intact"`
	Problems       []Problem `json:"problems"`
}

// OK reports whether no problems were found.
func (r *VerifyReport) OK() bool { return len(r.Problems) == 0 }

type sealPayload struct {
	HeadSeq   int64  `json:"head_seq"`
	HeadHash  string `json:"head_hash"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func sealMessage(ledgerID string, seq int64, hash string) []byte {
	return []byte("tracestate-seal-v1\n" + ledgerID + "\n" + strconv.FormatInt(seq, 10) + "\n" + hash)
}

// Verify walks the whole chain and reports every integrity problem: missing
// WORM triggers, sequence gaps (deleted or inserted rows), broken links,
// entries whose content no longer matches their hash, invalid or untrusted
// seals, and a head that doesn't match the expected anchor.
func (l *Ledger) Verify(ctx context.Context, opts VerifyOptions) (*VerifyReport, error) {
	rep := &VerifyReport{LedgerID: l.id, Problems: []Problem{}}

	var triggers int
	if err := l.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name IN
		('entries_no_update','entries_no_delete','meta_no_update','meta_no_delete')`).Scan(&triggers); err != nil {
		return nil, err
	}
	rep.TriggersIntact = triggers == 4
	if !rep.TriggersIntact {
		rep.Problems = append(rep.Problems, Problem{Reason: fmt.Sprintf(
			"%d of 4 write-once triggers are missing; the file has been modified outside TraceState", 4-triggers)})
	}

	entries, err := l.Entries(ctx)
	if err != nil {
		return nil, err
	}
	rep.Entries = len(entries)
	hashAt := map[int64]string{}
	keys := map[string]bool{}
	prev, want := genesisHash(l.id), int64(1)
	for _, e := range entries {
		if e.Seq != want {
			rep.Problems = append(rep.Problems, Problem{Seq: e.Seq, Reason: fmt.Sprintf(
				"sequence gap: expected entry %d, found %d (entries were removed or inserted)", want, e.Seq)})
		}
		if e.PrevHash != prev {
			rep.Problems = append(rep.Problems, Problem{Seq: e.Seq, Reason: "broken chain: prev_hash doesn't match the preceding entry"})
		}
		if HashEntry(e) != e.Hash {
			rep.Problems = append(rep.Problems, Problem{Seq: e.Seq, Reason: "content modified: entry no longer matches its hash"})
		}
		switch e.Kind {
		case KindScanStarted:
			rep.Scans++
		case KindFinding:
			rep.Findings++
		case KindSeal:
			rep.Seals++
			if p, ok := l.checkSeal(e, hashAt, opts.TrustedKey, rep); ok {
				rep.SealsVerified++
				rep.LastSealSeq = e.Seq
				rep.SealedThrough = p.HeadSeq
				keys[p.PublicKey] = true
			}
		}
		hashAt[e.Seq] = e.Hash
		prev, want = e.Hash, e.Seq+1
	}
	if n := len(entries); n > 0 {
		rep.HeadSeq, rep.HeadHash = entries[n-1].Seq, entries[n-1].Hash
	} else {
		rep.HeadHash = genesisHash(l.id)
	}
	for k := range keys {
		rep.SealKeys = append(rep.SealKeys, k)
	}
	// With a pinned key, a ledger without any seal by that key proves nothing:
	// whoever rewrote it could simply have left the seals out.
	if opts.TrustedKey != nil && rep.SealsVerified == 0 {
		rep.Problems = append(rep.Problems, Problem{Reason: "no valid seal by the trusted key (unsealed, or rewritten without its seals)"})
	}
	if opts.ExpectHead != "" {
		checkAnchor(opts.ExpectHead, hashAt, rep)
	}
	return rep, nil
}

func (l *Ledger) checkSeal(e Entry, hashAt map[int64]string, trusted ed25519.PublicKey, rep *VerifyReport) (sealPayload, bool) {
	fail := func(reason string) (sealPayload, bool) {
		rep.Problems = append(rep.Problems, Problem{Seq: e.Seq, Reason: "seal: " + reason})
		return sealPayload{}, false
	}
	var p sealPayload
	if err := json.Unmarshal([]byte(e.Payload), &p); err != nil {
		return fail("unreadable payload")
	}
	if p.HeadSeq >= e.Seq {
		return fail("covers entries that come after it")
	}
	if hashAt[p.HeadSeq] != p.HeadHash && (p.HeadSeq != 0 || p.HeadHash != genesisHash(l.id)) {
		return fail(fmt.Sprintf("signed head (entry %d) doesn't match the chain", p.HeadSeq))
	}
	pub, err := hex.DecodeString(p.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fail("invalid public key")
	}
	sig, err := hex.DecodeString(p.Signature)
	if err != nil || !ed25519.Verify(pub, sealMessage(l.id, p.HeadSeq, p.HeadHash), sig) {
		return fail("signature does not verify")
	}
	if trusted != nil && !bytes.Equal(pub, trusted) {
		return fail("signed by a key that isn't the trusted key")
	}
	return p, true
}

func checkAnchor(anchor string, hashAt map[int64]string, rep *VerifyReport) {
	seqStr, hash, ok := strings.Cut(anchor, ":")
	if !ok {
		for _, h := range hashAt {
			if h == anchor {
				return
			}
		}
		rep.Problems = append(rep.Problems, Problem{Reason: "anchor hash not found in the ledger (history rewritten or truncated)"})
		return
	}
	seq, err := strconv.ParseInt(seqStr, 10, 64)
	if err != nil {
		rep.Problems = append(rep.Problems, Problem{Reason: fmt.Sprintf("invalid anchor %q (want seq:hash)", anchor)})
		return
	}
	got, exists := hashAt[seq]
	switch {
	case !exists:
		rep.Problems = append(rep.Problems, Problem{Seq: seq, Reason: fmt.Sprintf("anchored entry %d is missing (ledger truncated)", seq)})
	case got != hash:
		rep.Problems = append(rep.Problems, Problem{Seq: seq, Reason: "anchored entry has a different hash (history rewritten)"})
	}
}

// Seal signs the current head with priv and appends the signature as a seal
// entry. It returns the seal entry.
func (l *Ledger) Seal(ctx context.Context, priv ed25519.PrivateKey) (Entry, error) {
	a, err := l.begin(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer rollback(a.tx)
	p := sealPayload{
		HeadSeq:   a.seq,
		HeadHash:  a.prev,
		PublicKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}
	p.Signature = hex.EncodeToString(ed25519.Sign(priv, sealMessage(l.id, p.HeadSeq, p.HeadHash)))
	payload, err := marshal(p)
	if err != nil {
		return Entry{}, err
	}
	e, err := a.add(ctx, KindSeal, "", payload)
	if err != nil {
		return Entry{}, err
	}
	return e, a.tx.Commit()
}

// GenerateKeyPair writes a new Ed25519 key pair to prefix+".key" (private,
// mode 0600) and prefix+".pub", refusing to overwrite existing files.
func GenerateKeyPair(prefix string) (pubPath, keyPath string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	keyPath, pubPath = prefix+".key", prefix+".pub"
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return "", "", fmt.Errorf("%s already exists; refusing to overwrite a key", p)
		}
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil { //nolint:gosec // a public key is meant to be shared
		return "", "", err
	}
	return pubPath, keyPath, nil
}

// ReadPrivateKey loads a private key written by GenerateKeyPair.
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a TraceState private key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ParsePublicKey accepts either a path to a .pub file or the hex key itself.
func ParsePublicKey(pathOrHex string) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(pathOrHex)
	if b, err := os.ReadFile(s); err == nil {
		s = strings.TrimSpace(string(b))
	}
	pub, err := hex.DecodeString(s)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%q is not an Ed25519 public key (file or hex)", pathOrHex)
	}
	return pub, nil
}
