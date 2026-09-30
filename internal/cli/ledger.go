package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jampanikomal/tracestate/v2/pkg/ledger"
	"github.com/jampanikomal/tracestate/v2/pkg/report"
)

func (a *app) ledgerCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "ledger",
		Short: "Inspect, verify, seal and export the audit ledger",
		Long: `The ledger is an append-only SQLite file in which every entry commits to
the SHA-256 hash of the one before it. Scans are recorded automatically.

  tracestate ledger verify                      check the whole chain
  tracestate ledger keygen ci-seal              create an Ed25519 key pair
  tracestate ledger seal --key ci-seal.key      sign the current head
  tracestate ledger verify --pubkey ci-seal.pub detect even a full rewrite
  tracestate ledger head                        print an anchor to store elsewhere`,
	}
	cmd.PersistentFlags().StringVar(&path, "ledger", defaultLedger(), "ledger file (env TRACESTATE_LEDGER)")
	cmd.AddCommand(
		a.ledgerInitCmd(&path), a.ledgerVerifyCmd(&path), a.ledgerScansCmd(&path), a.ledgerShowCmd(&path),
		a.ledgerExportCmd(&path), a.ledgerHeadCmd(&path), a.ledgerKeygenCmd(), a.ledgerSealCmd(&path),
	)
	return cmd
}

// withLedger opens an existing ledger read-only-style (never creating it or
// touching its schema), runs fn and closes it.
func withLedger(ctx context.Context, path string, fn func(*ledger.Ledger) error) error {
	l, err := ledger.OpenExisting(ctx, path)
	if err != nil {
		return usageErr(err)
	}
	defer l.Close()
	return fn(l)
}

func (a *app) ledgerInitCmd(path *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create an empty ledger (scans create one automatically)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			existed := fileExists(*path)
			l, err := ledger.Open(cmd.Context(), *path)
			if err != nil {
				return usageErr(err)
			}
			defer l.Close()
			if existed {
				fmt.Fprintf(a.stdout, "ledger %s already exists at %s\n", l.ID(), *path)
			} else {
				fmt.Fprintf(a.stdout, "created ledger %s at %s\n", l.ID(), *path)
			}
			return nil
		},
	}
}

func (a *app) ledgerVerifyCmd(path *string) *cobra.Command {
	var pubkey, expectHead, format string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the hash chain, triggers, seals and (optionally) an external anchor",
		Long: `Verify recomputes every entry's hash and reports every problem it finds,
not just the first: edited content, broken links, missing or inserted
entries, removed write-once triggers and invalid seals.

Without --pubkey, seals are only checked for internal consistency; someone
who rewrites the whole file could also re-sign it with a key of their own.
Pin the public key you trust to rule that out. Entries appended after the
last seal and then removed can only be detected with --expect-head, using an
anchor printed earlier by 'tracestate ledger head'.

Exits 1 if any problem is found.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := ledger.VerifyOptions{ExpectHead: expectHead}
			if pubkey != "" {
				k, err := ledger.ParsePublicKey(pubkey)
				if err != nil {
					return usageErr(err)
				}
				opts.TrustedKey = k
			}
			return withLedger(cmd.Context(), *path, func(l *ledger.Ledger) error {
				rep, err := l.Verify(cmd.Context(), opts)
				if err != nil {
					return err
				}
				switch format {
				case "json":
					if err := writeJSON(a.stdout, rep); err != nil {
						return err
					}
				case "text":
					a.printVerify(*path, rep, opts)
				default:
					return usageErr(fmt.Errorf("unknown format %q (want text or json)", format))
				}
				if !rep.OK() {
					return fail()
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&pubkey, "pubkey", os.Getenv("TRACESTATE_SEAL_PUBKEY"), "trusted seal public key: a .pub file or hex (env TRACESTATE_SEAL_PUBKEY)")
	cmd.Flags().StringVar(&expectHead, "expect-head", "", "anchor 'seq:hash' recorded earlier with `ledger head`")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "text or json")
	return cmd
}

func (a *app) printVerify(path string, rep *ledger.VerifyReport, opts ledger.VerifyOptions) {
	w := a.stdout
	color := a.color(w)
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + "\033[0m"
	}
	fmt.Fprintf(w, "Ledger %s (%s)\n", rep.LedgerID, path)
	fmt.Fprintf(w, "  entries   %d (%d scans, %d findings, %d seals)\n", rep.Entries, rep.Scans, rep.Findings, rep.Seals)
	fmt.Fprintf(w, "  head      %d:%s\n", rep.HeadSeq, rep.HeadHash)
	if rep.TriggersIntact {
		fmt.Fprintf(w, "  triggers  intact\n")
	} else {
		fmt.Fprintf(w, "  triggers  %s\n", paint("\033[1;31m", "MISSING"))
	}
	if rep.Seals == 0 {
		fmt.Fprintf(w, "  seals     none\n")
	} else {
		pinned := "not pinned (pass --pubkey to rule out a re-signed rewrite)"
		if opts.TrustedKey != nil {
			pinned = "pinned key"
		}
		keys := make([]string, len(rep.SealKeys))
		for i, k := range rep.SealKeys {
			keys[i] = shortID(k)
		}
		fmt.Fprintf(w, "  seals     %d of %d valid, latest covers entries 1-%d, key %s, %s\n",
			rep.SealsVerified, rep.Seals, rep.SealedThrough, strings.Join(keys, ", "), pinned)
		if tail := rep.HeadSeq - rep.SealedThrough; rep.SealsVerified > 0 && tail > 1 {
			fmt.Fprintf(w, "            %d later entries are chained but not yet sealed\n", tail-1)
		}
	}
	if opts.ExpectHead != "" {
		fmt.Fprintf(w, "  anchor    %s\n", opts.ExpectHead)
	}
	fmt.Fprintln(w)
	if rep.OK() {
		fmt.Fprintln(w, paint("\033[32m", "OK")+": the chain is intact.")
		if rep.Seals == 0 && opts.ExpectHead == "" {
			fmt.Fprintln(w, "Note: an unsealed chain proves internal consistency only. Seal it (`ledger seal`) or store `ledger head` somewhere else to detect a full rewrite or truncation.")
		}
		return
	}
	fmt.Fprintf(w, "%s: %d problem(s)\n", paint("\033[1;31m", "TAMPERING DETECTED"), len(rep.Problems))
	for _, p := range rep.Problems {
		if p.Seq > 0 {
			fmt.Fprintf(w, "  entry %-6d %s\n", p.Seq, p.Reason)
		} else {
			fmt.Fprintf(w, "  %s\n", p.Reason)
		}
	}
}

func (a *app) ledgerScansCmd(path *string) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "scans",
		Short: "List recorded scans",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withLedger(cmd.Context(), *path, func(l *ledger.Ledger) error {
				scans, err := l.Scans(cmd.Context())
				if err != nil {
					return err
				}
				if format == "json" {
					if scans == nil {
						scans = []ledger.ScanInfo{}
					}
					return writeJSON(a.stdout, scans)
				}
				if format != "table" {
					return usageErr(fmt.Errorf("unknown format %q (want table or json)", format))
				}
				if len(scans) == 0 {
					fmt.Fprintln(a.stdout, "no scans recorded yet")
					return nil
				}
				tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "SCAN\tSTARTED\tFINDINGS\tSEVERITY\tENTRIES\tTARGET")
				for _, s := range scans {
					entries := fmt.Sprintf("%d-%d", s.FirstSeq, s.LastSeq)
					if !s.Complete {
						entries += " (incomplete)"
					}
					fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", shortID(s.ID), s.StartedAt.Local().Format("2006-01-02 15:04:05"),
						s.Findings, severitySummary(s.BySeverity), entries, s.Target)
				}
				return tw.Flush()
			})
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "table or json")
	return cmd
}

// severitySummary renders counts compactly: "2C 5H 1M".
func severitySummary(m map[string]int) string {
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if n := m[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", n, strings.ToUpper(s[:1])))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func (a *app) ledgerShowCmd(path *string) *cobra.Command {
	var format, out string
	cmd := &cobra.Command{
		Use:   "show [SCAN]",
		Short: "Rebuild the report of a recorded scan (default: the latest)",
		Long: `Show rebuilds a past scan's full report from the ledger alone, in any
report format. The report is exactly what was recorded, even if the rule
files have changed since. SCAN is a scan ID, a unique prefix of at least 6
characters, or "latest".`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !validFormat(format) {
				return usageErr(fmt.Errorf("unknown format %q (want one of %s)", format, strings.Join(report.Formats, ", ")))
			}
			want := "latest"
			if len(args) == 1 {
				want = args[0]
			}
			return withLedger(cmd.Context(), *path, func(l *ledger.Ledger) error {
				id, err := l.ResolveScan(cmd.Context(), want)
				if err != nil {
					return usageErr(err)
				}
				rep, err := l.LoadScan(cmd.Context(), id)
				if err != nil {
					return err
				}
				return a.writeReport(format, out, rep)
			})
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "report format: "+strings.Join(report.Formats, ", "))
	cmd.Flags().StringVarP(&out, "output", "o", "", "write to this file instead of stdout")
	return cmd
}

// exportedEntry is one line of `ledger export`: the entry plus the ID of the
// ledger it belongs to, which the genesis hash and every seal are bound to.
type exportedEntry struct {
	LedgerID string `json:"ledger_id"`
	ledger.Entry
}

func (a *app) ledgerExportCmd(path *string) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write every entry as JSON Lines, for archiving or independent verification",
		Long: `Export writes each ledger entry (ledger_id, seq, kind, created_at, scan_id,
payload, prev_hash, hash) as one JSON object per line. The hashing scheme is
documented in docs/LEDGER.md, so an export can be verified without
TraceState (scripts/verify-export.py does exactly that).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withLedger(cmd.Context(), *path, func(l *ledger.Ledger) error {
				entries, err := l.Entries(cmd.Context())
				if err != nil {
					return err
				}
				w, closeFn, err := a.output(out)
				if err != nil {
					return err
				}
				enc := json.NewEncoder(w)
				for _, e := range entries {
					if err := enc.Encode(exportedEntry{LedgerID: l.ID(), Entry: e}); err != nil {
						_ = closeFn()
						return err
					}
				}
				if err := closeFn(); err != nil {
					return err
				}
				a.note("exported %d entries of ledger %s", len(entries), l.ID())
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "write to this file instead of stdout")
	return cmd
}

func (a *app) ledgerHeadCmd(path *string) *cobra.Command {
	return &cobra.Command{
		Use:   "head",
		Short: "Print the current head as 'seq:hash', an anchor to record somewhere else",
		Long: `Head prints the latest entry's sequence number and hash. Store it outside
the ledger (a CI artifact, a ticket, a commit message, a timestamping
service) and later run 'ledger verify --expect-head seq:hash' to prove that
nothing up to that point was removed or rewritten.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withLedger(cmd.Context(), *path, func(l *ledger.Ledger) error {
				seq, hash, err := l.Head(cmd.Context())
				if err != nil {
					return err
				}
				fmt.Fprintf(a.stdout, "%d:%s\n", seq, hash)
				return nil
			})
		},
	}
}

func (a *app) ledgerKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen [PREFIX]",
		Short: "Create an Ed25519 seal key pair (PREFIX.key and PREFIX.pub)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := "tracestate-seal"
			if len(args) == 1 {
				prefix = args[0]
			}
			pubPath, keyPath, err := ledger.GenerateKeyPair(prefix)
			if err != nil {
				return usageErr(err)
			}
			pub, err := os.ReadFile(pubPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "private key  %s  (keep secret; store it as a CI secret, never commit it)\n", keyPath)
			fmt.Fprintf(a.stdout, "public key   %s  %s\n", pubPath, strings.TrimSpace(string(pub)))
			return nil
		},
	}
}

func (a *app) ledgerSealCmd(path *string) *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Sign the current head with an Ed25519 key and append the seal",
		Long: `Seal signs the ledger's current head (its sequence number and hash, bound
to the ledger ID) and appends the signature as a new entry. Anyone holding
the public key can then verify that nothing up to that point has changed,
even against an attacker who can rewrite the whole file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keyPath == "" {
				return usageErr(fmt.Errorf("--key is required (create one with `tracestate ledger keygen`)"))
			}
			priv, err := ledger.ReadPrivateKey(keyPath)
			if err != nil {
				return usageErr(err)
			}
			return withLedger(cmd.Context(), *path, func(l *ledger.Ledger) error {
				e, err := l.Seal(cmd.Context(), priv)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.stdout, "sealed entries 1-%d of ledger %s as entry %d (%s)\n", e.Seq-1, l.ID(), e.Seq, shortID(e.Hash))
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&keyPath, "key", "k", os.Getenv("TRACESTATE_SEAL_KEY"), "private key file from `ledger keygen` (env TRACESTATE_SEAL_KEY)")
	return cmd
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
