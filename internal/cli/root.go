// Package cli implements the tracestate command.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"

	_ "github.com/jampanikomal/tracestate/v2/pkg/wires" // registers the built-in wires
)

// Exit codes. They are part of the command's interface: CI pipelines branch
// on them, so they must stay stable.
const (
	ExitOK       = 0 // success, and nothing at or above the failure threshold
	ExitFindings = 1 // scan: findings at or above --fail-on; verify: integrity problems; validate: invalid rules
	ExitError    = 2 // the command itself failed (bad flags, unreadable files, ...)
)

// exitError carries a specific exit code up through cobra. A nil err means
// the command already printed everything it wanted to say.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

// fail returns an error that makes the command exit with code 1 without
// printing anything further.
func fail() error { return &exitError{code: ExitFindings} }

type app struct {
	version string
	stdout  io.Writer
	stderr  io.Writer
	noColor bool
	quiet   bool
}

// Execute runs the tracestate command with args and returns the process
// exit code.
func Execute(ctx context.Context, version string, args []string, stdout, stderr io.Writer) int {
	a := &app{version: resolveVersion(version), stdout: stdout, stderr: stderr}
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintln(stderr, "tracestate:", ee.err)
		}
		return ee.code
	}
	fmt.Fprintln(stderr, "tracestate:", err)
	return ExitError
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "tracestate",
		Short: "Policy-as-code compliance scanner with a tamper-evident audit ledger",
		Long: `TraceState checks a codebase against security and compliance rules
(ISO 27001, India's DPDP Act, HIPAA, PCI DSS, NIST CSF, SEBI CSCRF, OWASP,
CWE, CIS Docker), maps every finding to the controls it violates, and records
each scan in an append-only, hash-chained ledger that can be sealed with an
Ed25519 key and verified later.

Exit codes: 0 success, 1 findings at or above --fail-on (or failed
verification), 2 error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       a.version,
	}
	root.PersistentFlags().BoolVar(&a.noColor, "no-color", false, "disable coloured output (also honours NO_COLOR)")
	root.PersistentFlags().BoolVarP(&a.quiet, "quiet", "q", false, "only print the report, no progress notes on stderr")
	root.SetVersionTemplate("tracestate {{.Version}}\n")
	root.AddCommand(a.scanCmd(), a.rulesCmd(), a.frameworksCmd(), a.ledgerCmd(), a.versionCmd())
	return root
}

// note prints a progress message to stderr unless --quiet is set.
func (a *app) note(format string, args ...any) {
	if !a.quiet {
		fmt.Fprintf(a.stderr, format+"\n", args...)
	}
}

// color reports whether ANSI colour should be used on w.
func (a *app) color(w io.Writer) bool {
	if a.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	return ok && isTerminal(f)
}

func resolveVersion(v string) string {
	if v != "" && v != "dev" {
		return v
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(a.stdout, "tracestate %s\n", a.version)
			if bi, ok := debug.ReadBuildInfo(); ok {
				fmt.Fprintf(a.stdout, "go         %s\n", bi.GoVersion)
				for _, s := range bi.Settings {
					if s.Key == "vcs.revision" {
						fmt.Fprintf(a.stdout, "commit     %s\n", s.Value)
					}
				}
			}
			return nil
		},
	}
}

// output opens path for writing, or returns stdout for "" and "-".
func (a *app) output(path string) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return a.stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

// defaultLedger is where scans are recorded unless --ledger says otherwise.
func defaultLedger() string {
	if p := os.Getenv("TRACESTATE_LEDGER"); p != "" {
		return p
	}
	return "tracestate-ledger.db"
}
