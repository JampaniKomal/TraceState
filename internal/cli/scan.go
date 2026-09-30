package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/ledger"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/report"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

type scanOptions struct {
	rules      []string
	noDefaults bool
	exclude    []string
	format     string
	output     string
	extra      map[string]*string // format -> additional output path
	failOn     string
	ledger     string
	noLedger   bool
	online     bool
}

// extraFormats can be written alongside the main report with --<format>-output.
var extraFormats = []string{"json", "sarif", "markdown", "html"}

func (a *app) scanCmd() *cobra.Command {
	o := &scanOptions{extra: map[string]*string{}}
	for _, name := range extraFormats {
		o.extra[name] = new(string)
	}
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory or file and record the result in the ledger",
		Long: `Scan evaluates every rule against the target (default: the current
directory), prints a report, and appends the scan to the audit ledger.

One scan can write several reports at once, for example a table on the
terminal, SARIF for code scanning and Markdown for a job summary:

  tracestate scan . --sarif-output results.sarif --markdown-output summary.md

The exit code is 1 if any finding is at or above --fail-on (default high).`,
		Example: `  tracestate scan
  tracestate scan ./deploy --rules company-rules.yaml --fail-on medium
  tracestate scan . --format html --output report.html
  tracestate scan . --online            # also query OSV for vulnerable dependencies`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return a.runScan(cmd, path, o)
		},
	}
	f := cmd.Flags()
	f.StringArrayVarP(&o.rules, "rules", "r", nil, "additional rule file (YAML or JSON); repeatable; a rule with a built-in ID overrides it")
	f.BoolVar(&o.noDefaults, "no-default-rules", false, "don't load the built-in rule pack")
	f.StringArrayVarP(&o.exclude, "exclude", "e", nil, "glob of paths to leave out of the scan entirely (e.g. 'tests/**'); repeatable")
	f.StringVarP(&o.format, "format", "f", "table", "report format: "+strings.Join(report.Formats, ", "))
	f.StringVarP(&o.output, "output", "o", "", "write the report to this file instead of stdout")
	for _, name := range extraFormats {
		f.StringVar(o.extra[name], name+"-output", "", "also write a "+name+" report to this file")
	}
	f.StringVar(&o.failOn, "fail-on", "high", "exit 1 if a finding is at or above this severity (critical, high, medium, low, info, none)")
	f.StringVar(&o.ledger, "ledger", defaultLedger(), "ledger file to record the scan in (env TRACESTATE_LEDGER)")
	f.BoolVar(&o.noLedger, "no-ledger", false, "don't record the scan")
	f.BoolVar(&o.online, "online", false, "allow network lookups (OSV.dev advisories for dependency rules)")
	return cmd
}

func (a *app) runScan(cmd *cobra.Command, path string, o *scanOptions) error {
	threshold, never, err := parseFailOn(o.failOn)
	if err != nil {
		return usageErr(err)
	}
	if !validFormat(o.format) {
		return usageErr(fmt.Errorf("unknown format %q (want one of %s)", o.format, strings.Join(report.Formats, ", ")))
	}

	rs, err := policy.Load(!o.noDefaults, o.rules...)
	if err != nil {
		return usageErr(err)
	}
	t, err := scanner.NewTarget(path)
	if err != nil {
		return usageErr(err)
	}
	excluded, err := t.Exclude(o.exclude)
	if err != nil {
		return usageErr(err)
	}
	if excluded > 0 {
		a.note("excluded %d file(s)", excluded)
	}

	res, err := scanner.Run(cmd.Context(), t, rs, scanner.Options{Online: o.online})
	if err != nil {
		return err
	}
	rep := report.FromResult(res, a.version, o.online)

	if !o.noLedger {
		l, err := ledger.Open(cmd.Context(), o.ledger)
		if err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
		id, err := l.RecordScan(cmd.Context(), rep)
		if err == nil {
			var seq int64
			var hash string
			if seq, hash, err = l.Head(cmd.Context()); err == nil {
				a.note("ledger: scan %s recorded in %s (head %d:%s)", id, o.ledger, seq, shortID(hash))
			}
		}
		if cerr := l.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
	}

	if err := a.writeReport(o.format, o.output, rep); err != nil {
		return err
	}
	for _, format := range extraFormats {
		if path := *o.extra[format]; path != "" {
			if err := a.writeReport(format, path, rep); err != nil {
				return err
			}
		}
	}

	if worst, any := finding.Worst(rep.Findings); any && !never && worst >= threshold {
		return fail()
	}
	return nil
}

// writeReport renders rep in format to path ("" for stdout).
func (a *app) writeReport(format, path string, rep *report.Report) error {
	w, closeFn, err := a.output(path)
	if err != nil {
		return err
	}
	color := path == "" && a.color(a.stdout)
	if err := report.Render(format, w, rep, color); err != nil {
		_ = closeFn()
		return err
	}
	if err := closeFn(); err != nil {
		return err
	}
	if path != "" && path != "-" {
		a.note("wrote %s report to %s", format, path)
	}
	return nil
}

func parseFailOn(v string) (policy.Severity, bool, error) {
	if strings.EqualFold(strings.TrimSpace(v), "none") {
		return 0, true, nil
	}
	s, err := policy.ParseSeverity(v)
	if err != nil {
		return 0, false, fmt.Errorf("--fail-on: %w (or none)", err)
	}
	return s, false, nil
}

func validFormat(f string) bool {
	switch f {
	case "table", "text", "json", "sarif", "markdown", "md", "html":
		return true
	}
	return false
}

// usageErr marks an error as caused by the invocation (exit code 2).
func usageErr(err error) error { return &exitError{code: ExitError, err: err} }

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
