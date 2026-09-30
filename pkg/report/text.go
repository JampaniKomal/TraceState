package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/policy"
)

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"
)

var severityColor = map[policy.Severity]string{
	policy.Critical: "\033[1;35m",
	policy.High:     "\033[1;31m",
	policy.Medium:   "\033[33m",
	policy.Low:      "\033[36m",
	policy.Info:     "\033[37m",
}

// Text writes a human-readable report for the terminal.
func Text(w io.Writer, r *Report, color bool) error {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + ansiReset
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s · %d files in %s · %d ms · rules sha256:%s\n\n",
		paint(ansiBold, r.Tool), r.Version, r.FilesIndexed, r.Target, r.DurationMS, shortHash(r.RuleSetSHA256))

	if len(r.Findings) == 0 {
		b.WriteString(paint("\033[32m", "No violations found.") + "\n\n")
	}
	for _, f := range r.Findings {
		sev := fmt.Sprintf("%-8s", strings.ToUpper(f.Severity.String()))
		fmt.Fprintf(&b, "%s  %s  %s\n", paint(severityColor[f.Severity], sev), paint(ansiBold, f.RuleID), f.Title)
		fmt.Fprintf(&b, "          %s\n", Location(f))
		fmt.Fprintf(&b, "          %s\n", f.Message)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "          %s\n", paint(ansiDim, "evidence: "+f.Evidence))
		}
		if len(f.Controls) > 0 {
			fmt.Fprintf(&b, "          %s\n", paint(ansiDim, ControlsLine(f.Controls)))
		}
		b.WriteByte('\n')
	}

	s := r.Summary()
	fmt.Fprintf(&b, "%s %d finding(s) (%s) in %d file(s)", paint(ansiBold, "Findings:"), s.Total, severityCounts(s.BySeverity), s.FilesAffected)
	if s.Suppressed > 0 {
		fmt.Fprintf(&b, " · %d suppressed", s.Suppressed)
	}
	fmt.Fprintf(&b, "\n%s %d failed · %d passed · %d not applicable", paint(ansiBold, "Rules:   "), s.RulesFailed, s.RulesPassed, s.RulesNA)
	if s.RulesSkipped > 0 {
		fmt.Fprintf(&b, " · %d not evaluated (need --online)", s.RulesSkipped)
	}
	b.WriteByte('\n')
	var fws []string
	for _, fc := range r.Coverage() {
		fws = append(fws, fmt.Sprintf("%s %d/%d", fc.ID, fc.Failed, fc.Failed+fc.Passed))
	}
	if len(fws) > 0 {
		fmt.Fprintf(&b, "%s %s %s\n", paint(ansiBold, "Controls:"), strings.Join(fws, " · "), paint(ansiDim, "(failed/evaluated)"))
	}
	_, err := io.WriteString(w, b.String())
	return err
}
