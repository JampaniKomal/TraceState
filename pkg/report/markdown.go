package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

var statusLabel = map[scanner.RuleStatus]string{
	scanner.Failed:        "Failed",
	scanner.Passed:        "Passed",
	scanner.NotApplicable: "Not applicable",
	scanner.NotEvaluated:  "Not evaluated",
}

// Markdown writes a compliance report suitable for a pull request comment,
// a wiki page or a GitHub Actions job summary.
func Markdown(w io.Writer, r *Report) error {
	var b strings.Builder
	s := r.Summary()
	b.WriteString("# TraceState compliance report\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Target | `%s` |\n", r.Target)
	fmt.Fprintf(&b, "| Scanned | %s (%d ms, %d files) |\n", r.StartedAt.Format("2006-01-02 15:04 MST"), r.DurationMS, r.FilesIndexed)
	fmt.Fprintf(&b, "| Rule set | `sha256:%s` from %s |\n", shortHash(r.RuleSetSHA256), strings.Join(r.RuleSources, ", "))
	if r.ScanID != "" {
		fmt.Fprintf(&b, "| Ledger scan ID | `%s` |\n", r.ScanID)
	}
	fmt.Fprintf(&b, "| Findings | **%d** (%s) in %d file(s), %d suppressed |\n", s.Total, severityCounts(s.BySeverity), s.FilesAffected, s.Suppressed)
	fmt.Fprintf(&b, "| Rules | %d failed · %d passed · %d not applicable · %d not evaluated |\n\n", s.RulesFailed, s.RulesPassed, s.RulesNA, s.RulesSkipped)

	b.WriteString("## Framework coverage\n\n")
	b.WriteString("A control **fails** if any rule mapped to it found a violation, and **passes** if at least one mapped rule was evaluated against matching files and found nothing. Passing here means \"no violation of these specific checks\", not certification.\n\n")
	for _, fc := range r.Coverage() {
		fmt.Fprintf(&b, "### %s\n\n%d failed · %d passed · %d not applicable · %d not evaluated\n\n", fc.Name, fc.Failed, fc.Passed, fc.NotApplicable, fc.NotEvaluated)
		b.WriteString("| Control | Title | Status | Rules | Findings |\n|---|---|---|---|---:|\n")
		for _, c := range fc.Controls {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %d |\n", c.Control, c.Title, statusLabel[c.Status], strings.Join(c.Rules, ", "), c.Findings)
		}
		b.WriteByte('\n')
	}

	b.WriteString("## Findings\n\n")
	groups := r.Groups()
	if len(groups) == 0 {
		b.WriteString("No violations found.\n")
	}
	for _, g := range groups {
		fmt.Fprintf(&b, "### %s · %s · %s\n\n", strings.ToUpper(g.Severity.String()), g.Rule.ID, g.Rule.Title)
		if len(g.Rule.Controls) > 0 {
			fmt.Fprintf(&b, "**Controls:** %s\n\n", ControlsLine(g.Rule.Controls))
		}
		b.WriteString("| Location | Detail | Evidence |\n|---|---|---|\n")
		for _, f := range g.Findings {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", Location(f), mdCell(f.Message), mdCode(f.Evidence))
		}
		if g.Rule.Remediation != "" {
			fmt.Fprintf(&b, "\n**Remediation:** %s\n", g.Rule.Remediation)
		}
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func mdCell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}

func mdCode(s string) string {
	if s == "" {
		return ""
	}
	return "`" + strings.NewReplacer("`", "'", "|", `\|`, "\n", " ").Replace(s) + "`"
}
