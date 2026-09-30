package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
)

// Formats lists the output formats Render accepts.
var Formats = []string{"table", "json", "sarif", "markdown", "html"}

// Render writes r in the named format. color only affects "table".
func Render(format string, w io.Writer, r *Report, color bool) error {
	switch format {
	case "table", "text":
		return Text(w, r, color)
	case "json":
		return JSON(w, r)
	case "sarif":
		return SARIF(w, r)
	case "markdown", "md":
		return Markdown(w, r)
	case "html":
		return HTML(w, r)
	}
	return fmt.Errorf("unknown format %q (want one of %s)", format, strings.Join(Formats, ", "))
}

// JSON writes the report together with its summary and coverage matrix.
func JSON(w io.Writer, r *Report) error {
	out := struct {
		*Report
		Summary  Summary             `json:"summary"`
		Coverage []FrameworkCoverage `json:"coverage"`
	}{r, r.Summary(), r.Coverage()}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// RuleGroup is a failed rule with every finding it produced; the Markdown
// and HTML reports are organised this way so each remediation appears once.
type RuleGroup struct {
	Rule     RuleOutcome
	Severity policy.Severity
	Findings []finding.Finding
}

// Groups returns findings grouped by rule, worst severity first.
func (r *Report) Groups() []RuleGroup {
	byRule := map[string]*RuleGroup{}
	rules := map[string]RuleOutcome{}
	for _, ro := range r.Rules {
		rules[ro.ID] = ro
	}
	var order []string
	for _, f := range r.Findings {
		g, ok := byRule[f.RuleID]
		if !ok {
			ro, known := rules[f.RuleID]
			if !known {
				ro = RuleOutcome{ID: f.RuleID, Title: f.Title, Severity: f.Severity, Controls: f.Controls, Remediation: f.Remediation}
			}
			g = &RuleGroup{Rule: ro}
			byRule[f.RuleID] = g
			order = append(order, f.RuleID)
		}
		g.Findings = append(g.Findings, f)
		if f.Severity > g.Severity {
			g.Severity = f.Severity
		}
	}
	out := make([]RuleGroup, 0, len(order))
	for _, id := range order {
		out = append(out, *byRule[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Rule.ID < out[j].Rule.ID
	})
	return out
}

// Location formats file:line for display.
func Location(f finding.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// ControlsLine renders controls compactly: "ISO27001 A.8.2, A.8.27 · CWE CWE-668".
func ControlsLine(refs []policy.ControlRef) string {
	var parts []string
	var fw string
	var cur []string
	flush := func() {
		if fw != "" {
			parts = append(parts, fw+" "+strings.Join(cur, ", "))
		}
	}
	for _, c := range refs {
		if c.Framework != fw {
			flush()
			fw, cur = c.Framework, nil
		}
		cur = append(cur, c.Control)
	}
	flush()
	return strings.Join(parts, " · ")
}

// severityCounts renders "5 critical, 12 high" skipping zeros.
func severityCounts(counts map[string]int) string {
	var parts []string
	for s := policy.Critical; s >= policy.Info; s-- {
		if n := counts[s.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
