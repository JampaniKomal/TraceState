package report

import (
	_ "embed"
	"html/template"
	"io"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

//go:embed report.html.tmpl
var htmlTemplate string

var htmlFuncs = template.FuncMap{
	"upper":    strings.ToUpper,
	"location": Location,
	"controls": ControlsLine,
	"short":    shortHash,
	"status":   func(s scanner.RuleStatus) string { return statusLabel[s] },
	"sevclass": func(s policy.Severity) string { return "sev-" + s.String() },
	"join":     strings.Join,
	"count":    func(m map[string]int, k string) int { return m[k] },
	"severities": func() []string {
		return []string{"critical", "high", "medium", "low", "info"}
	},
}

var htmlTmpl = template.Must(template.New("report").Funcs(htmlFuncs).Parse(htmlTemplate))

// HTML writes a standalone HTML compliance report (no external assets).
func HTML(w io.Writer, r *Report) error {
	return htmlTmpl.Execute(w, struct {
		*Report
		Summary  Summary
		Coverage []FrameworkCoverage
		Groups   []RuleGroup
	}{r, r.Summary(), r.Coverage(), r.Groups()})
}
