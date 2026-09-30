// Package report turns a scan result into the formats people and tools
// consume: a terminal table, JSON, SARIF, Markdown and a standalone HTML
// compliance report, plus the framework-control coverage matrix they share.
package report

import (
	"sort"
	"time"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// ToolName and ToolURL identify TraceState in machine-readable output.
const (
	ToolName = "TraceState"
	ToolURL  = "https://github.com/JampaniKomal/TraceState"
)

// RuleOutcome is a rule plus what happened to it in one scan. It carries the
// rule's metadata so a report can be rebuilt from the ledger even after the
// rule files have changed.
type RuleOutcome struct {
	ID           string              `json:"id"`
	Title        string              `json:"title"`
	Severity     policy.Severity     `json:"severity"`
	Check        string              `json:"check"`
	Status       scanner.RuleStatus  `json:"status"`
	FilesMatched int                 `json:"files_matched"`
	Findings     int                 `json:"findings"`
	Reason       string              `json:"reason,omitempty"`
	Controls     []policy.ControlRef `json:"controls,omitempty"`
	Remediation  string              `json:"remediation,omitempty"`
	Description  string              `json:"description,omitempty"`
}

// Report is the complete, self-describing record of one scan.
type Report struct {
	Tool          string            `json:"tool"`
	Version       string            `json:"version"`
	ScanID        string            `json:"scan_id,omitempty"`
	Target        string            `json:"target"`
	StartedAt     time.Time         `json:"started_at"`
	DurationMS    int64             `json:"duration_ms"`
	FilesIndexed  int               `json:"files_indexed"`
	FilesSkipped  int               `json:"files_skipped"`
	Online        bool              `json:"online"`
	RuleSetSHA256 string            `json:"ruleset_sha256"`
	RuleSources   []string          `json:"ruleset_sources"`
	Suppressed    int               `json:"suppressed"`
	Findings      []finding.Finding `json:"findings"`
	Rules         []RuleOutcome     `json:"rules"`
}

// FromResult builds a Report from an engine result.
func FromResult(res *scanner.Result, version string, online bool) *Report {
	r := &Report{
		Tool:          ToolName,
		Version:       version,
		Target:        res.Target,
		StartedAt:     res.StartedAt,
		DurationMS:    res.Duration.Milliseconds(),
		FilesIndexed:  res.FilesIndexed,
		FilesSkipped:  res.FilesSkipped,
		Online:        online,
		RuleSetSHA256: res.RuleSetSHA,
		RuleSources:   res.RuleSources,
		Suppressed:    res.Suppressed,
		Findings:      res.Findings,
	}
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	for _, rr := range res.Rules {
		r.Rules = append(r.Rules, RuleOutcome{
			ID:           rr.Rule.ID,
			Title:        rr.Rule.Title,
			Severity:     rr.Rule.Severity,
			Check:        rr.Rule.Check,
			Status:       rr.Status,
			FilesMatched: rr.FilesMatched,
			Findings:     rr.Findings,
			Reason:       rr.Reason,
			Controls:     rr.Rule.Controls(),
			Remediation:  rr.Rule.Remediation,
			Description:  rr.Rule.Description,
		})
	}
	return r
}

// Summary is the at-a-glance count block every format shows.
type Summary struct {
	Total         int            `json:"total"`
	BySeverity    map[string]int `json:"by_severity"`
	Suppressed    int            `json:"suppressed"`
	RulesFailed   int            `json:"rules_failed"`
	RulesPassed   int            `json:"rules_passed"`
	RulesNA       int            `json:"rules_not_applicable"`
	RulesSkipped  int            `json:"rules_not_evaluated"`
	FilesAffected int            `json:"files_affected"`
}

// Summary computes the report's counts.
func (r *Report) Summary() Summary {
	s := Summary{Total: len(r.Findings), BySeverity: finding.CountBySeverity(r.Findings), Suppressed: r.Suppressed}
	files := map[string]bool{}
	for _, f := range r.Findings {
		files[f.File] = true
	}
	s.FilesAffected = len(files)
	for _, ro := range r.Rules {
		switch ro.Status {
		case scanner.Failed:
			s.RulesFailed++
		case scanner.Passed:
			s.RulesPassed++
		case scanner.NotApplicable:
			s.RulesNA++
		case scanner.NotEvaluated:
			s.RulesSkipped++
		}
	}
	return s
}

// ControlCoverage is the status of one framework control across every rule
// mapped to it.
type ControlCoverage struct {
	Control  string             `json:"control"`
	Title    string             `json:"title,omitempty"`
	Status   scanner.RuleStatus `json:"status"`
	Rules    []string           `json:"rules"`
	Findings int                `json:"findings"`
}

// FrameworkCoverage groups control coverage for one framework.
type FrameworkCoverage struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Controls      []ControlCoverage `json:"controls"`
	Failed        int               `json:"failed"`
	Passed        int               `json:"passed"`
	NotApplicable int               `json:"not_applicable"`
	NotEvaluated  int               `json:"not_evaluated"`
}

// statusRank orders statuses so the "worst" one wins when a control is
// evidenced by several rules: a single failing rule fails the control.
var statusRank = map[scanner.RuleStatus]int{
	scanner.NotApplicable: 0, scanner.NotEvaluated: 1, scanner.Passed: 2, scanner.Failed: 3,
}

// Coverage computes, for every framework the rules map to, the status of
// each control: failed if any mapped rule failed, passed if at least one
// mapped rule was evaluated and passed, otherwise not evaluated / not
// applicable. It answers "which controls did this scan actually evidence?".
func (r *Report) Coverage() []FrameworkCoverage {
	type key struct{ fw, control string }
	controls := map[key]*ControlCoverage{}
	for _, ro := range r.Rules {
		for _, c := range ro.Controls {
			k := key{c.Framework, c.Control}
			cc, ok := controls[k]
			if !ok {
				cc = &ControlCoverage{Control: c.Control, Title: c.Title, Status: scanner.NotApplicable}
				controls[k] = cc
			}
			cc.Rules = append(cc.Rules, ro.ID)
			cc.Findings += ro.Findings
			if statusRank[ro.Status] > statusRank[cc.Status] {
				cc.Status = ro.Status
			}
		}
	}
	byFw := map[string]*FrameworkCoverage{}
	for k, cc := range controls {
		fc, ok := byFw[k.fw]
		if !ok {
			fc = &FrameworkCoverage{ID: k.fw, Name: policy.FrameworkName(k.fw)}
			byFw[k.fw] = fc
		}
		fc.Controls = append(fc.Controls, *cc)
		switch cc.Status {
		case scanner.Failed:
			fc.Failed++
		case scanner.Passed:
			fc.Passed++
		case scanner.NotApplicable:
			fc.NotApplicable++
		case scanner.NotEvaluated:
			fc.NotEvaluated++
		}
	}
	out := make([]FrameworkCoverage, 0, len(byFw))
	for _, fc := range byFw {
		sort.Slice(fc.Controls, func(i, j int) bool { return policy.ControlLess(fc.Controls[i].Control, fc.Controls[j].Control) })
		out = append(out, *fc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
