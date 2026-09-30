package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
)

// RuleStatus says what happened to a rule during a scan.
type RuleStatus string

const (
	// Failed: the rule produced at least one (unsuppressed) finding.
	Failed RuleStatus = "failed"
	// Passed: the rule was evaluated against at least one file and found nothing.
	Passed RuleStatus = "passed"
	// NotApplicable: no file in the target matched the rule's globs.
	NotApplicable RuleStatus = "not_applicable"
	// NotEvaluated: the rule was skipped (e.g. it needs --online).
	NotEvaluated RuleStatus = "not_evaluated"
)

// RuleResult is the per-rule outcome of a scan.
type RuleResult struct {
	Rule         *policy.Rule `json:"-"`
	RuleID       string       `json:"rule_id"`
	Status       RuleStatus   `json:"status"`
	FilesMatched int          `json:"files_matched"`
	Findings     int          `json:"findings"`
	Reason       string       `json:"reason,omitempty"`
}

// Result is everything a scan produced.
type Result struct {
	Target       string            `json:"target"`
	StartedAt    time.Time         `json:"started_at"`
	Duration     time.Duration     `json:"duration_ns"`
	FilesIndexed int               `json:"files_indexed"`
	FilesSkipped int               `json:"files_skipped"`
	Findings     []finding.Finding `json:"findings"`
	Suppressed   int               `json:"suppressed"`
	Rules        []RuleResult      `json:"rules"`
	RuleSetSHA   string            `json:"ruleset_sha256"`
	RuleSources  []string          `json:"ruleset_sources"`
}

// Run evaluates every rule in rs against t and returns the combined result.
// Rules are dispatched to the wire that owns their check; findings on lines
// carrying a `tracestate:ignore` comment are suppressed and counted.
func Run(ctx context.Context, t *Target, rs *policy.RuleSet, opts Options) (*Result, error) {
	if err := rs.Validate(KnownChecks()); err != nil {
		return nil, err
	}
	res := &Result{
		Target:       t.Root,
		StartedAt:    time.Now().UTC(),
		FilesIndexed: len(t.Files()),
		FilesSkipped: t.Skipped(),
		RuleSetSHA:   rs.SHA256,
		RuleSources:  rs.Sources,
	}

	byWire := map[string][]Job{}
	var wireOrder []string
	results := make([]RuleResult, len(rs.Rules))
	index := map[string]int{}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		index[r.ID] = i
		rr := RuleResult{Rule: r, RuleID: r.ID}
		files := t.Match(r.Files, r.Exclude)
		rr.FilesMatched = len(files)
		switch {
		case r.Online && !opts.Online:
			rr.Status, rr.Reason = NotEvaluated, "requires --online"
		case len(files) == 0:
			rr.Status = NotApplicable
		default:
			rr.Status = Passed
			w := r.Wire()
			if _, seen := byWire[w]; !seen {
				wireOrder = append(wireOrder, w)
			}
			byWire[w] = append(byWire[w], Job{Rule: r, Files: files})
		}
		results[i] = rr
	}

	for _, name := range wireOrder {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		w, ok := lookup(name)
		if !ok {
			return nil, fmt.Errorf("no wire registered for %q", name)
		}
		found, err := w.Scan(ctx, t, byWire[name], opts)
		if err != nil {
			return nil, fmt.Errorf("wire %s: %w", name, err)
		}
		for _, f := range found {
			if suppressed(t, f) {
				res.Suppressed++
				continue
			}
			res.Findings = append(res.Findings, f.Seal())
			if i, ok := index[f.RuleID]; ok {
				results[i].Findings++
				results[i].Status = Failed
			}
		}
	}

	finding.Sort(res.Findings)
	res.Rules = results
	res.Duration = time.Since(res.StartedAt)
	return res, nil
}

var (
	ignoreRe = regexp.MustCompile(`tracestate:ignore(?:[=\s]+([A-Za-z0-9_,\- ]+))?`)
	// Rule IDs are upper case (TS-SEC-003), which keeps free-text reasons
	// such as "false-positive" from being mistaken for one.
	ruleIDRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$`)
)

// suppressed reports whether the finding is covered by a
// `tracestate:ignore` directive, either at the end of the finding's own line
// or alone on a comment line directly above it. The directive may name the
// rules it covers (`tracestate:ignore TS-SEC-003, TS-LOG-001 reason...`);
// without rule IDs it covers every rule.
func suppressed(t *Target, f finding.Finding) bool {
	if f.Line <= 0 {
		return false
	}
	data, err := t.Read(f.File)
	if err != nil {
		return false
	}
	lines := Lines(data)
	for _, n := range []int{f.Line - 1, f.Line - 2} {
		if n < 0 || n >= len(lines) {
			continue
		}
		if n == f.Line-2 && !CommentOnly(lines[n]) {
			continue
		}
		m := ignoreRe.FindStringSubmatch(lines[n])
		if m == nil {
			continue
		}
		var ids []string
		for _, tok := range strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' }) {
			if ruleIDRe.MatchString(tok) {
				ids = append(ids, tok)
			}
		}
		// A bare `tracestate:ignore` (optionally followed by a free-text
		// reason) suppresses every rule on that line.
		if len(ids) == 0 {
			return true
		}
		for _, id := range ids {
			if strings.EqualFold(id, f.RuleID) {
				return true
			}
		}
	}
	return false
}

// CommentOnly reports whether a line holds nothing but a comment. Wires use
// it to skip code examples and commented-out statements.
func CommentOnly(line string) bool {
	l := strings.TrimSpace(line)
	for _, p := range []string{"#", "//", "/*", "*", "<!--", "--", ";", "{{/*", "rem ", "REM "} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}
