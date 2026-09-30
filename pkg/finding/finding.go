// Package finding defines the result type every scanner wire produces.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/jampanikomal/tracestate/v2/pkg/policy"
)

// Finding is one violation of one rule at one location.
type Finding struct {
	RuleID      string              `json:"rule_id"`
	Title       string              `json:"title"`
	Severity    policy.Severity     `json:"severity"`
	Wire        string              `json:"wire"`
	File        string              `json:"file"`
	Line        int                 `json:"line,omitempty"`
	Message     string              `json:"message"`
	Evidence    string              `json:"evidence,omitempty"`
	Occurrences int                 `json:"occurrences,omitempty"`
	Controls    []policy.ControlRef `json:"controls,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
	Fingerprint string              `json:"fingerprint"`
}

// New starts a finding for rule r at file:line. Callers fill in Message and,
// where useful, Evidence and Occurrences, then call Seal.
func New(r *policy.Rule, file string, line int) Finding {
	return Finding{
		RuleID:      r.ID,
		Title:       r.Title,
		Severity:    r.Severity,
		Wire:        r.Wire(),
		File:        file,
		Line:        line,
		Controls:    r.Controls(),
		Remediation: r.Remediation,
	}
}

// Seal computes the finding's fingerprint: a stable identifier built from
// the rule, the file and the (already redacted) evidence, deliberately not
// the line number, so a finding keeps its identity when unrelated lines move.
func (f Finding) Seal() Finding {
	h := sha256.New()
	for _, part := range []string{f.RuleID, f.File, f.Evidence, f.Message} {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
	}
	f.Fingerprint = hex.EncodeToString(h.Sum(nil))[:32]
	return f
}

// Sort orders findings by severity (highest first), then file, line and rule.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

// CountBySeverity tallies findings per severity name.
func CountBySeverity(fs []Finding) map[string]int {
	counts := map[string]int{}
	for s := policy.Info; s <= policy.Critical; s++ {
		counts[s.String()] = 0
	}
	for _, f := range fs {
		counts[f.Severity.String()]++
	}
	return counts
}

// Worst returns the highest severity present, and false if fs is empty.
func Worst(fs []Finding) (policy.Severity, bool) {
	if len(fs) == 0 {
		return policy.Info, false
	}
	worst := policy.Info
	for _, f := range fs {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst, true
}
