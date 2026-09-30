// Package policy defines TraceState's policy-as-code model: rules, the
// frameworks they map to, and how rule files are loaded and validated.
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Rule is one policy statement: what to check, where to look, how serious a
// violation is, and which compliance controls it evidences.
type Rule struct {
	ID          string              `yaml:"id" json:"id"`
	Title       string              `yaml:"title" json:"title"`
	Description string              `yaml:"description,omitempty" json:"description,omitempty"`
	Severity    Severity            `yaml:"severity" json:"severity"`
	Check       string              `yaml:"check" json:"check"`
	Files       []string            `yaml:"files" json:"files"`
	Exclude     []string            `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	Pattern     string              `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Redact      bool                `yaml:"redact,omitempty" json:"redact,omitempty"`
	Frameworks  map[string][]string `yaml:"frameworks,omitempty" json:"frameworks,omitempty"`
	Remediation string              `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	References  []string            `yaml:"references,omitempty" json:"references,omitempty"`
	Online      bool                `yaml:"online,omitempty" json:"online,omitempty"`

	compiled *regexp.Regexp
}

// Regexp returns the compiled Pattern. It is only valid after Validate.
func (r *Rule) Regexp() *regexp.Regexp { return r.compiled }

// Wire is the scanner module responsible for this rule: the part of Check
// before the first dot ("compose.user_root" -> "compose").
func (r *Rule) Wire() string {
	if i := strings.IndexByte(r.Check, '.'); i >= 0 {
		return r.Check[:i]
	}
	return r.Check
}

// Controls returns the rule's framework mappings as a sorted list.
func (r *Rule) Controls() []ControlRef { return SortedControls(r.Frameworks) }

// RuleSet is an ordered collection of rules plus the fingerprint of the
// source files they were loaded from, which is recorded in the ledger so a
// scan can always be tied back to the exact policy it ran.
type RuleSet struct {
	Rules   []Rule
	Sources []string
	SHA256  string
}

// Validate checks every rule for structural problems. knownChecks is the set
// of check identifiers the registered wires implement.
func (rs *RuleSet) Validate(knownChecks map[string]bool) error {
	var problems []string
	seen := map[string]bool{}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		where := fmt.Sprintf("rule %q", r.ID)
		if r.ID == "" {
			where = fmt.Sprintf("rule #%d", i+1)
			problems = append(problems, where+": missing id")
		}
		if seen[r.ID] {
			problems = append(problems, where+": duplicate id")
		}
		seen[r.ID] = true
		if r.Title == "" {
			problems = append(problems, where+": missing title")
		}
		if r.Check == "" {
			problems = append(problems, where+": missing check")
		} else if knownChecks != nil && !knownChecks[r.Check] {
			problems = append(problems, fmt.Sprintf("%s: unknown check %q", where, r.Check))
		}
		if len(r.Files) == 0 {
			problems = append(problems, where+": no file patterns (files)")
		}
		for _, g := range append(append([]string{}, r.Files...), r.Exclude...) {
			if !doublestar.ValidatePattern(g) {
				problems = append(problems, fmt.Sprintf("%s: invalid glob %q", where, g))
			}
		}
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: invalid pattern: %v", where, err))
			}
			r.compiled = re
		} else if strings.HasPrefix(r.Check, "regex.") {
			problems = append(problems, where+": regex checks need a pattern")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid ruleset:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// Frameworks returns the sorted, de-duplicated list of framework IDs the rule
// set maps to.
func (rs *RuleSet) Frameworks() []string {
	set := map[string]bool{}
	for _, r := range rs.Rules {
		for fw := range r.Frameworks {
			set[fw] = true
		}
	}
	out := make([]string, 0, len(set))
	for fw := range set {
		out = append(out, fw)
	}
	sortStrings(out)
	return out
}
