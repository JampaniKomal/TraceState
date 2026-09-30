package wires

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/detect"
	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// piiWire looks for personal data and credentials in logs and data exports.
// Identifiers with a checksum (Aadhaar's Verhoeff digit, card numbers' Luhn
// digit) are validated before being reported, which removes most of the false
// positives a plain regex produces. Findings are aggregated per file and the
// evidence is always masked, so the ledger never stores the data itself.
type piiWire struct{}

// match is one detected value on one line.
type match struct {
	line   int
	masked string
	note   string
}

type piiDetector struct {
	what   string
	detect func(line string) []match
	// maybe is a cheap test a line must pass before detect runs.
	maybe func(line string) bool
}

func atLeastDigits(n int) func(string) bool {
	return func(line string) bool { return digitCount(line) >= n }
}

var piiDetectors = map[string]piiDetector{
	"pii.aadhaar":      {"Aadhaar number", detectAadhaar, atLeastDigits(12)},
	"pii.pan_in":       {"PAN", detectPAN, atLeastDigits(4)},
	"pii.payment_card": {"payment card number", detectCards, atLeastDigits(13)},
	"pii.email":        {"email address", detectEmails, func(l string) bool { return strings.Contains(l, "@") }},
	"pii.phone_in":     {"Indian mobile number", detectPhones, atLeastDigits(10)},
	"pii.credential_in_log": {"credential", detectLoggedCredentials, func(l string) bool {
		return containsAnyFold(l, []string{"pass", "pwd", "secret", "key", "token", "auth"})
	}},
}

func (piiWire) Name() string     { return "pii" }
func (piiWire) Checks() []string { return keys(piiDetectors) }

func (piiWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, job := range jobs {
		d := piiDetectors[job.Rule.Check]
		err := forEachFile(t, job, func(file string, data []byte) error {
			var all []match
			for i, line := range scanner.Lines(data) {
				if !d.maybe(line) {
					continue
				}
				for _, m := range d.detect(line) {
					m.line = i + 1
					all = append(all, m)
				}
			}
			if f, ok := aggregate(job.Rule, file, d.what, all); ok {
				out = append(out, f)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// aggregate turns every match in one file into a single finding that points
// at the first occurrence and counts the rest.
func aggregate(r *policy.Rule, file, what string, ms []match) (finding.Finding, bool) {
	if len(ms) == 0 {
		return finding.Finding{}, false
	}
	lines := map[int]bool{}
	notes := map[string]int{}
	for _, m := range ms {
		lines[m.line] = true
		if m.note != "" {
			notes[m.note]++
		}
	}
	msg := fmt.Sprintf("%d %s value(s) in cleartext across %d line(s)", len(ms), what, len(lines))
	if len(notes) > 0 {
		var parts []string
		for _, n := range keys(notes) {
			parts = append(parts, fmt.Sprintf("%d %s", notes[n], n))
		}
		msg += " (" + strings.Join(parts, ", ") + ")"
	}
	f := newFinding(r, file, ms[0].line, msg, "first: "+ms[0].masked)
	f.Occurrences = len(ms)
	return f, true
}

var (
	aadhaarBare     = regexp.MustCompile(`(?:^|\D)([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?:\D|$)`)
	aadhaarLabelled = regexp.MustCompile(`(?i)aadhaa?r\w*["']?\s*[:=]\s*["']?(\d{4}[ -]?\d{4}[ -]?\d{4})\b`)
)

func detectAadhaar(line string) []match {
	var out []match
	seen := map[string]bool{}
	for _, m := range aadhaarLabelled.FindAllStringSubmatch(line, -1) {
		d := detect.Digits(m[1])
		seen[d] = true
		note := "labelled as Aadhaar"
		if detect.IsAadhaar(d) {
			note = "checksum-valid"
		}
		out = append(out, match{masked: detect.MaskTail(m[1], 4), note: note})
	}
	for _, m := range aadhaarBare.FindAllStringSubmatch(line, -1) {
		d := detect.Digits(m[1])
		if seen[d] || !detect.IsAadhaar(d) {
			continue
		}
		seen[d] = true
		out = append(out, match{masked: detect.MaskTail(m[1], 4), note: "checksum-valid"})
	}
	return out
}

var panRe = regexp.MustCompile(`\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b`)

func detectPAN(line string) []match {
	var out []match
	for _, m := range panRe.FindAllString(line, -1) {
		out = append(out, match{masked: detect.MaskTail(m, 2)})
	}
	return out
}

var cardRe = regexp.MustCompile(`(?:^|[^\d])((?:\d[ -]?){12,18}\d)(?:[^\d]|$)`)

func detectCards(line string) []match {
	var out []match
	for _, m := range cardRe.FindAllStringSubmatch(line, -1) {
		if detect.IsPaymentCard(m[1]) {
			out = append(out, match{masked: detect.MaskTail(m[1], 4), note: "Luhn-valid"})
		}
	}
	return out
}

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

func detectEmails(line string) []match {
	var out []match
	for _, m := range emailRe.FindAllString(line, -1) {
		out = append(out, match{masked: detect.MaskEmail(m)})
	}
	return out
}

var phoneRe = regexp.MustCompile(`(?:^|[^\d+])((?:\+91[ -]?)?[6-9]\d{9})(?:\D|$)`)

func detectPhones(line string) []match {
	var out []match
	for _, m := range phoneRe.FindAllStringSubmatch(line, -1) {
		out = append(out, match{masked: detect.MaskTail(m[1], 4)})
	}
	return out
}

var (
	loggedCredential = regexp.MustCompile(`(?i)["']?\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token|authorization)\b["']?\s*[:=]\s*["']?((?:Bearer\s+)?[^\s"',;}\]]{3,})`)
	redactedValue    = regexp.MustCompile(`(?i)^(none|null|nil|undefined|\*+|\[?redacted\]?|<redacted>|masked|hidden|x+|-)$`)
)

func detectLoggedCredentials(line string) []match {
	var out []match
	for _, m := range loggedCredential.FindAllStringSubmatch(line, -1) {
		val := strings.TrimPrefix(m[2], "Bearer ")
		if redactedValue.MatchString(val) {
			continue
		}
		out = append(out, match{masked: m[1] + "=" + detect.MaskSecret(val), note: strings.ToLower(m[1])})
	}
	return out
}
