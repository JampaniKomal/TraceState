package wires

import (
	"context"
	"fmt"

	"github.com/jampanikomal/tracestate/v2/pkg/detect"
	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// regexWire runs user-defined pattern rules, so a team can encode an
// organisation-specific policy in YAML without writing Go:
//
//   - regex.match:  every file matching the globs must NOT contain the pattern
//   - regex.absent: every file matching the globs MUST contain the pattern
type regexWire struct{}

var regexChecks = map[string]fileCheck{
	"regex.match":  regexMatch,
	"regex.absent": regexAbsent,
}

func (regexWire) Name() string     { return "regex" }
func (regexWire) Checks() []string { return keys(regexChecks) }

func (regexWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	return runFileChecks(t, jobs, regexChecks)
}

func regexMatch(r *policy.Rule, file string, data []byte) []finding.Finding {
	re := r.Regexp()
	var first int
	var evidence string
	count := 0
	for i, line := range scanner.Lines(data) {
		ms := re.FindAllString(line, -1)
		if len(ms) == 0 {
			continue
		}
		if count == 0 {
			first = i + 1
			evidence = ms[0]
			if r.Redact {
				evidence = detect.MaskSecret(evidence)
			}
			evidence = snippet(evidence)
		}
		count += len(ms)
	}
	if count == 0 {
		return nil
	}
	f := newFinding(r, file, first, fmt.Sprintf("pattern matched %d time(s)", count), evidence)
	f.Occurrences = count
	return []finding.Finding{f}
}

func regexAbsent(r *policy.Rule, file string, data []byte) []finding.Finding {
	if r.Regexp().Match(data) {
		return nil
	}
	return []finding.Finding{newFinding(r, file, 0,
		fmt.Sprintf("required pattern %q not found", r.Pattern), "")}
}
