// Package wires contains TraceState's built-in scanner modules. Importing it
// (usually for side effects) registers every built-in wire with the scanner.
package wires

import (
	"bytes"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

func init() {
	scanner.Register(composeWire{})
	scanner.Register(dockerfileWire{})
	scanner.Register(secretsWire{})
	scanner.Register(corsWire{})
	scanner.Register(tlsWire{})
	scanner.Register(piiWire{})
	scanner.Register(loggingWire{})
	scanner.Register(newDepsWire())
	scanner.Register(regexWire{})
	scanner.Register(schemaWire{})
}

// secretName matches identifiers that conventionally hold credentials.
var secretName = regexp.MustCompile(`(?i)(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|private[_-]?key|credential|bypass|backdoor)`)

// notSecretName excludes identifiers that match secretName but conventionally
// hold something harmless (a token's type, a password policy's length...).
var notSecretName = regexp.MustCompile(`(?i)(_?(type|kind|name|field|header|url|uri|endpoint|path|file|length|len|min|max|policy|regex|pattern|prefix|expiry|expires|ttl|count|id)$|^token_?(type|endpoint)|placeholder)`)

// isPlaceholder reports values that are clearly not real secrets.
func isPlaceholder(v string) bool {
	l := strings.ToLower(v)
	if l == "" || strings.HasPrefix(l, "$") || strings.HasPrefix(l, "%") || strings.Contains(l, "{{") {
		return true
	}
	// A path to a mounted secret file (Docker/Kubernetes secrets) is a
	// reference to the secret, not the secret.
	if strings.HasPrefix(l, "/run/secrets/") || strings.HasPrefix(l, "/var/run/secrets/") {
		return true
	}
	for _, p := range []string{"<", "your_", "your-", "example", "xxxx", "****", "redacted", "placeholder", "dummy", "replace", "insert_", "todo"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// forEachFile reads each file of a job, skipping binary files.
func forEachFile(t *scanner.Target, job scanner.Job, fn func(file string, data []byte) error) error {
	for _, file := range job.Files {
		data, err := t.Read(file)
		if errors.Is(err, scanner.ErrBinary) {
			continue
		}
		if err != nil {
			return err
		}
		if err := fn(file, data); err != nil {
			return err
		}
	}
	return nil
}

// minified reports files that are machine-generated bundles (very long
// lines): statement-level checks on them produce noise, not findings.
func minified(data []byte) bool {
	if len(data) < 4096 {
		return false
	}
	lines := bytes.Count(data, []byte{'\n'}) + 1
	return len(data)/lines > 400
}

// newFinding is a small convenience wrapper around finding.New.
func newFinding(r *policy.Rule, file string, line int, msg, evidence string) finding.Finding {
	f := finding.New(r, file, line)
	f.Message = msg
	f.Evidence = evidence
	return f
}

// snippet trims a source line for use as evidence.
func snippet(line string) string {
	s := strings.TrimSpace(line)
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

// keys returns a map's keys in sorted order.
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// containsAny reports whether s contains any of lits. Wires use it as a cheap
// prefilter so that regular expressions only run on lines that could match.
func containsAny(s string, lits []string) bool {
	for _, l := range lits {
		if strings.Contains(s, l) {
			return true
		}
	}
	return false
}

// containsAnyFold is containsAny ignoring ASCII case; lits must be lower case.
func containsAnyFold(s string, lits []string) bool {
	return containsAny(strings.ToLower(s), lits)
}

// digitCount counts ASCII digits in s.
func digitCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}
