package wires

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// loggingWire finds log statements in source code that interpolate
// credentials, authorization headers or whole request/response payloads.
// It catches the leak at its origin, before any log file exists.
type loggingWire struct{}

var loggingChecks = map[string]fileCheck{"logging.sensitive_data": sensitiveLogCalls}

func (loggingWire) Name() string     { return "logging" }
func (loggingWire) Checks() []string { return keys(loggingChecks) }

func (loggingWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	return runFileChecks(t, jobs, loggingChecks)
}

var (
	// logger.info(...), log.Printf(...), console.error(...), auditLogger.warn(...),
	// or a helper whose name says it writes to a log/audit trail.
	logCall = regexp.MustCompile(`(?i)(?:\b[\w]*(?:log|logger|logging|console)\s*\.\s*(?:info|warn|warning|error|debug|critical|fatal|trace|log|exception|print|printf|println|infof|warnf|errorf|debugf)|\b(?:record|write|emit|append)_?audit\w*|\baudit_?log\w*|\blog_(?:event|info|warning|error|debug))\s*\(`)
	// {expr} (f-strings, str.format), ${expr} (JS templates), %s args are
	// handled by also scanning the call's trailing arguments.
	interpolation = regexp.MustCompile(`\$?\{([^{}]+)\}`)
	identifier    = regexp.MustCompile(`[A-Za-z_][\w]*`)
	sensitiveVar  = regexp.MustCompile(`(?i)^(password|passwd|pwd|secret|token|auth|authorization|auth_?header|api_?key|apikey|access_?token|refresh_?token|session_?id|cookie|aadhaar\w*|ssn|pan|card\w*|cvv|dob|payload|response_?data|responsedata|request_?body|req_?body|body|patients?|credentials?)$`)
)

func sensitiveLogCalls(r *policy.Rule, file string, data []byte) []finding.Finding {
	if minified(data) {
		return nil
	}
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		if !containsAnyFold(line, []string{"log", "console", "audit"}) || scanner.CommentOnly(line) {
			continue
		}
		loc := logCall.FindStringIndex(line)
		if loc == nil {
			continue
		}
		args := line[loc[1]:]
		var exprs []string
		for _, m := range interpolation.FindAllStringSubmatch(args, -1) {
			exprs = append(exprs, m[1])
		}
		// Positional arguments after the format string: logger.info("%s", token)
		if comma := strings.LastIndex(args, `",`); comma >= 0 {
			exprs = append(exprs, args[comma+2:])
		} else if comma := strings.LastIndex(args, `',`); comma >= 0 {
			exprs = append(exprs, args[comma+2:])
		}
		if name := firstSensitive(exprs); name != "" {
			out = append(out, newFinding(r, file, i+1,
				fmt.Sprintf("log statement writes %q, which can carry credentials or personal data", name),
				snippet(line)))
		}
	}
	return out
}

func firstSensitive(exprs []string) string {
	for _, e := range exprs {
		for _, id := range identifier.FindAllString(e, -1) {
			if sensitiveVar.MatchString(id) {
				return id
			}
		}
	}
	return ""
}
