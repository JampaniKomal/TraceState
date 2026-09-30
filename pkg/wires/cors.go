package wires

import (
	"context"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// corsWire recognises "allow every origin" CORS configurations across the
// common web frameworks, and raises the severity when credentials are allowed
// alongside a wildcard.
type corsWire struct{}

var corsChecks = map[string]fileCheck{"cors.wildcard_origin": wildcardCORS}

func (corsWire) Name() string     { return "cors" }
func (corsWire) Checks() []string { return keys(corsChecks) }

func (corsWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	return runFileChecks(t, jobs, corsChecks)
}

// jsFiles limits the Express patterns to JavaScript and TypeScript, where
// cors() and { origin: true } mean what the patterns assume.
var jsFiles = []string{".js", ".mjs", ".cjs", ".ts"}

var corsPatterns = []struct {
	framework string
	re        *regexp.Regexp
	exts      []string // file extensions the pattern applies to; nil means any
}{
	{"FastAPI/Starlette", regexp.MustCompile(`allow_origins\s*=\s*\[\s*["']\*["']`), nil},
	{"Flask-CORS", regexp.MustCompile(`\bCORS\(\s*app\s*\)|\bCORS\([^)]*\borigins\s*=\s*["']\*["']`), nil},
	{"Express cors()", regexp.MustCompile(`\bcors\(\s*\)`), jsFiles},
	{"Express cors options", regexp.MustCompile(`\borigin\s*:\s*(?:["']\*["']|true\b)`), jsFiles},
	{"Access-Control-Allow-Origin header", regexp.MustCompile(`(?i)Access-Control-Allow-Origin["']?\s*[,:=]?\s*["']?\*`), nil},
	{"django-cors-headers", regexp.MustCompile(`CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True`), nil},
	{"Go CORS middleware", regexp.MustCompile(`AllowedOrigins:\s*\[\]string\{\s*"\*"|AllowAllOrigins:\s*true`), nil},
	{"Spring @CrossOrigin", regexp.MustCompile(`@CrossOrigin\(\s*(?:origins\s*=\s*)?"\*"|allowedOrigins\(\s*"\*"\s*\)`), nil},
	{"ASP.NET CORS policy", regexp.MustCompile(`\.AllowAnyOrigin\(\)`), nil},
}

var corsCredentials = regexp.MustCompile(`(?i)(allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|credentials\s*:\s*true|AllowCredentials\s*[:(]\s*true|\.AllowCredentials\(\)|Access-Control-Allow-Credentials["']?\s*[,:=]?\s*["']?true)`)

func wildcardCORS(r *policy.Rule, file string, data []byte) []finding.Finding {
	if minified(data) {
		return nil
	}
	var out []finding.Finding
	ext := strings.ToLower(path.Ext(file))
	lines := scanner.Lines(data)
	for i, line := range lines {
		if !containsAnyFold(line, []string{"origin", "cors"}) || scanner.CommentOnly(line) {
			continue
		}
		for _, p := range corsPatterns {
			if (p.exts != nil && !slices.Contains(p.exts, ext)) || !p.re.MatchString(line) {
				continue
			}
			f := newFinding(r, file, i+1, p.framework+" allows requests from any origin", snippet(line))
			window := strings.Join(lines[max(0, i-6):min(len(lines), i+8)], "\n")
			if corsCredentials.MatchString(window) {
				f.Message = p.framework + " allows any origin and also allows credentials"
				if f.Severity < policy.High {
					f.Severity = policy.High
				}
			}
			out = append(out, f)
			break
		}
	}
	return out
}
