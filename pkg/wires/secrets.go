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

// secretsWire finds credentials committed to source: provider tokens with a
// recognisable format, private keys, credential-named variables assigned a
// literal (including "env var with a literal fallback"), static bearer-token
// comparisons, and plaintext password storage.
type secretsWire struct{}

type fileCheck func(r *policy.Rule, file string, data []byte) []finding.Finding

var secretsChecks = map[string]fileCheck{
	"secrets.provider_token":             providerTokens,
	"secrets.private_key":                privateKeys,
	"secrets.hardcoded_credential":       hardcodedCredentials,
	"secrets.static_token_comparison":    staticTokenComparisons,
	"secrets.plaintext_password_storage": plaintextPasswordStorage,
}

func (secretsWire) Name() string     { return "secrets" }
func (secretsWire) Checks() []string { return keys(secretsChecks) }

func (secretsWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	return runFileChecks(t, jobs, secretsChecks)
}

// runFileChecks runs a per-file check function for each job.
func runFileChecks(t *scanner.Target, jobs []scanner.Job, checks map[string]fileCheck) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, job := range jobs {
		check := checks[job.Rule.Check]
		err := forEachFile(t, job, func(file string, data []byte) error {
			out = append(out, check(job.Rule, file, data)...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// providerPatterns recognise credentials by their documented format. hints
// are literals every match contains; a pattern only runs on files and lines
// that contain one, which keeps the scan fast on large trees.
var providerPatterns = []struct {
	name  string
	hints []string
	re    *regexp.Regexp
}{
	{"AWS access key ID", []string{"AKIA", "ASIA"}, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"GitHub token", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"GitHub fine-grained token", []string{"github_pat_"}, regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{50,}\b`)},
	{"GitLab personal access token", []string{"glpat-"}, regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"Slack token", []string{"xox"}, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"Slack webhook URL", []string{"hooks.slack.com"}, regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}`)},
	{"Google API key", []string{"AIza"}, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"Stripe live key", []string{"_live_"}, regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b`)},
	{"OpenAI API key", []string{"sk-"}, regexp.MustCompile(`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}`)},
	{"Anthropic API key", []string{"sk-ant-"}, regexp.MustCompile(`\bsk-ant-[a-z]+\d{2}-[A-Za-z0-9_-]{80,}`)},
	{"SendGrid API key", []string{"SG."}, regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)},
	{"npm access token", []string{"npm_"}, regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"Azure storage account key", []string{"AccountKey="}, regexp.MustCompile(`AccountKey=[A-Za-z0-9+/]{80,}={0,2}`)},
	{"JSON Web Token", []string{"eyJ"}, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

func providerTokens(r *policy.Rule, file string, data []byte) []finding.Finding {
	text := string(data)
	var active []int
	for i, p := range providerPatterns {
		if containsAny(text, p.hints) {
			active = append(active, i)
		}
	}
	if len(active) == 0 {
		return nil
	}
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		for _, pi := range active {
			p := providerPatterns[pi]
			if !containsAny(line, p.hints) {
				continue
			}
			if m := p.re.FindString(line); m != "" {
				out = append(out, newFinding(r, file, i+1, p.name+" found in source", p.name+": "+detect.MaskSecret(m)))
			}
		}
	}
	return out
}

var privateKeyRe = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)

func privateKeys(r *policy.Rule, file string, data []byte) []finding.Finding {
	if !strings.Contains(string(data), "PRIVATE KEY") {
		return nil
	}
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		if m := privateKeyRe.FindString(line); m != "" {
			out = append(out, newFinding(r, file, i+1, "private key material committed to the repository", m))
		}
	}
	return out
}

var (
	// NAME = "literal", NAME: 'literal', "NAME": "literal", NAME := "literal"
	literalAssign = regexp.MustCompile(`(?:^|[^\w.$])([A-Za-z_$][\w$-]*)["']?\s*(?::=|=>|=|:)\s*[rbuRBU]?(["'` + "`" + `])([^"'` + "`" + `\n]{6,})["'` + "`" + `]`)
	// os.getenv("NAME", "literal") / os.environ.get("NAME", "literal")
	pyEnvFallback = regexp.MustCompile(`(?:getenv|environ\.get)\(\s*["']([A-Za-z_][\w]*)["']\s*,\s*["']([^"'\n]{4,})["']`)
	// process.env.NAME || 'literal' / process.env["NAME"] ?? 'literal'
	jsEnvFallback = regexp.MustCompile(`process\.env(?:\.([A-Za-z_][\w]*)|\[\s*["']([A-Za-z_][\w]*)["']\s*\])\s*(?:\|\||\?\?)\s*["'` + "`" + `]([^"'` + "`" + `\n]{4,})["'` + "`" + `]`)
	// words that mark an identifier as UI text rather than a credential
	proseName = regexp.MustCompile(`(?i)(label|hint|prompt|message|msg|text|title|help|error|description|desc|caption)`)
)

func credentialName(name string) bool {
	return secretName.MatchString(name) && !notSecretName.MatchString(name) && !proseName.MatchString(name)
}

// credentialHints are lower-case fragments every secretName match contains.
var credentialHints = []string{"pass", "pwd", "secret", "token", "key", "credential", "bypass", "backdoor"}

func credentialValue(v string) bool {
	return !isPlaceholder(v) && !strings.ContainsAny(v, " \t") && !strings.Contains(v, "${")
}

func hardcodedCredentials(r *policy.Rule, file string, data []byte) []finding.Finding {
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		lineNo := i + 1
		if !containsAnyFold(line, credentialHints) {
			continue
		}
		if m := pyEnvFallback.FindStringSubmatch(line); m != nil && credentialName(m[1]) && credentialValue(m[2]) {
			out = append(out, newFinding(r, file, lineNo,
				fmt.Sprintf("%s falls back to a hard-coded value when the environment variable is unset", m[1]),
				m[1]+" fallback = "+detect.MaskSecret(m[2])))
			continue
		}
		if m := jsEnvFallback.FindStringSubmatch(line); m != nil {
			name := m[1] + m[2]
			if credentialName(name) && credentialValue(m[3]) {
				out = append(out, newFinding(r, file, lineNo,
					fmt.Sprintf("%s falls back to a hard-coded value when the environment variable is unset", name),
					name+" fallback = "+detect.MaskSecret(m[3])))
				continue
			}
		}
		for _, m := range literalAssign.FindAllStringSubmatch(line, -1) {
			name, value := m[1], m[3]
			if !credentialName(name) || !credentialValue(value) || strings.EqualFold(value, name) {
				continue
			}
			out = append(out, newFinding(r, file, lineNo,
				fmt.Sprintf("%s is assigned a literal credential", name),
				name+" = "+detect.MaskSecret(value)))
			break
		}
	}
	return out
}

var (
	bearerLiteral   = regexp.MustCompile(`(?:==|!=)=?\s*[fbrFBR]?(["'` + "`" + `])Bearer\s+([A-Za-z0-9._~+/=-]{6,})["'` + "`" + `]|(["'` + "`" + `])Bearer\s+([A-Za-z0-9._~+/=-]{6,})["'` + "`" + `]\s*(?:==|!=)`)
	tokenLiteralCmp = regexp.MustCompile(`(?i)\b(authorization|auth_?token|access_?token|api_?key|x-api-key|token)\b\s*(?:==|!=)=?\s*["'` + "`" + `]([^"'` + "`" + `${}\s]{8,})["'` + "`" + `]`)
)

func staticTokenComparisons(r *policy.Rule, file string, data []byte) []finding.Finding {
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		if !strings.Contains(line, "==") && !strings.Contains(line, "!=") {
			continue
		}
		if m := bearerLiteral.FindStringSubmatch(line); m != nil {
			tok := m[2] + m[4]
			out = append(out, newFinding(r, file, i+1,
				"request authorization is compared against a hard-coded bearer token",
				"Bearer "+detect.MaskSecret(tok)))
			continue
		}
		if m := tokenLiteralCmp.FindStringSubmatch(line); m != nil && !isPlaceholder(m[2]) {
			out = append(out, newFinding(r, file, i+1,
				fmt.Sprintf("%s is compared against a hard-coded value", m[1]),
				m[1]+" == "+detect.MaskSecret(m[2])))
		}
	}
	return out
}

var (
	insertStmt       = regexp.MustCompile(`(?is)INSERT\s+INTO\s+[\w."` + "`" + `\[\]]+\s*\(([^)]*)\)\s*VALUES`)
	passwordColumn   = regexp.MustCompile(`(?i)pass(word|wd)?|pwd`)
	plaintextColumn  = regexp.MustCompile(`(?i)\b((?:plain(?:text)?|clear(?:text)?)_?pass(?:word|wd)?|pass(?:word|wd)?_?(?:plain(?:text)?|clear(?:text)?))\b\s+(?:VARCHAR|NVARCHAR|CHAR|TEXT|STRING)`)
	sqlStringLiteral = regexp.MustCompile(`'[^'\n]{3,}'`)
)

func plaintextPasswordStorage(r *policy.Rule, file string, data []byte) []finding.Finding {
	var out []finding.Finding
	text := string(data)
	for _, loc := range insertStmt.FindAllStringSubmatchIndex(text, -1) {
		cols := text[loc[2]:loc[3]]
		if !passwordColumn.MatchString(cols) {
			continue
		}
		if !sqlStringLiteral.MatchString(valueTuples(text[loc[1]:])) {
			continue // parameterised insert (?, %s, $1): not a seeded plaintext value
		}
		out = append(out, newFinding(r, file, scanner.LineOf(data, loc[0]),
			"INSERT writes literal values into a password column",
			snippet(strings.Join(strings.Fields(text[loc[0]:loc[1]]), " "))))
	}
	for _, loc := range plaintextColumn.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, newFinding(r, file, scanner.LineOf(data, loc[0]),
			fmt.Sprintf("schema defines a plaintext password column (%s)", text[loc[2]:loc[3]]),
			snippet(text[loc[0]:loc[1]])))
	}
	return out
}

// valueTuples returns the contents of the parenthesised tuples that follow
// VALUES ("(1, 'a'), (2, 'b')"), stopping at the first thing that isn't a
// tuple, so string literals elsewhere in the file are never attributed to the
// INSERT. Quotes are respected when matching parentheses.
func valueTuples(s string) string {
	var b strings.Builder
	i := 0
	skipSpace := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
			i++
		}
	}
	for {
		skipSpace()
		if i >= len(s) || s[i] != '(' {
			return b.String()
		}
		depth, quote, start := 0, byte(0), i
	scan:
		for ; i < len(s); i++ {
			c := s[i]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '\'' || c == '"':
				quote = c
			case c == '(':
				depth++
			case c == ')':
				depth--
				if depth == 0 {
					i++
					break scan
				}
			}
		}
		b.WriteString(s[start:i])
		b.WriteByte(' ')
		if b.Len() > 8192 {
			return b.String()
		}
		skipSpace()
		if i >= len(s) || s[i] != ',' {
			return b.String()
		}
		i++
	}
}
