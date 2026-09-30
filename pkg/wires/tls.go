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

// tlsWire checks declared TLS policy in web-server configs (nginx, Apache,
// HAProxy) and in application code.
type tlsWire struct{}

var tlsChecks = map[string]fileCheck{
	"tls.deprecated_protocol":   deprecatedProtocols,
	"tls.weak_cipher":           weakCiphers,
	"tls.verification_disabled": verificationDisabled,
}

func (tlsWire) Name() string     { return "tls" }
func (tlsWire) Checks() []string { return keys(tlsChecks) }

func (tlsWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	return runFileChecks(t, jobs, tlsChecks)
}

var deprecatedTokens = map[string]string{
	"sslv2": "SSLv2", "sslv3": "SSLv3", "tlsv1": "TLSv1.0", "tlsv1.0": "TLSv1.0", "tlsv1.1": "TLSv1.1",
}

var (
	nginxProtocols  = regexp.MustCompile(`^\s*ssl_protocols\s+([^;#]+)`)
	apacheProtocols = regexp.MustCompile(`(?i)^\s*SSLProtocol\s+([^#]+)`)
	haproxyMinVer   = regexp.MustCompile(`ssl-min-ver\s+(SSLv3|TLSv1\.0|TLSv1\.1)\b`)
	codeProtocols   = regexp.MustCompile(`ssl\.PROTOCOL_(?:TLSv1|TLSv1_1|SSLv3|SSLv23)\b|TLSVersion\.(?:TLSv1|TLSv1_1)\b|minVersion\s*:\s*['"]TLSv1(?:\.1)?['"]|secureProtocol\s*:\s*['"](?:TLSv1|TLSv1_1|SSLv3)_method['"]|MinVersion:\s*tls\.Version(?:TLS10|TLS11|SSL30)\b`)
)

func deprecatedProtocols(r *policy.Rule, file string, data []byte) []finding.Finding {
	if minified(data) {
		return nil
	}
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		if !containsAnyFold(line, []string{"ssl", "tls"}) {
			continue
		}
		var enabled []string
		if m := nginxProtocols.FindStringSubmatch(line); m != nil {
			for _, tok := range strings.Fields(m[1]) {
				if name, ok := deprecatedTokens[strings.ToLower(tok)]; ok {
					enabled = append(enabled, name)
				}
			}
		} else if m := apacheProtocols.FindStringSubmatch(line); m != nil {
			enabled = apacheEnabled(strings.Fields(m[1]))
		} else if m := haproxyMinVer.FindStringSubmatch(line); m != nil {
			enabled = []string{m[1]}
		} else if m := codeProtocols.FindString(line); m != "" {
			enabled = []string{m}
		}
		if len(enabled) > 0 {
			out = append(out, newFinding(r, file, i+1,
				fmt.Sprintf("deprecated protocol(s) enabled: %s", strings.Join(enabled, ", ")), snippet(line)))
		}
	}
	return out
}

// apacheEnabled evaluates an SSLProtocol directive ("all -SSLv3 +TLSv1.2").
func apacheEnabled(tokens []string) []string {
	on := map[string]bool{}
	for _, tok := range tokens {
		t := strings.ToLower(tok)
		sign := byte('+')
		if t[0] == '+' || t[0] == '-' {
			sign, t = t[0], t[1:]
		}
		var names []string
		if t == "all" {
			names = []string{"tlsv1", "tlsv1.1", "tlsv1.2", "tlsv1.3"}
		} else {
			names = []string{t}
		}
		for _, n := range names {
			on[n] = sign == '+'
		}
	}
	var out []string
	for _, n := range []string{"sslv2", "sslv3", "tlsv1", "tlsv1.1"} {
		if on[n] {
			out = append(out, deprecatedTokens[n])
		}
	}
	return out
}

var (
	cipherDirective = regexp.MustCompile(`^\s*(?:ssl_ciphers|SSLCipherSuite|ssl-default-bind-ciphers|ciphers)\s+['"]?([^;'"#\s]+)`)
	weakCipherToken = regexp.MustCompile(`(?i)^(RC4|DES|3DES|DES-CBC3-SHA|NULL|eNULL|aNULL|EXPORT|EXP|LOW|MD5|ADH|AECDH)$|RC4|DES-CBC|EXP-|NULL-`)
)

func weakCiphers(r *policy.Rule, file string, data []byte) []finding.Finding {
	if minified(data) {
		return nil
	}
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		if !containsAnyFold(line, []string{"cipher"}) {
			continue
		}
		m := cipherDirective.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var weak []string
		for _, tok := range strings.Split(m[1], ":") {
			if tok == "" || tok[0] == '!' || tok[0] == '-' {
				continue // explicitly excluded
			}
			tok = strings.TrimPrefix(tok, "+")
			if weakCipherToken.MatchString(tok) {
				weak = append(weak, tok)
			}
		}
		if len(weak) > 0 {
			out = append(out, newFinding(r, file, i+1,
				"weak cipher(s) allowed: "+strings.Join(weak, ", "), snippet(line)))
		}
	}
	return out
}

var verifyOff = regexp.MustCompile(`\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|ssl\._create_unverified_context|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)|\bcurl\s+[^|;\n]*(?:-k\b|--insecure\b)|\bwget\s+[^|;\n]*--no-check-certificate`)

var verifyHints = []string{"verify", "reject", "insecure", "unverified", "no-check-certificate", "curl"}

func verificationDisabled(r *policy.Rule, file string, data []byte) []finding.Finding {
	if minified(data) {
		return nil
	}
	var out []finding.Finding
	for i, line := range scanner.Lines(data) {
		if !containsAnyFold(line, verifyHints) {
			continue
		}
		if m := verifyOff.FindString(line); m != "" {
			out = append(out, newFinding(r, file, i+1,
				"TLS certificate verification is turned off", snippet(line)))
		}
	}
	return out
}
