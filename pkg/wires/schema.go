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

// schemaWire reads SQL table definitions (in .sql files or embedded in
// application code) and flags columns that hold regulated identifiers,
// such as Aadhaar, PAN, card and account numbers, as plain values. A column
// named for hashed, encrypted, tokenised or masked data is left alone.
type schemaWire struct{}

var schemaChecks = map[string]fileCheck{"schema.plaintext_identifier": plaintextIdentifierColumns}

func (schemaWire) Name() string     { return "schema" }
func (schemaWire) Checks() []string { return keys(schemaChecks) }

func (schemaWire) Scan(_ context.Context, t *scanner.Target, jobs []scanner.Job, _ scanner.Options) ([]finding.Finding, error) {
	return runFileChecks(t, jobs, schemaChecks)
}

var (
	createTable = regexp.MustCompile("(?i)CREATE\\s+(?:TEMP(?:ORARY)?\\s+)?TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?([\\w.\"`\\[\\]]+)\\s*\\(")
	columnDef   = regexp.MustCompile("(?i)^\\s*[\"`\\[]?([A-Za-z_]\\w*)[\"`\\]]?\\s+(N?VARCHAR2?|N?CHAR|CHARACTER\\s+VARYING|N?TEXT|STRING|CLOB|BIGINT|INT(?:EGER)?|NUMERIC|NUMBER|DECIMAL)\\b")
	// protectedColumn marks a column whose name says the value is already
	// transformed; storing a hash or a token of an identifier is the fix.
	protectedColumn = regexp.MustCompile(`(?i)(hash|digest|hmac|enc|cipher|token|mask|last_?4|last_?four|suffix|salt)`)
)

// identifierKinds maps column-name patterns to what they hold. The patterns
// are matched against the whole column name.
var identifierKinds = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`(?i)^(aadhaa?r|uidai|uid)(_?(number|no|num|id))?$`), "Aadhaar number"},
	{regexp.MustCompile(`(?i)^(pan|pan_?(number|no|card)|permanent_account_number)$`), "PAN (Indian tax ID) or card PAN"},
	{regexp.MustCompile(`(?i)^(card_?(pan|number|no|num)|cc_?(number|num|no)|credit_?card(_?(number|no|num))?|debit_?card(_?(number|no|num))?)$`), "payment card number"},
	{regexp.MustCompile(`(?i)^((bank_?)?account_?(number|no|num)|iban)$`), "bank account number"},
	{regexp.MustCompile(`(?i)^(ssn|social_security(_?(number|no))?)$`), "social security number"},
	{regexp.MustCompile(`(?i)^(passport(_?(number|no))?|voter_?id|driving_?licen[cs]e(_?(number|no))?)$`), "government ID number"},
	{regexp.MustCompile(`(?i)^(mrn|medical_record(_?(number|no))?)$`), "medical record number"},
}

func plaintextIdentifierColumns(r *policy.Rule, file string, data []byte) []finding.Finding {
	var out []finding.Finding
	text := string(data)
	for _, loc := range createTable.FindAllStringSubmatchIndex(text, -1) {
		table := strings.Trim(text[loc[2]:loc[3]], "\"`[]")
		bodyStart := loc[1] // just after the opening parenthesis
		for _, col := range splitColumns(text, bodyStart) {
			m := columnDef.FindStringSubmatch(col.def)
			if m == nil || protectedColumn.MatchString(m[1]) {
				continue
			}
			for _, k := range identifierKinds {
				if k.re.MatchString(m[1]) {
					out = append(out, newFinding(r, file, scanner.LineOf(data, col.offset),
						fmt.Sprintf("table %s stores %s in plaintext column %s", table, k.what, m[1]),
						m[1]+" "+strings.ToUpper(m[2])))
					break
				}
			}
		}
	}
	return out
}

type columnSpan struct {
	def    string
	offset int // byte offset of the definition's first non-space character
}

// splitColumns splits a CREATE TABLE body starting at start (just inside its
// opening parenthesis) on top-level commas, up to the closing parenthesis.
func splitColumns(text string, start int) []columnSpan {
	var out []columnSpan
	depth, quote, from := 0, byte(0), start
	emit := func(end int) {
		def := text[from:end]
		trimmed := strings.TrimLeft(def, " \t\r\n")
		out = append(out, columnSpan{def: trimmed, offset: from + len(def) - len(trimmed)})
	}
	for i := start; i < len(text) && i-start < 32<<10; i++ {
		c := text[i]
		switch {
		case quote != 0:
			// DDL string literals and quoted identifiers don't span lines, so
			// a newline also ends a quote; an unbalanced quote can't swallow
			// the rest of the file.
			if c == quote || c == '\n' {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				emit(i)
				return out
			}
			depth--
		case c == ',' && depth == 0:
			emit(i)
			from = i + 1
		}
	}
	return out
}
