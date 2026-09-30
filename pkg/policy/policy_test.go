package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
	_ "github.com/jampanikomal/tracestate/v2/pkg/wires"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultRulesAreValid(t *testing.T) {
	rs, err := policy.DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Validate(scanner.KnownChecks()); err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) < 30 {
		t.Fatalf("expected the full default pack, got %d rules", len(rs.Rules))
	}
	for _, r := range rs.Rules {
		if r.Remediation == "" {
			t.Errorf("%s has no remediation", r.ID)
		}
		if len(r.Frameworks) == 0 {
			t.Errorf("%s maps to no framework", r.ID)
		}
		for _, c := range r.Controls() {
			if _, known := policy.Catalog[c.Framework]; !known {
				t.Errorf("%s maps to unknown framework %q", r.ID, c.Framework)
			} else if c.Title == "" {
				t.Errorf("%s maps to %s %s, which the catalogue has no title for", r.ID, c.Framework, c.Control)
			}
		}
	}
}

// Every check a wire implements should be exercised by at least one built-in
// rule, otherwise it is dead code as far as users of the default pack go.
func TestEveryCheckHasADefaultRule(t *testing.T) {
	rs, err := policy.DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, r := range rs.Rules {
		used[r.Check] = true
	}
	for check := range scanner.KnownChecks() {
		if strings.HasPrefix(check, "regex.") {
			continue // generic building blocks for user rules
		}
		if !used[check] {
			t.Errorf("check %s has no rule in the default pack", check)
		}
	}
}

func TestLoadOverridesByID(t *testing.T) {
	custom := writeFile(t, "custom.yaml", `
version: 2
rules:
  - id: TS-CTR-001
    title: Root containers are forbidden here
    severity: critical
    check: compose.user_root
    files: ["deploy/**/*.yml"]
  - id: ACME-001
    title: No internal hostnames in client code
    severity: low
    check: regex.match
    files: ["web/**/*.js"]
    pattern: 'corp\.acme\.internal'
    frameworks: {ISO27001: [A.8.12]}
`)
	defaults, _ := policy.DefaultRules()
	rs, err := policy.Load(true, custom)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != len(defaults.Rules)+1 {
		t.Fatalf("got %d rules, want %d", len(rs.Rules), len(defaults.Rules)+1)
	}
	if rs.Rules[0].ID != "TS-CTR-001" || rs.Rules[0].Severity != policy.Critical || rs.Rules[0].Files[0] != "deploy/**/*.yml" {
		t.Errorf("override not applied in place: %+v", rs.Rules[0])
	}
	if last := rs.Rules[len(rs.Rules)-1]; last.ID != "ACME-001" {
		t.Errorf("custom rule not appended, last is %s", last.ID)
	}
	if len(rs.Sources) != 2 || rs.Sources[0] != policy.DefaultRulesName {
		t.Errorf("sources = %v", rs.Sources)
	}
	if err := rs.Validate(scanner.KnownChecks()); err != nil {
		t.Fatal(err)
	}

	// The fingerprint changes with the content of any source.
	other := writeFile(t, "custom.yaml", strings.Replace(readFile(t, custom), "low", "medium", 1))
	rs2, err := policy.Load(true, other)
	if err != nil {
		t.Fatal(err)
	}
	if rs.SHA256 == rs2.SHA256 {
		t.Error("rule set fingerprint ignores rule content")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadJSONv2(t *testing.T) {
	p := writeFile(t, "rules.json", `{"version": 2, "rules": [{"id": "J-1", "title": "t", "severity": "high",
		"check": "regex.match", "files": ["**/*"], "pattern": "x"}]}`)
	rs, err := policy.Load(false, p)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Rules[0].Severity != policy.High {
		t.Errorf("severity = %v", rs.Rules[0].Severity)
	}
}

func TestLoadLegacyV1(t *testing.T) {
	p := writeFile(t, "ruleset.json", `{
  "version": "1.1",
  "frameworks": ["ISO27001", "DPDPA"],
  "rules": [
    {"id": "ISO-A9-01", "description": "Containers must not run as root user.", "target_file": "docker-compose.yml", "regex": "user:\\s*root"},
    {"id": "DPDPA-03", "description": "Logs must not contain emails.", "target_file": "logs/app_audit.log", "regex": "[a-z]+@[a-z]+\\.com"}
  ]
}`)
	rs, err := policy.Load(false, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Validate(scanner.KnownChecks()); err != nil {
		t.Fatal(err)
	}
	r := rs.Rules[0]
	if r.Check != "regex.match" || r.Files[0] != "docker-compose.yml" || r.Frameworks["ISO27001"][0] != "ISO-A9-01" {
		t.Errorf("legacy rule converted wrongly: %+v", r)
	}
	if rs.Rules[1].Frameworks["DPDPA"] == nil {
		t.Errorf("framework not inferred from DPDPA- prefix")
	}
}

func TestLoadRejectsUnknownFieldsAndVersions(t *testing.T) {
	cases := map[string]string{
		"typo.yaml":    "version: 2\nrules:\n  - id: X-1\n    titel: oops\n",
		"version.yaml": "version: 3\nrules: []\n",
		"sev.yaml":     "version: 2\nrules:\n  - id: X-1\n    severity: urgent\n",
		"typo.json":    `{"version": 2, "rules": [{"id": "X-1", "severty": "high"}]}`,
	}
	for name, body := range cases {
		if _, err := policy.Load(false, writeFile(t, name, body)); err == nil {
			t.Errorf("%s: expected a parse error", name)
		}
	}
	if _, err := policy.Load(false); err == nil {
		t.Error("loading nothing should fail")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	rs := &policy.RuleSet{Rules: []policy.Rule{
		{ID: "A-1", Title: "ok", Check: "regex.match", Files: []string{"**/*"}, Pattern: "x"},
		{ID: "A-1", Title: "dup", Check: "regex.match", Files: []string{"**/*"}, Pattern: "x"},
		{ID: "A-2", Check: "nope.nothing", Files: []string{"**/*"}},
		{ID: "A-3", Title: "bad glob", Check: "regex.match", Files: []string{"[unclosed"}, Pattern: "x"},
		{ID: "A-4", Title: "bad regex", Check: "regex.match", Files: []string{"*"}, Pattern: "(unclosed"},
		{ID: "A-5", Title: "no pattern", Check: "regex.absent", Files: []string{"*"}},
		{Title: "no id", Check: "regex.match", Pattern: "x"},
	}}
	err := rs.Validate(scanner.KnownChecks())
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{
		`"A-1": duplicate id`, `"A-2": missing title`, `unknown check "nope.nothing"`, `invalid glob "[unclosed"`,
		`"A-4": invalid pattern`, `"A-5": regex checks need a pattern`, "rule #7: missing id", "rule #7: no file patterns",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestSeverity(t *testing.T) {
	for _, name := range []string{"info", "low", "medium", "high", "critical"} {
		s, err := policy.ParseSeverity(strings.ToUpper(name))
		if err != nil || s.String() != name {
			t.Errorf("ParseSeverity(%q) = %v, %v", name, s, err)
		}
	}
	if policy.Critical.SARIFLevel() != "error" || policy.Medium.SARIFLevel() != "warning" || policy.Low.SARIFLevel() != "note" {
		t.Error("SARIF level mapping changed")
	}
	b, _ := json.Marshal(struct{ S policy.Severity }{policy.High})
	if string(b) != `{"S":"high"}` {
		t.Errorf("JSON = %s", b)
	}
}

func TestControlLessIsNatural(t *testing.T) {
	ids := []string{"A.8.11", "A.8.2", "A.5.15", "A.8.28", "A.8.20", "CWE-79", "CWE-200", "CWE-1004"}
	sort.Slice(ids, func(i, j int) bool { return policy.ControlLess(ids[i], ids[j]) })
	want := "A.5.15 A.8.2 A.8.11 A.8.20 A.8.28 CWE-79 CWE-200 CWE-1004"
	if got := strings.Join(ids, " "); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
