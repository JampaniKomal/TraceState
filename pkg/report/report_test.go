package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

func ref(fw, c string) policy.ControlRef {
	return policy.ControlRef{Framework: fw, Control: c, Title: policy.ControlTitle(fw, c)}
}

func sample() *Report {
	root := []policy.ControlRef{ref("CWE", "CWE-250"), ref("ISO27001", "A.8.2")}
	secret := []policy.ControlRef{ref("CWE", "CWE-798"), ref("ISO27001", "A.5.17")}
	return &Report{
		Tool: ToolName, Version: "v2.0.0-test", ScanID: "0123456789abcdef", Target: "/repo",
		StartedAt: time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC), DurationMS: 42, FilesIndexed: 10,
		RuleSetSHA256: "deadbeefdeadbeefdeadbeef", RuleSources: []string{policy.DefaultRulesName}, Suppressed: 1,
		Findings: []finding.Finding{
			{RuleID: "TS-SEC-004", Title: "Credential in client code", Severity: policy.Critical, File: "web/<app>.js", Line: 7,
				Message: "API_TOKEN is assigned a literal credential", Evidence: `API_TOKEN = "<script>alert(1)</script>"`, Controls: secret, Fingerprint: "fp1"},
			{RuleID: "TS-CTR-001", Title: "Container runs as root", Severity: policy.High, File: "compose.yml", Line: 4,
				Message: `service "api" runs as root`, Evidence: "user: root", Controls: root, Fingerprint: "fp2"},
			{RuleID: "TS-CTR-001", Title: "Container runs as root", Severity: policy.High, File: "deploy/compose.yml", Line: 9,
				Message: `service "db" runs as root`, Evidence: "user: root", Controls: root, Fingerprint: "fp3", Occurrences: 3},
		},
		Rules: []RuleOutcome{
			{ID: "TS-CTR-001", Title: "Container runs as root", Severity: policy.High, Check: "compose.user_root", Status: scanner.Failed,
				FilesMatched: 2, Findings: 2, Controls: root, Remediation: "Run as an unprivileged user."},
			{ID: "TS-SEC-004", Title: "Credential in client code", Severity: policy.Critical, Check: "secrets.hardcoded_credential",
				Status: scanner.Failed, FilesMatched: 1, Findings: 1, Controls: secret, Remediation: "Move it server-side."},
			{ID: "TS-IMG-001", Title: "Image runs as root", Severity: policy.Medium, Check: "dockerfile.root_user", Status: scanner.Passed,
				FilesMatched: 1, Controls: root},
			{ID: "TS-DEP-001", Title: "Known vulnerable dependency", Severity: policy.High, Check: "deps.known_vulnerable",
				Status: scanner.NotEvaluated, Reason: "requires --online", Controls: []policy.ControlRef{ref("ISO27001", "A.8.8")}},
			{ID: "TS-DAT-001", Title: "Aadhaar in logs", Severity: policy.Critical, Check: "pii.aadhaar",
				Status: scanner.NotApplicable, Controls: []policy.ControlRef{ref("DPDPA", "s.8(5)")}},
		},
	}
}

func TestSummaryAndCoverage(t *testing.T) {
	r := sample()
	s := r.Summary()
	if s.Total != 3 || s.BySeverity["critical"] != 1 || s.BySeverity["high"] != 2 || s.FilesAffected != 3 ||
		s.RulesFailed != 2 || s.RulesPassed != 1 || s.RulesSkipped != 1 || s.RulesNA != 1 || s.Suppressed != 1 {
		t.Errorf("summary = %+v", s)
	}
	cov := map[string]map[string]ControlCoverage{}
	for _, fc := range r.Coverage() {
		cov[fc.ID] = map[string]ControlCoverage{}
		for _, c := range fc.Controls {
			cov[fc.ID][c.Control] = c
		}
	}
	// A.8.2 is evidenced by a failing rule (TS-CTR-001) and a passing one
	// (TS-IMG-001): one failure fails the control.
	if c := cov["ISO27001"]["A.8.2"]; c.Status != scanner.Failed || len(c.Rules) != 2 || c.Findings != 2 {
		t.Errorf("A.8.2 = %+v", c)
	}
	if c := cov["ISO27001"]["A.8.8"]; c.Status != scanner.NotEvaluated {
		t.Errorf("A.8.8 = %+v", c)
	}
	if c := cov["DPDPA"]["s.8(5)"]; c.Status != scanner.NotApplicable {
		t.Errorf("DPDPA s.8(5) = %+v", c)
	}
	var ids []string
	for _, fc := range r.Coverage() {
		ids = append(ids, fc.ID)
	}
	if strings.Join(ids, ",") != "CWE,DPDPA,ISO27001" {
		t.Errorf("framework order = %v", ids)
	}
}

func TestGroups(t *testing.T) {
	g := sample().Groups()
	if len(g) != 2 || g[0].Rule.ID != "TS-SEC-004" || g[1].Rule.ID != "TS-CTR-001" || len(g[1].Findings) != 2 {
		t.Fatalf("groups = %+v", g)
	}
	if g[1].Rule.Remediation == "" {
		t.Error("group lost the rule's remediation")
	}
}

func render(t *testing.T, format string) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(format, &b, sample(), false); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestSARIF(t *testing.T) {
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							Tags             []string `json:"tags"`
							SecuritySeverity string   `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				RuleIndex           int               `json:"ruleIndex"`
				Level               string            `json:"level"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Locations           []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(render(t, "sarif")), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("not a SARIF 2.1.0 log: %+v", log)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 5 || len(run.Results) != 3 {
		t.Fatalf("rules=%d results=%d", len(run.Tool.Driver.Rules), len(run.Results))
	}
	for _, res := range run.Results {
		if got := run.Tool.Driver.Rules[res.RuleIndex].ID; got != res.RuleID {
			t.Errorf("ruleIndex %d points at %s, not %s", res.RuleIndex, got, res.RuleID)
		}
		if res.PartialFingerprints["tracestate/v1"] == "" {
			t.Error("missing partial fingerprint")
		}
	}
	first := run.Results[0]
	if first.Level != "error" || first.Locations[0].PhysicalLocation.Region.StartLine != 7 {
		t.Errorf("first result = %+v", first)
	}
	r0 := run.Tool.Driver.Rules[0]
	if r0.Properties.SecuritySeverity != "8.0" || !contains(r0.Properties.Tags, "external/cwe/cwe-250") ||
		!contains(r0.Properties.Tags, "ISO27001:A.8.2") {
		t.Errorf("rule properties = %+v", r0.Properties)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestJSONIncludesSummaryAndCoverage(t *testing.T) {
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(render(t, "json")), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tool", "scan_id", "findings", "rules", "summary", "coverage", "ruleset_sha256"} {
		if _, ok := out[k]; !ok {
			t.Errorf("JSON report lacks %q", k)
		}
	}
	if !strings.Contains(string(out["findings"]), `"severity": "critical"`) {
		t.Error("severities are not rendered by name")
	}
}

func TestHTMLIsSelfContainedAndEscaped(t *testing.T) {
	html := render(t, "html")
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "<app>") {
		t.Error("evidence or paths are not HTML-escaped")
	}
	for _, want := range []string{"<!doctype html>", "TS-SEC-004", "ISO/IEC 27001", "A.8.2", "Run as an unprivileged user.",
		`class="pill failed"`, `id="show-critical"`, "(×3)", "0123456789abcdef"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	for _, external := range []string{`src="http`, `href="http://`, "<link "} {
		if strings.Contains(html, external) {
			t.Errorf("HTML loads an external resource (%s)", external)
		}
	}
}

func TestMarkdownAndText(t *testing.T) {
	md := render(t, "markdown")
	for _, want := range []string{"# TraceState compliance report", "## Framework coverage", "### CRITICAL · TS-SEC-004",
		"| A.8.2 |", "**Remediation:** Run as an unprivileged user."} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if strings.Contains(md, "| `web/<app>.js:7` | API_TOKEN") && strings.Count(md, "|") < 10 {
		t.Error("markdown table broken")
	}
	text := render(t, "table")
	if strings.Contains(text, "\033[") {
		t.Error("colour codes in uncoloured output")
	}
	for _, want := range []string{"CRITICAL  TS-SEC-004", "compose.yml:4", "Findings: 3 finding(s) (1 critical, 2 high)", "1 not evaluated (need --online)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	var coloured bytes.Buffer
	if err := Render("table", &coloured, sample(), true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(coloured.String(), "\033[1;35m") {
		t.Error("no colour when requested")
	}
	if err := Render("pdf", &coloured, sample(), false); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestEmptyReport(t *testing.T) {
	r := &Report{Tool: ToolName, Version: "x", Findings: []finding.Finding{}}
	for _, f := range Formats {
		var b bytes.Buffer
		if err := Render(f, &b, r, false); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	var b bytes.Buffer
	if err := Render("html", &b, r, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No violations found.") {
		t.Error("empty HTML report lacks the all-clear message")
	}
}
