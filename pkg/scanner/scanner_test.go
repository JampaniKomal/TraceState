package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jampanikomal/tracestate/pkg/rules"
)

func writeFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// TestScanTargetSkipsMissingComposeFileInsteadOfAborting is a regression
// test: ScanTarget used to return a hard error - killing all six wires -
// the moment docker-compose.yml was missing, even though wires 2-6 don't
// need it at all. A target with no Docker Compose file (a plain codebase,
// for instance) should still be scannable.
func TestScanTargetSkipsMissingComposeFileInsteadOfAborting(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/api.py", `MASTER_BACKDOOR_KEY_2026`)

	rs := rules.RuleSet{Rules: []rules.Rule{
		{ID: "ISO-A8-28-01", Description: "Hardcoded backdoor key in API.", TargetFile: "src/api.py", Regex: "MASTER_BACKDOOR_KEY_2026"},
	}}

	findings, err := ScanTarget(dir, rs)
	if err != nil {
		t.Fatalf("expected ScanTarget to succeed without a docker-compose.yml, got error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected wire 3 (code) to still run and find 1 violation, got %d", len(findings))
	}
}

func TestScanTargetFindsInfrastructureViolationWhenComposeFilePresent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docker-compose.yml", "services:\n  api:\n    user: root\n")

	rs := rules.RuleSet{Rules: []rules.Rule{
		{ID: "ISO-A9-01", Description: "Containers must not run as root user.", TargetFile: "docker-compose.yml", Regex: "user:\\s*root"},
	}}

	findings, err := ScanTarget(dir, rs)
	if err != nil {
		t.Fatalf("ScanTarget: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 infrastructure violation, got %d", len(findings))
	}
	if findings[0].Category != "infrastructure" {
		t.Errorf("expected category 'infrastructure', got %q", findings[0].Category)
	}
}

func TestScanCodeSkipsRulesForOtherWires(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/api.py", "allow_origins=[\"*\"]")

	rs := rules.RuleSet{Rules: []rules.Rule{
		// Wrong prefix for ScanCode (this belongs to the network wire) -
		// ScanCode must not pick it up.
		{ID: "ISO-A8-20-01", Description: "Overly permissive CORS.", TargetFile: "src/api.py", Regex: "allow_origins=\\[\"\\*\"\\]"},
	}}

	findings, err := ScanCode(dir, rs)
	if err != nil {
		t.Fatalf("ScanCode: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected ScanCode to ignore a network-wire rule, got %d findings", len(findings))
	}
}

func TestScanCodeSkipsMissingTargetFile(t *testing.T) {
	dir := t.TempDir()
	// src/api.py deliberately not created.
	rs := rules.RuleSet{Rules: []rules.Rule{
		{ID: "ISO-A8-28-01", Description: "Hardcoded backdoor key.", TargetFile: "src/api.py", Regex: "MASTER_BACKDOOR_KEY_2026"},
	}}

	findings, err := ScanCode(dir, rs)
	if err != nil {
		t.Fatalf("expected a missing target file to be skipped, not errored: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a missing file, got %d", len(findings))
	}
}
