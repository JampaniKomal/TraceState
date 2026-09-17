package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesParsesAValidRuleset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ruleset.json")
	content := `{"version":"1.0","frameworks":["ISO27001"],"rules":[{"id":"X-1","description":"d","target_file":"f","regex":"r"}]}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write ruleset: %v", err)
	}

	rs, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].ID != "X-1" {
		t.Fatalf("unexpected ruleset contents: %+v", rs)
	}
}

func TestLoadRulesReturnsErrorForMissingFile(t *testing.T) {
	// Regression test: LoadRules used to panic() on a missing or
	// malformed file, crashing the whole CLI with a raw stack trace
	// instead of a clean error message.
	_, err := LoadRules(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected an error for a missing ruleset file, got nil")
	}
}

func TestLoadRulesReturnsErrorForMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ruleset.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("write ruleset: %v", err)
	}

	_, err := LoadRules(path)
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}
