package rules

import (
	"encoding/json"
	"fmt"
	"os"
)

type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	TargetFile  string `json:"target_file"`
	Regex       string `json:"regex"`
}

type RuleSet struct {
	Version    string   `json:"version"`
	Frameworks []string `json:"frameworks"`
	Rules      []Rule   `json:"rules"`
}

func LoadRules(filePath string) (RuleSet, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return RuleSet{}, fmt.Errorf("could not read ruleset at %s: %w", filePath, err)
	}

	var rs RuleSet
	if err := json.Unmarshal(content, &rs); err != nil {
		return RuleSet{}, fmt.Errorf("could not parse ruleset at %s: %w", filePath, err)
	}
	return rs, nil
}
