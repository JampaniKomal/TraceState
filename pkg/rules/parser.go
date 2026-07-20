package rules

import (
	"encoding/json"
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

func LoadRules(filePath string) RuleSet {
	content, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}

	var rs RuleSet
	if err := json.Unmarshal(content, &rs); err != nil {
		panic(err)
	}
	return rs
}
