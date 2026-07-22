package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jampanikomal/tracestate/pkg/rules"
)

func ScanDatabase(targetDir string, rs rules.RuleSet) ([]Finding, error) {
	var findings []Finding
	for _, rule := range rs.Rules {
		// Target Database & IAM rules
		if !strings.HasPrefix(rule.ID, "ISO-A9-2") {
			continue
		}

		filePath := filepath.Join(targetDir, rule.TargetFile)
		content, err := os.ReadFile(filePath)
		if err != nil {
			// Skip if file doesn't exist
			continue
		}

		matched, err := regexp.MatchString(rule.Regex, string(content))
		if err != nil {
			return nil, err
		}
		if matched {
			finding := Finding{File: filePath, Category: "database", Framework: "ISO-27001", Message: rule.Description}
			findings = append(findings, finding)
			fmt.Printf("[VIOLATION DETECTED] FLAW: %s\n", rule.Description)
			fmt.Println("  -> Framework: ISO-27001 (User Access Provisioning / IAM)")
		}
	}
	return findings, nil
}
