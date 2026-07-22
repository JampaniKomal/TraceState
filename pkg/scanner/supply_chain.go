package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jampanikomal/tracestate/pkg/rules"
)

func ScanSupplyChain(targetDir string, rs rules.RuleSet) ([]Finding, error) {
	var findings []Finding
	for _, rule := range rs.Rules {
		// Target SBOM/Supply Chain rules
		if !strings.HasPrefix(rule.ID, "ISO-A8-8") {
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
			finding := Finding{File: filePath, Category: "supply-chain", Framework: "ISO-27001", Message: rule.Description}
			findings = append(findings, finding)
			fmt.Printf("[VIOLATION DETECTED] FLAW: %s\n", rule.Description)
			fmt.Println("  -> Framework: ISO-27001 (Management of Technical Vulnerabilities)")
		}
	}
	return findings, nil
}
