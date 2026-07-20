package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jampanikomal/tracestate/pkg/rules"
)

func ScanLogs(targetDir string, rs rules.RuleSet) ([]Finding, error) {
	var findings []Finding
	for _, rule := range rs.Rules {
		if rule.TargetFile != "logs/app_audit.log" {
			continue
		}

		err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(path), ".log") {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			matched, _ := regexp.MatchString(rule.Regex, string(content))
			if matched {
				findings = append(findings, Finding{File: path, Category: "telemetry", Framework: "DPDPA", Message: rule.Description})
				fmt.Printf("[VIOLATION DETECTED] FLAW: %s\n", rule.Description)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return findings, nil
}
