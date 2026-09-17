package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/jampanikomal/tracestate/pkg/rules"
)

type Finding struct {
	File      string
	Category  string
	Framework string
	Message   string
}

type infrastructureWire struct{}

func (infrastructureWire) Name() string { return "WIRE 1: INFRASTRUCTURE SCAN" }

func (infrastructureWire) Scan(targetDir string, rs rules.RuleSet) ([]Finding, error) {
	return ScanInfrastructure(targetDir, rs)
}

// ScanInfrastructure checks docker-compose.yml for container-privilege,
// unencrypted-volume, and exposed-socket violations. A target with no
// docker-compose.yml simply has nothing for this wire to check - it
// returns no findings rather than an error, so the other wires (which
// don't depend on any container orchestration file) still run.
func ScanInfrastructure(targetPath string, rs rules.RuleSet) ([]Finding, error) {
	var findings []Finding

	composePath := filepath.Join(targetPath, "docker-compose.yml")
	content, err := os.ReadFile(composePath)
	if err != nil {
		fmt.Printf("[SKIPPED] No docker-compose.yml found at %s\n", composePath)
		return findings, nil
	}

	yamlData := string(content)
	for _, rule := range rs.Rules {
		if rule.TargetFile != "docker-compose.yml" {
			continue
		}
		matched, err := regexp.MatchString(rule.Regex, yamlData)
		if err != nil {
			return nil, err
		}
		if matched {
			finding := Finding{File: composePath, Category: "infrastructure", Framework: "ISO-27001", Message: rule.Description}
			fmt.Printf("[VIOLATION DETECTED] FLAW: %s\n", finding.Message)
			fmt.Println("  -> Framework: ISO-27001 (Access Control)")
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// ScanTarget runs every registered wire against targetPath, in
// registration order, and returns the combined findings.
func ScanTarget(targetPath string, rs rules.RuleSet) ([]Finding, error) {
	var findings []Finding

	for _, wire := range registeredWires {
		fmt.Printf("--- [%s] ---\n", wire.Name())
		wireFindings, err := wire.Scan(targetPath, rs)
		if err != nil {
			return nil, err
		}
		findings = append(findings, wireFindings...)
	}

	fmt.Println("-------------------------------------")
	printFindings(findings)
	return findings, nil
}

func printFindings(findings []Finding) {
	if len(findings) == 0 {
		return
	}
	for _, finding := range findings {
		fmt.Printf("- %s | %s | %s | %s\n", finding.Category, finding.Framework, finding.File, finding.Message)
	}
}
