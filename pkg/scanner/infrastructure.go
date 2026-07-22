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

// ScanTarget executes the available wires across the target repository.
func ScanTarget(targetPath string, rs rules.RuleSet) ([]Finding, error) {
	var findings []Finding

	fmt.Println("--- [WIRE 1: INFRASTRUCTURE SCAN] ---")

	composePath := filepath.Join(targetPath, "docker-compose.yml")
	content, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("could not attach to target infrastructure at %s: %w", composePath, err)
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

	fmt.Println("--- [WIRE 2: TELEMETRY SCAN] ---")
	telemetryFindings, err := ScanLogs(targetPath, rs)
	if err != nil {
		return nil, err
	}
	findings = append(findings, telemetryFindings...)

	fmt.Println("--- [WIRE 3: SOURCE CODE SCAN] ---")
	codeFindings, err := ScanCode(targetPath, rs)
	if err != nil {
		return nil, err
	}
	findings = append(findings, codeFindings...)

	fmt.Println("--- [WIRE 4: NETWORK SCAN] ---")
	networkFindings, err := ScanNetwork(targetPath, rs)
	if err != nil {
		return nil, err
	}
	findings = append(findings, networkFindings...)

	fmt.Println("--- [WIRE 5: SUPPLY CHAIN SCAN] ---")
	supplyChainFindings, err := ScanSupplyChain(targetPath, rs)
	if err != nil {
		return nil, err
	}
	findings = append(findings, supplyChainFindings...)

	fmt.Println("--- [WIRE 6: DATABASE & IAM SCAN] ---")
	databaseFindings, err := ScanDatabase(targetPath, rs)
	if err != nil {
		return nil, err
	}
	findings = append(findings, databaseFindings...)

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
