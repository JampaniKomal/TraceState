package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Ruleset struct {
	Frameworks          []string `json:"frameworks"`
	InfrastructureRules struct {
		AllowRootExecution      bool     `json:"allow_root_execution"`
		RequireVolumeEncryption bool     `json:"require_volume_encryption"`
		ForbiddenEnvStrings     []string `json:"forbidden_env_strings"`
	} `json:"infrastructure_rules"`
	DataRules struct {
		AllowPlaintextPIIInLogs bool `json:"allow_plaintext_pii_in_logs"`
	} `json:"data_rules"`
}

type Finding struct {
	File      string
	Category  string
	Framework string
	Message   string
}

// ScanTarget executes the available wires across the target repository.
func ScanTarget(targetPath string) ([]Finding, error) {
	var findings []Finding

	ruleset, err := loadRuleset(filepath.Join(".", "ruleset.json"))
	if err != nil {
		return nil, err
	}
	_ = ruleset

	fmt.Println("--- [WIRE 1: INFRASTRUCTURE SCAN] ---")

	composePath := filepath.Join(targetPath, "docker-compose.yml")
	content, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("could not attach to target infrastructure at %s: %w", composePath, err)
	}

	yamlData := string(content)

	// Rule Evaluation 1: Root User Check (ISO 27001 Least Privilege)
	if strings.Contains(yamlData, "user: root") {
		fmt.Println("[VIOLATION DETECTED] FLAW: Container configured to execute as root user.")
		fmt.Println("  -> Framework: ISO-27001 (Access Control)")
		findings = append(findings, Finding{File: composePath, Category: "infrastructure", Framework: "ISO-27001", Message: "Container configured to execute as root user."})
	}

	// Rule Evaluation 2: Hardcoded Secrets Check
	if strings.Contains(yamlData, "supersecretplaintext") || strings.Contains(yamlData, "DB_PASS") {
		fmt.Println("[VIOLATION DETECTED] FLAW: Hardcoded plaintext credentials found in environment variables.")
		fmt.Println("  -> Framework: Supply Chain / Config Drift")
		findings = append(findings, Finding{File: composePath, Category: "infrastructure", Framework: "ISO-27001", Message: "Hardcoded plaintext credentials found in environment variables."})
	}

	fmt.Println("--- [WIRE 2: TELEMETRY SCAN] ---")
	telemetryFindings, err := scanLogs(targetPath)
	if err != nil {
		return nil, err
	}
	findings = append(findings, telemetryFindings...)

	fmt.Println("-------------------------------------")
	printFindings(findings)
	return findings, nil
}

func loadRuleset(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ruleset Ruleset
	if err := json.Unmarshal(data, &ruleset); err != nil {
		return nil, err
	}
	return &ruleset, nil
}

func scanLogs(targetPath string) ([]Finding, error) {
	var findings []Finding
	piiRegex := regexp.MustCompile(`\b\d{12}\b`)
	cardRegex := regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)

	err := filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".log") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if piiRegex.MatchString(line) || cardRegex.MatchString(line) {
				findings = append(findings, Finding{File: path, Category: "telemetry", Framework: "DPDPA-2026", Message: "Unmasked PII or payment data detected in logs."})
				fmt.Printf("[VIOLATION DETECTED] FLAW: Sensitive data found in %s\n", path)
			}
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
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
