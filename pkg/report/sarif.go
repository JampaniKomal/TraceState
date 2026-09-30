package report

import (
	"encoding/json"
	"io"
	"strings"
)

// SARIF 2.1.0 output, the format GitHub code scanning and most security
// dashboards ingest. Only the fields TraceState fills in are modelled.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration sarifLevel     `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
	Precision        string   `json:"precision"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// SARIF writes the report as a SARIF 2.1.0 log.
func SARIF(w io.Writer, r *Report) error {
	driver := sarifDriver{Name: r.Tool, Version: r.Version, InformationURI: ToolURL, Rules: []sarifRule{}}
	index := map[string]int{}
	for _, ro := range r.Rules {
		index[ro.ID] = len(driver.Rules)
		tags := []string{"security", "compliance"}
		for _, c := range ro.Controls {
			if c.Framework == "CWE" {
				tags = append(tags, "external/cwe/"+strings.ToLower(c.Control))
			} else {
				tags = append(tags, c.Framework+":"+c.Control)
			}
		}
		help := ro.Remediation
		if help == "" {
			help = ro.Title
		}
		md := "**" + ro.Title + "**\n\n" + help
		if len(ro.Controls) > 0 {
			md += "\n\nControls: " + ControlsLine(ro.Controls)
		}
		driver.Rules = append(driver.Rules, sarifRule{
			ID:                   ro.ID,
			Name:                 sarifName(ro.Title),
			ShortDescription:     sarifText{Text: ro.Title},
			FullDescription:      sarifText{Text: firstNonEmpty(ro.Description, ro.Title)},
			Help:                 sarifText{Text: help, Markdown: md},
			DefaultConfiguration: sarifLevel{Level: ro.Severity.SARIFLevel()},
			Properties:           sarifRuleProps{Tags: tags, SecuritySeverity: ro.Severity.SecurityScore(), Precision: "high"},
		})
	}

	results := []sarifResult{}
	for _, f := range r.Findings {
		loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File, URIBaseID: "%SRCROOT%"}}
		if f.Line > 0 {
			loc.Region = &sarifRegion{StartLine: f.Line}
		}
		msg := f.Message
		if f.Evidence != "" {
			msg += " (evidence: " + f.Evidence + ")"
		}
		res := sarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           index[f.RuleID],
			Level:               f.Severity.SARIFLevel(),
			Message:             sarifText{Text: msg},
			Locations:           []sarifLocation{{PhysicalLocation: loc}},
			PartialFingerprints: map[string]string{"tracestate/v1": f.Fingerprint},
		}
		if f.Occurrences > 1 {
			res.Properties = map[string]any{"occurrences": f.Occurrences}
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:        sarifTool{Driver: driver},
			Results:     results,
			Invocations: []sarifInvocation{{ExecutionSuccessful: true}},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifName converts a title to the PascalCase identifier SARIF rule names use.
func sarifName(title string) string {
	var b strings.Builder
	for _, word := range strings.FieldsFunc(title, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	}) {
		b.WriteString(strings.ToUpper(word[:1]) + word[1:])
	}
	return b.String()
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
