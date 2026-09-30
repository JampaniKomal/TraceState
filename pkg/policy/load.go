package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default_rules.yaml
var defaultRules []byte

// DefaultRulesName is how the embedded rule pack is identified in reports.
const DefaultRulesName = "builtin:default_rules.yaml"

type ruleFile struct {
	Version int    `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

// legacyRuleFile is the TraceState v1 ruleset.json format: a flat list of
// {id, description, target_file, regex}.
type legacyRuleFile struct {
	Version    string `json:"version"`
	Frameworks []string
	Rules      []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		TargetFile  string `json:"target_file"`
		Regex       string `json:"regex"`
	} `json:"rules"`
}

// DefaultRules returns the embedded rule pack.
func DefaultRules() (*RuleSet, error) {
	return parse(DefaultRulesName, defaultRules)
}

// DefaultRulesYAML returns the raw embedded rule pack, e.g. for `rules export`.
func DefaultRulesYAML() []byte { return append([]byte(nil), defaultRules...) }

// Load builds a rule set from the embedded defaults (unless includeDefaults
// is false) followed by each file in paths. A later rule with the same ID as
// an earlier one replaces it, so a custom file can override a built-in rule.
func Load(includeDefaults bool, paths ...string) (*RuleSet, error) {
	type source struct {
		name string
		data []byte
	}
	var sources []source
	if includeDefaults {
		sources = append(sources, source{DefaultRulesName, defaultRules})
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading rules %s: %w", p, err)
		}
		sources = append(sources, source{p, data})
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no rules: defaults disabled and no rule files given")
	}

	merged := &RuleSet{}
	index := map[string]int{}
	h := sha256.New()
	for _, src := range sources {
		rs, err := parse(src.name, src.data)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(h, "%s\n%d\n", filepath.Base(src.name), len(src.data))
		h.Write(src.data)
		merged.Sources = append(merged.Sources, src.name)
		for _, r := range rs.Rules {
			if i, ok := index[r.ID]; ok {
				merged.Rules[i] = r
				continue
			}
			index[r.ID] = len(merged.Rules)
			merged.Rules = append(merged.Rules, r)
		}
	}
	merged.SHA256 = hex.EncodeToString(h.Sum(nil))
	return merged, nil
}

func parse(name string, data []byte) (*RuleSet, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if rs, ok, err := parseLegacy(name, trimmed); ok || err != nil {
			return rs, err
		}
		var f ruleFile
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		return fromFile(name, data, f)
	}
	var f ruleFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", name, err)
	}
	return fromFile(name, data, f)
}

func fromFile(name string, data []byte, f ruleFile) (*RuleSet, error) {
	if f.Version != 0 && f.Version != 2 {
		return nil, fmt.Errorf("%s: unsupported ruleset version %d (want 2)", name, f.Version)
	}
	sum := sha256.Sum256(data)
	return &RuleSet{Rules: f.Rules, Sources: []string{name}, SHA256: hex.EncodeToString(sum[:])}, nil
}

// parseLegacy converts a v1 ruleset.json. It reports ok=false when the data
// isn't in the legacy shape so the caller can try the v2 JSON form.
func parseLegacy(name string, data []byte) (*RuleSet, bool, error) {
	var probe struct {
		Rules []map[string]json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(data, &probe); err != nil || len(probe.Rules) == 0 {
		return nil, false, nil
	}
	if _, ok := probe.Rules[0]["target_file"]; !ok {
		return nil, false, nil
	}
	var legacy legacyRuleFile
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, true, fmt.Errorf("parsing legacy ruleset %s: %w", name, err)
	}
	rs := &RuleSet{Sources: []string{name}}
	for _, lr := range legacy.Rules {
		rs.Rules = append(rs.Rules, Rule{
			ID:         lr.ID,
			Title:      lr.Description,
			Severity:   Medium,
			Check:      "regex.match",
			Files:      []string{lr.TargetFile},
			Pattern:    lr.Regex,
			Frameworks: legacyFramework(lr.ID),
		})
	}
	sum := sha256.Sum256(data)
	rs.SHA256 = hex.EncodeToString(sum[:])
	return rs, true, nil
}

// legacyFramework infers a framework from a v1 rule ID prefix such as
// "ISO-A8-28-01" or "DPDPA-02".
func legacyFramework(id string) map[string][]string {
	upper := strings.ToUpper(id)
	for _, p := range []struct{ prefix, fw string }{
		{"ISO", "ISO27001"}, {"DPDPA", "DPDPA"}, {"HIPAA", "HIPAA"},
		{"SEBI", "SEBI-CSCRF"}, {"CERT", "CERT-In"}, {"PCI", "PCI-DSS"},
	} {
		if strings.HasPrefix(upper, p.prefix) {
			return map[string][]string{p.fw: {id}}
		}
	}
	return nil
}

func sortStrings(s []string) { sort.Strings(s) }
