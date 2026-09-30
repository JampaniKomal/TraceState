package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity ranks how serious a violated rule is. The zero value is Info.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity accepts the lowercase names used in rule files and on the
// command line ("info", "low", "medium", "high", "critical").
func ParseSeverity(v string) (Severity, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	for i, name := range severityNames {
		if v == name {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s)", v, strings.Join(severityNames[:], ", "))
}

// SARIFLevel maps a severity onto the three SARIF result levels.
func (s Severity) SARIFLevel() string {
	switch {
	case s >= High:
		return "error"
	case s >= Medium:
		return "warning"
	default:
		return "note"
	}
}

// SecurityScore is the numeric "security-severity" GitHub code scanning
// uses to bucket SARIF results (>= 9.0 critical, >= 7.0 high, >= 4.0 medium).
func (s Severity) SecurityScore() string {
	switch s {
	case Critical:
		return "9.5"
	case High:
		return "8.0"
	case Medium:
		return "5.5"
	case Low:
		return "3.0"
	default:
		return "0.0"
	}
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	parsed, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	return s.UnmarshalText([]byte(v))
}

func (s *Severity) UnmarshalYAML(n *yaml.Node) error {
	return s.UnmarshalText([]byte(n.Value))
}
