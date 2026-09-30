package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/report"
)

type scanStarted struct {
	Target        string    `json:"target"`
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	StartedAt     time.Time `json:"started_at"`
	Online        bool      `json:"online"`
	RuleSetSHA256 string    `json:"ruleset_sha256"`
	RuleSources   []string  `json:"ruleset_sources"`
	FilesIndexed  int       `json:"files_indexed"`
	FilesSkipped  int       `json:"files_skipped"`
}

type scanCompleted struct {
	DurationMS int64                `json:"duration_ms"`
	Suppressed int                  `json:"suppressed"`
	Summary    report.Summary       `json:"summary"`
	Rules      []report.RuleOutcome `json:"rules"`
}

// RecordScan appends a complete scan (a start entry, one entry per finding
// and a completion entry) atomically, and returns the new scan's ID.
func (l *Ledger) RecordScan(ctx context.Context, rep *report.Report) (string, error) {
	scanID := newID()
	a, err := l.begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(a.tx)

	start, err := marshal(scanStarted{
		Target: rep.Target, Tool: rep.Tool, Version: rep.Version, StartedAt: rep.StartedAt,
		Online: rep.Online, RuleSetSHA256: rep.RuleSetSHA256, RuleSources: rep.RuleSources,
		FilesIndexed: rep.FilesIndexed, FilesSkipped: rep.FilesSkipped,
	})
	if err != nil {
		return "", err
	}
	if _, err := a.add(ctx, KindScanStarted, scanID, start); err != nil {
		return "", err
	}
	for _, f := range rep.Findings {
		payload, err := marshal(f)
		if err != nil {
			return "", err
		}
		if _, err := a.add(ctx, KindFinding, scanID, payload); err != nil {
			return "", err
		}
	}
	done, err := marshal(scanCompleted{
		DurationMS: rep.DurationMS, Suppressed: rep.Suppressed, Summary: rep.Summary(), Rules: rep.Rules,
	})
	if err != nil {
		return "", err
	}
	if _, err := a.add(ctx, KindScanCompleted, scanID, done); err != nil {
		return "", err
	}
	if err := a.tx.Commit(); err != nil {
		return "", err
	}
	rep.ScanID = scanID
	return scanID, nil
}

// ScanInfo summarises one recorded scan.
type ScanInfo struct {
	ID         string         `json:"id"`
	StartedAt  time.Time      `json:"started_at"`
	Target     string         `json:"target"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
	FirstSeq   int64          `json:"first_seq"`
	LastSeq    int64          `json:"last_seq"`
	Complete   bool           `json:"complete"`
}

// Scans lists recorded scans in the order they were written.
func (l *Ledger) Scans(ctx context.Context) ([]ScanInfo, error) {
	entries, err := l.query(ctx,
		`SELECT seq, kind, created_at, scan_id, payload, prev_hash, entry_hash FROM entries WHERE kind IN (?, ?) ORDER BY seq`,
		KindScanStarted, KindScanCompleted)
	if err != nil {
		return nil, err
	}
	var out []ScanInfo
	index := map[string]int{}
	for _, e := range entries {
		switch e.Kind {
		case KindScanStarted:
			var s scanStarted
			if err := json.Unmarshal([]byte(e.Payload), &s); err != nil {
				return nil, fmt.Errorf("entry %d: %w", e.Seq, err)
			}
			index[e.ScanID] = len(out)
			out = append(out, ScanInfo{ID: e.ScanID, StartedAt: s.StartedAt, Target: s.Target, FirstSeq: e.Seq})
		case KindScanCompleted:
			i, ok := index[e.ScanID]
			if !ok {
				continue
			}
			var c scanCompleted
			if err := json.Unmarshal([]byte(e.Payload), &c); err != nil {
				return nil, fmt.Errorf("entry %d: %w", e.Seq, err)
			}
			out[i].Findings, out[i].BySeverity = c.Summary.Total, c.Summary.BySeverity
			out[i].LastSeq, out[i].Complete = e.Seq, true
		}
	}
	return out, nil
}

// ResolveScan expands a scan ID prefix (at least 6 characters) or the word
// "latest" to a full scan ID.
func (l *Ledger) ResolveScan(ctx context.Context, idOrPrefix string) (string, error) {
	scans, err := l.Scans(ctx)
	if err != nil {
		return "", err
	}
	if len(scans) == 0 {
		return "", fmt.Errorf("the ledger has no scans yet")
	}
	if idOrPrefix == "" || idOrPrefix == "latest" {
		return scans[len(scans)-1].ID, nil
	}
	if len(idOrPrefix) < 6 {
		return "", fmt.Errorf("scan ID prefix %q is too short (use at least 6 characters)", idOrPrefix)
	}
	var match string
	for _, s := range scans {
		if strings.HasPrefix(s.ID, idOrPrefix) {
			if match != "" {
				return "", fmt.Errorf("scan ID prefix %q is ambiguous", idOrPrefix)
			}
			match = s.ID
		}
	}
	if match == "" {
		return "", fmt.Errorf("no scan with ID %q", idOrPrefix)
	}
	return match, nil
}

// LoadScan rebuilds the full report of a recorded scan.
func (l *Ledger) LoadScan(ctx context.Context, scanID string) (*report.Report, error) {
	entries, err := l.query(ctx,
		`SELECT seq, kind, created_at, scan_id, payload, prev_hash, entry_hash FROM entries WHERE scan_id = ? ORDER BY seq`, scanID)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no scan with ID %q", scanID)
	}
	rep := &report.Report{ScanID: scanID, Findings: []finding.Finding{}}
	for _, e := range entries {
		switch e.Kind {
		case KindScanStarted:
			var s scanStarted
			if err := json.Unmarshal([]byte(e.Payload), &s); err != nil {
				return nil, err
			}
			rep.Tool, rep.Version, rep.Target, rep.StartedAt = s.Tool, s.Version, s.Target, s.StartedAt
			rep.Online, rep.RuleSetSHA256, rep.RuleSources = s.Online, s.RuleSetSHA256, s.RuleSources
			rep.FilesIndexed, rep.FilesSkipped = s.FilesIndexed, s.FilesSkipped
		case KindFinding:
			var f finding.Finding
			if err := json.Unmarshal([]byte(e.Payload), &f); err != nil {
				return nil, err
			}
			rep.Findings = append(rep.Findings, f)
		case KindScanCompleted:
			var c scanCompleted
			if err := json.Unmarshal([]byte(e.Payload), &c); err != nil {
				return nil, err
			}
			rep.DurationMS, rep.Suppressed, rep.Rules = c.DurationMS, c.Suppressed, c.Rules
		}
	}
	finding.Sort(rep.Findings)
	return rep, nil
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
