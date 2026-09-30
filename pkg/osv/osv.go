// Package osv is a minimal client for the OSV.dev vulnerability database
// (https://osv.dev), used to check pinned dependencies for known advisories.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the public OSV API. TRACESTATE_OSV_URL overrides it,
// which is useful behind a mirror or proxy.
const DefaultBaseURL = "https://api.osv.dev"

// Package identifies one dependency at one version.
type Package struct {
	Name      string
	Ecosystem string // "PyPI", "npm", "Go"
	Version   string
}

// Vuln is the subset of an OSV record TraceState reports.
type Vuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity string   `json:"severity"` // GitHub advisory level: LOW, MODERATE, HIGH, CRITICAL
	Fixed    []string `json:"fixed"`
}

// Client queries OSV. The zero value is not usable; call New.
type Client struct {
	base string
	http *http.Client

	mu      sync.Mutex
	details map[string]Vuln
}

// New returns a client using TRACESTATE_OSV_URL if set, else the public API.
func New() *Client {
	base := DefaultBaseURL
	if v := os.Getenv("TRACESTATE_OSV_URL"); v != "" {
		base = strings.TrimRight(v, "/")
	}
	return &Client{base: base, http: &http.Client{Timeout: 20 * time.Second}, details: map[string]Vuln{}}
}

type batchQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// Query returns the known vulnerabilities of each package, keyed by package.
// Packages without vulnerabilities are absent from the result.
func (c *Client) Query(ctx context.Context, pkgs []Package) (map[Package][]Vuln, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	body := struct {
		Queries []batchQuery `json:"queries"`
	}{}
	for _, p := range pkgs {
		var q batchQuery
		q.Package.Name, q.Package.Ecosystem, q.Version = p.Name, p.Ecosystem, p.Version
		body.Queries = append(body.Queries, q)
	}
	var resp struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/querybatch", body, &resp); err != nil {
		return nil, err
	}
	if len(resp.Results) != len(pkgs) {
		return nil, fmt.Errorf("osv: expected %d results, got %d", len(pkgs), len(resp.Results))
	}
	out := map[Package][]Vuln{}
	for i, r := range resp.Results {
		for _, v := range r.Vulns {
			d, err := c.vuln(ctx, v.ID, pkgs[i].Name)
			if err != nil {
				return nil, err
			}
			out[pkgs[i]] = append(out[pkgs[i]], d)
		}
		sort.Slice(out[pkgs[i]], func(a, b int) bool { return out[pkgs[i]][a].ID < out[pkgs[i]][b].ID })
	}
	return out, nil
}

// vuln fetches (and caches) one advisory, extracting the fixed versions that
// apply to pkgName.
func (c *Client) vuln(ctx context.Context, id, pkgName string) (Vuln, error) {
	key := id + "|" + pkgName
	c.mu.Lock()
	if v, ok := c.details[key]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	var rec struct {
		ID       string   `json:"id"`
		Summary  string   `json:"summary"`
		Aliases  []string `json:"aliases"`
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &rec); err != nil {
		return Vuln{}, err
	}
	v := Vuln{ID: rec.ID, Summary: rec.Summary, Aliases: rec.Aliases, Severity: strings.ToUpper(rec.DatabaseSpecific.Severity)}
	seen := map[string]bool{}
	for _, a := range rec.Affected {
		if !strings.EqualFold(a.Package.Name, pkgName) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" && !seen[f] {
					seen[f] = true
					v.Fixed = append(v.Fixed, f)
				}
			}
		}
	}
	c.mu.Lock()
	c.details[key] = v
	c.mu.Unlock()
	return v, nil
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tracestate")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("osv: %s %s: %s: %s", method, path, res.Status, bytes.TrimSpace(msg))
	}
	return json.NewDecoder(res.Body).Decode(out)
}
