package wires

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/osv"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// depsWire reads dependency manifests (requirements*.txt, package.json,
// go.mod). It flags unpinned versions offline, and, with --online, checks
// every pinned version against the OSV.dev advisory database.
type depsWire struct {
	client func() *osv.Client
}

func newDepsWire() depsWire { return depsWire{client: osv.New} }

func (depsWire) Name() string { return "deps" }
func (depsWire) Checks() []string {
	return []string{"deps.known_vulnerable", "deps.unpinned"}
}

// dependency is one declared dependency and where it was declared.
type dependency struct {
	name, version, ecosystem string
	pinned                   bool
	line                     int
}

func (w depsWire) Scan(ctx context.Context, t *scanner.Target, jobs []scanner.Job, opts scanner.Options) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, job := range jobs {
		manifests := map[string][]dependency{}
		err := forEachFile(t, job, func(file string, data []byte) error {
			manifests[file] = parseManifest(file, data)
			return nil
		})
		if err != nil {
			return nil, err
		}
		switch job.Rule.Check {
		case "deps.unpinned":
			for _, file := range job.Files {
				if lockedByLockfile(t, file) {
					continue
				}
				if f, ok := unpinnedFinding(job.Rule, file, manifests[file]); ok {
					out = append(out, f)
				}
			}
		case "deps.known_vulnerable":
			if !opts.Online {
				continue
			}
			found, err := w.vulnerable(ctx, job.Rule, job.Files, manifests)
			if err != nil {
				return nil, err
			}
			out = append(out, found...)
		}
	}
	return out, nil
}

func parseManifest(file string, data []byte) []dependency {
	base := path.Base(file)
	switch {
	case base == "package.json":
		return parsePackageJSON(data)
	case base == "go.mod":
		return parseGoMod(data)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return parseRequirements(data)
	}
	return nil
}

var reqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$`)

func parseRequirements(data []byte) []dependency {
	var out []dependency
	for i, raw := range scanner.Lines(data) {
		line := strings.TrimSpace(raw)
		if c := strings.Index(line, " #"); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			continue
		}
		if semi := strings.IndexByte(line, ';'); semi >= 0 { // environment marker
			line = strings.TrimSpace(line[:semi])
		}
		m := reqLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		d := dependency{name: m[1], ecosystem: "PyPI", line: i + 1}
		spec := strings.TrimSpace(m[3])
		if v, ok := strings.CutPrefix(spec, "=="); ok && !strings.ContainsAny(v, "*,<>!~") {
			d.version, d.pinned = strings.TrimSpace(v), true
		}
		out = append(out, d)
	}
	return out
}

var exactSemver = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

func parsePackageJSON(data []byte) []dependency {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	text := string(data)
	var out []dependency
	for _, section := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for _, name := range keys(section) {
			spec := section[name]
			if strings.Contains(spec, ":") || strings.Contains(spec, "/") { // git, file, url, workspace deps
				continue
			}
			d := dependency{name: name, ecosystem: "npm"}
			if idx := strings.Index(text, `"`+name+`"`); idx >= 0 {
				d.line = scanner.LineOf(data, idx)
			}
			if exactSemver.MatchString(spec) {
				d.version, d.pinned = strings.TrimPrefix(spec, "v"), true
			}
			out = append(out, d)
		}
	}
	return out
}

var goRequire = regexp.MustCompile(`^\s*(?:require\s+)?([A-Za-z0-9.\-_~/]+\.[A-Za-z]{2,}[A-Za-z0-9.\-_~/]*)\s+(v[0-9][^\s]*)`)

func parseGoMod(data []byte) []dependency {
	var out []dependency
	inBlock := false
	for i, raw := range scanner.Lines(data) {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case !inBlock && !strings.HasPrefix(line, "require "):
			continue
		}
		if m := goRequire.FindStringSubmatch(line); m != nil {
			// OSV records Go versions without the "v" prefix.
			out = append(out, dependency{name: m[1], version: strings.TrimPrefix(m[2], "v"), ecosystem: "Go", pinned: true, line: i + 1})
		}
	}
	return out
}

// npmLockfiles pin every package.json range to an exact version.
var npmLockfiles = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}

// lockedByLockfile reports whether a package.json's version ranges are
// pinned by a lockfile next to it or in a parent directory (workspaces keep
// one lockfile at the root). Ranges plus a lockfile is normal npm practice.
func lockedByLockfile(t *scanner.Target, manifest string) bool {
	if path.Base(manifest) != "package.json" {
		return false
	}
	for dir := path.Dir(manifest); ; dir = path.Dir(dir) {
		for _, lock := range npmLockfiles {
			if t.Exists(path.Join(dir, lock)) {
				return true
			}
		}
		if dir == "." || dir == "/" {
			return false
		}
	}
}

func unpinnedFinding(r *policy.Rule, file string, deps []dependency) (finding.Finding, bool) {
	var names []string
	line := 0
	for _, d := range deps {
		if !d.pinned {
			names = append(names, d.name)
			if line == 0 {
				line = d.line
			}
		}
	}
	if len(names) == 0 {
		return finding.Finding{}, false
	}
	shown := names
	if len(shown) > 8 {
		shown = append(shown[:8:8], fmt.Sprintf("and %d more", len(names)-8))
	}
	f := newFinding(r, file, line,
		fmt.Sprintf("%d of %d dependencies are not pinned to an exact version", len(names), len(deps)),
		strings.Join(shown, ", "))
	f.Occurrences = len(names)
	return f, true
}

var osvSeverity = map[string]policy.Severity{
	"LOW": policy.Low, "MODERATE": policy.Medium, "MEDIUM": policy.Medium, "HIGH": policy.High, "CRITICAL": policy.Critical,
}

func (w depsWire) vulnerable(ctx context.Context, r *policy.Rule, files []string, manifests map[string][]dependency) ([]finding.Finding, error) {
	type loc struct {
		file string
		line int
	}
	where := map[osv.Package][]loc{}
	var pkgs []osv.Package
	for _, file := range files {
		for _, d := range manifests[file] {
			if !d.pinned {
				continue
			}
			p := osv.Package{Name: d.name, Ecosystem: d.ecosystem, Version: d.version}
			if _, dup := where[p]; !dup {
				pkgs = append(pkgs, p)
			}
			where[p] = append(where[p], loc{file, d.line})
		}
	}
	results, err := w.client().Query(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, p := range pkgs {
		vulns := results[p]
		if len(vulns) == 0 {
			continue
		}
		worst, rated := policy.Info, false
		var ids, fixed []string
		for _, v := range vulns {
			ids = append(ids, v.ID)
			fixed = append(fixed, v.Fixed...)
			if s, ok := osvSeverity[v.Severity]; ok {
				rated = true
				if s > worst {
					worst = s
				}
			}
		}
		msg := fmt.Sprintf("%s@%s has %d known advisory(ies): %s", p.Name, p.Version, len(vulns), strings.Join(ids, ", "))
		if fix := highestVersion(fixed); fix != "" {
			msg += "; fixed in " + fix
		}
		for _, l := range where[p] {
			f := newFinding(r, l.file, l.line, msg, fmt.Sprintf("%s %s==%s", p.Ecosystem, p.Name, p.Version))
			if rated {
				f.Severity = worst
			}
			f.Occurrences = len(vulns)
			out = append(out, f)
		}
	}
	return out, nil
}

// highestVersion picks the largest of a set of dotted versions, which is the
// first version clear of every listed advisory.
func highestVersion(vs []string) string {
	best := ""
	for _, v := range vs {
		if best == "" || compareVersions(v, best) > 0 {
			best = v
		}
	}
	return best
}

func compareVersions(a, b string) int {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = leadingInt(pa[i])
		}
		if i < len(pb) {
			y = leadingInt(pb[i])
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

// leadingInt parses the digits at the start of a version component, so "3"
// and "3rc1" both give 3. It returns 0 when there are none.
func leadingInt(s string) int {
	n := 0
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}
