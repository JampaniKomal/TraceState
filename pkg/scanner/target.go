package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
)

// MaxFileSize is the largest file a wire will read. Larger files are skipped
// (and counted) rather than loaded into memory.
const MaxFileSize = 8 << 20

// skipDirs are never descended into: VCS metadata, dependency caches and
// virtualenvs contain third-party code that isn't the target's own policy
// surface.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true, ".tox": true, ".mypy_cache": true,
	".pytest_cache": true, ".idea": true, ".vscode": true, ".terraform": true,
}

// Target is an indexed, read-only view of the directory (or single file)
// being scanned. File paths are always slash-separated and relative to Root.
type Target struct {
	Root    string
	files   []string
	skipped int

	mu    sync.Mutex
	cache map[string][]byte
}

// NewTarget indexes every regular, non-binary file under path. If path is a
// file, the target contains just that file.
func NewTarget(path string) (*Target, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("scan target: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	t := &Target{cache: map[string][]byte{}}
	if !info.IsDir() {
		t.Root = filepath.Dir(abs)
		t.files = []string{filepath.Base(abs)}
		return t, nil
	}
	t.Root = abs
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				t.skipped++
				return nil
			}
			return err
		}
		if d.IsDir() {
			if p != abs && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() > MaxFileSize {
			t.skipped++
			return nil
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return err
		}
		t.files = append(t.files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("indexing %s: %w", path, err)
	}
	sort.Strings(t.files)
	return t, nil
}

// Exclude drops every indexed file matching one of globs (doublestar syntax,
// relative to Root) and returns how many were dropped. Excluded files are
// invisible to every rule, unlike a rule's own exclude list.
func (t *Target) Exclude(globs []string) (int, error) {
	for _, g := range globs {
		if !doublestar.ValidatePattern(g) {
			return 0, fmt.Errorf("invalid exclude glob %q", g)
		}
	}
	if len(globs) == 0 {
		return 0, nil
	}
	kept := t.files[:0]
	for _, f := range t.files {
		if !matchAny(globs, f) {
			kept = append(kept, f)
		}
	}
	n := len(t.files) - len(kept)
	t.files = kept
	return n, nil
}

// Exists reports whether rel exists under Root, whether or not it was indexed
// (a lockfile larger than MaxFileSize still exists, for example).
func (t *Target) Exists(rel string) bool {
	_, err := os.Stat(filepath.Join(t.Root, filepath.FromSlash(rel)))
	return err == nil
}

// Files returns every indexed file.
func (t *Target) Files() []string { return t.files }

// Skipped is the number of files left out because they were too large or
// unreadable.
func (t *Target) Skipped() int { return t.skipped }

// Match returns the indexed files matching any include glob and no exclude
// glob. Globs use doublestar syntax ("**/*.py", "src/{a,b}/*.js").
func (t *Target) Match(include, exclude []string) []string {
	var out []string
	for _, f := range t.files {
		if matchAny(include, f) && !matchAny(exclude, f) {
			out = append(out, f)
		}
	}
	return out
}

func matchAny(globs []string, path string) bool {
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, path); ok {
			return true
		}
	}
	return false
}

// Read returns a file's contents, or ErrBinary for files that look binary.
// Contents are cached, since several rules usually read the same file.
func (t *Target) Read(rel string) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if data, ok := t.cache[rel]; ok {
		if data == nil {
			return nil, ErrBinary
		}
		return data, nil
	}
	data, err := os.ReadFile(filepath.Join(t.Root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	if looksBinary(data) {
		t.cache[rel] = nil
		return nil, ErrBinary
	}
	t.cache[rel] = data
	return data, nil
}

// ErrBinary is returned by Read for files that aren't text.
var ErrBinary = errors.New("binary file")

func looksBinary(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// Lines splits file contents into lines without their line terminators.
func Lines(data []byte) []string {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.Split(s, "\n")
}

// LineOf returns the 1-based line number containing byte offset off.
func LineOf(data []byte, off int) int {
	if off > len(data) {
		off = len(data)
	}
	return bytes.Count(data[:off], []byte{'\n'}) + 1
}
