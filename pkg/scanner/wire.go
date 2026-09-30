// Package scanner runs policy rules against a target through pluggable
// scanner modules called wires.
package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/jampanikomal/tracestate/v2/pkg/finding"
	"github.com/jampanikomal/tracestate/v2/pkg/policy"
)

// Job is one rule together with the target files its globs selected.
type Job struct {
	Rule  *policy.Rule
	Files []string
}

// Options carries run-wide settings to the wires.
type Options struct {
	// Online allows wires to call external services (for example the OSV
	// vulnerability database). Rules marked `online: true` are skipped, and
	// reported as not evaluated, when it is false.
	Online bool
}

// Wire is one independently pluggable scanner module. It owns a family of
// checks ("compose.*", "pii.*", ...) and evaluates the rules that name them.
//
// A new wire needs no changes anywhere else: implement this interface and call
// Register from an init function in the package that defines it.
type Wire interface {
	// Name is the check prefix the wire owns, e.g. "compose".
	Name() string
	// Checks lists the full check identifiers the wire implements.
	Checks() []string
	// Scan evaluates jobs, each already narrowed to the files its rule's
	// globs matched, and returns every finding.
	Scan(ctx context.Context, t *Target, jobs []Job, opts Options) ([]finding.Finding, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Wire{}
)

// Register makes a wire available to every engine. It panics on a duplicate
// name, since that can only be a programming error.
func Register(w Wire) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[w.Name()]; dup {
		panic(fmt.Sprintf("scanner: wire %q registered twice", w.Name()))
	}
	registry[w.Name()] = w
}

// Wires returns the registered wires sorted by name.
func Wires() []Wire {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Wire, 0, len(registry))
	for _, w := range registry {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// KnownChecks is the set of check identifiers all registered wires implement,
// used to validate rule files.
func KnownChecks() map[string]bool {
	known := map[string]bool{}
	for _, w := range Wires() {
		for _, c := range w.Checks() {
			known[c] = true
		}
	}
	return known
}

func lookup(name string) (Wire, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	w, ok := registry[name]
	return w, ok
}
