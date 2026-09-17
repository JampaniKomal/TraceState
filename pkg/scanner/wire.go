package scanner

import "github.com/jampanikomal/tracestate/pkg/rules"

// Wire is a single, independently pluggable scanner module. TraceState's
// six built-in wires each implement this interface. Adding a new wire -
// a check for a different framework, a different target file type, or
// an org-specific policy - means writing a new type that implements
// Wire and calling RegisterWire with it. Nothing in ScanTarget, or in
// any existing wire, needs to change.
type Wire interface {
	// Name is the short label printed in scan output, e.g.
	// "WIRE 3: SOURCE CODE SCAN".
	Name() string
	// Scan runs this wire's checks against targetDir using the given
	// ruleset and returns any findings.
	Scan(targetDir string, rs rules.RuleSet) ([]Finding, error)
}

var registeredWires []Wire

// RegisterWire adds a wire to the set ScanTarget runs, in registration
// order. The six built-in wires register themselves below, in a fixed
// order; a custom wire - defined anywhere, in this package or another -
// can call RegisterWire from its own init() (after importing this
// package for its side effects) to plug into every future scan.
func RegisterWire(w Wire) {
	registeredWires = append(registeredWires, w)
}

func init() {
	RegisterWire(infrastructureWire{})
	RegisterWire(telemetryWire{})
	RegisterWire(codeWire{})
	RegisterWire(networkWire{})
	RegisterWire(supplyChainWire{})
	RegisterWire(databaseWire{})
}
