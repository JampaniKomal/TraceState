# Contributing to TraceState

Bug reports, false positives, new rules and new wires are all welcome.

## Build and test

```bash
go test -race ./...
go run ./cmd/tracestate scan .
golangci-lint run          # v2, config in .golangci.yml
```

Before opening a pull request, also run the benchmark check against
[Auditable](https://github.com/JampaniKomal/Auditable) at the pinned commit
(CI does this too):

```bash
go build -o tracestate ./cmd/tracestate
scripts/check-benchmark.sh ./tracestate path/to/Auditable
```

## Reporting a false positive

A false positive is a bug. Open an issue with the rule ID, the line that was
flagged (redact anything real) and why it's wrong. The fix goes in the wire,
and the line becomes a fixture in `TestCleanProjectHasNoFindings`
(`pkg/wires/wires_test.go`) so it stays fixed.

## Adding or changing a rule

Rules live in `pkg/policy/default_rules.yaml`. A rule must be generic: it may
not name a file, variable or string from any particular project. Map it only
to controls it is genuine evidence against, and add the control's title to the
catalogue in `pkg/policy/frameworks.go` if it is new (a test enforces this).

Then regenerate the docs that are built from the rule pack:

```bash
go test ./internal/cli -run TestGeneratedDocs -update
```

## Adding a wire

A wire is a scanner module that owns a family of checks. The engine knows
nothing about individual wires, so a new one is a new file:

1. Create `pkg/wires/<name>.go` with a type that implements `scanner.Wire`:

   ```go
   type k8sWire struct{}

   func (k8sWire) Name() string     { return "k8s" }
   func (k8sWire) Checks() []string { return []string{"k8s.privileged_pod"} }
   func (k8sWire) Scan(ctx context.Context, t *scanner.Target, jobs []scanner.Job, opts scanner.Options) ([]finding.Finding, error) {
       // Each job is one rule plus the files its globs matched.
       // Read files with t.Read, report with newFinding(rule, file, line, message, evidence).
   }
   ```

2. Register it in the `init` function in `pkg/wires/common.go`.
3. Add rules that use its checks to `default_rules.yaml`.
4. Add tests in `pkg/wires/wires_test.go`: a fixture that must be found, and
   realistic code that must not be.

Guidelines that keep wires fast and quiet:

- Parse structure when the format has it (YAML, Dockerfile instructions, SQL
  column lists) instead of matching raw text.
- Put a cheap literal test (`containsAny`, `containsAnyFold`) before every
  regular expression; most lines can't match.
- Skip comment-only lines (`scanner.CommentOnly`) and minified bundles
  (`minified`) in statement-level checks.
- Never put a secret or personal data in evidence unmasked; use the helpers
  in `pkg/detect`.

## Pull requests

Keep them small and focused, explain what changed and how you verified it,
and update the docs when user-facing behaviour changes. By contributing you
agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
