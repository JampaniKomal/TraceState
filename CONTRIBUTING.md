# Contributing to TraceState

Thanks for helping improve TraceState, the open-source Policy-as-Code engine.

## Principles

- Keep additions focused on improving the core engine's performance, stability, and ruleset parsing logic.
- Favor small, reviewable commits.
- Ensure that any new 'Wires' added to `pkg/scanner/` are highly decoupled from the PSU.
- Add or update rules in `ruleset.json` carefully to avoid false positives.

## Recommended Workflow

1. Fork or branch from `main`.
2. Make the smallest change that solves the problem.
3. Validate the core logic with `go build` and `go test` (if applicable).
4. Update documentation if the user-facing CLI behavior changes.
5. Open a pull request with a clear summary of the change and any verification performed.

## Reporting Issues

- Use a concise title and clearly describe the bug or feature request.
- Provide the exact command or file path involved.
- Include panic logs or screenshots when possible.
