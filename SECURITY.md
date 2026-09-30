# Security policy

TraceState is used as audit evidence, so a flaw that lets a finding disappear
or a ledger change go unnoticed matters as much as a crash.

## In scope

- Ways to alter, remove or forge ledger entries or seals that `tracestate
  ledger verify` (or `scripts/verify-export.py`) does not report
- Findings leaking unmasked secrets or personal data into reports or the
  ledger
- Crafted target files or rule files that crash the scanner, hang it
  (catastrophic patterns), or make it read outside the target
- Vulnerabilities in the GitHub Action, the release artifacts or their
  provenance
- Dependencies with known high or critical advisories

## Out of scope

- Problems in intentionally vulnerable targets such as
  [Auditable](https://github.com/JampaniKomal/Auditable)
- Rules that miss something (please open a normal issue)

## Reporting

Please don't open a public issue. Use GitHub's private vulnerability
reporting ("Report a vulnerability" on the Security tab), or email
jampanikomal2005@gmail.com. Include the version (`tracestate version`),
steps to reproduce, and what you expected. You'll get a reply within a week.

Only the latest release receives fixes.
