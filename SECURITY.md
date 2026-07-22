# Security Policy

TraceState takes the security of our engine seriously. Because we handle cryptographic ledgers (WORM) and analyze highly sensitive compliance data, any vulnerability in our core logic could compromise an audit.

## Supported Scope

- Vulnerabilities in the core Go CLI (`main.go`, `cmd/`)
- Bugs leading to bypassing the `pkg/worm` cryptographic hash-chain
- Regex injection vulnerabilities in the rules engine
- Dependencies with known High/Critical CVEs

## Out of Scope

- Flaws in intentionally vulnerable target environments (like the `Auditable` repository)
- General configuration issues by the end-user

## Reporting a Problem

If you discover a security vulnerability within TraceState, please DO NOT open a public issue. 
Instead, please send an email directly to the maintainers or use the private GitHub Security Advisory feature.

Include:
- Exact version of TraceState
- Reproduction steps
- Expected versus actual result
