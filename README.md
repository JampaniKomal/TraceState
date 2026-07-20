# TraceState: Policy-as-Code Compliance Engine

## Project Overview
TraceState is the central enforcement engine (The PSU) of our dual-repository GRC framework. It is a standalone Go binary designed to scan target infrastructure, evaluate it against a Policy-as-Code JSON ruleset, and permanently log violations to a mathematically secure SQLite WORM (Write-Once-Read-Many) database.

## The Architecture

### 1. The PSU (Power Supply Unit - Core Engine)

- `cmd/`: Contains the Cobra CLI framework. This acts as the terminal interface (`tracestate scan`, `tracestate ledger`).
- `pkg/worm/`: The cryptographic vault. Handles SHA-256 hash chaining and SQLite database triggers to prevent log tampering.
- `ruleset.json`: The dynamic "Brain". Contains the ISO 27001 and DPDPA rules.

### 2. The Wires (Scanner Modules)

- `pkg/scanner/`: The modular plugins that physically reach into the target environments.

- **Wire 1 (Infrastructure):** Scans `docker-compose.yml` for root privileges and hardcoded secrets.
- **Wire 2 (Telemetry):** Scans physical log files for unmasked PII.

## Quick Start (Development)

1. Initialize the module: `go mod init github.com/jampanikomal/tracestate`
2. Install dependencies: `go get github.com/spf13/cobra` && `go get github.com/mattn/go-sqlite3`
3. Run a test scan: `go run main.go scan --target ../Auditable/scenarios/01-fintech-startup`

## Ruleset

```json
{
	"frameworks": ["ISO-27001", "DPDPA-2026"],
	"infrastructure_rules": {
		"allow_root_execution": false,
		"require_volume_encryption": true,
		"forbidden_env_strings": ["password", "secret", "token"]
	},
	"data_rules": {
		"allow_plaintext_pii_in_logs": false
	}
}
```