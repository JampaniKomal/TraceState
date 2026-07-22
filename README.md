# TraceState: Policy-as-Code Compliance Engine

## Project Overview
TraceState is an enterprise-grade enforcement engine for Information Security Management Systems (ISMS). It is a standalone Go binary designed to scan any target infrastructure, evaluate it against a Policy-as-Code JSON ruleset, and permanently log violations to a mathematically secure SQLite WORM (Write-Once-Read-Many) database.

TraceState is completely framework-agnostic. By modifying the `ruleset.json`, auditors can enforce ISO 27001, DPDPA, HIPAA, or custom enterprise policies across any target environment.

## The Architecture

### 1. The PSU (Power Supply Unit - Core Engine)

- `cmd/`: Contains the Cobra CLI framework. This acts as the terminal interface (`tracestate init`, `tracestate scan`, `tracestate ledger verify`).
- `pkg/worm/`: The cryptographic vault. Handles SHA-256 hash chaining and SQLite database triggers to prevent log tampering.
- `ruleset.json`: The dynamic "Brain". Contains the compliance rules.

### 2. The Wires (Scanner Modules)

- `pkg/scanner/`: The modular plugins that physically reach into the target environments.
- **Wire 1 (Infrastructure):** Scans infrastructure configurations (e.g., `docker-compose.yml`, `kubernetes.yaml`) for privileges and secrets.
- **Wire 2 (Telemetry):** Scans physical log files for unmasked PII.
- **Wire 3 (Source Code):** Scans source code for hardcoded secrets and backdoors.
- **Wire 4 (Network):** Scans network and web server configurations for CORS policies and deprecated protocols.
- **Wire 5 (Supply Chain):** Scans SBOMs and package files for vulnerable dependencies.
- **Wire 6 (Database & IAM):** Scans database initialization scripts for weak cryptography and plaintext passwords.

## Quick Start (Development)

1. Initialize the module: `go mod init github.com/jampanikomal/tracestate`
2. Install dependencies: `go get github.com/spf13/cobra` && `go get github.com/mattn/go-sqlite3`
3. Run a test scan: `go run main.go scan --target /path/to/target/infrastructure`
4. Verify the ledger: `go run main.go ledger verify`
5. Export a JSON report: `go run main.go export --format json`
6. Build with Make: `make build`

## License
MIT License. See [LICENSE](LICENSE) for more information.