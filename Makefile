.PHONY: build test clean

build:
	@echo "Building TraceState binary..."
	go build -o bin/tracestate main.go
	@echo "Build complete. Run with ./bin/tracestate"

test:
	@echo "Running cryptographic unit tests..."
	go test ./pkg/worm/... -v

clean:
	@echo "Cleaning up..."
	rm -rf bin/
	rm -f audit_ledger.db tracestate_report.json