// Command tracestate scans a codebase against policy-as-code compliance rules
// and records every scan in a tamper-evident audit ledger.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/jampanikomal/tracestate/v2/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=v2.0.0".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Execute(ctx, version, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
