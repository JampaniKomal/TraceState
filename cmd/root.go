package cmd

import (
	"os"

	"github.com/jampanikomal/tracestate/pkg/worm"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tracestate",
	Short: "A dual-mode Policy-as-Code GRC Framework",
	Long: `TraceState is an automated compliance enforcement engine.
It scans infrastructure against ruleset.json and logs violations to an immutable WORM ledger.`,
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initializes the local WORM ledger",
	RunE: func(cmd *cobra.Command, args []string) error {
		return worm.InitializeLedger()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(initCmd)
}
