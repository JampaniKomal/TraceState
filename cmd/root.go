package cmd

import (
	"fmt"
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

var verifyLedgerCmd = &cobra.Command{
	Use:   "verify-ledger",
	Short: "Verifies the integrity of the local WORM ledger",
	RunE: func(cmd *cobra.Command, args []string) error {
		ok, err := worm.VerifyLedger()
		if err != nil {
			return err
		}
		if ok {
			fmt.Println("[+] Ledger integrity verified.")
			return nil
		}
		return fmt.Errorf("ledger integrity check failed")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(verifyLedgerCmd)
}
