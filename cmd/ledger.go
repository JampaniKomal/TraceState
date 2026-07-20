package cmd

import (
	"fmt"

	"github.com/jampanikomal/tracestate/pkg/worm"
	"github.com/spf13/cobra"
)

var ledgerCmd = &cobra.Command{
	Use:   "ledger",
	Short: "Ledger operations for the TraceState WORM store",
}

var ledgerVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Cryptographically verify the integrity of the audit logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		ok, err := worm.VerifyLedger()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("ledger integrity check failed")
		}
		fmt.Println("[+] Ledger integrity verified.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ledgerCmd)
	ledgerCmd.AddCommand(ledgerVerifyCmd)
}
