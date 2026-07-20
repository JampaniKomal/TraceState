package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/jampanikomal/tracestate/pkg/worm"
	"github.com/spf13/cobra"
)

var exportFormat string

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the WORM ledger to a report",
	RunE: func(cmd *cobra.Command, args []string) error {
		if exportFormat != "json" {
			return fmt.Errorf("unsupported export format: %s", exportFormat)
		}
		outputPath := filepath.Join(".", "tracestate_report.json")
		if err := worm.ExportLedgerJSON(outputPath); err != nil {
			return err
		}
		fmt.Printf("[SUCCESS] Ledger exported to %s\n", outputPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVar(&exportFormat, "format", "json", "Export format (json)")
}
