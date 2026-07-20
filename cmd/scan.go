package cmd

import (
	"fmt"

	"github.com/jampanikomal/tracestate/pkg/scanner"
	"github.com/jampanikomal/tracestate/pkg/worm"
	"github.com/spf13/cobra"
)

var targetPath string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Initiates a compliance scan against a target directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[*] TraceState PSU Initialized.\n")
		fmt.Printf("[*] Loading ruleset.json...\n")
		fmt.Printf("[*] Deploying Wires to target: %s\n\n", targetPath)

		findings, err := scanner.ScanTarget(targetPath)
		if err != nil {
			return err
		}

		if err := worm.InitializeLedger(); err != nil {
			return err
		}

		for _, finding := range findings {
			if err := worm.LogViolation(finding); err != nil {
				return err
			}
		}

		if len(findings) == 0 {
			fmt.Println("[+] No violations detected.")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&targetPath, "target", "t", "./", "Path to the target infrastructure repository")
	_ = scanCmd.MarkFlagRequired("target")
}
