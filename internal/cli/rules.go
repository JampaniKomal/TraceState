package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jampanikomal/tracestate/v2/pkg/policy"
	"github.com/jampanikomal/tracestate/v2/pkg/scanner"
)

// ruleSource holds the flags shared by commands that load a rule set.
type ruleSource struct {
	rules      []string
	noDefaults bool
}

func (s *ruleSource) register(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&s.rules, "rules", "r", nil, "additional rule file (YAML or JSON); repeatable")
	cmd.Flags().BoolVar(&s.noDefaults, "no-default-rules", false, "don't load the built-in rule pack")
}

func (s *ruleSource) load() (*policy.RuleSet, error) {
	rs, err := policy.Load(!s.noDefaults, s.rules...)
	if err != nil {
		return nil, usageErr(err)
	}
	if err := rs.Validate(scanner.KnownChecks()); err != nil {
		return nil, usageErr(err)
	}
	return rs, nil
}

func (a *app) rulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List, inspect, validate and export rules",
	}
	cmd.AddCommand(a.rulesListCmd(), a.rulesShowCmd(), a.rulesValidateCmd(), a.rulesExportCmd(), a.rulesChecksCmd())
	return cmd
}

func (a *app) rulesListCmd() *cobra.Command {
	var src ruleSource
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the rules a scan would run",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rs, err := src.load()
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return writeJSON(a.stdout, rs.Rules)
			case "markdown", "md":
				return rulesMarkdown(a.stdout, rs.Rules)
			case "table":
				tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tSEVERITY\tCHECK\tFRAMEWORKS\tTITLE")
				for _, r := range rs.Rules {
					fws := make([]string, 0, len(r.Frameworks))
					for fw := range r.Frameworks {
						fws = append(fws, fw)
					}
					sort.Strings(fws)
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Check, strings.Join(fws, ","), r.Title)
				}
				if err := tw.Flush(); err != nil {
					return err
				}
				a.note("%d rules from %s (sha256:%s)", len(rs.Rules), strings.Join(rs.Sources, ", "), shortID(rs.SHA256))
				return nil
			}
			return usageErr(fmt.Errorf("unknown format %q (want table, markdown or json)", format))
		},
	}
	src.register(cmd)
	cmd.Flags().StringVarP(&format, "format", "f", "table", "table, markdown or json")
	return cmd
}

func (a *app) rulesShowCmd() *cobra.Command {
	var src ruleSource
	cmd := &cobra.Command{
		Use:   "show RULE-ID",
		Short: "Show everything about one rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rs, err := src.load()
			if err != nil {
				return err
			}
			for _, r := range rs.Rules {
				if strings.EqualFold(r.ID, args[0]) {
					a.printRule(r)
					return nil
				}
			}
			return usageErr(fmt.Errorf("no rule %q (see `tracestate rules list`)", args[0]))
		},
	}
	src.register(cmd)
	return cmd
}

func (a *app) printRule(r policy.Rule) {
	w := a.stdout
	fmt.Fprintf(w, "%s  %s\n\n", r.ID, r.Title)
	field := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "  %-12s %s\n", k, v)
		}
	}
	field("severity", r.Severity.String())
	field("check", r.Check)
	field("files", strings.Join(r.Files, ", "))
	field("exclude", strings.Join(r.Exclude, ", "))
	field("pattern", r.Pattern)
	if r.Online {
		field("online", "yes (needs --online)")
	}
	if r.Description != "" {
		fmt.Fprintf(w, "\n  %s\n", r.Description)
	}
	if refs := r.Controls(); len(refs) > 0 {
		fmt.Fprintln(w, "\n  Controls")
		for _, c := range refs {
			title := c.Title
			if title == "" {
				title = "-"
			}
			fmt.Fprintf(w, "    %-11s %-16s %s\n", c.Framework, c.Control, title)
		}
	}
	if r.Remediation != "" {
		fmt.Fprintf(w, "\n  Remediation\n    %s\n", r.Remediation)
	}
	if len(r.References) > 0 {
		fmt.Fprintln(w, "\n  References")
		for _, ref := range r.References {
			fmt.Fprintf(w, "    %s\n", ref)
		}
	}
}

func (a *app) rulesValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [FILE...]",
		Short: "Check rule files for errors (the built-in pack if no files are given)",
		Long: `Validate parses each rule file on its own and checks every rule: required
fields, known checks, valid globs, compilable patterns and duplicate IDs.
It exits 1 if any file is invalid, so it can guard rule changes in CI.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			known := scanner.KnownChecks()
			if len(args) == 0 {
				rs, err := policy.DefaultRules()
				if err == nil {
					err = rs.Validate(known)
				}
				return a.reportValidation(policy.DefaultRulesName, rs, err)
			}
			bad := false
			for _, path := range args {
				rs, err := policy.Load(false, path)
				if err == nil {
					err = rs.Validate(known)
				}
				if a.reportValidation(path, rs, err) != nil {
					bad = true
				}
			}
			if bad {
				return fail()
			}
			return nil
		},
	}
}

func (a *app) reportValidation(name string, rs *policy.RuleSet, err error) error {
	if err != nil {
		fmt.Fprintf(a.stdout, "FAIL  %s\n      %s\n", name, strings.ReplaceAll(err.Error(), "\n", "\n      "))
		return fail()
	}
	fmt.Fprintf(a.stdout, "ok    %s (%d rules)\n", name, len(rs.Rules))
	return nil
}

func (a *app) rulesExportCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the built-in rule pack as YAML, as a starting point for your own",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w, closeFn, err := a.output(out)
			if err != nil {
				return err
			}
			if _, err := w.Write(policy.DefaultRulesYAML()); err != nil {
				_ = closeFn()
				return err
			}
			return closeFn()
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "write to this file instead of stdout")
	return cmd
}

func (a *app) rulesChecksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "checks",
		Short: "List the checks rules can use, grouped by the wire that implements them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, w := range scanner.Wires() {
				checks := append([]string(nil), w.Checks()...)
				sort.Strings(checks)
				fmt.Fprintf(a.stdout, "%s\n", w.Name())
				for _, c := range checks {
					fmt.Fprintf(a.stdout, "  %s\n", c)
				}
			}
			return nil
		},
	}
}

func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// rulesMarkdown writes the rules as a Markdown table, one row per rule, with
// its controls grouped by framework. docs/RULES.md embeds this table.
func rulesMarkdown(w io.Writer, rules []policy.Rule) error {
	var b strings.Builder
	b.WriteString("| ID | Severity | Rule | Check | Controls |\n|---|---|---|---|---|\n")
	for _, r := range rules {
		var groups []string
		refs := r.Controls()
		for i := 0; i < len(refs); {
			j := i
			var ids []string
			for ; j < len(refs) && refs[j].Framework == refs[i].Framework; j++ {
				ids = append(ids, refs[j].Control)
			}
			if refs[i].Framework == "CWE" {
				groups = append(groups, strings.Join(ids, ", ")) // the IDs already say CWE
			} else {
				groups = append(groups, refs[i].Framework+" "+strings.Join(ids, ", "))
			}
			i = j
		}
		title := r.Title
		if r.Online {
			title += " (needs `--online`)"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` | %s |\n",
			r.ID, r.Severity, mdCell(title), r.Check, mdCell(strings.Join(groups, "; ")))
	}
	_, err := io.WriteString(w, b.String())
	return err
}
