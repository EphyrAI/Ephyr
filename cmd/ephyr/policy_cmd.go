package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/EphyrAI/Ephyr/internal/policy"
	"gopkg.in/yaml.v3"
)

func cmdPolicy(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: ephyr policy <command>")
		fmt.Fprintln(os.Stderr, "  validate   Validate policy configuration")
		os.Exit(1)
	}
	switch args[0] {
	case "validate":
		cmdPolicyValidate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ephyr policy: unknown command %q\n", args[0])
		os.Exit(1)
	}
}

// jsonValidationResult mirrors ValidationResult for JSON output.
type jsonValidationResult struct {
	Section  string `json:"section"`
	Severity string `json:"severity"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message"`
}

// jsonValidationReport mirrors ValidationReport for JSON output.
type jsonValidationReport struct {
	Path     string                 `json:"path"`
	Results  []jsonValidationResult `json:"results"`
	Errors   int                    `json:"errors"`
	Warnings int                    `json:"warnings"`
}

func cmdPolicyValidate(args []string) {
	fs := flag.NewFlagSet("policy-validate", flag.ExitOnError)
	policyPath := fs.String("policy", "/etc/ephyr/policy.yaml", "Policy file path")
	strict := fs.Bool("strict", false, "Treat warnings as errors")
	jsonOutput := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)

	// Read and parse the YAML directly (not via LoadFromFile, which
	// fail-fasts on the first error).
	data, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", *policyPath, err)
		os.Exit(2)
	}

	var cfg policy.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing YAML: %v\n", err)
		os.Exit(2)
	}

	// Apply defaults the same way the loader does.
	ApplyPolicyDefaults(&cfg)

	// Run comprehensive validation.
	rpt := policy.ValidatePolicy(&cfg)

	if *jsonOutput {
		printJSONReport(*policyPath, rpt)
	} else {
		printColorReport(*policyPath, rpt)
	}

	exitCode := rpt.ExitCode()
	if *strict && rpt.Warnings > 0 && exitCode < 2 {
		exitCode = 2
	}
	os.Exit(exitCode)
}

// ApplyPolicyDefaults fills zero-value fields with sensible defaults.
// This mirrors the applyDefaults function in the policy loader.
func ApplyPolicyDefaults(cfg *policy.Config) {
	if cfg.Global.MaxActiveCerts == 0 {
		cfg.Global.MaxActiveCerts = 10
	}
	if cfg.Global.DefaultTTL == "" {
		cfg.Global.DefaultTTL = "5m"
	}
	if cfg.Global.MaxTTL == "" {
		cfg.Global.MaxTTL = "30m"
	}
	if cfg.Global.RateLimit.RequestsPerWindow == 0 {
		cfg.Global.RateLimit.RequestsPerWindow = 10
	}
	if cfg.Global.RateLimit.WindowSeconds == 0 {
		cfg.Global.RateLimit.WindowSeconds = 60
	}
	for name, agent := range cfg.Agents {
		if agent.MaxConcurrentCerts == 0 {
			agent.MaxConcurrentCerts = 3
		}
		cfg.Agents[name] = agent
	}
	for name, target := range cfg.Targets {
		if target.Port == 0 {
			target.Port = 22
		}
		cfg.Targets[name] = target
	}
}

// printColorReport renders the validation results in colorized text.
func printColorReport(path string, rpt *policy.ValidationReport) {
	// ANSI color codes.
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		red    = "\033[31m"
		green  = "\033[32m"
		yellow = "\033[33m"
		cyan   = "\033[36m"
		dim    = "\033[2m"
	)

	fmt.Printf("\n%s=== Policy Validation: %s ===%s\n", bold, path, reset)

	// Group results by section, preserving order.
	type sectionGroup struct {
		name    string
		results []policy.ValidationResult
	}
	seen := make(map[string]int)
	var groups []sectionGroup
	for _, r := range rpt.Results {
		idx, ok := seen[r.Section]
		if !ok {
			idx = len(groups)
			seen[r.Section] = idx
			groups = append(groups, sectionGroup{name: r.Section})
		}
		groups[idx].results = append(groups[idx].results, r)
	}

	for _, g := range groups {
		// Count items (OK results only for the section header count).
		count := 0
		for _, r := range g.results {
			if r.Severity == policy.SeverityOK {
				count++
			}
		}

		header := g.name
		if count > 0 {
			header = fmt.Sprintf("%s (%d)", g.name, count)
		}
		fmt.Printf("\n  %s%s%s\n", cyan, header, reset)

		for _, r := range g.results {
			var tag string
			switch r.Severity {
			case policy.SeverityOK:
				tag = fmt.Sprintf("%s[OK]%s  ", green, reset)
			case policy.SeverityWarn:
				tag = fmt.Sprintf("%s[WARN]%s", yellow, reset)
				if r.Code != "" {
					tag += fmt.Sprintf(" %s(%s)%s", dim, r.Code, reset)
				}
			case policy.SeverityError:
				tag = fmt.Sprintf("%s[ERR]%s ", red, reset)
				if r.Code != "" {
					tag += fmt.Sprintf(" %s(%s)%s", dim, r.Code, reset)
				}
			}
			fmt.Printf("    %s %s\n", tag, r.Message)
		}
	}

	// Summary.
	fmt.Println()
	summaryColor := green
	if rpt.Errors > 0 {
		summaryColor = red
	} else if rpt.Warnings > 0 {
		summaryColor = yellow
	}
	fmt.Printf("  %s%sSummary: %d errors, %d warnings%s\n\n",
		bold, summaryColor, rpt.Errors, rpt.Warnings, reset)
}

// printJSONReport renders the validation results as JSON.
func printJSONReport(path string, rpt *policy.ValidationReport) {
	out := jsonValidationReport{
		Path:     path,
		Results:  make([]jsonValidationResult, len(rpt.Results)),
		Errors:   rpt.Errors,
		Warnings: rpt.Warnings,
	}
	for i, r := range rpt.Results {
		out.Results[i] = jsonValidationResult{
			Section:  r.Section,
			Severity: r.Severity.String(),
			Code:     r.Code,
			Message:  r.Message,
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "error: json encode: %v\n", err)
		os.Exit(2)
	}
}
