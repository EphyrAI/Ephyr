package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ben-spanswick/ephyr/internal/macaroon"
)

// inspectJSON mirrors the output structure for --json mode.
type inspectJSON struct {
	RootTaskID        string                    `json:"root_task_id"`
	Location          string                    `json:"location"`
	CaveatCount       int                       `json:"caveat_count"`
	Caveats           []string                  `json:"caveats"`
	EffectiveEnvelope *inspectEnvelopeJSON      `json:"effective_envelope,omitempty"`
	Metadata          *inspectMetadataJSON      `json:"metadata,omitempty"`
	ReducerError      string                    `json:"reducer_error,omitempty"`
	TokenSizeBytes    int                       `json:"token_size_bytes"`
	HolderBinding     *inspectHolderBindingJSON `json:"holder_binding"`
}

type inspectHolderBindingJSON struct {
	Note string `json:"note"`
}

type inspectEnvelopeJSON struct {
	Targets         []string `json:"targets"`
	Roles           []string `json:"roles"`
	Services        []string `json:"services"`
	Remotes         []string `json:"remotes"`
	Methods         []string `json:"methods"`
	CanDelegate     bool     `json:"can_delegate"`
	DelegationDepth int      `json:"delegation_depth"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
}

type inspectMetadataJSON struct {
	Agent       string `json:"agent"`
	InitiatedBy string `json:"initiated_by"`
}

// cmdInspect handles: ephyr inspect [--token TOKEN | --json] [TOKEN]
//
// Decodes a macaroon token WITHOUT verifying the HMAC chain (no root key
// needed) and displays its caveats, effective envelope, and metadata.
func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "Macaroon token string")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")
	_ = fs.Parse(args)

	tokenStr := resolveToken(*tokenFlag, fs.Args())

	if tokenStr == "" {
		fmt.Fprintln(os.Stderr, "error: no token provided")
		fmt.Fprintln(os.Stderr, "Usage: ephyr inspect [--token TOKEN | --json] [TOKEN]")
		fmt.Fprintln(os.Stderr, "       echo TOKEN | ephyr inspect")
		os.Exit(1)
	}

	// Strip "mac_" prefix if present.
	tokenStr = strings.TrimPrefix(tokenStr, "mac_")

	// Decode base64url (no padding).
	data, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid base64url encoding: %v\n", err)
		os.Exit(1)
	}

	// Unmarshal (no verification — inspection only).
	var mac macaroon.Macaroon
	if err := mac.UnmarshalBinary(data); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to decode macaroon: %v\n", err)
		os.Exit(1)
	}

	// Build caveat strings for the reducer.
	caveatStrs := make([]string, len(mac.Caveats()))
	for i, c := range mac.Caveats() {
		caveatStrs[i] = string(c)
	}

	// Run the reducer to get the effective envelope.
	result, reduceErr := macaroon.Reduce(caveatStrs)

	if *jsonFlag {
		printInspectJSON(&mac, data, caveatStrs, result, reduceErr)
	} else {
		printInspectText(&mac, data, caveatStrs, result, reduceErr)
	}
}

// resolveToken determines the token string from flag, positional arg, or stdin.
func resolveToken(tokenFlag string, positional []string) string {
	// 1. --token flag
	if tokenFlag != "" {
		return tokenFlag
	}

	// 2. First positional argument
	if len(positional) > 0 {
		return positional[0]
	}

	// 3. stdin (only if piped, not a terminal)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			return strings.TrimSpace(scanner.Text())
		}
	}

	return ""
}

// printInspectText writes the human-readable inspection output.
func printInspectText(mac *macaroon.Macaroon, data []byte, caveatStrs []string, result *macaroon.ReducerOutput, reduceErr error) {
	fmt.Printf("Root Task ID:  %s\n", string(mac.Id()))
	fmt.Printf("Location:      %s\n", mac.Location())
	fmt.Printf("Caveats:       %d\n", len(mac.Caveats()))

	// Display raw caveats.
	fmt.Println("\n--- Caveats ---")
	for i, c := range caveatStrs {
		fmt.Printf("  [%d] %s\n", i+1, c)
	}

	// Display effective envelope from reducer.
	if reduceErr != nil {
		fmt.Printf("\nReducer error: %v\n", reduceErr)
	} else {
		fmt.Println("\n--- Effective Envelope ---")
		fmt.Printf("  Targets:          %s\n", fmtList(result.Envelope.Targets))
		fmt.Printf("  Roles:            %s\n", fmtList(result.Envelope.Roles))
		fmt.Printf("  Services:         %s\n", fmtList(result.Envelope.Services))
		fmt.Printf("  Remotes:          %s\n", fmtList(result.Envelope.Remotes))
		fmt.Printf("  Methods:          %s\n", fmtList(result.Envelope.Methods))
		fmt.Printf("  Can Delegate:     %v\n", result.Envelope.CanDelegate)
		fmt.Printf("  Delegation Depth: %d\n", result.Envelope.DelegationDepth)
		if !result.Envelope.ExpiresAt.IsZero() {
			fmt.Printf("  Expires At:       %s\n", result.Envelope.ExpiresAt.Format(time.RFC3339))
		} else {
			fmt.Printf("  Expires At:       (none)\n")
		}

		fmt.Println("\n--- Metadata ---")
		fmt.Printf("  Agent:        %s\n", fmtOrNone(result.Metadata.Agent))
		fmt.Printf("  Initiated By: %s\n", fmtOrNone(result.Metadata.InitiatedBy))
	}

	// Token size info.
	fmt.Printf("\n--- Token ---")
	fmt.Printf("\n  Size:    %d bytes", len(data))
	if len(data) > macaroon.TokenSizeWarn {
		fmt.Printf(" (WARNING: exceeds %d byte threshold)", macaroon.TokenSizeWarn)
	}
	fmt.Println()

	// Holder binding info.
	fmt.Println("\n--- Holder Binding ---")
	fmt.Println("  Note: Binding status is broker-side state, not encoded in the macaroon.")
	fmt.Println("        Use task_info to check holder_bound status.")
}

// printInspectJSON writes the machine-readable JSON inspection output.
func printInspectJSON(mac *macaroon.Macaroon, data []byte, caveatStrs []string, result *macaroon.ReducerOutput, reduceErr error) {
	out := inspectJSON{
		RootTaskID:     string(mac.Id()),
		Location:       mac.Location(),
		CaveatCount:    len(mac.Caveats()),
		Caveats:        caveatStrs,
		TokenSizeBytes: len(data),
		HolderBinding: &inspectHolderBindingJSON{
			Note: "Binding status is broker-side state. Use task_info to check.",
		},
	}

	if reduceErr != nil {
		out.ReducerError = reduceErr.Error()
	} else {
		expiresStr := ""
		if !result.Envelope.ExpiresAt.IsZero() {
			expiresStr = result.Envelope.ExpiresAt.Format(time.RFC3339)
		}
		out.EffectiveEnvelope = &inspectEnvelopeJSON{
			Targets:         nonNilSlice(result.Envelope.Targets),
			Roles:           nonNilSlice(result.Envelope.Roles),
			Services:        nonNilSlice(result.Envelope.Services),
			Remotes:         nonNilSlice(result.Envelope.Remotes),
			Methods:         nonNilSlice(result.Envelope.Methods),
			CanDelegate:     result.Envelope.CanDelegate,
			DelegationDepth: result.Envelope.DelegationDepth,
			ExpiresAt:       expiresStr,
		}
		out.Metadata = &inspectMetadataJSON{
			Agent:       result.Metadata.Agent,
			InitiatedBy: result.Metadata.InitiatedBy,
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "error: json encode: %v\n", err)
		os.Exit(1)
	}
}

// fmtList formats a string slice for display, returning "(none)" if empty.
func fmtList(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

// fmtOrNone returns the string or "(none)" if empty.
func fmtOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// nonNilSlice ensures a nil slice is marshalled as [] rather than null.
func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
