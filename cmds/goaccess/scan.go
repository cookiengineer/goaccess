package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cookiengineer/goaccess/report"
	"github.com/cookiengineer/goaccess/types"
)

func runScan(arguments []string) {
	flags := flag.NewFlagSet("scan", flag.ExitOnError)
	vendor := flags.String("vendor", "", "Filter exploits by vendor")
	deviceType := flags.String("type", "", "Filter by device type (router, camera, misc)")
	threads := flags.Int("threads", 8, "Number of parallel threads")
	timeoutSeconds := flags.Int("timeout", 8, "Timeout in seconds")
	skipCreds := flags.Bool("skip-creds", false, "Skip credential checks")
	skipExploits := flags.Bool("skip-exploits", false, "Skip exploit checks")
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	verbose := flags.Bool("verbose", false, "Verbose output")

	flags.Parse(arguments)

	target := flags.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		fmt.Fprintln(os.Stderr, "Usage: goaccess scan <target> [flags]")
		os.Exit(1)
	}

	output := report.NewReport(*jsonOutput, *verbose, os.Stdout)

	config := &types.ScanConfig{
		Target:          target,
		Threads:         *threads,
		Timeout:         time.Duration(*timeoutSeconds) * time.Second,
		Verbose:         *verbose,
		VendorFilter:    *vendor,
		TypeFilter:      types.DeviceType(*deviceType),
		SkipCredentials: *skipCreds,
		SkipExploits:    *skipExploits,
	}

	scanner := defaultScanner(config)

	output.Status("Starting scan of %s...", target)
	output.Status("Threads: %d, Timeout: %ds", *threads, *timeoutSeconds)

	resultChannel, err := scanner.Scan(target, config)
	if err != nil {
		output.Error("Scan failed: %s", err)
		os.Exit(1)
	}

	vulnerabilityCount := 0
	credentialCount := 0

	for result := range resultChannel {
		if result.Vulnerability != nil && result.Vulnerability.Confirmed {
			vulnerabilityCount++
			output.PrintScanResult(result)
		}
		if len(result.Credentials) > 0 {
			credentialCount += len(result.Credentials)
			output.PrintScanResult(result)
		}
	}

	fmt.Println()
	output.Success("Scan complete: %d vulnerabilities, %d credentials found", vulnerabilityCount, credentialCount)
	if vulnerabilityCount == 0 && credentialCount == 0 {
		output.Info("No vulnerabilities or default credentials found.")
	}
}
