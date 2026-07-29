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
	outputFile := flags.String("output", "", "Write JSON output to file")
	verbose := flags.Bool("verbose", false, "Verbose output")

	flags.Parse(arguments)

	target := flags.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		fmt.Fprintln(os.Stderr, "Usage: goaccess scan <target> [flags]")
		os.Exit(1)
	}

	outputWriter := os.Stdout
	if *outputFile != "" && !*jsonOutput {
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create output file: %s\n", err)
			os.Exit(1)
		}
		defer file.Close()
		outputWriter = file
	}

	output := report.NewReport(*jsonOutput, *verbose, outputWriter)

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

	scanEngine := defaultScanner(config)

	output.Status("Starting scan of %s...", target)
	output.Status("Threads: %d, Timeout: %ds", *threads, *timeoutSeconds)
	if *vendor != "" {
		output.Status("Vendor filter: %s", *vendor)
	}
	if *deviceType != "" {
		output.Status("Type filter: %s", *deviceType)
	}

	resultChannel, err := scanEngine.Scan(target, config)
	if err != nil {
		output.Error("Scan failed: %s", err)
		os.Exit(1)
	}

	vulnerabilityCount := 0
	credentialCount := 0
	resultCount := 0
	var allResults []*types.ScanResult

	for result := range resultChannel {
		resultCount++

		if result.Vulnerability != nil && result.Vulnerability.Confirmed {
			vulnerabilityCount++
			if !*jsonOutput {
				output.PrintScanResult(result)
			}
		}
		if len(result.Credentials) > 0 {
			credentialCount += len(result.Credentials)
			if !*jsonOutput {
				output.PrintScanResult(result)
			}
		}
		if *jsonOutput {
			output.PrintScanResult(result)
			allResults = append(allResults, result)
		}

		if !*jsonOutput && resultCount%10 == 0 {
			fmt.Fprintf(os.Stderr, "\r[*] Progress: %d checks, %d vulns, %d creds",
				resultCount, vulnerabilityCount, credentialCount)
		}
	}
	if !*jsonOutput && resultCount > 0 {
		fmt.Fprintf(os.Stderr, "\r[*] Progress: %d checks, %d vulns, %d creds\n",
			resultCount, vulnerabilityCount, credentialCount)
	}

	if *jsonOutput {
		if *outputFile != "" {
			file, err := os.Create(*outputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot create output file: %s\n", err)
				os.Exit(1)
			}
			defer file.Close()
			jsonRep := report.NewReport(true, false, file)
			jsonRep.PrintScanResultsJSON(allResults)
		}
	} else if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create output file: %s\n", err)
			os.Exit(1)
		}
		defer file.Close()
		jsonRep := report.NewReport(true, false, file)
		jsonRep.PrintScanResultsJSON(allResults)
	}

	if !*jsonOutput {
		fmt.Fprintln(outputWriter)
		output.Success("Scan complete: %d vulnerabilities, %d credentials found", vulnerabilityCount, credentialCount)
	}
	if vulnerabilityCount == 0 && credentialCount == 0 {
		output.Info("No vulnerabilities or default credentials found.")
	}
}
