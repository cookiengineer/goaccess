package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cookiengineer/goaccess/report"
	"github.com/cookiengineer/goaccess/types"
)

func runAccess(arguments []string) {
	flags := flag.NewFlagSet("access", flag.ExitOnError)
	threads := flags.Int("threads", 8, "Number of parallel threads")
	timeoutSeconds := flags.Int("timeout", 8, "Timeout in seconds")
	payloadArch := flags.String("payload", "", "Preferred payload architecture")
	listenPort := flags.Int("listen", 0, "Listen port for reverse shells")
	noExploit := flags.Bool("no-exploit", false, "Skip exploitation, creds only")
	noCreds := flags.Bool("no-creds", false, "Skip credential checks, exploits only")
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	verbose := flags.Bool("verbose", false, "Verbose output")

	flags.Parse(arguments)

	target := flags.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		fmt.Fprintln(os.Stderr, "Usage: goaccess access <target> [flags]")
		os.Exit(1)
	}

	output := report.NewReport(*jsonOutput, *verbose, os.Stdout)

	config := &types.ScanConfig{
		Target:          target,
		Threads:         *threads,
		Timeout:         time.Duration(*timeoutSeconds) * time.Second,
		Verbose:         *verbose,
		SkipCredentials: *noCreds,
		SkipExploits:    *noExploit,
	}

	scanner := defaultScanner(config)

	output.Status("Starting access attempt on %s...", target)

	result, err := scanner.Access(target, config)
	if err != nil {
		output.Error("Access failed: %s", err)
		os.Exit(1)
	}

	output.PrintAccessResult(result)

	_ = payloadArch
	_ = listenPort
}
