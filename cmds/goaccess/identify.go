package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cookiengineer/goaccess/report"
)

func runIdentify(arguments []string) {
	flags := flag.NewFlagSet("identify", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	ouiOnly := flags.Bool("oui-only", false, "Only show OUI vendor lookup")
	verbose := flags.Bool("verbose", false, "Verbose output")
	threads := flags.Int("threads", 8, "Number of parallel threads")
	timeoutSeconds := flags.Int("timeout", 8, "Timeout in seconds")

	flags.Parse(arguments)

	target := flags.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		fmt.Fprintln(os.Stderr, "Usage: goaccess identify <target> [flags]")
		os.Exit(1)
	}

	output := report.NewReport(*jsonOutput, *verbose, os.Stdout)

	config := defaultConfig(target)
	config.Threads = *threads
	config.Verbose = *verbose

	scanner := defaultScanner(config)

	output.Status("Identifying %s...", target)

	result, err := scanner.Identify(target, config)
	if err != nil {
		output.Error("Identify failed: %s", err)
		os.Exit(1)
	}

	if *ouiOnly {
		if result.MAC != "" {
			fmt.Printf("MAC: %s\n", result.MAC)
		}
		if result.OUI != "" {
			fmt.Printf("OUI: %s\n", result.OUI)
		}
		return
	}

	output.PrintFingerprint(result)
	_ = timeoutSeconds // used for config
}
