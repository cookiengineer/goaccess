package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cookiengineer/goaccess/oui"
	"github.com/cookiengineer/goaccess/report"
)

func runIdentify(arguments []string) {
	flags := flag.NewFlagSet("identify", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	ouiOnly := flags.Bool("oui-only", false, "Only show OUI vendor lookup")
	verbose := flags.Bool("verbose", false, "Verbose output")
	threads := flags.Int("threads", 8, "Number of parallel threads")
	timeoutSeconds := flags.Int("timeout", 8, "Timeout in seconds")
	outputFile := flags.String("output", "", "Write JSON output to file")

	flags.Parse(arguments)

	target := flags.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		fmt.Fprintln(os.Stderr, "Usage: goaccess identify <target> [flags]")
		os.Exit(1)
	}

	outputWriter := os.Stdout
	if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create output file: %s\n", err)
			os.Exit(1)
		}
		defer file.Close()
		outputWriter = file
	}

	output := report.NewReport(*jsonOutput, *verbose, outputWriter)

	config := defaultConfig(target)
	config.Threads = *threads
	config.Verbose = *verbose
	config.Timeout = time.Duration(*timeoutSeconds) * time.Second
	config.ProgressWriter = os.Stderr

	if *ouiOnly {
		macAddress := config.MACAddress
		vendor := oui.Lookup(macAddress)
		if macAddress != "" {
			fmt.Printf("MAC: %s\n", macAddress)
		}
		fmt.Printf("OUI: %s\n", vendor)
		return
	}

	scanEngine := defaultScanner(config)

	result, err := scanEngine.Identify(target, config)
	if err != nil {
		output.Error("Identify failed: %s", err)
		os.Exit(1)
	}

	output.PrintFingerprint(result)
}
