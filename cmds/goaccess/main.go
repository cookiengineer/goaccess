package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cookiengineer/goaccess/scanner"
	"github.com/cookiengineer/goaccess/types"

	// Trigger exploit registration via init()
	_ "github.com/cookiengineer/goaccess/exploits"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	arguments := os.Args[2:]

	switch command {
	case "identify":
		runIdentify(arguments)
	case "scan":
		runScan(arguments)
	case "access":
		runAccess(arguments)
	case "list":
		runList(arguments)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("GoAccess — IoT Exploitation Framework")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  goaccess identify <target>            Fingerprint target hardware")
	fmt.Println("  goaccess scan <target>                Scan for vulnerabilities")
	fmt.Println("  goaccess access <target>              Active exploitation & access")
	fmt.Println("  goaccess list <resource>              List exploits, creds, payloads, keys")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  goaccess identify 192.168.1.1")
	fmt.Println("  goaccess scan 192.168.1.1 --threads 32")
	fmt.Println("  goaccess access 192.168.1.1 --payload arm")
	fmt.Println("  goaccess list exploits --vendor dlink")
}

func defaultConfig(target string) *types.ScanConfig {
	return &types.ScanConfig{
		Target:  target,
		Threads: 8,
		Timeout: 8 * time.Second,
	}
}

func defaultScanner(config *types.ScanConfig) *scanner.Scanner {
	return scanner.NewScanner(config)
}
