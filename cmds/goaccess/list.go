package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cookiengineer/goaccess/exploit"
	"github.com/cookiengineer/goaccess/payload"
	"github.com/cookiengineer/goaccess/ssh_keys"
)

func runList(arguments []string) {
	if len(arguments) < 1 {
		fmt.Fprintln(os.Stderr, "Error: resource type required")
		fmt.Fprintln(os.Stderr, "Usage: goaccess list <exploits|credentials|payloads|keys|vendors>")
		os.Exit(1)
	}

	resource := arguments[0]
	remaining := arguments[1:]

	switch resource {
	case "exploits":
		listExploits(remaining)
	case "credentials":
		listCredentials(remaining)
	case "payloads":
		listPayloads(remaining)
	case "keys":
		listKeys(remaining)
	case "vendors":
		listVendors(remaining)
	default:
		fmt.Fprintf(os.Stderr, "Unknown resource: %s\n", resource)
		os.Exit(1)
	}
}

func listExploits(arguments []string) {
	flags := flag.NewFlagSet("list-exploits", flag.ExitOnError)
	vendor := flags.String("vendor", "", "Filter by vendor")
	flags.Parse(arguments)

	allExploits := exploit.All()
	if *vendor != "" {
		allExploits = exploit.ByVendor(*vendor)
	}

	fmt.Printf("Exploits: %d\n", len(allExploits))
	for _, e := range allExploits {
		info := e.Info()
		if info != nil {
			fmt.Printf("  %-50s %-12s %-6s %s\n",
				info.Name, info.Vendor, e.Protocol().String(), info.DeviceType)
		}
	}
}

func listCredentials(arguments []string) {
	flags := flag.NewFlagSet("list-creds", flag.ExitOnError)
	vendor := flags.String("vendor", "", "Filter by vendor")
	flags.Parse(arguments)

	allCreds := exploit.AllCredentials()
	if *vendor != "" {
		allCreds = exploit.CredentialsByVendor(*vendor)
	}

	fmt.Printf("Credentials modules: %d\n", len(allCreds))
	for _, c := range allCreds {
		info := c.Info()
		if info != nil {
			fmt.Printf("  %-50s %-12s %s\n", info.Name, info.Vendor, c.Protocol().String())
		}
	}
}

func listPayloads(_ []string) {
	payloads := payload.List()
	fmt.Printf("Payloads: %d\n", len(payloads))
	for _, p := range payloads {
		fmt.Printf("  %-8s %-12s %d bytes\n", p.Arch, p.Handler, p.Size)
	}
}

func listKeys(_ []string) {
	keys := ssh_keys.All()
	fmt.Printf("SSH keys: %d\n", len(keys))
	for _, k := range keys {
		fmt.Printf("  %-20s %-20s %s (%s)\n", k.Vendor, k.Model, k.Username, k.Type)
	}
}

func listVendors(_ []string) {
	vendorSet := make(map[string]bool)
	for _, e := range exploit.All() {
		info := e.Info()
		if info != nil && info.Vendor != "" {
			vendorSet[info.Vendor] = true
		}
	}
	fmt.Printf("Vendors: %d\n", len(vendorSet))
	for vendor := range vendorSet {
		fmt.Printf("  %s\n", vendor)
	}
}
