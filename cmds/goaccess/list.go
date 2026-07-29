package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cookiengineer/goaccess/exploit"
	"github.com/cookiengineer/goaccess/payload"
	"github.com/cookiengineer/goaccess/report"
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
	deviceType := flags.String("type", "", "Filter by device type")
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	flags.Parse(arguments)

	allExploits := exploit.All()
	if *vendor != "" {
		allExploits = exploit.ByVendor(*vendor)
	}

	rep := report.NewReport(*jsonOutput, false, os.Stdout)

	if *jsonOutput {
		type exploitInfo struct {
			Name       string `json:"name"`
			Vendor     string `json:"vendor"`
			DeviceType string `json:"device_type"`
			Protocol   string `json:"protocol"`
			Models     []string `json:"models"`
			CVE        []string `json:"cve"`
		}
		var list []exploitInfo
		for _, e := range allExploits {
			info := e.Info()
			if info != nil {
				if *deviceType != "" && string(info.DeviceType) != *deviceType {
					continue
				}
				list = append(list, exploitInfo{
					Name: info.Name, Vendor: info.Vendor,
					DeviceType: string(info.DeviceType),
					Protocol:   e.Protocol().String(),
					Models:     info.Models, CVE: info.CVE,
				})
			}
		}
		rep.WriteJSON(list)
		return
	}

	fmt.Printf("Exploits: %d\n", len(allExploits))
	for _, e := range allExploits {
		info := e.Info()
		if info != nil {
			if *deviceType != "" && string(info.DeviceType) != *deviceType {
				continue
			}
			fmt.Printf("  %-50s %-12s %-6s %s\n",
				info.Name, info.Vendor, e.Protocol().String(), info.DeviceType)
		}
	}
}

func listCredentials(arguments []string) {
	flags := flag.NewFlagSet("list-creds", flag.ExitOnError)
	vendor := flags.String("vendor", "", "Filter by vendor")
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	flags.Parse(arguments)

	allCreds := exploit.AllCredentials()
	if *vendor != "" {
		allCreds = exploit.CredentialsByVendor(*vendor)
	}

	rep := report.NewReport(*jsonOutput, false, os.Stdout)

	if *jsonOutput {
		type credsInfo struct {
			Name     string `json:"name"`
			Vendor   string `json:"vendor"`
			Protocol string `json:"protocol"`
		}
		var list []credsInfo
		for _, c := range allCreds {
			info := c.Info()
			if info != nil {
				list = append(list, credsInfo{
					Name: info.Name, Vendor: info.Vendor,
					Protocol: c.Protocol().String(),
				})
			}
		}
		rep.WriteJSON(list)
		return
	}

	fmt.Printf("Credentials modules: %d\n", len(allCreds))
	for _, c := range allCreds {
		info := c.Info()
		if info != nil {
			fmt.Printf("  %-50s %-12s %s\n", info.Name, info.Vendor, c.Protocol().String())
		}
	}
}

func listPayloads(arguments []string) {
	flags := flag.NewFlagSet("list-payloads", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	flags.Parse(arguments)

	payloads := payload.List()

	if *jsonOutput {
		rep := report.NewReport(true, false, os.Stdout)
		rep.WriteJSON(payloads)
		return
	}

	fmt.Printf("Payloads: %d\n", len(payloads))
	for _, p := range payloads {
		fmt.Printf("  %-8s %-12s %d bytes\n", p.Arch, p.Handler, p.Size)
	}
}

func listKeys(arguments []string) {
	flags := flag.NewFlagSet("list-keys", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	flags.Parse(arguments)

	keys := ssh_keys.All()

	if *jsonOutput {
		rep := report.NewReport(true, false, os.Stdout)
		rep.WriteJSON(keys)
		return
	}

	fmt.Printf("SSH keys: %d\n", len(keys))
	for _, k := range keys {
		fmt.Printf("  %-20s %-20s %s (%s)\n", k.Vendor, k.Model, k.Username, k.Type)
	}
}

func listVendors(arguments []string) {
	flags := flag.NewFlagSet("list-vendors", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	flags.Parse(arguments)

	vendorSet := make(map[string]bool)
	for _, e := range exploit.All() {
		info := e.Info()
		if info != nil && info.Vendor != "" {
			vendorSet[info.Vendor] = true
		}
	}

	if *jsonOutput {
		vendors := make([]string, 0, len(vendorSet))
		for v := range vendorSet {
			vendors = append(vendors, v)
		}
		rep := report.NewReport(true, false, os.Stdout)
		rep.WriteJSON(vendors)
		return
	}

	fmt.Printf("Vendors: %d\n", len(vendorSet))
	for vendor := range vendorSet {
		fmt.Printf("  %s\n", vendor)
	}
}
