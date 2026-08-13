package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cookiengineer/goaccess/exploit"
	"github.com/cookiengineer/goaccess/interfaces"
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

var deviceTypeOrder = map[string]int{
	"generic": 0,
	"router":  1,
	"camera":  2,
	"drone":   3,
	"server":  4,
	"misc":    5,
}

func sortExploits(exploits []interfaces.Exploit) {
	sort.SliceStable(exploits, func(i, j int) bool {
		ai, aj := exploits[i].Info(), exploits[j].Info()
		if ai == nil || aj == nil {
			return ai != nil
		}
		typeI := deviceTypeOrder[string(ai.DeviceType)]
		typeJ := deviceTypeOrder[string(aj.DeviceType)]
		if typeI != typeJ {
			return typeI < typeJ
		}
		if ai.Vendor != aj.Vendor {
			return strings.ToLower(ai.Vendor) < strings.ToLower(aj.Vendor)
		}
		if ai.Name != aj.Name {
			return strings.ToLower(ai.Name) < strings.ToLower(aj.Name)
		}
		return exploits[i].Protocol().String() < exploits[j].Protocol().String()
	})
}

func sortCredentials(creds []interfaces.CredentialsModule) {
	sort.SliceStable(creds, func(i, j int) bool {
		ai, aj := creds[i].Info(), creds[j].Info()
		if ai == nil || aj == nil {
			return ai != nil
		}
		typeI := deviceTypeOrder[string(ai.DeviceType)]
		typeJ := deviceTypeOrder[string(aj.DeviceType)]
		if typeI != typeJ {
			return typeI < typeJ
		}
		if ai.Vendor != aj.Vendor {
			return strings.ToLower(ai.Vendor) < strings.ToLower(aj.Vendor)
		}
		return strings.ToLower(ai.Name) < strings.ToLower(aj.Name)
	})
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

	sortExploits(allExploits)

	rep := report.NewReport(*jsonOutput, false, os.Stdout)

	if *jsonOutput {
		type exploitInfo struct {
			Name       string   `json:"name"`
			Vendor     string   `json:"vendor"`
			DeviceType string   `json:"device_type"`
			Protocol   string   `json:"protocol"`
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

	nameWidth, vendorWidth, protoWidth, typeWidth := 0, 0, 0, 0
	for _, e := range allExploits {
		info := e.Info()
		if info == nil {
			continue
		}
		if *deviceType != "" && string(info.DeviceType) != *deviceType {
			continue
		}
		if len(info.Name) > nameWidth {
			nameWidth = len(info.Name)
		}
		if len(info.Vendor) > vendorWidth {
			vendorWidth = len(info.Vendor)
		}
		if len(e.Protocol().String()) > protoWidth {
			protoWidth = len(e.Protocol().String())
		}
		if len(string(info.DeviceType)) > typeWidth {
			typeWidth = len(string(info.DeviceType))
		}
	}

	fmt.Printf("Exploits: %d\n", len(allExploits))
	format := fmt.Sprintf("  %%-%ds | %%-%ds | %%-%ds | %%-%ds\n", typeWidth, vendorWidth, nameWidth, protoWidth)
	for _, e := range allExploits {
		info := e.Info()
		if info != nil {
			if *deviceType != "" && string(info.DeviceType) != *deviceType {
				continue
			}
			fmt.Printf(format,
				info.DeviceType, info.Vendor, info.Name, e.Protocol().String())
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

	sortCredentials(allCreds)

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

	typeWidth, nameWidth, vendorWidth, protoWidth := 0, 0, 0, 0
	for _, c := range allCreds {
		info := c.Info()
		if info == nil {
			continue
		}
		if len(info.Name) > nameWidth {
			nameWidth = len(info.Name)
		}
		if len(info.Vendor) > vendorWidth {
			vendorWidth = len(info.Vendor)
		}
		if len(c.Protocol().String()) > protoWidth {
			protoWidth = len(c.Protocol().String())
		}
		if len(string(info.DeviceType)) > typeWidth {
			typeWidth = len(string(info.DeviceType))
		}
	}

	fmt.Printf("Credentials modules: %d\n", len(allCreds))
	format := fmt.Sprintf("  %%-%ds | %%-%ds | %%-%ds | %%-%ds\n", typeWidth, vendorWidth, nameWidth, protoWidth)
	for _, c := range allCreds {
		info := c.Info()
		if info != nil {
			fmt.Printf(format, info.DeviceType, info.Vendor, info.Name, c.Protocol().String())
		}
	}
}

func listPayloads(arguments []string) {
	flags := flag.NewFlagSet("list-payloads", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	flags.Parse(arguments)

	payloads := payload.List()

	sort.SliceStable(payloads, func(i, j int) bool {
		if payloads[i].Arch != payloads[j].Arch {
			return string(payloads[i].Arch) < string(payloads[j].Arch)
		}
		return string(payloads[i].Handler) < string(payloads[j].Handler)
	})

	if *jsonOutput {
		rep := report.NewReport(true, false, os.Stdout)
		rep.WriteJSON(payloads)
		return
	}

	archWidth, handlerWidth := 0, 0
	for _, p := range payloads {
		if len(p.Arch) > archWidth {
			archWidth = len(p.Arch)
		}
		if len(p.Handler) > handlerWidth {
			handlerWidth = len(p.Handler)
		}
	}

	fmt.Printf("Payloads: %d\n", len(payloads))
	format := fmt.Sprintf("  %%-%ds | %%-%ds | %%s\n", archWidth, handlerWidth)
	for _, p := range payloads {
		fmt.Printf(format, p.Arch, p.Handler, fmt.Sprintf("%d bytes", p.Size))
	}
}

func listKeys(arguments []string) {
	flags := flag.NewFlagSet("list-keys", flag.ExitOnError)
	jsonOutput := flags.Bool("json", false, "Output as JSON")
	flags.Parse(arguments)

	keys := ssh_keys.All()

	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].Vendor != keys[j].Vendor {
			return strings.ToLower(keys[i].Vendor) < strings.ToLower(keys[j].Vendor)
		}
		if keys[i].Model != keys[j].Model {
			return strings.ToLower(keys[i].Model) < strings.ToLower(keys[j].Model)
		}
		return strings.ToLower(keys[i].Username) < strings.ToLower(keys[j].Username)
	})

	if *jsonOutput {
		rep := report.NewReport(true, false, os.Stdout)
		rep.WriteJSON(keys)
		return
	}

	vendorWidth, modelWidth, userWidth, typeWidth := 0, 0, 0, 0
	for _, k := range keys {
		if len(k.Vendor) > vendorWidth {
			vendorWidth = len(k.Vendor)
		}
		if len(k.Model) > modelWidth {
			modelWidth = len(k.Model)
		}
		if len(k.Username) > userWidth {
			userWidth = len(k.Username)
		}
		if len(k.Type) > typeWidth {
			typeWidth = len(k.Type)
		}
	}

	fmt.Printf("SSH keys: %d\n", len(keys))
	format := fmt.Sprintf("  %%-%ds | %%-%ds | %%-%ds | %%-%ds\n", vendorWidth, modelWidth, userWidth, typeWidth)
	for _, k := range keys {
		fmt.Printf(format, k.Vendor, k.Model, k.Username, k.Type)
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

	vendors := make([]string, 0, len(vendorSet))
	for v := range vendorSet {
		vendors = append(vendors, v)
	}
	sort.Strings(vendors)

	if *jsonOutput {
		rep := report.NewReport(true, false, os.Stdout)
		rep.WriteJSON(vendors)
		return
	}

	fmt.Printf("Vendors: %d\n", len(vendors))
	for _, vendor := range vendors {
		fmt.Printf("  %s\n", vendor)
	}
}
