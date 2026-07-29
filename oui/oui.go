package oui

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.dat
var databaseContent string

var (
	once           sync.Once
	ouiToVendor    map[string]string // uppercase MAC prefix (6 hex chars) → vendor name
	vendorToPrefix map[string][]string
)

func init() {
	ensureParsed()
}

func ensureParsed() {
	once.Do(parseDatabase)
}

func parseDatabase() {
	ouiToVendor = make(map[string]string)
	vendorToPrefix = make(map[string][]string)

	lines := strings.Split(databaseContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}

		macPrefix := strings.ToUpper(strings.TrimSpace(parts[0]))
		vendorName := strings.TrimSpace(parts[1])

		if len(macPrefix) < 6 {
			continue
		}

		ouiToVendor[macPrefix] = vendorName
		vendorToPrefix[vendorName] = append(vendorToPrefix[vendorName], macPrefix)
	}
}

// Lookup resolves a MAC address to a vendor name.
// The MAC address may contain colons, dashes, or dots as separators.
// Returns an empty string if no match is found.
func Lookup(mac string) string {
	ensureParsed()

	clean := cleanMAC(mac)
	if len(clean) < 6 {
		return ""
	}

	return ouiToVendor[clean[:6]]
}

// LookupPrefixes returns all known OUI prefixes for the given vendor.
// The search is case-sensitive substring match.
func LookupPrefixes(vendor string) []string {
	ensureParsed()

	var result []string
	for name, prefixes := range vendorToPrefix {
		if strings.Contains(strings.ToLower(name), strings.ToLower(vendor)) {
			result = append(result, prefixes...)
		}
	}
	return result
}

// VendorCount returns the number of unique vendors in the OUI database.
func VendorCount() int {
	ensureParsed()
	return len(vendorToPrefix)
}

// cleanMAC removes separators and uppercases the MAC address.
func cleanMAC(mac string) string {
	var builder strings.Builder
	builder.Grow(len(mac))
	for _, char := range mac {
		if char == ':' || char == '-' || char == '.' || char == ' ' {
			continue
		}
		if char >= 'a' && char <= 'f' {
			char -= 32 // uppercase
		}
		builder.WriteRune(char)
	}
	return builder.String()
}
