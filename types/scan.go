package types

import "time"

// ScanConfig specifies the parameters for a scan operation.
type ScanConfig struct {
	// Target is the IP address or hostname to scan.
	Target string

	// Threads is the number of concurrent worker goroutines.
	Threads int

	// Timeout is the per-exploit connection and read timeout.
	Timeout time.Duration

	// Verbose enables detailed output during scanning.
	Verbose bool

	// VendorFilter restricts scanning to exploits for a specific vendor.
	// Empty string means all vendors.
	VendorFilter string

	// TypeFilter restricts scanning to exploits for a specific device type.
	// Empty string means all device types.
	TypeFilter DeviceType

	// SkipCredentials disables credential brute-force checks.
	SkipCredentials bool

	// SkipExploits disables vulnerability checks.
	SkipExploits bool

	// MACAddress is a pre-resolved MAC address for OUI lookup (avoids ARP).
	MACAddress string

	// Payload selects the preferred payload architecture for shell deployment.
	Payload string

	// LPORT is the listening port for reverse shell connections.
	LPORT int
}

// ScanResult is emitted by the scanner for each exploit or credentials module checked.
type ScanResult struct {
	// Exploit is the metadata for the module that produced this result.
	Exploit *Info

	// Vulnerability is the check result; nil if the target is not vulnerable.
	Vulnerability *VulnResult

	// Credentials contains recovered credentials from a credentials module.
	Credentials []*CredsResult

	// Error is any error encountered during the check.
	Error error

	// Module identifies the exploit package path, e.g. "routers/dlink/dir_300_600_rce".
	Module string

	// Timestamp records when the check was performed.
	Timestamp time.Time
}
