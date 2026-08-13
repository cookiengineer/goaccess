package types

// Fingerprint describes a detection signature used during the identify phase
// to match a target device against a known vendor, model, or firmware version.
type Fingerprint struct {
	// URL is the HTTP path to probe, e.g. "/HNAP1/".
	URL string

	// SSL indicates the probe should be sent over HTTPS (defaults to HTTP).
	SSL bool

	// Method is the HTTP method for the probe request, e.g. "GET", "POST".
	Method string

	// Headers maps expected HTTP response header names to substrings they must contain.
	// Example: {"Server": "DIR-"} matches any Server header containing "DIR-".
	Headers map[string]string

	// Body is a substring expected in the HTTP response body.
	Body string

	// Banner is a substring expected in a raw TCP or UDP service banner.
	Banner string

	// UPnPResponse is a substring expected in the UPnP M-SEARCH response.
	UPnPResponse string

	// SNMPOID is the SNMP OID to query, e.g. "1.3.6.1.2.1.1.1.0" (sysDescr).
	SNMPOID string

	// SNMPValue is a substring expected in the SNMP GET response for SNMPOID.
	SNMPValue string

	// MACPrefixes lists known OUI prefixes for the vendor.
	// Used to match the target via ARP-based MAC address lookup.
	// Format: uppercase hex without separators, e.g. "0050BA", "1CAFF7".
	MACPrefixes []string
}

// FirmwarePattern describes a URL endpoint and regex pattern used to extract
// the firmware version string from a device's HTTP response.
type FirmwarePattern struct {
	// URL is the HTTP path that reveals firmware version info.
	URL string

	// Pattern is the regex pattern to extract the version.
	// The pattern must contain exactly one capture group for the version.
	Pattern string

	// Group is the regex capture group index containing the version (1-based).
	Group int
}
