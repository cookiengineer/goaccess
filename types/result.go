package types

// VulnResult reports the outcome of a vulnerability check.
type VulnResult struct {
	// Confirmed is true when the target is verified vulnerable.
	Confirmed bool

	// Details provides a human-readable description of the vulnerability found.
	Details string

	// RawData holds the raw network response that confirmed the vulnerability.
	RawData []byte
}

// CredsResult reports a successfully recovered credential pair.
type CredsResult struct {
	// Target is the IP address of the device.
	Target string

	// Port is the service port where the credential was found.
	Port int

	// Service is the protocol name, e.g. "telnet", "ssh", "http".
	Service string

	// Protocol is the enumerated protocol constant.
	Protocol Protocol

	// Username is the discovered account name.
	Username string

	// Password is the discovered account password or community string.
	Password string
}

// ExploitResult reports the outcome of an active exploit execution.
type ExploitResult struct {
	// Success indicates whether the exploit achieved its goal.
	Success bool

	// Action describes what the exploit accomplished, e.g. "credentials_dumped", "admin_created", "shell_spawned".
	Action string

	// Output contains the command output or file content extracted from the target.
	Output string

	// Files maps filenames to their raw content for multi-file extraction exploits.
	Files map[string][]byte
}

// FingerprintResult aggregates the results of the device identification phase.
type FingerprintResult struct {
	// IP is the target IP address.
	IP string

	// MAC is the resolved MAC address, if available (same subnet).
	MAC string

	// OUI is the vendor name resolved from the MAC OUI prefix.
	OUI string

	// Vendor is the matched vendor identifier (lowercase).
	Vendor string

	// Model is the best-guess device model string.
	Model string

	// Firmware is the detected firmware version, if available.
	Firmware string

	// Services lists open ports detected on the target.
	Services []int

	// Hints contains human-readable clues gathered during fingerprinting.
	Hints []string

	// Confidence is a score from 0.0 to 1.0 indicating match certainty.
	Confidence float64
}
