package types

import "time"

// Options holds configurable parameters for an exploit module.
// Default values are set by each exploit and can be overridden by the scanner or CLI.
type Options struct {
	// Target is the IP address or hostname of the device under test.
	Target string

	// Port is the target network port.
	Port int

	// SSL enables TLS for protocols that support it (HTTP, FTP).
	SSL bool

	// Timeout is the connection and read timeout.
	Timeout time.Duration

	// Verbose enables detailed diagnostic output.
	Verbose bool

	// Username is the login username for authenticated exploits.
	Username string

	// Password is the login password for authenticated exploits.
	Password string

	// Filename is the file path for path-traversal or file-read exploits.
	Filename string

	// Defaults is a list of "username:password" credential pairs for brute-force modules.
	Defaults []string

	// LHOST is the attacker's IP for reverse-shell payloads.
	LHOST string

	// LPORT is the attacker's listening port for reverse-shell payloads.
	LPORT int

	// RHOST is the remote host for bind-shell payloads.
	RHOST string

	// RPORT is the remote port for bind-shell payloads.
	RPORT int

	// Payload selects the payload architecture, e.g. "arm", "mipsle".
	Payload string

	// Method selects the payload transfer method: "wget", "echo", or "cmd".
	Method string

	// Location is the writable directory on the target for payload deployment, e.g. "/tmp".
	Location string

	// Extra holds additional module-specific parameters that do not fit the standard fields.
	Extra map[string]interface{}
}

// Clone returns a shallow copy of Options. Extra map values are shared.
func (options *Options) Clone() *Options {
	if options == nil {
		return &Options{}
	}
	clone := *options
	clone.Extra = make(map[string]interface{}, len(options.Extra))
	for key, value := range options.Extra {
		clone.Extra[key] = value
	}
	return &clone
}
