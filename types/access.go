package types

import "net"

// AccessStep represents a phase in the access exploitation pipeline.
type AccessStep int

const (
	StepIdentify      AccessStep = iota // Device fingerprinting
	StepCredentials                       // Credential recovery
	StepExploit                          // Active exploitation
	StepShell                            // Shell deployment / access
	StepComplete                         // Access successfully achieved
	StepFailed                           // Access attempt failed
)

// String returns the human-readable step name.
func (step AccessStep) String() string {
	switch step {
	case StepIdentify:
		return "identify"
	case StepCredentials:
		return "credentials"
	case StepExploit:
		return "exploit"
	case StepShell:
		return "shell"
	case StepComplete:
		return "complete"
	case StepFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// AccessResult reports the final outcome of an access attempt.
type AccessResult struct {
	Target      string           // Target IP or hostname
	Vendor      string           // Identified vendor
	Model       string           // Identified model
	Credentials []*CredsResult   // Recovered credentials
	Exploits    []*ExploitResult // Successful exploitation results
	Shell       *ShellSession    // Established shell session, if any
	Steps       []AccessStepLog  // Step-by-step execution log
	Success     bool             // Whether any access was achieved
}

// AccessStepLog records the outcome of a single access pipeline step.
type AccessStepLog struct {
	Step    AccessStep
	Success bool
	Detail  string
	Error   error
}

// ShellSession represents an established interactive connection to a target.
type ShellSession struct {
	// Type describes the connection: "reverse", "bind", "ssh", or "telnet".
	Type string

	// Conn is the underlying network connection (net.Conn is an interface, not required in types/).
	Conn net.Conn

	// Host is the remote host for this session.
	Host string

	// Port is the remote port for this session.
	Port int
}
