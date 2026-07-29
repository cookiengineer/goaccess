package types

// Protocol defines the network protocol used by an exploit module.
type Protocol int

const (
	ProtocolHTTP    Protocol = iota // HTTP (TCP port 80)
	ProtocolHTTPS                   // HTTPS (TCP port 443, TLS)
	ProtocolTCP                     // Raw TCP socket
	ProtocolUDP                     // Raw UDP socket
	ProtocolSSH                     // SSH (TCP port 22)
	ProtocolTelnet                  // Telnet (TCP port 23)
	ProtocolFTP                     // FTP (TCP port 21)
	ProtocolSNMP                    // SNMP (UDP port 161)
)

// String returns the human-readable protocol name.
func (protocol Protocol) String() string {
	switch protocol {
	case ProtocolHTTP:
		return "http"
	case ProtocolHTTPS:
		return "https"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolSSH:
		return "ssh"
	case ProtocolTelnet:
		return "telnet"
	case ProtocolFTP:
		return "ftp"
	case ProtocolSNMP:
		return "snmp"
	default:
		return "unknown"
	}
}

// DefaultPort returns the standard port for the protocol.
func (protocol Protocol) DefaultPort() int {
	switch protocol {
	case ProtocolHTTP:
		return 80
	case ProtocolHTTPS:
		return 443
	case ProtocolSSH:
		return 22
	case ProtocolTelnet:
		return 23
	case ProtocolFTP:
		return 21
	case ProtocolSNMP:
		return 161
	case ProtocolTCP, ProtocolUDP:
		return 0 // No default; must be specified
	default:
		return 0
	}
}
