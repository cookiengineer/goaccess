package interfaces

import "github.com/cookiengineer/goaccess/types"

// CredentialedExploit extends Exploit for exploits that can extract credentials
// from exploited devices and verify them through login.
type CredentialedExploit interface {
	Exploit

	// Credentials executes the exploit and extracts a credential pair from the device.
	// Returns nil if no credentials can be extracted from this exploit.
	Credentials() (*types.Credential, error)

	// Login verifies that an extracted credential works by authenticating
	// against the device's login endpoint via the appropriate protocol.
	Login(credential types.Credential) error
}
