package interfaces

import "github.com/cookiengineer/goaccess/types"

// PasswordGenerator produces possible passwords for a given device
// based on known password derivation algorithms.
//
// Many IoT vendors use predictable password generation based on
// the device's MAC address, serial number, or model identifier.
// Implementations of this interface encode those algorithms.
type PasswordGenerator interface {
	// Generate returns credential pairs derived from the device's identifiers.
	//
	// Parameters:
	//   - mac: the device's MAC address, e.g. "00:50:BA:12:34:56"
	//   - serial: the device's serial number, if known (may be empty)
	//   - model: the device model string, e.g. "DIR-300"
	//
	// Returns nil if the generator cannot produce passwords for the given inputs.
	Generate(mac, serial, model string) []types.Credential

	// Name returns a human-readable name for this generator,
	// e.g. "D-Link WPA Default Key Generator".
	Name() string

	// Vendor returns the lowercase vendor identifier this generator applies to.
	Vendor() string
}
