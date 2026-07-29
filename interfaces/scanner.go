package interfaces

import "github.com/cookiengineer/goaccess/types"

// Scanner defines the high-level scanning and access interface.
// The concrete implementation in package scanner provides the full engine.
type Scanner interface {
	// Identify fingerprints a target device and returns the detected vendor, model, firmware, and services.
	// This is the implementation of the "identify" CLI action.
	Identify(target string, config *types.ScanConfig) (*types.FingerprintResult, error)

	// Scan runs vulnerability checks and credential brute-force against a target.
	// Results are streamed through the returned channel as each check completes.
	// The channel is closed when scanning finishes.
	//
	// This is the implementation of the "scan" CLI action.
	Scan(target string, config *types.ScanConfig) (<-chan *types.ScanResult, error)

	// Access actively exploits a target to gain access (shell or credentials).
	// Returns the final access result on completion.
	//
	// This is the implementation of the "access" CLI action.
	Access(target string, config *types.ScanConfig) (*types.AccessResult, error)
}
