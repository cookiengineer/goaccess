package types

// DeviceType classifies the kind of IoT device an exploit targets.
type DeviceType string

const (
	DeviceRouter  DeviceType = "router"
	DeviceCamera  DeviceType = "camera"
	DeviceMisc    DeviceType = "misc"
	DeviceGeneric DeviceType = "generic"
)

// Info holds static metadata for an exploit or credentials module.
// Every exploit must provide this through its Info() method.
type Info struct {
	// Name is the human-readable exploit name, e.g. "D-Link DIR-300 RCE".
	Name string

	// Description explains what the exploit does in detail.
	Description string

	// Vendor is the lowercase vendor identifier, e.g. "dlink", "tplink", "cisco".
	Vendor string

	// DeviceType classifies the target device.
	DeviceType DeviceType

	// Models is a list of affected device model strings, e.g. ["DIR-300", "DIR-600"].
	Models []string

	// CVE is the list of CVE identifiers, e.g. ["CVE-2013-XXXX"].
	CVE []string

	// References is a list of URLs pointing to advisories, exploit-db entries, or writeups.
	References []string
}
