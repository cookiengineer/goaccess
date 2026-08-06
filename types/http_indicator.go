package types

// HTTPIndicator defines patterns to match against a router's HTTP welcome page
// or other HTTP-accessible resource during the identify phase.
//
// All populated field groups must match for the indicator to fire (AND across fields).
// Within each field group:
//   - Headers: ALL entries must contain their substring (AND)
//   - HeaderContent: ANY substring must appear in the concatenated header string (OR)
//   - Title: ANY substring must match (OR)
//   - Content: ALL substrings must be present in the response body (AND)
//   - TitleRegex: ANY regex must match (OR)
//   - ContentRegex: ANY regex must match (OR)
//   - MD5: exact body/favicon hash match
//
// Fields left at their zero value (nil slice / empty map / empty string) are skipped.
type HTTPIndicator struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Path    string `json:"path"`

	Headers       map[string]string `json:"headers,omitempty"`
	HeaderContent []string          `json:"header_content,omitempty"`
	Title         []string          `json:"title,omitempty"`
	Content       []string          `json:"content,omitempty"`
	TitleRegex    []string          `json:"title_regex,omitempty"`
	ContentRegex  []string          `json:"content_regex,omitempty"`
	MD5           string            `json:"md5,omitempty"`

	// FirmwareRegex is an optional regex pattern to extract the firmware version
	// from the HTTP response body when this indicator matches.
	// Must contain exactly one capture group for the version string.
	FirmwareRegex string `json:"firmware_regex,omitempty"`

	// FirmwareGroup is the capture group index (1-based) in FirmwareRegex
	// that contains the firmware version. Defaults to 1.
	FirmwareGroup int `json:"firmware_group,omitempty"`
}
