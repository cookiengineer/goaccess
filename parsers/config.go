package parsers

import (
	"encoding/xml"
	"regexp"
	"strings"
)

// XMLNode represents a lightweight XML element for config file parsing.
type XMLNode struct {
	Name     string            `xml:"-"`
	Text     string            `xml:",chardata"`
	Children []XMLNode         `xml:",any"`
	Attrs    map[string]string `xml:"-"`
}

// ParseXMLConfig parses raw XML bytes and returns a map of tag→value pairs.
func ParseXMLConfig(data []byte) (map[string]string, error) {
	var root struct {
		Elements []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	}

	if err := xml.Unmarshal(data, &root); err != nil {
		// Fallback: use regex for malformed XML
		return ParseXMLRegex(data), nil
	}

	result := make(map[string]string)
	for _, element := range root.Elements {
		name := element.XMLName.Local
		value := strings.TrimSpace(element.Value)
		if value != "" {
			result[name] = value
		}
	}
	return result, nil
}

// ParseXMLRegex extracts tag→value pairs from potentially malformed XML using regex.
func ParseXMLRegex(data []byte) map[string]string {
	result := make(map[string]string)
	content := string(data)

	// Match <tagname>value</tagname> patterns using find-and-verify approach
	tagPattern := regexp.MustCompile(`<(\w+)>([^<]*)</(\w+)>`)
	matches := tagPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) == 4 && match[1] == match[3] {
			result[strings.ToLower(match[1])] = strings.TrimSpace(match[2])
		}
	}

	return result
}

// ParseINIConfig parses INI-style configuration data.
// Handles key=value pairs and [section] headers.
func ParseINIConfig(data []byte) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			continue // section header, skip for flat map
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			result[key] = value
		}
	}

	return result
}

// ParseKeyValueLines parses colon-separated or equals-separated key:value pairs from text.
func ParseKeyValueLines(data []byte) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		separator := ":"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			separator = "="
			parts = strings.SplitN(line, "=", 2)
		}
		if len(parts) == 2 {
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			result[key] = value
		}
		_ = separator
	}
	return result
}

// ExtractPassword attempts to find a password in arbitrary text by looking for
// common patterns like "password:xxx", "pass=xxx", "pwd=xxx", etc.
// Handles both quoted and unquoted values.
func ExtractPassword(data []byte) string {
	content := string(data)
	patterns := []string{
		`(?i)password\s*[:=]\s*"?([^"\n\r]+?)"?\s*(?:\n|$)`,
		`(?i)passwd\s*[:=]\s*"?([^"\n\r]+?)"?\s*(?:\n|$)`,
		`(?i)pass\s*[:=]\s*"?([^"\n\r]+?)"?\s*(?:\n|$)`,
		`(?i)pwd\s*[:=]\s*"?([^"\n\r]+?)"?\s*(?:\n|$)`,
		`(?i)admin_password\s*[:=]\s*"?([^"\n\r]+?)"?\s*(?:\n|$)`,
		`(?i)wpa_passphrase\s*[:=]\s*"?([^"\n\r]+?)"?\s*(?:\n|$)`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindStringSubmatch(content)
		if len(matches) > 1 {
			password := strings.TrimSpace(strings.Trim(matches[1], `"'`))
			if len(password) > 0 && len(password) < 128 {
				return password
			}
		}
	}
	return ""
}

// ExtractUsername attempts to find a username in arbitrary text.
func ExtractUsername(data []byte) string {
	content := string(data)
	patterns := []string{
		`(?i)username\s*[:=]\s*"?([^"\s\n\r]+)"?`,
		`(?i)user\s*[:=]\s*"?([^"\s\n\r]+)"?`,
		`(?i)login\s*[:=]\s*"?([^"\s\n\r]+)"?`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindStringSubmatch(content)
		if len(matches) > 1 {
			username := strings.Trim(matches[1], `"'`)
			if len(username) > 0 && len(username) < 64 {
				return username
			}
		}
	}
	return ""
}

// ExtractCredentialsFromHTML extracts login form fields from HTML.
// Returns username_field_name, password_field_name, action_url.
func ExtractCredentialsFromHTML(data []byte) (userField, passField, actionURL string) {
	content := string(data)

	// Find form action
	actionRegex := regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["']`)
	actionMatch := actionRegex.FindStringSubmatch(content)
	if len(actionMatch) > 1 {
		actionURL = actionMatch[1]
	}

	// Find input fields
	inputRegex := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']*)["'][^>]*>`)
	matches := inputRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			inputLine := match[0]
			if strings.Contains(name, "user") || strings.Contains(name, "login") || strings.Contains(name, "name") {
				if userField == "" {
					userField = match[1]
				}
			}
			if strings.Contains(name, "pass") || strings.Contains(name, "pwd") {
				if passField == "" {
					passField = match[1]
				}
			}
			_ = inputLine
		}
	}

	return
}
