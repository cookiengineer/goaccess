package wordlist

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/cookiengineer/goaccess/types"
)

//go:embed defaults.txt
var defaultsData string

//go:embed passwords.txt
var passwordsData string

//go:embed usernames.txt
var usernamesData string

//go:embed snmp.txt
var snmpData string

// Defaults returns the embedded default credential pairs as user:password strings.
func Defaults() []types.Credential {
	return parseCredentials(defaultsData)
}

// Passwords returns the embedded list of common passwords (no username).
func Passwords() []string {
	return parseLines(passwordsData)
}

// Usernames returns the embedded list of common usernames.
func Usernames() []string {
	return parseLines(usernamesData)
}

// SNMPCommunities returns the embedded list of common SNMP community strings.
func SNMPCommunities() []string {
	return parseLines(snmpData)
}

// parseCredentials splits each non-empty, non-comment line on the first colon.
func parseCredentials(data string) []types.Credential {
	lines := parseLines(data)
	result := make([]types.Credential, 0, len(lines))
	for _, line := range lines {
		credential := types.ParseCredential(line)
		if credential.Username != "" || credential.Password != "" {
			result = append(result, credential)
		}
	}
	return result
}

// parseLines returns non-empty, non-comment lines from the data.
func parseLines(data string) []string {
	raw := strings.Split(data, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// Iterator provides a thread-safe iterator over a slice of Credentials.
// Multiple goroutines can call Next() concurrently without races.
type Iterator struct {
	mutex       sync.Mutex
	credentials []types.Credential
	position    int
}

// NewIterator creates an Iterator from a slice of credentials.
func NewIterator(credentials []types.Credential) *Iterator {
	return &Iterator{
		credentials: credentials,
	}
}

// Next returns the next credential and true, or a zero Credential and false when exhausted.
func (iterator *Iterator) Next() (types.Credential, bool) {
	iterator.mutex.Lock()
	defer iterator.mutex.Unlock()

	if iterator.position >= len(iterator.credentials) {
		return types.Credential{}, false
	}
	credential := iterator.credentials[iterator.position]
	iterator.position++
	return credential, true
}

// Reset restarts iteration from the beginning.
func (iterator *Iterator) Reset() {
	iterator.mutex.Lock()
	defer iterator.mutex.Unlock()
	iterator.position = 0
}

// Remaining returns the number of unread credentials.
func (iterator *Iterator) Remaining() int {
	iterator.mutex.Lock()
	defer iterator.mutex.Unlock()
	return len(iterator.credentials) - iterator.position
}
