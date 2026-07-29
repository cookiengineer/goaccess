package types

import "fmt"

// Credential represents a username and password pair.
type Credential struct {
	Username string
	Password string
}

// String returns the credential in "username:password" format.
func (credential Credential) String() string {
	return fmt.Sprintf("%s:%s", credential.Username, credential.Password)
}

// ParseCredential splits a "username:password" string into a Credential.
// If the string does not contain a colon, Username is set to the entire string and Password is empty.
func ParseCredential(raw string) Credential {
	for index := 0; index < len(raw); index++ {
		if raw[index] == ':' {
			return Credential{
				Username: raw[:index],
				Password: raw[index+1:],
			}
		}
	}
	return Credential{Username: raw}
}
