package wordlist

import (
	"sync"
	"testing"

	"github.com/cookiengineer/goaccess/types"
)

func TestDefaults(t *testing.T) {
	credentials := Defaults()
	if len(credentials) < 100 {
		t.Errorf("Defaults() returned %d credentials, expected at least 100", len(credentials))
	}

	for _, credential := range credentials {
		if credential.Username == "" && credential.Password == "" {
			t.Error("Defaults() contains empty credential")
		}
	}
}

func TestPasswords(t *testing.T) {
	passwords := Passwords()
	if len(passwords) < 100 {
		t.Errorf("Passwords() returned %d entries, expected at least 100", len(passwords))
	}

	for _, password := range passwords {
		if password == "" {
			t.Error("Passwords() contains empty string")
		}
	}
}

func TestUsernames(t *testing.T) {
	usernames := Usernames()
	if len(usernames) < 50 {
		t.Errorf("Usernames() returned %d entries, expected at least 50", len(usernames))
	}

	for _, username := range usernames {
		if username == "" {
			t.Error("Usernames() contains empty string")
		}
	}
}

func TestSNMPCommunities(t *testing.T) {
	communities := SNMPCommunities()
	if len(communities) < 10 {
		t.Errorf("SNMPCommunities() returned %d entries, expected at least 10", len(communities))
	}
}

func TestIterator_Sequential(t *testing.T) {
	credentials := []types.Credential{
		{Username: "admin", Password: "admin"},
		{Username: "root", Password: "root"},
		{Username: "user", Password: "pass"},
	}

	iterator := NewIterator(credentials)

	count := 0
	for {
		credential, ok := iterator.Next()
		if !ok {
			break
		}
		count++
		if credential.Username == "" {
			t.Errorf("Unexpected empty username at position %d", count)
		}
	}

	if count != 3 {
		t.Errorf("Iterator yielded %d credentials, expected 3", count)
	}

	_, ok := iterator.Next()
	if ok {
		t.Error("Iterator should be exhausted")
	}
}

func TestIterator_Reset(t *testing.T) {
	credentials := []types.Credential{
		{Username: "first", Password: "pass"},
	}

	iterator := NewIterator(credentials)

	first, ok := iterator.Next()
	if !ok || first.Username != "first" {
		t.Fatal("First Next() failed")
	}

	_, exhausted := iterator.Next()
	if exhausted {
		t.Fatal("Should be exhausted")
	}

	iterator.Reset()

	firstAgain, okAgain := iterator.Next()
	if !okAgain || firstAgain.Username != "first" {
		t.Error("After Reset(), first Next() should return first element again")
	}
}

func TestIterator_Remaining(t *testing.T) {
	credentials := []types.Credential{
		{Username: "a"}, {Username: "b"}, {Username: "c"},
	}

	iterator := NewIterator(credentials)

	if iterator.Remaining() != 3 {
		t.Errorf("Remaining() = %d, want 3", iterator.Remaining())
	}

	iterator.Next()
	if iterator.Remaining() != 2 {
		t.Errorf("Remaining() = %d, want 2", iterator.Remaining())
	}
}

func TestIterator_Concurrent(t *testing.T) {
	credentials := make([]types.Credential, 100)
	for index := range credentials {
		credentials[index] = types.Credential{
			Username: "user",
			Password: "pass",
		}
	}

	iterator := NewIterator(credentials)

	var waitGroup sync.WaitGroup
	results := make(chan int, 10)

	for index := 0; index < 10; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			count := 0
			for {
				_, ok := iterator.Next()
				if !ok {
					break
				}
				count++
			}
			results <- count
		}()
	}
	waitGroup.Wait()
	close(results)

	total := 0
	for count := range results {
		total += count
	}

	if total != 100 {
		t.Errorf("Concurrent iterator consumed %d credentials, expected 100", total)
	}
}

func TestIterator_Empty(t *testing.T) {
	iterator := NewIterator(nil)
	_, ok := iterator.Next()
	if ok {
		t.Error("Empty iterator should return ok=false")
	}
	if iterator.Remaining() != 0 {
		t.Errorf("Empty iterator Remaining() = %d, want 0", iterator.Remaining())
	}
}
