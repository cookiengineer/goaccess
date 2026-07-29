package snmp

import (
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client.Port != 161 {
		t.Errorf("default port = %d, want 161", client.Port)
	}
	if client.Community != "public" {
		t.Errorf("default community = %q, want 'public'", client.Community)
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("default timeout = %v, want 5s", client.Timeout)
	}
}

func TestGet_ConnectionRefused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19992
	client.Timeout = 500 * time.Millisecond

	_, err := client.Get("1.3.6.1.2.1.1.1.0")
	if err == nil {
		t.Error("Expected connection refused error")
	}
}

func TestTestConnect_Unavailable(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19991
	client.Timeout = 500 * time.Millisecond

	available, err := client.TestConnect()
	if err != nil {
		t.Errorf("TestConnect() returned error: %v", err)
	}
	if available {
		t.Error("TestConnect() should return false when SNMP is unavailable")
	}
}
