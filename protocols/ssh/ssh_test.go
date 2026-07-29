package ssh

import (
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client.Port != 22 {
		t.Errorf("default port = %d, want 22", client.Port)
	}
	if client.Timeout != 8*time.Second {
		t.Errorf("default timeout = %v, want 8s", client.Timeout)
	}
}

func TestLogin_ConnectionRefused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19997
	client.Timeout = 100 * time.Millisecond

	err := client.Login("root", "password")
	if err == nil {
		t.Error("Expected connection refused error")
	}
}

func TestTestConnect_ConnectionRefused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19996
	client.Timeout = 100 * time.Millisecond

	available, err := client.TestConnect()
	if err != nil {
		t.Errorf("TestConnect() returned error: %v", err)
	}
	if available {
		t.Error("TestConnect() should return false when SSH is unavailable")
	}
}

func TestExecute_NotConnected(t *testing.T) {
	client := NewClient()
	_, err := client.Execute("ls")
	if err == nil {
		t.Error("Execute() without connection should return error")
	}
}

func TestClose_NilConnection(t *testing.T) {
	client := NewClient()
	err := client.Close()
	if err != nil {
		t.Errorf("Close() on nil connection should not error: %v", err)
	}
}
