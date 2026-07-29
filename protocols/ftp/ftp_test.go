package ftp

import (
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client.Port != 21 {
		t.Errorf("default port = %d, want 21", client.Port)
	}
	if client.Timeout != 10*time.Second {
		t.Errorf("default timeout = %v, want 10s", client.Timeout)
	}
}

func TestLogin_ConnectionRefused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19994
	client.Timeout = 500 * time.Millisecond

	err := client.Login("admin", "admin")
	if err == nil {
		t.Error("Expected connection refused error")
	}
}

func TestTestConnect_ConnectionRefused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19993
	client.Timeout = 500 * time.Millisecond

	available, err := client.TestConnect()
	if err != nil {
		t.Errorf("TestConnect() returned error: %v", err)
	}
	if available {
		t.Error("TestConnect() should return false when FTP is unavailable")
	}
}

func TestList_NotConnected(t *testing.T) {
	client := NewClient()
	_, err := client.List("/")
	if err == nil {
		t.Error("List() without Login() should return error")
	}
}

func TestRetrieve_NotConnected(t *testing.T) {
	client := NewClient()
	_, err := client.Retrieve("/etc/passwd")
	if err == nil {
		t.Error("Retrieve() without Login() should return error")
	}
}

func TestClose_NilConnection(t *testing.T) {
	client := NewClient()
	err := client.Close()
	if err != nil {
		t.Errorf("Close() on nil connection should not error: %v", err)
	}
}
