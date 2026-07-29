package telnet

import (
	"net"
	"testing"
	"time"
)

func startMockTelnetServer(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock Telnet server: %v", err)
	}

	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		handler(connection)
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

func parseAddress(address string) (string, int) {
	host, port, _ := net.SplitHostPort(address)
	portNum := 0
	for _, ch := range []byte(port) {
		portNum = portNum*10 + int(ch-'0')
	}
	return host, portNum
}

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client.Port != 23 {
		t.Errorf("default port = %d, want 23", client.Port)
	}
}

func TestTestConnect(t *testing.T) {
	address, cleanup := startMockTelnetServer(t, func(conn net.Conn) {
		conn.Write([]byte("Login: "))
		conn.Close()
	})
	defer cleanup()

	host, port := parseAddress(address)

	client := NewClient()
	client.Target = host
	client.Port = port
	client.Timeout = 2 * time.Second

	available, err := client.TestConnect()
	if err != nil {
		t.Fatalf("TestConnect() error: %v", err)
	}
	if !available {
		t.Error("TestConnect() should return true for available Telnet service")
	}
}

func TestLogin_Success(t *testing.T) {
	address, cleanup := startMockTelnetServer(t, func(conn net.Conn) {
		buffer := make([]byte, 256)

		// Send login prompt
		conn.Write([]byte("Router login: "))

		// Read username
		conn.Read(buffer)

		// Send password prompt
		conn.Write([]byte("Password: "))

		// Read password
		conn.Read(buffer)

		// Send prompt indicating success
		conn.Write([]byte("Welcome!\r\n# "))
		conn.Close()
	})
	defer cleanup()

	host, port := parseAddress(address)

	client := NewClient()
	client.Target = host
	client.Port = port
	client.Timeout = 2 * time.Second

	success := client.Login("admin", "admin")
	if !success {
		t.Error("Login() should succeed with valid credentials")
	}
}

func TestLogin_Failure(t *testing.T) {
	address, cleanup := startMockTelnetServer(t, func(conn net.Conn) {
		buffer := make([]byte, 256)

		conn.Write([]byte("Login: "))
		conn.Read(buffer)

		conn.Write([]byte("Password: "))
		conn.Read(buffer)

		conn.Write([]byte("Login incorrect\r\n"))
		conn.Close()
	})
	defer cleanup()

	host, port := parseAddress(address)

	client := NewClient()
	client.Target = host
	client.Port = port
	client.Timeout = 2 * time.Second

	success := client.Login("admin", "wrong")
	if success {
		t.Error("Login() should fail with invalid credentials")
	}
}

func TestConnect_Refused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19995
	client.Timeout = 100 * time.Millisecond

	err := client.Connect()
	if err == nil {
		t.Error("Expected connection refused error")
	}
}
