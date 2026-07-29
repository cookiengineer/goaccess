package tcp

import (
	"net"
	"testing"
	"time"
)

func startMockTCPServer(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP server: %v", err)
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

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client.Timeout != 8*time.Second {
		t.Errorf("default timeout = %v, want 8s", client.Timeout)
	}
}

func TestConnect_Success(t *testing.T) {
	address, cleanup := startMockTCPServer(t, func(conn net.Conn) { conn.Close() })
	defer cleanup()

	client := NewClient()
	client.Target, client.Port = parseAddress(address)

	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	if !client.IsConnected() {
		t.Error("IsConnected() should return true after Connect()")
	}

	client.Close()
	if client.IsConnected() {
		t.Error("IsConnected() should return false after Close()")
	}
}

func TestConnect_Refused(t *testing.T) {
	client := NewClient()
	client.Target = "127.0.0.1"
	client.Port = 19998
	client.Timeout = 100 * time.Millisecond

	err := client.Connect()
	if err == nil {
		t.Error("Expected connection refused error")
	}
}

func TestSendRecv(t *testing.T) {
	address, cleanup := startMockTCPServer(t, func(conn net.Conn) {
		buffer := make([]byte, 5)
		conn.Read(buffer)
		conn.Write([]byte("MMcS\x00"))
		conn.Close()
	})
	defer cleanup()

	client := NewClient()
	client.Target, client.Port = parseAddress(address)

	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	defer client.Close()

	err = client.Send([]byte("ABCDE"))
	if err != nil {
		t.Fatalf("Send() failed: %v", err)
	}

	response, err := client.Recv(5)
	if err != nil {
		t.Fatalf("Recv() failed: %v", err)
	}
	if string(response) != "MMcS\x00" {
		t.Errorf("Recv() = %q, want %q", string(response), "MMcS\x00")
	}
}

func TestSend_NotConnected(t *testing.T) {
	client := NewClient()
	err := client.Send([]byte("data"))
	if err == nil {
		t.Error("Send() without Connect() should return error")
	}
}

func TestRecv_NotConnected(t *testing.T) {
	client := NewClient()
	_, err := client.Recv(10)
	if err == nil {
		t.Error("Recv() without Connect() should return error")
	}
}

func TestClose_NilConnection(t *testing.T) {
	client := NewClient()
	err := client.Close()
	if err != nil {
		t.Errorf("Close() on nil connection should not error: %v", err)
	}
}

func parseAddress(address string) (string, int) {
	host, port, _ := net.SplitHostPort(address)
	portNum := 0
	for _, ch := range []byte(port) {
		portNum = portNum*10 + int(ch-'0')
	}
	return host, portNum
}
