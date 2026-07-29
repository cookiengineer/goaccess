package udp

import (
	"net"
	"testing"
	"time"
)

func startMockUDPServer(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to start mock UDP server: %v", err)
	}

	go func() {
		buffer := make([]byte, 1024)
		bytesRead, remoteAddr, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		// Create a "connection" for the handler
		pseudoConn := &udpConn{udpConn: connection, remote: remoteAddr, buffer: buffer[:bytesRead]}
		handler(pseudoConn)
	}()

	return connection.LocalAddr().String(), func() { connection.Close() }
}

type udpConn struct {
	udpConn *net.UDPConn
	remote  *net.UDPAddr
	buffer  []byte
}

func (u *udpConn) Read(b []byte) (int, error) {
	copy(b, u.buffer)
	return len(u.buffer), nil
}

func (u *udpConn) Write(b []byte) (int, error) {
	return u.udpConn.WriteToUDP(b, u.remote)
}

func (u *udpConn) Close() error                       { return nil }
func (u *udpConn) LocalAddr() net.Addr                { return u.udpConn.LocalAddr() }
func (u *udpConn) RemoteAddr() net.Addr               { return u.remote }
func (u *udpConn) SetDeadline(t time.Time) error      { return nil }
func (u *udpConn) SetReadDeadline(t time.Time) error  { return nil }
func (u *udpConn) SetWriteDeadline(t time.Time) error { return nil }

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
	if client.Timeout != 5*time.Second {
		t.Errorf("default timeout = %v, want 5s", client.Timeout)
	}
}

func TestConnectSendRecv(t *testing.T) {
	address, cleanup := startMockUDPServer(t, func(conn net.Conn) {
		conn.Read(make([]byte, 8))
		conn.Write([]byte("\xD0\xA5Login:"))
	})
	defer cleanup()

	host, port := parseAddress(address)

	client := NewClient()
	client.Target = host
	client.Port = port

	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	defer client.Close()

	err = client.Send(make([]byte, 8))
	if err != nil {
		t.Fatalf("Send() failed: %v", err)
	}

	response, err := client.Recv(1024)
	if err != nil {
		t.Fatalf("Recv() failed: %v", err)
	}
	if len(response) < 4 {
		t.Errorf("Recv() returned %d bytes, expected at least 4", len(response))
	}
}

func TestSend_NotConnected(t *testing.T) {
	client := NewClient()
	err := client.Send([]byte("data"))
	if err == nil {
		t.Error("Send() without Connect() should return error")
	}
}
