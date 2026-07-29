package tcp

import (
	"fmt"
	"net"
	"time"
)

// Client provides raw TCP communication with a target device.
// Embed this struct into exploit modules that use raw TCP protocols.
type Client struct {
	Target  string
	Port    int
	Timeout time.Duration
	Verbose bool

	connection net.Conn
}

// NewClient creates a TCP client with sensible defaults.
func NewClient() *Client {
	return &Client{
		Timeout: 8 * time.Second,
	}
}

// Connect establishes a TCP connection to the target.
// Returns nil on success, or an error if the connection could not be established.
func (client *Client) Connect() error {
	address := client.address()
	dialer := net.Dialer{Timeout: client.Timeout}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("tcp: connect to %s failed: %w", address, err)
	}
	client.connection = connection
	return nil
}

// Send writes data to the established connection.
// Connect() must be called first.
func (client *Client) Send(data []byte) error {
	if client.connection == nil {
		return fmt.Errorf("tcp: not connected")
	}
	_, err := client.connection.Write(data)
	if err != nil {
		return fmt.Errorf("tcp: send failed: %w", err)
	}
	return nil
}

// Recv reads up to length bytes from the connection.
// Connect() must be called first.
func (client *Client) Recv(length int) ([]byte, error) {
	if client.connection == nil {
		return nil, fmt.Errorf("tcp: not connected")
	}

	buffer := make([]byte, length)
	bytesRead, err := client.connection.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("tcp: recv failed: %w", err)
	}
	return buffer[:bytesRead], nil
}

// RecvAll reads exactly length bytes from the connection, blocking until all bytes arrive.
func (client *Client) RecvAll(length int) ([]byte, error) {
	if client.connection == nil {
		return nil, fmt.Errorf("tcp: not connected")
	}

	buffer := make([]byte, length)
	totalRead := 0
	for totalRead < length {
		bytesRead, err := client.connection.Read(buffer[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("tcp: recvAll failed: %w", err)
		}
		if bytesRead == 0 {
			break
		}
		totalRead += bytesRead
	}
	return buffer[:totalRead], nil
}

// Close terminates the TCP connection.
func (client *Client) Close() error {
	if client.connection == nil {
		return nil
	}
	err := client.connection.Close()
	client.connection = nil
	if err != nil {
		return fmt.Errorf("tcp: close failed: %w", err)
	}
	return nil
}

// IsConnected returns true if a TCP connection is active.
func (client *Client) IsConnected() bool {
	return client.connection != nil
}

func (client *Client) address() string {
	port := client.Port
	if port == 0 {
		port = 80
	}
	return net.JoinHostPort(client.Target, fmt.Sprintf("%d", port))
}
