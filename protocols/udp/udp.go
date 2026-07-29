package udp

import (
	"fmt"
	"net"
	"time"
)

// Client provides raw UDP communication with a target device.
// Embed this struct into exploit modules that use raw UDP protocols
// (e.g., UPnP-based exploits, Netcore UDP backdoor).
type Client struct {
	Target  string
	Port    int
	Timeout time.Duration
	Verbose bool

	connection net.Conn
}

// NewClient creates a UDP client with sensible defaults.
func NewClient() *Client {
	return &Client{
		Timeout: 5 * time.Second,
	}
}

// Connect opens a UDP "connection" to the target.
// UDP is connectionless, but we use Dial to bind a local address for send/recv.
func (client *Client) Connect() error {
	address := client.address()
	dialer := net.Dialer{Timeout: client.Timeout}
	connection, err := dialer.Dial("udp", address)
	if err != nil {
		return fmt.Errorf("udp: connect to %s failed: %w", address, err)
	}
	client.connection = connection
	return nil
}

// Send writes data to the target via UDP.
func (client *Client) Send(data []byte) error {
	if client.connection == nil {
		return fmt.Errorf("udp: not connected")
	}
	_, err := client.connection.Write(data)
	if err != nil {
		return fmt.Errorf("udp: send failed: %w", err)
	}
	return nil
}

// Recv reads up to length bytes from the UDP connection.
func (client *Client) Recv(length int) ([]byte, error) {
	if client.connection == nil {
		return nil, fmt.Errorf("udp: not connected")
	}

	buffer := make([]byte, length)
	bytesRead, err := client.connection.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("udp: recv failed: %w", err)
	}
	return buffer[:bytesRead], nil
}

// Close terminates the UDP connection.
func (client *Client) Close() error {
	if client.connection == nil {
		return nil
	}
	err := client.connection.Close()
	client.connection = nil
	if err != nil {
		return fmt.Errorf("udp: close failed: %w", err)
	}
	return nil
}

func (client *Client) address() string {
	port := client.Port
	if port == 0 {
		port = 80
	}
	return net.JoinHostPort(client.Target, fmt.Sprintf("%d", port))
}
