package telnet

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// Client provides Telnet communication with a target device.
// Embed this struct into credential brute-force modules for Telnet services.
type Client struct {
	Target  string
	Port    int
	Timeout time.Duration
	Verbose bool

	connection net.Conn
}

// NewClient creates a Telnet client with sensible defaults.
func NewClient() *Client {
	return &Client{
		Port:    23,
		Timeout: 30 * time.Second,
	}
}

// Connect establishes a TCP connection to the Telnet server.
func (client *Client) Connect() error {
	address := client.address()
	dialer := net.Dialer{Timeout: client.Timeout}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("telnet: connect to %s failed: %w", address, err)
	}
	client.connection = connection
	return nil
}

// Login attempts authentication with the given username and password.
// It handles the typical Telnet login sequence:
// expects "Login:" / "Username:" → sends username
// expects "Password:" → sends password
// checks for a prompt (#, $, >) to confirm success
func (client *Client) Login(username, password string) bool {
	if err := client.Connect(); err != nil {
		return false
	}

	// Wait for login prompt and send username
	response := client.readUntilTimeout([]string{"login:", "username:", "Login:", "Username:", "ogin:"})
	if len(response) == 0 {
		client.Close()
		return false
	}

	client.write(username + "\r\n")

	// Wait for password prompt
	response = client.readUntilTimeout([]string{"password:", "Password:"})
	if len(response) == 0 {
		client.Close()
		return false
	}

	client.write(password + "\r\n")
	client.write("\r\n")

	// Wait for command prompt or failure message
	response = client.readUntilTimeout([]string{"#", "$", ">", "incorrect", "Incorrect", "Login incorrect", "fail"})
	if len(response) == 0 {
		client.Close()
		return false
	}

	// Check for successful login indicators
	lower := strings.ToLower(response)
	if strings.Contains(lower, "incorrect") || strings.Contains(lower, "fail") || strings.Contains(lower, "invalid") {
		client.Close()
		return false
	}

	// Success if we see a prompt
	if strings.Contains(response, "#") || strings.Contains(response, "$") || strings.Contains(response, ">") {
		return true
	}

	// Large banner with no failure text suggests successful login (e.g., MikroTik)
	if len(response) > 500 {
		return true
	}

	client.Close()
	return false
}

// TestConnect verifies that the Telnet service is available.
func (client *Client) TestConnect() (bool, error) {
	if err := client.Connect(); err != nil {
		return false, nil
	}
	defer client.Close()

	response := client.readUntilTimeout([]string{"login:", "username:", "Login:", "Username:", "ogin:"})
	if len(response) > 0 {
		return true, nil
	}

	return true, nil // Connected but no login prompt yet; service is up
}

// Write sends raw data to the Telnet connection.
func (client *Client) Write(data []byte) (int, error) {
	if client.connection == nil {
		return 0, fmt.Errorf("telnet: not connected")
	}
	return client.connection.Write(data)
}

// Read reads up to length bytes from the connection.
func (client *Client) Read(length int) ([]byte, error) {
	if client.connection == nil {
		return nil, fmt.Errorf("telnet: not connected")
	}
	buffer := make([]byte, length)
	bytesRead, err := client.connection.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:bytesRead], nil
}

// Close terminates the Telnet connection.
func (client *Client) Close() error {
	if client.connection == nil {
		return nil
	}
	err := client.connection.Close()
	client.connection = nil
	return err
}

func (client *Client) write(data string) error {
	if client.connection == nil {
		return fmt.Errorf("telnet: not connected")
	}
	client.connection.SetWriteDeadline(time.Now().Add(client.Timeout))
	_, err := client.connection.Write([]byte(data))
	return err
}

func (client *Client) readUntilTimeout(delimiters []string) string {
	if client.connection == nil {
		return ""
	}

	client.connection.SetReadDeadline(time.Now().Add(client.Timeout))

	var buffer bytes.Buffer
	readBuffer := make([]byte, 1)
	timeout := time.After(client.Timeout)

	for {
		select {
		case <-timeout:
			return buffer.String()
		default:
			bytesRead, err := client.connection.Read(readBuffer)
			if err != nil {
				return buffer.String()
			}
			if bytesRead > 0 {
				buffer.Write(readBuffer[:bytesRead])
				content := strings.ToLower(buffer.String())
				for _, delimiter := range delimiters {
					if strings.Contains(content, strings.ToLower(delimiter)) {
						return buffer.String()
					}
				}
			}
		}
	}
}

func (client *Client) address() string {
	port := client.Port
	if port == 0 {
		port = 23
	}
	return net.JoinHostPort(client.Target, fmt.Sprintf("%d", port))
}
