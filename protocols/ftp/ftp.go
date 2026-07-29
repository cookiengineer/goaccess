package ftp

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
)

// Client provides FTP communication with a target device.
// Embed this struct into credential brute-force modules for FTP services.
type Client struct {
	Target  string
	Port    int
	Timeout time.Duration
	Verbose bool

	ftpConnection *ftp.ServerConn
}

// NewClient creates an FTP client with sensible defaults.
func NewClient() *Client {
	return &Client{
		Port:    21,
		Timeout: 10 * time.Second,
	}
}

// Login authenticates to the FTP server with username and password.
// Returns nil on success, or an error if authentication fails.
func (client *Client) Login(username, password string) error {
	address := client.address()
	ftpConnection, err := ftp.Dial(address, ftp.DialWithTimeout(client.Timeout))
	if err != nil {
		return fmt.Errorf("ftp: dial to %s failed: %w", address, err)
	}

	err = ftpConnection.Login(username, password)
	if err != nil {
		ftpConnection.Quit()
		return fmt.Errorf("ftp: login failed: %w", err)
	}

	client.ftpConnection = ftpConnection
	return nil
}

// TestConnect verifies that the FTP service is available.
// Returns true if the FTP server accepts connections.
func (client *Client) TestConnect() (bool, error) {
	address := client.address()
	ftpConnection, err := ftp.Dial(address, ftp.DialWithTimeout(client.Timeout))
	if err != nil {
		return false, nil
	}
	ftpConnection.Quit()
	return true, nil
}

// List returns the directory listing for the given path.
// Login() must be called first.
func (client *Client) List(path string) ([]string, error) {
	if client.ftpConnection == nil {
		return nil, fmt.Errorf("ftp: not connected")
	}

	entries, err := client.ftpConnection.List(path)
	if err != nil {
		return nil, fmt.Errorf("ftp: list %s failed: %w", path, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names, nil
}

// Retrieve downloads a file from the FTP server.
// Login() must be called first.
func (client *Client) Retrieve(filename string) ([]byte, error) {
	if client.ftpConnection == nil {
		return nil, fmt.Errorf("ftp: not connected")
	}

	response, err := client.ftpConnection.Retr(filename)
	if err != nil {
		return nil, fmt.Errorf("ftp: retrieve %s failed: %w", filename, err)
	}
	defer response.Close()

	data, err := io.ReadAll(response)
	if err != nil {
		return nil, fmt.Errorf("ftp: reading file %s failed: %w", filename, err)
	}
	return data, nil
}

// Store uploads data to a file on the FTP server.
// Login() must be called first.
func (client *Client) Store(filename string, data []byte) error {
	if client.ftpConnection == nil {
		return fmt.Errorf("ftp: not connected")
	}

	err := client.ftpConnection.Stor(filename, strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("ftp: store %s failed: %w", filename, err)
	}
	return nil
}

// ChangeDirectory changes the current working directory.
// Login() must be called first.
func (client *Client) ChangeDirectory(path string) error {
	if client.ftpConnection == nil {
		return fmt.Errorf("ftp: not connected")
	}
	return client.ftpConnection.ChangeDir(path)
}

// Close terminates the FTP connection.
func (client *Client) Close() error {
	if client.ftpConnection == nil {
		return nil
	}
	err := client.ftpConnection.Quit()
	client.ftpConnection = nil
	return err
}

func (client *Client) address() string {
	port := client.Port
	if port == 0 {
		port = 21
	}
	return fmt.Sprintf("%s:%d", client.Target, port)
}
