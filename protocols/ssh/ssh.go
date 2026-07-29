package ssh

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client provides SSH communication with a target device.
// Embed this struct into exploit modules that use SSH (e.g., FortiGate backdoor, SSH key auth).
type Client struct {
	Target  string
	Port    int
	Timeout time.Duration
	Verbose bool

	sshClient *ssh.Client
}

// NewClient creates an SSH client with sensible defaults.
func NewClient() *Client {
	return &Client{
		Port:    22,
		Timeout: 8 * time.Second,
	}
}

// Login authenticates to the SSH server with username and password.
// Returns nil on success, or an error if authentication fails.
func (client *Client) Login(username, password string) error {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         client.Timeout,
	}

	return client.connect(config)
}

// LoginKey authenticates to the SSH server with a private key.
// The key should be PEM-encoded.
func (client *Client) LoginKey(username string, privateKey []byte) error {
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("ssh: failed to parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         client.Timeout,
	}

	return client.connect(config)
}

// TestConnect verifies that the SSH server accepts connections.
// It attempts authentication with a random username and checks that the server
// responds with an authentication error (not a connection error).
// Returns true if the SSH service is available.
func (client *Client) TestConnect() (bool, error) {
	config := &ssh.ClientConfig{
		User:            "nonexistent_test_user",
		Auth:            []ssh.AuthMethod{ssh.Password("nonexistent_test_password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         client.Timeout,
	}

	address := client.address()
	_, err := ssh.Dial("tcp", address, config)
	if err != nil {
		// If we got past the TCP handshake, the SSH server is available
		// (authentication failure is expected since we used a fake password)
		return isAuthenticationError(err), nil
	}
	return true, nil
}

// Execute runs a command on the SSH server and returns its combined output.
func (client *Client) Execute(command string) (string, error) {
	if client.sshClient == nil {
		return "", fmt.Errorf("ssh: not connected")
	}

	session, err := client.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh: failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("ssh: command failed: %w", err)
	}
	return string(output), nil
}

// NewSession creates a new SSH session for the authenticated connection.
// The caller is responsible for closing the session.
func (client *Client) NewSession() (*ssh.Session, error) {
	if client.sshClient == nil {
		return nil, fmt.Errorf("ssh: not connected")
	}
	return client.sshClient.NewSession()
}

// Close terminates the SSH connection.
func (client *Client) Close() error {
	if client.sshClient == nil {
		return nil
	}
	err := client.sshClient.Close()
	client.sshClient = nil
	return err
}

func (client *Client) connect(config *ssh.ClientConfig) error {
	address := client.address()
	sshClient, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return fmt.Errorf("ssh: dial to %s failed: %w", address, err)
	}
	client.sshClient = sshClient
	return nil
}

func (client *Client) address() string {
	port := client.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(client.Target, fmt.Sprintf("%d", port))
}

func isAuthenticationError(err error) bool {
	if err == nil {
		return false
	}
	errorMessage := err.Error()
	return strings.Contains(errorMessage, "unable to authenticate") ||
		strings.Contains(errorMessage, "no supported methods remain")
}
