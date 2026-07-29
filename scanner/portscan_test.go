package scanner

import (
	"net"
	"testing"
	"time"
)

func TestScanPort_Open(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	_, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber := parsePort(port)

	open := ScanPort("127.0.0.1", portNumber, 500*time.Millisecond)
	if !open {
		t.Errorf("ScanPort(%d) should return true for open port", portNumber)
	}
}

func TestScanPort_Closed(t *testing.T) {
	// Find a likely-closed port by trying to bind and immediately releasing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	listener.Close()

	open := ScanPort("127.0.0.1", parsePort(port), 200*time.Millisecond)
	if open {
		t.Errorf("ScanPort(%s) should return false for closed port", port)
	}
}

func TestScanPort_InvalidTarget(t *testing.T) {
	open := ScanPort("192.0.2.1", 12345, 100*time.Millisecond)
	if open {
		t.Error("ScanPort should return false for unreachable target")
	}
}

func TestScanPorts_Mixed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	_, openPort, _ := net.SplitHostPort(listener.Addr().String())
	openPortNumber := parsePort(openPort)

	closedPort := findClosedPort(t)

	ports := []int{openPortNumber, closedPort}
	open := ScanPorts("127.0.0.1", ports, 500*time.Millisecond)

	if len(open) != 1 {
		t.Errorf("ScanPorts returned %d open ports, want 1", len(open))
	}
	if open[0] != openPortNumber {
		t.Errorf("ScanPorts returned port %d, want %d", open[0], openPortNumber)
	}
}

func TestScanPorts_AllClosed(t *testing.T) {
	ports := []int{19999, 19998, 19997}
	open := ScanPorts("127.0.0.1", ports, 100*time.Millisecond)

	if len(open) != 0 {
		t.Errorf("ScanPorts returned %d open ports, want 0: %v", len(open), open)
	}
}

func TestScanPorts_Empty(t *testing.T) {
	open := ScanPorts("127.0.0.1", nil, 100*time.Millisecond)
	if len(open) != 0 {
		t.Errorf("ScanPorts with empty ports returned %d results", len(open))
	}
}

func TestCommonIOTPorts(t *testing.T) {
	if len(CommonIOTPorts) < 8 {
		t.Errorf("CommonIOTPorts has %d entries, expected at least 8", len(CommonIOTPorts))
	}
}

func findClosedPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind: %v", err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber := parsePort(port)
	listener.Close()
	return portNumber
}
