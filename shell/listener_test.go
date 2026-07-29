package shell

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestStartReverseListener_Bind(t *testing.T) {
	listener, err := StartReverseListener(0)
	if err != nil {
		t.Fatalf("StartReverseListener failed: %v", err)
	}
	defer listener.Close()

	if listener == nil {
		t.Error("StartReverseListener returned nil listener")
	}
}

func TestStartReverseListener_SpecificPort(t *testing.T) {
	// Use port 0 for dynamic allocation
	listener, err := StartReverseListener(0)
	if err != nil {
		t.Fatalf("StartReverseListener failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	if addr.Port == 0 {
		t.Error("Listen port should not be 0")
	}
}

func TestRunReverseListener_AcceptConnection(t *testing.T) {
	listener, err := StartReverseListener(0)
	if err != nil {
		t.Fatalf("StartReverseListener failed: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)

	go func() {
		defer waitGroup.Done()
		conn, dialErr := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if dialErr != nil {
			t.Errorf("dial failed: %v", dialErr)
			return
		}
		conn.Close()
	}()

	// Accept the connection
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	conn.Close()

	waitGroup.Wait()
}

func TestRunReverseListener_Timeout(t *testing.T) {
	listener, err := StartReverseListener(0)
	if err != nil {
		t.Fatalf("StartReverseListener failed: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		done <- RunReverseListener(listener, 100*time.Millisecond)
	}()

	select {
	case err := <-done:
		t.Logf("RunReverseListener returned: %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Error("RunReverseListener did not return within timeout")
	}
}
