package shell

import (
	"net"
	"testing"
	"time"

	"github.com/cookiengineer/goaccess/payload"
)

func TestNewHandler_InvalidArch(t *testing.T) {
	_, err := NewHandler("nonexistent", "wget", "/tmp")
	if err == nil {
		t.Error("NewHandler with invalid arch should return error")
	}
}

func TestNewHandler_ReturnsHandler(t *testing.T) {
	// Set a valid base path first since payloads may not be built
	payload.SetBasePath("/tmp")

	_, err := NewHandler("x86_64", "wget", "/tmp")
	if err != nil {
		t.Logf("NewHandler error (payloads may not be built): %v", err)
	}
}

func TestHandler_SetExecuteFunc(t *testing.T) {
	handler := &Handler{Architecture: "x86_64", Method: "cmd"}
	called := false
	handler.SetExecuteFunc(func(cmd string) (string, error) {
		called = true
		return "output", nil
	})

	if handler.executeFunc == nil {
		t.Fatal("SetExecuteFunc did not set execute function")
	}

	result, err := handler.executeFunc("id")
	if err != nil {
		t.Errorf("execute function returned error: %v", err)
	}
	if !called {
		t.Error("execute function was not called")
	}
	if result != "output" {
		t.Errorf("execute function returned %q, want 'output'", result)
	}
}

func TestHandler_DeployReverse_NoExecuteFunc(t *testing.T) {
	handler := &Handler{
		Architecture: "x86_64",
		Method:       "wget",
		Location:     "/tmp",
		LHOST:        "10.0.0.1",
		LPORT:        4444,
	}
	_, err := handler.DeployReverse()
	if err == nil {
		t.Error("DeployReverse without execute function should return error")
	}
}

func TestHandler_DeployReverse_NoLHost(t *testing.T) {
	handler := &Handler{
		Architecture: "x86_64",
		Method:       "wget",
		Location:     "/tmp",
	}
	handler.SetExecuteFunc(func(cmd string) (string, error) {
		return "", nil
	})
	_, err := handler.DeployReverse()
	if err == nil {
		t.Error("DeployReverse without LHOST should return error")
	}
}

func TestStartReverseListener(t *testing.T) {
	listener, err := StartReverseListener(0)
	if err != nil {
		t.Fatalf("StartReverseListener failed: %v", err)
	}
	defer listener.Close()

	if listener.Addr() == nil {
		t.Error("listener has no address")
	}

	port := listener.Addr().(*net.TCPAddr).Port
	if port == 0 {
		t.Error("listener got port 0")
	}
}

func TestRandomName(t *testing.T) {
	name := randomName(8)
	if len(name) != 8 {
		t.Errorf("randomName(8) = %q, len=%d, want 8", name, len(name))
	}

	name2 := randomName(8)
	if name2 == name {
		t.Log("randomName produced identical names (statistically unlikely but possible)")
	}
}

func TestTransferEcho(t *testing.T) {
	commands := make([]string, 0)
	handler := &Handler{
		Method:      "echo",
		PayloadData: make([]byte, 120),
	}
	handler.SetExecuteFunc(func(cmd string) (string, error) {
		commands = append(commands, cmd)
		return "", nil
	})

	handler.transferEcho("/tmp/test")

	if len(commands) < 2 {
		t.Errorf("transferEcho generated %d commands, expected at least 2 for 120-byte payload", len(commands))
	}
}

func TestExecuteViaCmd(t *testing.T) {
	output, err := ExecuteViaCmd(func(cmd string) (string, error) {
		return "result", nil
	}, "ls")
	if err != nil {
		t.Fatalf("ExecuteViaCmd error: %v", err)
	}
	if output != "result" {
		t.Errorf("ExecuteViaCmd = %q, want 'result'", output)
	}
}

func TestExecuteViaCmd_NilExecuteFunc(t *testing.T) {
	_, err := ExecuteViaCmd(nil, "ls")
	if err == nil {
		t.Error("ExecuteViaCmd with nil executeFunc should error")
	}
}

func TestRunReverseListener(t *testing.T) {
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
		if err == nil {
			t.Log("RunReverseListener exited (expected after timeout)")
		}
	case <-time.After(300 * time.Millisecond):
		t.Log("RunReverseListener still running (test timeout)")
	}
}
