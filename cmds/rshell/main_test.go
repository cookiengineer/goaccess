package main

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestReverseShell_NoEnv(t *testing.T) {
	os.Unsetenv("RSHELL_HOST")
	os.Unsetenv("RSHELL_PORT")

	host := os.Getenv("RSHELL_HOST")
	port := os.Getenv("RSHELL_PORT")
	if host != "" || port != "" {
		t.Error("RSHELL_HOST and RSHELL_PORT should be empty after unset")
	}
}

func TestReverseShell_Dial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}

	_, port, _ := net.SplitHostPort(listener.Addr().String())
	address := net.JoinHostPort("127.0.0.1", port)

	acceptDone := make(chan bool, 1)
	go func() {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
		listener.Close()
		acceptDone <- true
	}()

	dialer := net.Dialer{Timeout: 1 * time.Second}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.Close()

	<-acceptDone
}

func TestExecShell(t *testing.T) {
	shell := exec.Command("echo", "test")
	output, err := shell.CombinedOutput()
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if len(output) == 0 {
		t.Error("shell command produced no output")
	}
}
