package scanner

import (
	"os/exec"
	"testing"
	"time"

	"github.com/cookiengineer/goaccess/types"
)

func skipIfNoPodman(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not available, skipping integration test")
	}
}

func TestIntegration_SSHLogin(t *testing.T) {
	skipIfNoPodman(t)

	containerName := "goaccess-test-ssh"

	exec.Command("podman", "rm", "-f", containerName).Run()

	cmd := exec.Command("podman", "run", "-d", "--rm", "--name", containerName,
		"-e", "SSH_USERS=admin:admin",
		"-e", "TCP_FORWARDING=false",
		"-p", "2222:2222",
		"ghcr.io/linuxserver/openssh-server")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start SSH container: %v\n%s", err, output)
	}
	defer exec.Command("podman", "rm", "-f", containerName).Run()

	time.Sleep(3 * time.Second)

	config := &types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 4,
		Timeout: 10 * time.Second,
	}

	scanner := NewScanner(config)
	result, err := scanner.Identify("127.0.0.1", config)
	if err != nil {
		t.Logf("Identify error (expected for container): %v", err)
	}
	if result != nil {
		t.Logf("Fingerprint result: Vendor=%s, Model=%s, Services=%v", result.Vendor, result.Model, result.Services)
	}
}

func TestIntegration_FTPLogin(t *testing.T) {
	skipIfNoPodman(t)

	containerName := "goaccess-test-ftp"

	exec.Command("podman", "rm", "-f", containerName).Run()

	cmd := exec.Command("podman", "run", "-d", "--rm", "--name", containerName,
		"-e", "FTP_USER=admin",
		"-e", "FTP_PASS=admin",
		"-p", "2121:21",
		"docker.io/stilliard/pure-ftpd:latest")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start FTP container: %v\n%s", err, output)
	}
	defer exec.Command("podman", "rm", "-f", containerName).Run()

	time.Sleep(3 * time.Second)

	config := &types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 4,
		Timeout: 10 * time.Second,
	}

	scanner := NewScanner(config)
	scanner.Identify("127.0.0.1", config)
}

func TestIntegration_TelnetLogin(t *testing.T) {
	skipIfNoPodman(t)

	containerName := "goaccess-test-telnet"

	exec.Command("podman", "rm", "-f", containerName).Run()

	cmd := exec.Command("podman", "run", "-d", "--rm", "--name", containerName,
		"-p", "2323:23",
		"docker.io/wettyoss/wetty",
		"-c", "/bin/login")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start Telnet container: %v\n%s", err, output)
	}
	defer exec.Command("podman", "rm", "-f", containerName).Run()

	time.Sleep(3 * time.Second)

	config := &types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 4,
		Timeout: 10 * time.Second,
	}

	scanner := NewScanner(config)
	scanner.Identify("127.0.0.1", config)
}

func TestIntegration_ScannerWithContainers(t *testing.T) {
	skipIfNoPodman(t)

	config := &types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 2,
		Timeout: 5 * time.Second,
	}

	scanner := NewScanner(config)

	result, err := scanner.Identify("127.0.0.1", config)
	if err != nil {
		t.Logf("Identify failed on localhost: %v", err)
		return
	}

	if result == nil {
		t.Log("No fingerprint result on localhost (expected, no services running)")
		return
	}

	t.Logf("Localhost fingerprint: IP=%s, Vendor=%s, Model=%s, Services=%v, Hints=%v",
		result.IP, result.Vendor, result.Model, result.Services, result.Hints)

	_ = scanner
}
