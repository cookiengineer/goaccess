package scanner

import (
	"fmt"
	"net"
	"time"
)

// CommonIOTPorts lists the TCP ports commonly found on IoT devices.
var CommonIOTPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	53,    // DNS
	80,    // HTTP
	443,   // HTTPS
	161,   // SNMP
	1900,  // UPnP SSDP
	8080,  // HTTP-alt
	8291,  // MikroTik WinBox
	32764, // SerComm backdoor
}

// ScanPort checks if a single TCP port is open on the target.
func ScanPort(target string, port int, timeout time.Duration) bool {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

// ScanPorts concurrently scans a list of ports and returns those that are open.
func ScanPorts(target string, ports []int, timeout time.Duration) []int {
	results := make(chan int, len(ports))

	for _, port := range ports {
		go func(p int) {
			if ScanPort(target, p, timeout) {
				results <- p
			} else {
				results <- -1
			}
		}(port)
	}

	open := make([]int, 0)
	seen := 0
	for seen < len(ports) {
		port := <-results
		seen++
		if port > 0 {
			open = append(open, port)
		}
	}
	close(results)

	return open
}
