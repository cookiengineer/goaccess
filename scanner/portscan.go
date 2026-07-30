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
	10000, // DJI vtwo_sdk
	32764, // SerComm backdoor
}

// DroneOUIs maps known drone vendor MAC OUI prefixes to vendor names.
var DroneOUIs = map[string]string{
	"60601F": "DJI",
	"E04F43": "DJI",
	"34D262": "DJI",
	"28E5B6": "DJI",
	"A0143D": "Parrot",
	"9003B7": "Parrot",
	"00267E": "Parrot",
	"AC3A7A": "Ryze (Tello)",
}

// DroneServicePorts maps drone-relevant ports to service descriptions.
var DroneServicePorts = map[int]string{
	21:    "FTP (Anonymous — Parrot, DJI, DBPOWER)",
	23:    "Telnet (No auth / root — Parrot AR Drone)",
	80:    "HTTP Media API (CVE-2023-6949 — DJI)",
	554:   "RTSP Video Stream",
	5555:  "Raw H.264 Video Stream (Parrot AR Drone)",
	8889:  "UDP SDK Command (Ryze Tello)",
	10000: "vtwo_sdk Root Service (DJI)",
	11111: "UDP Video Stream (Ryze Tello)",
}

// IsDroneOUI checks if a MAC OUI prefix matches a known drone vendor.
func IsDroneOUI(ouiPrefix string) (string, bool) {
	if len(ouiPrefix) < 6 {
		return "", false
	}
	vendor, ok := DroneOUIs[ouiPrefix[:6]]
	return vendor, ok
}

// DroneServiceHints returns service description hints for open drone ports.
func DroneServiceHints(openPorts []int) []string {
	var hints []string
	for _, port := range openPorts {
		if description, ok := DroneServicePorts[port]; ok {
			hints = append(hints, "port "+itos(port)+": "+description)
		}
	}
	return hints
}

func itos(value int) string {
	return fmt.Sprintf("%d", value)
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
