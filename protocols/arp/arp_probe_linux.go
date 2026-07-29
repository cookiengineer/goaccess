//go:build linux

package arp

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func (c *Client) probe(target string) (net.HardwareAddr, error) {
	ip := net.ParseIP(target).To4()
	if ip == nil {
		return nil, fmt.Errorf("arp: invalid IP %q", target)
	}

	if err := c.selectSource(ip); err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeARP)))
	if err != nil {
		return nil, fmt.Errorf("arp: raw socket: %w (try running with CAP_NET_RAW)", err)
	}
	defer unix.Close(fd)

	if err := unix.BindToDevice(fd, c.iface.Name); err != nil {
		return nil, fmt.Errorf("arp: bind device: %w", err)
	}

	frame := buildARPRequest(c.srcMAC, c.srcIP, ip)
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeARP),
		Ifindex:  c.iface.Index,
		Hatype:   unix.ARPHRD_ETHER,
		Halen:    hwAddrLen,
	}

	if err := unix.Sendto(fd, frame, 0, addr); err != nil {
		return nil, fmt.Errorf("arp: send: %w", err)
	}

	return readARPReply(fd, ip, c.timeout())
}

func readARPReply(fd int, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)

	for time.Now().Before(deadline) {
		if err := setReadDeadline(fd, deadline); err != nil {
			return nil, err
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if isTemporaryNetlink(err) {
				continue
			}
			return nil, fmt.Errorf("arp: recv: %w", err)
		}

		if n < 42 {
			continue
		}

		mac := parseARPReply(buf[:n], targetIP)
		if mac != nil {
			return mac, nil
		}
	}

	return nil, fmt.Errorf("arp: no reply from %s", targetIP)
}

func htons(val int) uint16 {
	return uint16(val)<<8 | uint16(val>>8)
}
