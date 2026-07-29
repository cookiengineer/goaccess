package arp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	arpOpRequest = 1
	arpOpReply   = 2
	etherTypeARP = 0x0806
	hwTypeEther  = 1
	protoTypeIP  = 0x0800
	hwAddrLen    = 6
	protoAddrLen = 4
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type Client struct {
	Target    string
	Interface string
	Timeout   time.Duration
	Verbose   bool

	srcMAC net.HardwareAddr
	srcIP  net.IP
	iface  *net.Interface
}

func NewClient() *Client {
	return &Client{
		Timeout: 2 * time.Second,
	}
}

func (c *Client) Resolve(target string) (net.HardwareAddr, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("arp: invalid IP %q", target)
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("arp: only IPv4 supported, got %q", target)
	}

	mac, err := c.lookup(target)
	if err == nil && mac != nil {
		return mac, nil
	}

	mac, err = c.probe(target)
	if err == nil && mac != nil {
		return mac, nil
	}

	mac, err = c.lookup(target)
	if err == nil && mac != nil {
		return mac, nil
	}

	return nil, fmt.Errorf("arp: %s not found", target)
}

func (c *Client) Close() error {
	return nil
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 2 * time.Second
}

func (c *Client) selectSource(ip net.IP) error {
	if c.srcMAC != nil && c.srcIP != nil {
		return nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("arp: interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if c.Interface != "" && iface.Name != c.Interface {
			continue
		}
		if iface.HardwareAddr == nil || len(iface.HardwareAddr) != hwAddrLen {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					if ipnet.Contains(ip) {
						c.srcIP = ip4.To4()
						c.srcMAC = iface.HardwareAddr
						c.iface = &iface
						return nil
					}
				}
			}
		}
	}

	for _, iface := range ifaces {
		if c.Interface != "" && iface.Name != c.Interface {
			continue
		}
		if iface.HardwareAddr == nil || len(iface.HardwareAddr) != hwAddrLen {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					c.srcIP = ip4.To4()
					c.srcMAC = iface.HardwareAddr
					c.iface = &iface
					return nil
				}
			}
		}
	}

	return fmt.Errorf("arp: no suitable interface found for %s", ip)
}

func buildARPRequest(srcMAC net.HardwareAddr, srcIP net.IP, targetIP net.IP) []byte {
	frame := make([]byte, 42)

	copy(frame[0:6], broadcastMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)

	binary.BigEndian.PutUint16(frame[14:16], hwTypeEther)
	binary.BigEndian.PutUint16(frame[16:18], protoTypeIP)
	frame[18] = hwAddrLen
	frame[19] = protoAddrLen
	binary.BigEndian.PutUint16(frame[20:22], arpOpRequest)

	copy(frame[22:28], srcMAC)
	copy(frame[28:32], srcIP.To4())

	copy(frame[38:42], targetIP.To4())

	return frame
}

func parseARPReply(frame []byte, targetIP net.IP) net.HardwareAddr {
	if len(frame) < 42 {
		return nil
	}
	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
		return nil
	}
	if binary.BigEndian.Uint16(frame[14:16]) != hwTypeEther {
		return nil
	}
	if binary.BigEndian.Uint16(frame[20:22]) != arpOpReply {
		return nil
	}
	if !net.IP(frame[28:32]).Equal(targetIP.To4()) {
		return nil
	}

	mac := make(net.HardwareAddr, hwAddrLen)
	copy(mac, frame[22:28])
	return mac
}
