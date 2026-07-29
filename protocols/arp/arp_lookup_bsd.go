//go:build darwin || freebsd || openbsd || netbsd

package arp

import (
	"fmt"
	"net"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func (c *Client) lookup(target string) (net.HardwareAddr, error) {
	ip := net.ParseIP(target).To4()

	rib, err := route.FetchRIB(unix.AF_INET, route.RIBType(unix.NET_RT_FLAGS), unix.RTF_LLINFO)
	if err != nil {
		return nil, fmt.Errorf("arp: fetch RIB: %w", err)
	}
	if len(rib) == 0 {
		return nil, fmt.Errorf("arp: empty ARP table")
	}

	msgs, err := route.ParseRIB(route.RIBType(unix.NET_RT_FLAGS), rib)
	if err != nil {
		return nil, fmt.Errorf("arp: parse RIB: %w", err)
	}

	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		if len(rm.Addrs) < 2 {
			continue
		}

		dstIP := addrToIP(rm.Addrs[0])
		if dstIP == nil || !dstIP.Equal(ip) {
			continue
		}

		la, ok := rm.Addrs[1].(*route.LinkAddr)
		if !ok || la == nil || len(la.Addr) < hwAddrLen {
			continue
		}

		mac := make(net.HardwareAddr, hwAddrLen)
		copy(mac, la.Addr)
		return mac, nil
	}

	return nil, fmt.Errorf("arp: %s not in ARP table", target)
}

func addrToIP(addr route.Addr) net.IP {
	switch a := addr.(type) {
	case *route.Inet4Addr:
		return net.IP(a.IP[:]).To4()
	default:
		return nil
	}
}
