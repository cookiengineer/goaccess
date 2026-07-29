//go:build windows

package arp

import (
	"fmt"
	"net"
)

func (c *Client) lookup(target string) (net.HardwareAddr, error) {
	return nil, fmt.Errorf("arp: lookup via iphlpapi not yet implemented on windows")
}
