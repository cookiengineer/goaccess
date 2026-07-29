//go:build !linux

package arp

import (
	"fmt"
	"net"
	"time"
)

func (c *Client) probe(target string) (net.HardwareAddr, error) {
	addr := net.JoinHostPort(target, "80")
	conn, err := net.DialTimeout("tcp", addr, c.timeout())
	if err != nil {
		return nil, nil
	}
	conn.Close()

	time.Sleep(50 * time.Millisecond)

	mac, err := c.lookup(target)
	if err != nil {
		return nil, nil
	}
	return mac, nil
}
