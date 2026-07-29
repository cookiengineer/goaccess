//go:build linux

package arp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func (c *Client) lookup(target string) (net.HardwareAddr, error) {
	ip := net.ParseIP(target).To4()

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("arp: netlink socket: %w", err)
	}
	defer unix.Close(fd)

	lsa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, lsa); err != nil {
		return nil, fmt.Errorf("arp: netlink bind: %w", err)
	}

	req := buildNeighGetRequest(ip)
	if _, err := unix.Write(fd, req); err != nil {
		return nil, fmt.Errorf("arp: netlink write: %w", err)
	}

	return readNeighReply(fd, ip, c.timeout())
}

func buildNeighGetRequest(ip net.IP) []byte {
	ndMsgLen := unix.SizeofNdMsg
	rtaLen := rtaAlign(unix.SizeofRtAttr + 4)
	totalLen := unix.NLMSG_HDRLEN + ndMsgLen + rtaLen

	buf := make([]byte, totalLen)

	hdr := unix.NlMsghdr{
		Len:   uint32(totalLen),
		Type:  uint16(unix.RTM_GETNEIGH),
		Flags: uint16(unix.NLM_F_REQUEST | unix.NLM_F_DUMP),
		Seq:   1,
		Pid:   uint32(unix.Getpid()),
	}

	binary.NativeEndian.PutUint32(buf[0:4], hdr.Len)
	binary.NativeEndian.PutUint16(buf[4:6], hdr.Type)
	binary.NativeEndian.PutUint16(buf[6:8], hdr.Flags)
	binary.NativeEndian.PutUint32(buf[8:12], hdr.Seq)
	binary.NativeEndian.PutUint32(buf[12:16], hdr.Pid)

	ndMsg := unix.NdMsg{Family: unix.AF_INET}
	off := unix.NLMSG_HDRLEN
	buf[off] = ndMsg.Family
	off += ndMsgLen

	rta := unix.RtAttr{
		Len:  uint16(unix.SizeofRtAttr + 4),
		Type: uint16(unix.NDA_DST),
	}
	binary.NativeEndian.PutUint16(buf[off:off+2], rta.Len)
	binary.NativeEndian.PutUint16(buf[off+2:off+4], rta.Type)
	copy(buf[off+4:off+8], ip.To4())

	return buf
}

func readNeighReply(fd int, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if err := setReadDeadline(fd, deadline); err != nil {
			return nil, fmt.Errorf("arp: netlink deadline: %w", err)
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if isTemporaryNetlink(err) {
				continue
			}
			return nil, fmt.Errorf("arp: netlink recv: %w", err)
		}

		if n < unix.NLMSG_HDRLEN {
			continue
		}

		mac, done, err := parseNetlinkMessages(buf[:n], targetIP)
		if err != nil {
			return nil, err
		}
		if done {
			return nil, fmt.Errorf("arp: %s not in neighbor table", targetIP)
		}
		if mac != nil {
			return mac, nil
		}
	}

	return nil, fmt.Errorf("arp: lookup timeout for %s", targetIP)
}

func parseNetlinkMessages(buf []byte, targetIP net.IP) (net.HardwareAddr, bool, error) {
	for len(buf) >= unix.NLMSG_HDRLEN {
		hdr := unix.NlMsghdr{
			Len:   binary.NativeEndian.Uint32(buf[0:4]),
			Type:  binary.NativeEndian.Uint16(buf[4:6]),
			Flags: binary.NativeEndian.Uint16(buf[6:8]),
			Seq:   binary.NativeEndian.Uint32(buf[8:12]),
			Pid:   binary.NativeEndian.Uint32(buf[12:16]),
		}

		if hdr.Len < unix.NLMSG_HDRLEN || int(hdr.Len) > len(buf) {
			break
		}

		data := buf[unix.NLMSG_HDRLEN:int(hdr.Len)]

		switch hdr.Type {
		case unix.NLMSG_ERROR:
			return nil, false, fmt.Errorf("arp: netlink error response")
		case unix.NLMSG_DONE:
			return nil, true, nil
		case unix.RTM_NEWNEIGH:
			if len(data) >= unix.SizeofNdMsg {
				mac := parseMACFromNdAttrs(data[unix.SizeofNdMsg:], targetIP)
				if mac != nil {
					return mac, false, nil
				}
			}
		}

		buf = buf[nlmsgAlign(int(hdr.Len)):]
	}
	return nil, false, nil
}

func parseMACFromNdAttrs(attrs []byte, targetIP net.IP) net.HardwareAddr {
	var mac net.HardwareAddr
	foundIP := false

	for len(attrs) >= unix.SizeofRtAttr {
		attr := unix.RtAttr{
			Len:  binary.NativeEndian.Uint16(attrs[0:2]),
			Type: binary.NativeEndian.Uint16(attrs[2:4]),
		}

		if attr.Len < unix.SizeofRtAttr {
			break
		}

		dataLen := int(attr.Len) - unix.SizeofRtAttr
		if dataLen < 0 || unix.SizeofRtAttr+dataLen > len(attrs) {
			break
		}

		data := attrs[unix.SizeofRtAttr : unix.SizeofRtAttr+dataLen]

		switch attr.Type {
		case unix.NDA_DST:
			if dataLen >= 4 && net.IP(data).Equal(targetIP) {
				foundIP = true
			}
		case unix.NDA_LLADDR:
			if dataLen >= hwAddrLen {
				mac = make(net.HardwareAddr, hwAddrLen)
				copy(mac, data[:hwAddrLen])
			}
		}

		attrs = attrs[rtaAlign(int(attr.Len)):]
	}

	if foundIP && mac != nil {
		return mac
	}
	return nil
}

func setReadDeadline(fd int, deadline time.Time) error {
	tv := unix.NsecToTimeval(deadline.UnixNano())
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}

func isTemporaryNetlink(err error) bool {
	if err == nil {
		return false
	}
	type temporary interface{ Temporary() bool }
	if tmp, ok := err.(temporary); ok {
		return tmp.Temporary()
	}
	return false
}

func rtaAlign(length int) int {
	return (length + int(unix.RTA_ALIGNTO) - 1) & ^(int(unix.RTA_ALIGNTO) - 1)
}

func nlmsgAlign(length int) int {
	return (length + int(unix.NLMSG_ALIGNTO) - 1) & ^(int(unix.NLMSG_ALIGNTO) - 1)
}
