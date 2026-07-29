//go:build linux

package arp

import (
	"net"
	"testing"
)

func TestLookup_Localhost(t *testing.T) {
	client := NewClient()
	client.Timeout = 1

	mac, err := client.lookup("127.0.0.1")
	if err != nil {
		t.Logf("lookup 127.0.0.1 returned error (expected if not in table): %v", err)
		return
	}
	if mac == nil {
		t.Log("lookup 127.0.0.1 returned nil MAC (expected if not in table)")
		return
	}
	t.Logf("lookup 127.0.0.1 -> %s", mac)
}

func TestLookup_EmptyTable(t *testing.T) {
	client := NewClient()
	client.Timeout = 1

	mac, err := client.lookup("10.255.255.255")
	if err != nil || mac != nil {
		t.Logf("lookup for nonexistent IP returned: mac=%s, err=%v", mac, err)
	}
}

func TestResolve_Loopback(t *testing.T) {
	client := NewClient()
	client.Timeout = 1

	mac, err := client.Resolve("127.0.0.1")
	if err != nil {
		t.Logf("Resolve 127.0.0.1 returned error (expected): %v", err)
		return
	}
	t.Logf("Resolve 127.0.0.1 -> %s", mac)
}

func TestProbe_RequiresCapNetRaw(t *testing.T) {
	client := NewClient()
	client.Timeout = 1

	mac, err := client.probe("10.255.255.255")
	if err != nil {
		t.Logf("probe returned error (expected without CAP_NET_RAW): %v", err)
		return
	}
	if mac == nil {
		t.Log("probe returned nil MAC (expected for unreachable target)")
	}
}

func TestNetlinkPacketBuild(t *testing.T) {
	ip := net.IP{192, 168, 1, 100}.To4()
	req := buildNeighGetRequest(ip)

	if len(req) < unixIntConst("NLMSG_HDRLEN", 16)+unixIntConst("SizeofNdMsg", 12) {
		t.Fatalf("request too short: %d bytes", len(req))
	}
}

func TestRtaAlign(t *testing.T) {
	if rtaAlign(0) != 0 {
		t.Errorf("rtaAlign(0) = %d, want 0", rtaAlign(0))
	}
	if rtaAlign(1) != 4 {
		t.Errorf("rtaAlign(1) = %d, want 4", rtaAlign(1))
	}
	if rtaAlign(4) != 4 {
		t.Errorf("rtaAlign(4) = %d, want 4", rtaAlign(4))
	}
	if rtaAlign(5) != 8 {
		t.Errorf("rtaAlign(5) = %d, want 8", rtaAlign(5))
	}
}

func TestNlmsgAlign(t *testing.T) {
	if nlmsgAlign(0) != 0 {
		t.Errorf("nlmsgAlign(0) = %d, want 0", nlmsgAlign(0))
	}
	if nlmsgAlign(1) != 4 {
		t.Errorf("nlmsgAlign(1) = %d, want 4", nlmsgAlign(1))
	}
	if nlmsgAlign(4) != 4 {
		t.Errorf("nlmsgAlign(4) = %d, want 4", nlmsgAlign(4))
	}
	if nlmsgAlign(5) != 8 {
		t.Errorf("nlmsgAlign(5) = %d, want 8", nlmsgAlign(5))
	}
}

func unixIntConst(name string, fallback int) int {
	return fallback
}
