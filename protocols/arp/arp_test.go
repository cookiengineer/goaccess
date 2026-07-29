package arp

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client.Timeout != 2*time.Second {
		t.Errorf("default timeout = %v, want 2s", client.Timeout)
	}
	if client.Interface != "" {
		t.Errorf("default interface = %q, want empty", client.Interface)
	}
}

func TestBuildARPRequest(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcIP := net.IP{192, 168, 1, 1}
	targetIP := net.IP{192, 168, 1, 100}

	frame := buildARPRequest(srcMAC, srcIP, targetIP)

	if len(frame) != 42 {
		t.Fatalf("frame length = %d, want 42", len(frame))
	}

	if !bytes.Equal(frame[0:6], broadcastMAC) {
		t.Errorf("destination MAC = %x, want broadcast", frame[0:6])
	}
	if !bytes.Equal(frame[6:12], srcMAC) {
		t.Errorf("source MAC = %x, want %x", frame[6:12], srcMAC)
	}
	if frame[12] != 0x08 || frame[13] != 0x06 {
		t.Errorf("ethertype = %04x, want 0806", uint16(frame[12])<<8|uint16(frame[13]))
	}
	if frame[14] != 0x00 || frame[15] != 0x01 {
		t.Errorf("htype = %04x, want 0001", uint16(frame[14])<<8|uint16(frame[15]))
	}
	if frame[16] != 0x08 || frame[17] != 0x00 {
		t.Errorf("ptype = %04x, want 0800", uint16(frame[16])<<8|uint16(frame[17]))
	}
	if frame[18] != 6 {
		t.Errorf("hlen = %d, want 6", frame[18])
	}
	if frame[19] != 4 {
		t.Errorf("plen = %d, want 4", frame[19])
	}
	if frame[20] != 0x00 || frame[21] != 0x01 {
		t.Errorf("oper = %04x, want 0001 (request)", uint16(frame[20])<<8|uint16(frame[21]))
	}
	if !bytes.Equal(frame[22:28], srcMAC) {
		t.Errorf("sender MAC = %x, want %x", frame[22:28], srcMAC)
	}
	if !bytes.Equal(frame[28:32], srcIP.To4()) {
		t.Errorf("sender IP = %v, want %v", net.IP(frame[28:32]), srcIP)
	}
	if !bytes.Equal(frame[38:42], targetIP.To4()) {
		t.Errorf("target IP = %v, want %v", net.IP(frame[38:42]), targetIP)
	}
}

func TestParseARPReply_Valid(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ourMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	srcIP := net.IP{192, 168, 1, 100}

	reply := buildARPReply(ourMAC, srcMAC, srcIP, net.IP{192, 168, 1, 1})

	mac := parseARPReply(reply, srcIP)
	if mac == nil {
		t.Fatal("parseARPReply returned nil for valid reply")
	}
	if !bytes.Equal(mac, srcMAC) {
		t.Errorf("parsed MAC = %x, want %x", mac, srcMAC)
	}
}

func TestParseARPReply_WrongIP(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ourMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	srcIP := net.IP{192, 168, 1, 100}

	reply := buildARPReply(ourMAC, srcMAC, srcIP, net.IP{192, 168, 1, 1})

	mac := parseARPReply(reply, net.IP{192, 168, 1, 99})
	if mac != nil {
		t.Errorf("expected nil for wrong target IP, got %x", mac)
	}
}

func TestParseARPReply_NotARP(t *testing.T) {
	frame := make([]byte, 60)
	frame[12] = 0x08
	frame[13] = 0x00
	frame[14] = 0x00
	frame[15] = 0x01
	frame[20] = 0x00
	frame[21] = 0x02

	mac := parseARPReply(frame, net.IP{192, 168, 1, 1})
	if mac != nil {
		t.Errorf("expected nil for non-ARP frame, got %x", mac)
	}
}

func TestParseARPReply_TooShort(t *testing.T) {
	mac := parseARPReply(make([]byte, 20), net.IP{192, 168, 1, 1})
	if mac != nil {
		t.Errorf("expected nil for short frame, got %x", mac)
	}
}

func TestResolve_InvalidIP(t *testing.T) {
	client := NewClient()
	_, err := client.Resolve("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestResolve_IPv6(t *testing.T) {
	client := NewClient()
	_, err := client.Resolve("::1")
	if err == nil {
		t.Error("expected error for IPv6 address")
	}
}

func TestSelectSource_AnyInterface(t *testing.T) {
	client := NewClient()
	err := client.selectSource(net.IP{192, 168, 1, 100})
	if err != nil {
		t.Logf("selectSource returned error (no suitable interface): %v", err)
		return
	}
	if client.srcMAC == nil {
		t.Error("srcMAC not set")
	}
	if client.srcIP == nil {
		t.Error("srcIP not set")
	}
	t.Logf("selected %s MAC=%s IP=%s", client.iface.Name, client.srcMAC, client.srcIP)
}

func TestHtons(t *testing.T) {
	if htons(0x0806) != 0x0608 {
		t.Errorf("htons(0x0806) = 0x%04x, want 0x0608", htons(0x0806))
	}
	if htons(0x0001) != 0x0100 {
		t.Errorf("htons(0x0001) = 0x%04x, want 0x0100", htons(0x0001))
	}
}

func buildARPReply(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	frame := make([]byte, 42)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	frame[12] = 0x08
	frame[13] = 0x06
	frame[14] = 0x00
	frame[15] = 0x01
	frame[16] = 0x08
	frame[17] = 0x00
	frame[18] = 6
	frame[19] = 4
	frame[20] = 0x00
	frame[21] = 0x02
	copy(frame[22:28], srcMAC)
	copy(frame[28:32], srcIP.To4())
	copy(frame[32:38], dstMAC)
	copy(frame[38:42], dstIP.To4())
	return frame
}
