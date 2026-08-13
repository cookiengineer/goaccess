package types

import (
	"testing"
	"time"
)

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		protocol Protocol
		expected string
	}{
		{ProtocolHTTP, "http"},
		{ProtocolHTTPS, "https"},
		{ProtocolTCP, "tcp"},
		{ProtocolUDP, "udp"},
		{ProtocolSSH, "ssh"},
		{ProtocolTelnet, "telnet"},
		{ProtocolFTP, "ftp"},
		{ProtocolSNMP, "snmp"},
		{ProtocolVTwoSDK, "vtwo_sdk"},
		{ProtocolAJP, "ajp"},
		{Protocol(999), "unknown"},
	}

	for _, test := range tests {
		result := test.protocol.String()
		if result != test.expected {
			t.Errorf("Protocol(%d).String() = %q, want %q", test.protocol, result, test.expected)
		}
	}
}

func TestProtocol_DefaultPort(t *testing.T) {
	tests := []struct {
		protocol Protocol
		expected int
	}{
		{ProtocolHTTP, 80},
		{ProtocolHTTPS, 443},
		{ProtocolSSH, 22},
		{ProtocolTelnet, 23},
		{ProtocolFTP, 21},
		{ProtocolSNMP, 161},
		{ProtocolVTwoSDK, 10000},
		{ProtocolAJP, 8009},
		{ProtocolTCP, 0},
		{ProtocolUDP, 0},
	}

	for _, test := range tests {
		result := test.protocol.DefaultPort()
		if result != test.expected {
			t.Errorf("Protocol(%d).DefaultPort() = %d, want %d", test.protocol, result, test.expected)
		}
	}
}

func TestDeviceType_Constants(t *testing.T) {
	if DeviceRouter != "router" {
		t.Errorf("DeviceRouter = %q, want %q", DeviceRouter, "router")
	}
	if DeviceCamera != "camera" {
		t.Errorf("DeviceCamera = %q, want %q", DeviceCamera, "camera")
	}
	if DeviceMisc != "misc" {
		t.Errorf("DeviceMisc = %q, want %q", DeviceMisc, "misc")
	}
	if DeviceGeneric != "generic" {
		t.Errorf("DeviceGeneric = %q, want %q", DeviceGeneric, "generic")
	}
	if DeviceDrone != "drone" {
		t.Errorf("DeviceDrone = %q, want %q", DeviceDrone, "drone")
	}
	if DeviceServer != "server" {
		t.Errorf("DeviceServer = %q, want %q", DeviceServer, "server")
	}
}

func TestInfo_Struct(t *testing.T) {
	info := &Info{
		Name:        "Test Exploit",
		Description: "A test exploit",
		Vendor:      "testvendor",
		DeviceType:  DeviceRouter,
		Models:      []string{"Model-A", "Model-B"},
		CVE:         []string{"CVE-2024-0001"},
		References:  []string{"https://example.com/advisory"},
	}

	if info.Vendor != "testvendor" {
		t.Errorf("Info.Vendor = %q, want %q", info.Vendor, "testvendor")
	}
	if len(info.Models) != 2 {
		t.Errorf("len(Info.Models) = %d, want 2", len(info.Models))
	}
}

func TestOptions_Clone(t *testing.T) {
	original := &Options{
		Target:   "192.168.1.1",
		Port:     80,
		SSL:      true,
		Timeout:  10 * time.Second,
		Verbose:  true,
		Username: "admin",
		Password: "secret",
		Filename: "/etc/passwd",
		Defaults: []string{"admin:admin", "root:root"},
		LHOST:    "10.0.0.1",
		LPORT:    4444,
		Extra: map[string]interface{}{
			"custom": "value",
		},
	}

	clone := original.Clone()

	if clone.Target != original.Target {
		t.Errorf("Clone.Target = %q, want %q", clone.Target, original.Target)
	}
	if clone.Extra["custom"] != "value" {
		t.Errorf("Clone.Extra[custom] = %v, want %v", clone.Extra["custom"], "value")
	}

	// Modify clone and verify original is unchanged
	clone.Target = "10.0.0.2"
	clone.Extra["custom"] = "modified"

	if original.Target != "192.168.1.1" {
		t.Errorf("Original.Target was mutated: got %q", original.Target)
	}
	if original.Extra["custom"] != "value" {
		t.Errorf("Original.Extra was mutated: got %v", original.Extra["custom"])
	}
}

func TestOptions_Clone_Nil(t *testing.T) {
	var original *Options
	clone := original.Clone()
	if clone == nil {
		t.Error("Clone of nil Options should return an empty Options, not nil")
	}
}

func TestAccessStep_String(t *testing.T) {
	tests := []struct {
		step     AccessStep
		expected string
	}{
		{StepIdentify, "identify"},
		{StepCredentials, "credentials"},
		{StepExploit, "exploit"},
		{StepShell, "shell"},
		{StepComplete, "complete"},
		{StepFailed, "failed"},
		{AccessStep(99), "unknown"},
	}

	for _, test := range tests {
		result := test.step.String()
		if result != test.expected {
			t.Errorf("AccessStep(%d).String() = %q, want %q", test.step, result, test.expected)
		}
	}
}

func TestCredential_String(t *testing.T) {
	credential := Credential{Username: "admin", Password: "secret"}
	if credential.String() != "admin:secret" {
		t.Errorf("Credential.String() = %q, want %q", credential.String(), "admin:secret")
	}
}

func TestParseCredential(t *testing.T) {
	tests := []struct {
		input    string
		expected Credential
	}{
		{"admin:secret", Credential{Username: "admin", Password: "secret"}},
		{"user:", Credential{Username: "user", Password: ""}},
		{":pass", Credential{Username: "", Password: "pass"}},
		{"nocolon", Credential{Username: "nocolon", Password: ""}},
		{"", Credential{Username: "", Password: ""}},
		{"a:b:c", Credential{Username: "a", Password: "b:c"}},
	}

	for _, test := range tests {
		result := ParseCredential(test.input)
		if result.Username != test.expected.Username || result.Password != test.expected.Password {
			t.Errorf("ParseCredential(%q) = {%q, %q}, want {%q, %q}",
				test.input,
				result.Username, result.Password,
				test.expected.Username, test.expected.Password)
		}
	}
}

func TestFingerprint_Struct(t *testing.T) {
	fingerprint := &Fingerprint{
		URL:    "/HNAP1/",
		Method: "GET",
		Headers: map[string]string{
			"Server": "DIR-",
		},
		Body:         "GetDeviceSettings",
		UPnPResponse: "Linux, UPnP/1.0, DIR-",
		SNMPOID:      "1.3.6.1.2.1.1.1.0",
		SNMPValue:    "D-Link",
		MACPrefixes:  []string{"0050BA", "1CAFF7"},
	}

	if fingerprint.URL != "/HNAP1/" {
		t.Errorf("Fingerprint.URL = %q, want %q", fingerprint.URL, "/HNAP1/")
	}
	if len(fingerprint.MACPrefixes) != 2 {
		t.Errorf("len(MACPrefixes) = %d, want 2", len(fingerprint.MACPrefixes))
	}
}

func TestScanConfig_Defaults(t *testing.T) {
	config := &ScanConfig{
		Target:  "192.168.1.1",
		Threads: 8,
		Timeout: 5 * time.Second,
	}

	if config.Verbose {
		t.Error("Verbose should default to false")
	}
	if config.SkipCredentials {
		t.Error("SkipCredentials should default to false")
	}
	if config.SkipExploits {
		t.Error("SkipExploits should default to false")
	}
}
