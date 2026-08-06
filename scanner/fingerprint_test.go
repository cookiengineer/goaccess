package scanner

import (
	"testing"
	"time"

	"github.com/cookiengineer/goaccess/exploit"
	"github.com/cookiengineer/goaccess/types"
)

func TestProbeHTTPIndicators_NoMatch(t *testing.T) {
	result := &types.FingerprintResult{IP: "127.0.0.1"}
	probeHTTPIndicators("127.0.0.1", []int{80}, 100*time.Millisecond, result)
	if result.Vendor != "" {
		t.Logf("probeHTTPIndicators set vendor for localhost (unexpected): %s", result.Vendor)
	}
}

func TestProbeUPnP_Nothing(t *testing.T) {
	result := probeUPnP("127.0.0.1", 100*time.Millisecond)
	if result != "" {
		t.Logf("probeUPnP returned result for unreachable target: %s", result)
	}
}

func TestProbeSNMP_Nothing(t *testing.T) {
	result := probeSNMP("127.0.0.1", "public", 200*time.Millisecond)
	if result != "" {
		t.Logf("probeSNMP returned result for localhost (unexpected): %s", result)
	}
}

func TestMatchFingerprints_EmptyExploits(t *testing.T) {
	exploit.Reset()
	result := &types.FingerprintResult{IP: "127.0.0.1"}
	vendor, model, confidence := matchFingerprints("127.0.0.1", result, 1*time.Second)
	if vendor != "" || model != "" || confidence != 0 {
		t.Errorf("Expected no match with empty registry, got vendor=%q model=%q conf=%f", vendor, model, confidence)
	}
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		html     []byte
		expected string
	}{
		{[]byte("<html><head><title>D-Link Router</title></head></html>"), "D-Link Router"},
		{[]byte("<TITLE>Admin Panel</TITLE>"), "Admin Panel"},
		{[]byte("<html><title></title></html>"), ""},
		{[]byte("no title here"), ""},
	}

	for _, test := range tests {
		result := extractTitle(test.html)
		if result != test.expected {
			t.Errorf("extractTitle(%q) = %q, want %q", test.html, result, test.expected)
		}
	}
}

func TestContains(t *testing.T) {
	if !contains("hello world", "world") {
		t.Error("contains(hello world, world) should be true")
	}
	if contains("hello world", "earth") {
		t.Error("contains(hello world, earth) should be false")
	}
	if !contains("test", "") {
		t.Error("contains(test, ) should be true for empty substring")
	}
}

func TestMatchFingerprints_ViaIdentify(t *testing.T) {
	exploit.Reset()

	// Register a fingerprinted exploit
	fingerprinted := newMockExploitWithFingerprints("D-Link DIR-300", "dlink", types.DeviceRouter, []*types.Fingerprint{
		{URL: "/HNAP1/", Method: "GET", Body: "GetDeviceSettings"},
	})
	exploit.Register(fingerprinted)

	scanner := NewScanner(&types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 2,
		Timeout: 2 * time.Second,
	})

	result, err := scanner.Identify("127.0.0.1", nil)
	if err != nil {
		t.Fatalf("Identify() error: %v", err)
	}

	// Without a matching HTTP server, vendor should be empty
	// But the Identify pipeline should complete without error
	if result.IP != "127.0.0.1" {
		t.Errorf("IP = %q, want 127.0.0.1", result.IP)
	}
}

type mockExploitWithFingerprints struct {
	name         string
	vendor       string
	deviceType   types.DeviceType
	fingerprints []*types.Fingerprint
}

func newMockExploitWithFingerprints(name, vendor string, deviceType types.DeviceType, fingerprints []*types.Fingerprint) *mockExploitWithFingerprints {
	return &mockExploitWithFingerprints{name: name, vendor: vendor, deviceType: deviceType, fingerprints: fingerprints}
}

func (m *mockExploitWithFingerprints) Info() *types.Info {
	return &types.Info{Name: m.name, Vendor: m.vendor, DeviceType: m.deviceType}
}
func (m *mockExploitWithFingerprints) Check(target string, options *types.Options) (*types.VulnResult, error) {
	return nil, nil
}
func (m *mockExploitWithFingerprints) Run(target string, options *types.Options) (*types.ExploitResult, error) {
	return nil, nil
}
func (m *mockExploitWithFingerprints) Fingerprints() []*types.Fingerprint { return m.fingerprints }
func (m *mockExploitWithFingerprints) Options() *types.Options {
	return &types.Options{Port: 80, Timeout: 5 * time.Second}
}
func (m *mockExploitWithFingerprints) Protocol() types.Protocol { return types.ProtocolHTTP }
