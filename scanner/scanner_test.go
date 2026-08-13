package scanner

import (
	"net"
	"testing"
	"time"

	"github.com/cookiengineer/goaccess/exploit"
	"github.com/cookiengineer/goaccess/interfaces"
	"github.com/cookiengineer/goaccess/types"
)

func parsePort(portString string) int {
	port := 0
	for _, character := range []byte(portString) {
		port = port*10 + int(character-'0')
	}
	return port
}

func TestScanner_Identify_PortScan(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	_, portString, _ := net.SplitHostPort(listener.Addr().String())

	scanner := NewScanner(&types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 4,
		Timeout: 500 * time.Millisecond,
	})

	result, err := scanner.Identify("127.0.0.1", nil)
	if err != nil {
		t.Fatalf("Identify() error: %v", err)
	}
	if result.IP != "127.0.0.1" {
		t.Errorf("IP = %q, want 127.0.0.1", result.IP)
	}
	if len(result.Hints) < 1 {
		t.Logf("No hints found for localhost (expected): %v", result.Hints)
	}
	_ = portString
}

func TestScanner_Scan_EmptyExploits(t *testing.T) {
	exploit.Reset()

	config := &types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 2,
		Timeout: 1 * time.Second,
	}

	scanner := NewScanner(config)

	resultChannel, err := scanner.Scan("127.0.0.1", config)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	resultCount := 0
	for range resultChannel {
		resultCount++
	}

	if resultCount != 0 {
		t.Errorf("Expected 0 results with empty registry, got %d", resultCount)
	}
}

func TestScanner_Scan_WithMockExploit(t *testing.T) {
	exploit.Reset()

	exploit.Register(newMockHTTPExploit("Test Vuln", "dlink-scanner-test", true))

	config := &types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 2,
		Timeout: 2 * time.Second,
	}

	scanner := NewScanner(config)

	resultChannel, err := scanner.Scan("127.0.0.1", config)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	vulnCount := 0
	for result := range resultChannel {
		if result.Vulnerability != nil && result.Vulnerability.Confirmed {
			vulnCount++
		}
	}

	if vulnCount != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", vulnCount)
	}
}

func TestScanner_Access_WithMockCredentials(t *testing.T) {
	exploit.Reset()

	module := newMockCredentialsModule("Test Creds", "dlink-access-test", []*types.CredsResult{
		{Target: "127.0.0.1", Port: 23, Service: "telnet", Username: "admin", Password: "admin", Protocol: types.ProtocolTelnet},
	})
	exploit.RegisterCredentials(module)

	config := &types.ScanConfig{
		Target:  "127.0.0.1",
		Threads: 2,
		Timeout: 2 * time.Second,
	}

	scanner := NewScanner(config)

	result, err := scanner.Access("127.0.0.1", config)
	if err != nil {
		t.Fatalf("Access() error: %v", err)
	}

	if len(result.Credentials) != 1 {
		t.Errorf("Expected 1 credential in Access result, got %d", len(result.Credentials))
	}
	if result.Credentials[0].Username != "admin" {
		t.Errorf("Expected username 'admin', got %q", result.Credentials[0].Username)
	}
}

func TestFilterExploits_ByVendor(t *testing.T) {
	exploit.Reset()

	exploit.Register(newMockHTTPExploit("D-Link Exploit", "dlinkfilter", true))
	exploit.Register(newMockHTTPExploit("TP-Link Exploit", "tplink", true))
	exploit.Register(newMockHTTPExploit("Cisco Exploit", "cisco", true))

	config := &types.ScanConfig{VendorFilter: "dlinkfilter"}
	result := filterExploits("", config)

	if len(result) != 1 {
		t.Errorf("filterExploits with vendor dlinkfilter returned %d, want 1", len(result))
	}
	if result[0].Info().Vendor != "dlinkfilter" {
		t.Errorf("Expected vendor dlinkfilter, got %s", result[0].Info().Vendor)
	}
}

func TestFilterExploits_ByDeviceType(t *testing.T) {
	exploit.Reset()

	exploit.Register(newMockHTTPExploit("Router Exploit", "dlink-filter-type", true))
	exploit.Register(newMockCameraExploit("Camera Exploit", "hikvision"))

	config := &types.ScanConfig{TypeFilter: types.DeviceRouter}
	result := filterExploits("", config)

	if len(result) != 1 {
		t.Errorf("filterExploits with type router returned %d, want 1", len(result))
	}
}

func TestNewScanner_Defaults(t *testing.T) {
	config := &types.ScanConfig{
		Target: "192.168.1.1",
	}
	scanner := NewScanner(config)
	if scanner.config.Threads != 8 {
		t.Errorf("default threads = %d, want 8", scanner.config.Threads)
	}
	if scanner.config.Timeout != 8*time.Second {
		t.Errorf("default timeout = %v, want 8s", scanner.config.Timeout)
	}
}

func TestNewScanner_ExplicitConfig(t *testing.T) {
	config := &types.ScanConfig{
		Threads: 32,
		Timeout: 15 * time.Second,
	}
	scanner := NewScanner(config)
	if scanner.config.Threads != 32 {
		t.Errorf("threads = %d, want 32", scanner.config.Threads)
	}
}

// --- Mock exploit implementations for testing ---

type mockHTTPExploit struct {
	name       string
	vendor     string
	vulnerable bool
}

func newMockHTTPExploit(name, vendor string, vulnerable bool) *mockHTTPExploit {
	return &mockHTTPExploit{name: name, vendor: vendor, vulnerable: vulnerable}
}

func (m *mockHTTPExploit) Info() *types.Info {
	return &types.Info{
		Name:       m.name,
		Vendor:     m.vendor,
		DeviceType: types.DeviceRouter,
	}
}

func (m *mockHTTPExploit) Check(target string, options *types.Options) (*types.VulnResult, error) {
	if m.vulnerable {
		return &types.VulnResult{Confirmed: true, Details: "mock vulnerability"}, nil
	}
	return nil, nil
}

func (m *mockHTTPExploit) Run(target string, options *types.Options) (*types.ExploitResult, error) {
	return &types.ExploitResult{Success: m.vulnerable}, nil
}

func (m *mockHTTPExploit) Fingerprints() []*types.Fingerprint { return nil }
func (m *mockHTTPExploit) Options() *types.Options {
	return &types.Options{Port: 80, Timeout: 5 * time.Second}
}
func (m *mockHTTPExploit) Protocol() types.Protocol { return types.ProtocolHTTP }

var _ interfaces.Exploit = (*mockHTTPExploit)(nil)

type mockCameraExploit struct {
	name   string
	vendor string
}

func newMockCameraExploit(name, vendor string) *mockCameraExploit {
	return &mockCameraExploit{name: name, vendor: vendor}
}

func (m *mockCameraExploit) Info() *types.Info {
	return &types.Info{
		Name:       m.name,
		Vendor:     m.vendor,
		DeviceType: types.DeviceCamera,
	}
}

func (m *mockCameraExploit) Check(target string, options *types.Options) (*types.VulnResult, error) {
	return nil, nil
}

func (m *mockCameraExploit) Run(target string, options *types.Options) (*types.ExploitResult, error) {
	return nil, nil
}

func (m *mockCameraExploit) Fingerprints() []*types.Fingerprint { return nil }
func (m *mockCameraExploit) Options() *types.Options {
	return &types.Options{Port: 80, Timeout: 5 * time.Second}
}
func (m *mockCameraExploit) Protocol() types.Protocol { return types.ProtocolHTTP }

var _ interfaces.Exploit = (*mockCameraExploit)(nil)

type mockCredentialsModule struct {
	mockHTTPExploit
	credentials []*types.CredsResult
}

func newMockCredentialsModule(name, vendor string, creds []*types.CredsResult) *mockCredentialsModule {
	return &mockCredentialsModule{
		mockHTTPExploit: mockHTTPExploit{name: name, vendor: vendor},
		credentials:     creds,
	}
}

func (m *mockCredentialsModule) CheckDefault(target string, options *types.Options) ([]*types.CredsResult, error) {
	return m.credentials, nil
}

var _ interfaces.CredentialsModule = (*mockCredentialsModule)(nil)

// mockAuthExploit only succeeds when a specific credential is supplied via
// options, simulating an authenticated takeover exploit.
type mockAuthExploit struct {
	name         string
	vendor       string
	requiredUser string
	requiredPass string
	attempts     int
	gotUser      string
	gotPass      string
}

func newMockAuthExploit(name, vendor, user, pass string) *mockAuthExploit {
	return &mockAuthExploit{name: name, vendor: vendor, requiredUser: user, requiredPass: pass}
}

func (m *mockAuthExploit) Info() *types.Info {
	return &types.Info{Name: m.name, Vendor: m.vendor, DeviceType: types.DeviceServer}
}

func (m *mockAuthExploit) Check(target string, options *types.Options) (*types.VulnResult, error) {
	return nil, nil
}

func (m *mockAuthExploit) Run(target string, options *types.Options) (*types.ExploitResult, error) {
	m.attempts++
	m.gotUser = options.Username
	m.gotPass = options.Password
	if options.Username == m.requiredUser && options.Password == m.requiredPass {
		return &types.ExploitResult{Success: true, Action: "takeover"}, nil
	}
	return &types.ExploitResult{Success: false}, nil
}

func (m *mockAuthExploit) Fingerprints() []*types.Fingerprint { return nil }
func (m *mockAuthExploit) Options() *types.Options {
	return &types.Options{Port: 80, Timeout: 5 * time.Second}
}
func (m *mockAuthExploit) Protocol() types.Protocol { return types.ProtocolHTTP }

var _ interfaces.Exploit = (*mockAuthExploit)(nil)

func TestRunExploitChain_InjectsCredentials(t *testing.T) {
	exploit.Reset()
	defer exploit.Reset()

	auth := newMockAuthExploit("Takeover", "mockauth", "admin", "secret")
	exploit.Register(auth)

	scanner := NewScanner(&types.ScanConfig{Target: "127.0.0.1"})
	config := &types.ScanConfig{Timeout: 5 * time.Second}
	fingerprint := &types.FingerprintResult{Vendor: "mockauth"}

	credentials := []types.Credential{
		{Username: "wrong", Password: "wrong"},
		{Username: "admin", Password: "secret"},
	}

	results := scanner.runExploitChain("127.0.0.1", fingerprint, config, credentials)

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if auth.attempts != 2 {
		t.Errorf("attempts = %d, want 2 (first cred fails, second succeeds)", auth.attempts)
	}
	if auth.gotUser != "admin" || auth.gotPass != "secret" {
		t.Errorf("last attempted credential = %s:%s, want admin:secret", auth.gotUser, auth.gotPass)
	}
}

func TestRunExploitChain_NoCredentials(t *testing.T) {
	exploit.Reset()
	defer exploit.Reset()

	auth := newMockAuthExploit("Takeover", "mockauth", "admin", "secret")
	exploit.Register(auth)

	scanner := NewScanner(&types.ScanConfig{Target: "127.0.0.1"})
	config := &types.ScanConfig{Timeout: 5 * time.Second}
	fingerprint := &types.FingerprintResult{Vendor: "mockauth"}

	results := scanner.runExploitChain("127.0.0.1", fingerprint, config, nil)

	if len(results) != 0 {
		t.Fatalf("results = %d, want 0 (no credential supplied)", len(results))
	}
	if auth.attempts != 1 {
		t.Errorf("attempts = %d, want 1", auth.attempts)
	}
}

func TestMergeCredentials_Deduplicates(t *testing.T) {
	merged := mergeCredentials(
		[]types.Credential{{Username: "admin", Password: "secret"}},
		[]types.Credential{{Username: "admin", Password: "secret"}, {Username: "root", Password: "toor"}},
	)
	if len(merged) != 2 {
		t.Fatalf("merged = %d, want 2 (deduplicated)", len(merged))
	}
	if merged[0].Username != "admin" || merged[1].Username != "root" {
		t.Errorf("order = %v, want [admin root]", merged)
	}
}

func TestSuppliedCredentials(t *testing.T) {
	credentials := suppliedCredentials(&types.ScanConfig{
		Username:  "admin",
		Password:  "single",
		Passwords: []string{"p1", "p2"},
	})
	if len(credentials) != 3 {
		t.Fatalf("credentials = %d, want 3", len(credentials))
	}
	if credentials[0].Username != "admin" || credentials[0].Password != "single" {
		t.Errorf("credentials[0] = %s:%s, want admin:single", credentials[0].Username, credentials[0].Password)
	}
	if credentials[1].Password != "p1" || credentials[2].Password != "p2" {
		t.Errorf("password list order = %v", credentials)
	}
	for _, credential := range credentials {
		if credential.Username != "admin" {
			t.Errorf("username = %q, want admin", credential.Username)
		}
	}
}

func TestSuppliedCredentials_DefaultUsername(t *testing.T) {
	credentials := suppliedCredentials(&types.ScanConfig{Password: "secret"})
	if len(credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(credentials))
	}
	if credentials[0].Username != "admin" || credentials[0].Password != "secret" {
		t.Errorf("credentials[0] = %s:%s, want admin:secret", credentials[0].Username, credentials[0].Password)
	}
}

func TestSuppliedCredentials_Empty(t *testing.T) {
	if credentials := suppliedCredentials(&types.ScanConfig{}); len(credentials) != 0 {
		t.Errorf("credentials = %d, want 0", len(credentials))
	}
}

func TestCredentialsToStrings(t *testing.T) {
	got := credentialsToStrings([]types.Credential{
		{Username: "admin", Password: "p1"},
		{Username: "admin", Password: "p2"},
		{Username: "", Password: ""},
	})
	if len(got) != 2 {
		t.Fatalf("got = %d, want 2", len(got))
	}
	if got[0] != "admin:p1" || got[1] != "admin:p2" {
		t.Errorf("got = %v", got)
	}
}

// mockRecordingCredentialsModule captures the Defaults wordlist it receives.
type mockRecordingCredentialsModule struct {
	mockHTTPExploit
	receivedDefaults []string
}

func newMockRecordingCredentialsModule(name, vendor string) *mockRecordingCredentialsModule {
	return &mockRecordingCredentialsModule{mockHTTPExploit: mockHTTPExploit{name: name, vendor: vendor}}
}

func (m *mockRecordingCredentialsModule) CheckDefault(target string, options *types.Options) ([]*types.CredsResult, error) {
	m.receivedDefaults = options.Defaults
	return nil, nil
}

var _ interfaces.CredentialsModule = (*mockRecordingCredentialsModule)(nil)

func TestRecoverCredentials_InjectSuppliedList(t *testing.T) {
	exploit.Reset()
	defer exploit.Reset()

	mod := newMockRecordingCredentialsModule("Recorder", "recorder")
	exploit.RegisterCredentials(mod)

	scanner := NewScanner(&types.ScanConfig{Target: "127.0.0.1"})
	config := &types.ScanConfig{
		Timeout:   2 * time.Second,
		Username:  "admin",
		Passwords: []string{"p1", "p2"},
	}
	fingerprint := &types.FingerprintResult{Vendor: "recorder"}

	scanner.recoverCredentials("127.0.0.1", fingerprint, config)

	if len(mod.receivedDefaults) != 2 {
		t.Fatalf("receivedDefaults = %v, want 2 entries", mod.receivedDefaults)
	}
	if mod.receivedDefaults[0] != "admin:p1" || mod.receivedDefaults[1] != "admin:p2" {
		t.Errorf("receivedDefaults = %v, want [admin:p1 admin:p2]", mod.receivedDefaults)
	}
}
