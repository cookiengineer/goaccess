# GoAccess Implementation TODO

## Phase 1: Foundation — Core Types, Interfaces, Registry, & Protocols

### 1.0 Project Initialization
- [x] Initialize Go module: `go mod init github.com/cookiengineer/goaccess`
- [x] Add dependencies: `golang.org/x/crypto`, `github.com/jlaffaye/ftp`, `github.com/gosnmp/gosnmp`
- [x] Run `go mod tidy` to resolve and lock versions
- [x] Create `.gitignore` (ignore `bin/`, `payload/arm/*`, `payload/mips/*`, etc.)

### 1.1 Types Package (`types/`)
- [x] Create `types/protocol.go` — Protocol enum (HTTP, HTTPS, TCP, UDP, SSH, Telnet, FTP, SNMP), DefaultPort(), String()
- [x] Create `types/protocol_test.go` — Enum tests, default port tests
- [x] Create `types/info.go` — Info struct (Name, Description, Vendor, DeviceType, Models, CVE, References), DeviceType enum
- [x] Create `types/info_test.go` — Struct validation tests
- [x] Create `types/options.go` — Options struct (Target, Port, SSL, Timeout, Verbose, Username, Password, Filename, Defaults, LHOST, LPORT, RHOST, RPORT, Payload, Method, Extra)
- [x] Create `types/options_test.go` — Options validation tests
- [x] Create `types/fingerprint.go` — Fingerprint struct (URL, Method, Headers, Body, Banner, UPnPResponse, SNMPOID, SNMPValue, MACPrefixes, FirmwarePatterns), FirmwarePattern struct
- [x] Create `types/fingerprint_test.go` — Struct tests
- [x] Create `types/result.go` — VulnResult, CredsResult, ExploitResult, ShellSession
- [x] Create `types/result_test.go` — Struct tests
- [x] Create `types/access.go` — AccessStep enum, AccessResult, AccessStepLog
- [x] Create `types/scan.go` — ScanConfig, ScanResult
- [x] Create `types/credentials.go` — Credential struct, String()
- [x] Create `types/credentials_test.go` — Credential tests
- [x] Run `go vet ./types/...` and `go test ./types/...`

### 1.2 Interfaces Package (`interfaces/`)
- [x] Create `interfaces/exploit.go` — Exploit interface, ExecuteExploit interface, CredentialsModule interface
- [x] Create `interfaces/scanner.go` — Scanner interface (Identify, Scan, Access)
- [x] Create `interfaces/password.go` — PasswordGenerator interface (Generate, Name, Vendor)
- [x] Run `go vet ./interfaces/...`

### 1.3 Exploit Registry (`exploit/`)
- [x] Create `exploit/registry.go` — Global registry with sync.RWMutex, Register(), RegisterCredentials(), RegisterPasswordGenerator()
- [x] Implement All(), AllCredentials(), ByVendor(), ByModel(), ByDeviceType(), ByProtocol(), CredentialsByVendor(), Get(), Count(), CredentialsCount(), PasswordGenerators()
- [x] Create `exploit/registry_test.go` — Registration + query tests, concurrent access tests
- [x] Run `go vet ./exploit/...` and `go test ./exploit/...`

### 1.4 OUI Database (`oui/`)
- [x] Port `oui.dat` from RouterSploit (23,798 lines, 2-column MAC→vendor) — copy into `oui/oui.dat`
- [x] Create `oui/oui.go` — `//go:embed oui.dat`, Parse() to build map, Lookup(mac) string, LookupPrefixes(vendor) []string
- [x] Create `oui/oui_test.go` — Table-driven tests: known MACs → expected vendors, LookupPrefixes tests, edge cases (empty, invalid, short MAC)
- [x] Run `go vet ./oui/...` and `go test ./oui/...`

### 1.5 Wordlists (`wordlist/`)
- [x] Port `defaults.txt` (653 lines user:pass pairs) → `wordlist/defaults.txt`
- [x] Port `passwords.txt` (716 lines passwords) → `wordlist/passwords.txt`
- [x] Port `usernames.txt` (354 lines usernames) → `wordlist/usernames.txt`
- [x] Port `snmp.txt` (120 lines SNMP communities) → `wordlist/snmp.txt`
- [x] Create `wordlist/data.go` — merged into `wordlist/wordlist.go` with `//go:embed` all four .txt files
- [x] Create `wordlist/wordlist.go` — Defaults() []Credential, Passwords() []string, Usernames() []string, SNMPCommunities() []string
- [x] Implement thread-safe Iterator: Next() (Credential, bool), Reset(), Remaining()
- [x] Create `wordlist/wordlist_test.go` — Verify loaded counts, iteration test, concurrent access test
- [x] Run `go vet ./wordlist/...` and `go test ./wordlist/...`

### 1.6 Report Formatting (`report/`)
- [x] Create `report/report.go` — Report struct (JSON, Verbose, Output), NewReport()
- [x] Implement colorized output: Info(), Success(), Error(), Warn(), Status() — use ANSI escape codes
- [x] Implement Table() — column-aligned table with headers and rows
- [x] Implement KeyValue() — key: value pair display
- [x] Implement JSONOutput() — via WriteJSON(), marshal any value to JSON with indentation
- [x] Implement Fingerprint() formatter, ScanResult() formatter, AccessResult() formatter
- [x] Create `report/report_test.go` — Color output tests, table alignment tests, JSON marshaling tests
- [x] Run `go vet ./report/...` and `go test ./report/...`

### 1.7 Protocols — HTTP (`protocols/http/`)
- [x] Create `protocols/http/http.go` — Client struct (Target, Port, SSL, Timeout, Verbose)
- [x] Implement NewClient(), Get(), Post(), Head(), Do(), SetBasicAuth(), GetTargetURL()
- [x] Create Response struct (StatusCode, Headers, Body) wrapping *http.Response
- [x] Handle SSL (self-signed certs via InsecureSkipVerify), timeouts, redirects (disable by default for fingerprinting)
- [x] Create `protocols/http/http_test.go` — Mock HTTP server tests: GET 200, POST, HEAD, 404, timeout, SSL, redirect disabled
- [x] Run `go vet ./protocols/http/...` and `go test ./protocols/http/...`

### 1.8 Protocols — TCP (`protocols/tcp/`)
- [x] Create `protocols/tcp/tcp.go` — Client struct (Target, Port, Timeout, Verbose)
- [x] Implement NewClient(), Connect(), Send([]byte), Recv(int), RecvAll(int), Close(), IsConnected()
- [x] Support both IPv4 and IPv6
- [x] Create `protocols/tcp/tcp_test.go` — Mock TCP server: connect, send/recv, recv_all, close, connection refused, timeout
- [x] Run `go vet ./protocols/tcp/...` and `go test ./protocols/tcp/...`

### 1.9 Protocols — UDP (`protocols/udp/`)
- [x] Create `protocols/udp/udp.go` — Client struct (Target, Port, Timeout, Verbose)
- [x] Implement NewClient(), Connect(), Send([]byte), Recv(int), Close()
- [x] Create `protocols/udp/udp_test.go` — Mock UDP server: send/recv, timeout, closed port
- [x] Run `go vet ./protocols/udp/...` and `go test ./protocols/udp/...`

### 1.10 Protocols — SSH (`protocols/ssh/`)
- [x] Create `protocols/ssh/ssh.go` — Client struct (Target, Port, Timeout, Verbose)
- [x] Implement NewClient(), Login(user, pass), LoginKey(user, key), Execute(cmd), TestConnect(), NewSession(), Close()
- [x] Use `golang.org/x/crypto/ssh` (pure Go)
- [x] Create `protocols/ssh/ssh_test.go` — Tests: defaults, connection refused, test_connect, execute not connected, close nil
- [x] Run `go vet ./protocols/ssh/...` and `go test ./protocols/ssh/...`

### 1.11 Protocols — Telnet (`protocols/telnet/`)
- [x] Create `protocols/telnet/telnet.go` — Client struct (Target, Port, Timeout, Verbose)
- [x] Implement NewClient(), Connect(), Login(user, pass), Write(data), Read(length), TestConnect(), Close()
- [x] Handle login sequence: expect "Login:", "Username:", "Password:" prompts
- [x] Detect successful login via presence of "#", "$", ">" prompt and absence of "incorrect"/"Incorrect"
- [x] Create `protocols/telnet/telnet_test.go` — Mock telnet server with login sequence, test connect, login success/failure
- [x] Run `go vet ./protocols/telnet/...` and `go test ./protocols/telnet/...`

### 1.12 Protocols — FTP (`protocols/ftp/`)
- [x] Create `protocols/ftp/ftp.go` — Client struct (Target, Port, Timeout, Verbose)
- [x] Implement NewClient(), Login(user, pass), ChangeDirectory(dir), Retrieve(filename), List(dir), Store(filename, data), Close()
- [x] Use `github.com/jlaffaye/ftp` (pure Go)
- [x] Create `protocols/ftp/ftp_test.go` — Tests: defaults, connection refused, test_connect, list/retrieve not connected, close nil
- [x] Run `go vet ./protocols/ftp/...` and `go test ./protocols/ftp/...`

### 1.13 Protocols — SNMP (`protocols/snmp/`)
- [x] Create `protocols/snmp/snmp.go` — Client struct (Target, Port, Community, Timeout, Verbose)
- [x] Implement NewClient(), Get(oid), Walk(oid), TestConnect()
- [x] Use `github.com/gosnmp/gosnmp` (pure Go)
- [x] Create `protocols/snmp/snmp_test.go` — Tests: defaults, connection refused, test_connect unavailable
- [x] Run `go vet ./protocols/snmp/...` and `go test ./protocols/snmp/...`

### 1.14 LZS Decompression (`libs/lzs/`)
- [x] Port LZS algorithm from routersploit `libs/lzs/lzs.py` to Go — bit-stream reader with sliding window ring buffer
- [x] Create `libs/lzs/lzs.go` — Decompress(data) ([]byte, error), DecompressChunk(data, offset) ([]byte, error), ringBuffer, bitReader
- [x] Create `libs/lzs/lzs_test.go` — Tests: empty input, literal bytes, two literals, back-reference, validation, chunk decompression, bit reader methods
- [x] Run `go vet ./libs/lzs/...` and `go test ./libs/lzs/...`

### 1.15 SSH Keys (`ssh_keys/`)
- [x] Port all 9 SSH key pairs from RouterSploit `resources/ssh_keys/` to `ssh_keys/`
- [x] Organize by vendor/model under `ssh_keys/<vendor>/<model>/`
- [x] Each directory contains: `<name>.key` (PEM private key) and `<name>.json` ({"username": "...", "type": "RSA/DSA", "comment": "..."})
- [x] Create `ssh_keys/keys.go` — `//go:embed` FS, KeyEntry struct, All() []KeyEntry, ByVendor(), ByVendorModel()
- [x] Create `ssh_keys/keys_test.go` — Verify all keys loaded, ByVendor queries, key parsing
- [x] Run `go vet ./ssh_keys/...` and `go test ./ssh_keys/...`

### 1.16 Payload FS Preparation
- [x] Create `payload/` directory with arch subdirectories: `arm/`, `arm64/`, `mips/`, `mipsle/`, `mips64/`, `x86/`, `x86_64/`
- [x] Create `payload/payload.go` — Arch type, Handler type, GetPayload(), List(), PayloadInfo (filesystem-based loading until `make payloads` is run)
- [x] Run `go vet ./payload/...`

### 1.17 Phase 1 Verification
- [x] Run `go build ./...` — verify all packages compile with CGO_ENABLED=0
- [x] Run `go vet ./...` — verify no vet warnings
- [x] Run `go test ./...` — verify all tests pass (114 tests across 13 test packages)
- [x] Verify `go.sum` is committed with locked dependency versions

---

## Phase 2: Scanner Engine

### 2.1 Scanner Core
- [x] Create `scanner/scanner.go` — Scanner struct (config, report, jobs chan, results chan, done chan, mu, fingerprint, vulnerabilities, credentials, errors)
- [x] Implement NewScanner(config) — initialize channels, report
- [x] Implement Identify(target, config) — runs all fingerprint steps, returns FingerprintResult
- [x] Implement IdentifyPhase:
  - [x] resolveIP(target) → net.IP
  - [x] resolveMAC(ip) → MAC (via /proc/net/arp or net.Interfaces) if on same subnet
  - [x] ouiLookup(mac) → vendor hint
  - [x] httpBanner(ip) → HEAD / → Server header, WWW-Authenticate, title, favicon hash
  - [x] upnpProbe(ip) → M-SEARCH → 239.255.255.250:1900 → USN, SERVER headers
  - [x] snmpProbe(ip) → GET sysDescr 1.3.6.1.2.1.1.1.0 with "public" community
  - [x] fingerprintMatch(allExploits) → iterate all exploits with Fingerprints(), match patterns
  - [x] aggregateResults() → best Vendor/Model/Firmware guess with confidence
- [x] Create `scanner/fingerprint_test.go` — Mock HTTP/UPnP/SNMP responses, verify resolution

### 2.2 Scanner — Scan Phase
- [x] Implement Scan(target, config) — returns (<-chan *ScanResult, error)
- [x] Implement Scan Phase:
  - [x] Phase 1: Call Identify() → get FingerprintResult
  - [x] Phase 2: Filter exploits by Vendor → exploit.ByVendor(fp.Vendor)
  - [x] Phase 3: Filter creds by Vendor → exploit.CredsByVendor(fp.Vendor)
  - [x] Feed exploits into jobs channel → workers call Check()
  - [x] Feed creds into jobs channel → workers call CheckDefault()
  - [x] Collector goroutine: read results channel, build ScanResult, send to output channel
  - [x] Signal completion: close output channel when all jobs processed
- [x] Implement filterExploits(): apply vendor filter, device type filter, protocol enable/disable

### 2.3 Scanner — Dispatcher
- [x] Create `scanner/dispatcher.go` — job struct (exploit, taskType), jobType enum (taskCheck, taskCheckDefault, taskFingerprint)
- [x] Implement startWorkers(n): spawn N goroutines that read from jobs channel
- [x] Worker logic:
  - [x] Set options: Target, Port (from exploit.Protocol().DefaultPort()), Timeout, Verbose
  - [x] For taskCheck: call exploit.Check() → produce VulnResult
  - [x] For taskCheckDefault: call credsModule.CheckDefault() → produce []CredsResult
  - [x] Send ScanResult to results channel
- [x] Implement dispatch jobs: feed exploits into jobs channel, close when done
- [x] Implement collect results: read from results channel, aggregate, stream to caller
- [x] Implement shutdown: close jobs → wait for workers → close results → signal done

### 2.4 Port Scanner
- [x] Create `scanner/portscan.go` — Lightweight TCP connect scanner
- [x] Common IoT ports: 21 (FTP), 22 (SSH), 23 (Telnet), 53 (DNS), 80 (HTTP), 443 (HTTPS), 161 (SNMP), 1900 (UPnP), 8080 (HTTP-ALT), 8291 (WinBox), 32764 (SerComm)
- [x] Implement TCPConnectScan(target, ports) — goroutine per port, timeout per attempt, return []int (open ports)
- [x] Create `scanner/portscan_test.go` — Mock listener on random port, verify detected as open

### 2.5 Scanner Tests
- [x] Create `scanner/scanner_test.go` — Integration tests:
  - [x] Test scanner with mock exploits (fake Exploit that returns known VulnResult)
  - [x] Test scanner with mock creds (fake CredsModule that returns known CredsResult)
  - [x] Test concurrent scanning (multiple targets? No — single target, multiple exploits)
  - [x] Test vendor filtering
  - [x] Test timeout handling
  - [x] Test scanner shutdown (context cancellation)
- [x] Run `go vet ./scanner/...` and `go test ./scanner/...`

---

## Phase 3: CLI, Reverse Shell, & Shell Handler

### 3.1 Reverse Shell Implant
- [x] Create `cmds/rshell/main.go` — reverse shell binary
  - [x] Read RSHELL_HOST, RSHELL_PORT from environment
  - [x] Retry loop: 30 attempts × 2-second delay
  - [x] Connect → exec /bin/sh → pipe stdin/stdout/stderr to connection
  - [ ] Option: PID disguise (set process name to something benign) (future enhancement)
  - [ ] Option: daemonize (detach from parent, run in background) (future enhancement)
- [x] Create `cmds/rshell/main_test.go` — Integration test with mock listener

### 3.2 Cross-Compilation
- [x] Create `Makefile` with targets:
  - [x] `build`: CGO_ENABLED=0 go build → `bin/goaccess`
  - [x] `payloads`: Cross-compile rshell for all 7 architectures (arm, arm64, mips, mipsle, mips64, x86, x86_64)
  - [x] `payloads-<arch>`: Individual arch build targets
  - [x] `test`: CGO_ENABLED=0 go test ./...
  - [x] `lint`: go vet ./...
  - [x] `clean`: Remove bin/ and payload binaries
- [ ] Build all payloads and verify file sizes (should be ~2-5MB static binaries) — deferred until cross-compilation toolchain available
- [ ] Verify `payload.GetPayload()` returns correct binary for each arch — deferred

### 3.3 Shell Handler
- [x] Create `shell/shell.go` — Handler struct:
  - [x] Handler: Architecture, Method, Location, Payload, LHOST, LPORT, executeFn
  - [x] NewHandler(arch, method, location) — load payload from payload.GetPayload()
  - [x] DeployReverse() — deploy payload via wget/echo/cmd, establish reverse connection
  - [ ] DeployBind() — deploy payload, connect to bind port (future enhancement)
  - [x] Interact(conn) — read/write loop with raw terminal (similar to telnetlib interact)
  - [x] SetExecuteFunc(fn) — set the command execution callback (from exploit's Execute())
- [x] Implement wget method: Start HTTP payload server → execute wget command on target → serve payload → execute binary
- [x] Implement echo method: Chunk binary into hex → execute echo -ne "\xNN..." >> /tmp/binary commands → chmod +x → execute
- [x] Implement cmd method: Attempt reverse shell via nc/bash /dev/tcp, no binary transfer
- [x] Create `shell/shell_test.go` — Mock execute function, test wget server, test echo chunking

### 3.4 Shell Listener
- [x] Create `shell/listener.go` — Listener struct (merged into `shell/shell.go`):
  - [x] StartReverseListener() — start TCP listener, return net.Listener
  - [x] RunReverseListener() — accept connections, spawn /bin/sh per connection
- [x] Create `shell/listener_test.go` — Mock reverse connection, payload serving

### 3.5 CLI — Identify Command
- [x] Create `cmds/goaccess/main.go` — main entry point
- [x] Create `cmds/goaccess/identify.go` — cmdIdentify(args):
  - [x] Parse flags: --json, --oui-only, --verbose, --threads, --timeout
  - [x] Validate target argument (IP or hostname)
  - [x] Create scanner.Scanner with config (threads + timeout wired)
  - [x] Call scanner.Identify()
  - [x] Format output: PrintFingerprint (table with Vendor, Model, Firmware, etc.)
  - [x] If --json: output FingerprintResult as JSON
  - [x] If --oui-only: only show OUI vendor lookup (no network probes)

### 3.6 CLI — Scan Command
- [x] Create `cmds/goaccess/scan.go` — cmdScan(args):
  - [x] Parse flags: --vendor, --type, --threads, --timeout, --skip-creds, --skip-exploits, --json, --output, --verbose
  - [x] Validate target argument
  - [x] Create scanner.Scanner with ScanConfig
  - [x] Call scanner.Scan() — get result channel
  - [x] Stream results: print each vulnerability/credential as discovered
  - [x] If --json --output: write JSON array to file
  - [x] Print summary: X vulnerabilities found, Y credentials found

### 3.7 CLI — Access Command
- [x] Create `cmds/goaccess/access.go` — cmdAccess(args):
  - [x] Parse flags: --threads, --timeout, --payload, --listen, --shell, --no-exploit, --no-creds, --json, --output, --verbose
  - [x] Validate target argument
  - [x] Create scanner.Scanner
  - [x] Prioritized access flow: Identify → Credential recovery → Exploitation → Shell access
  - [x] If --listen: start shell listener on specified port
  - [x] If --shell: drop to interactive shell after exploitation
  - [x] If --no-exploit: skip exploitation phase (creds only)
  - [x] If --no-creds: skip creds phase (exploits only)
  - [x] If --payload: select preferred payload architecture
  - [x] Format output: AccessResult with credentials, exploits used, shell status
  - [x] If --json --output: write JSON to file

### 3.8 CLI — List Command
- [x] Create `cmds/goaccess/list.go` — cmdList(args):
  - [x] Sub-resource: exploits, credentials, payloads, keys, vendors
  - [x] Parse flags: --vendor, --type, --json
  - [x] List exploits: query registry, print table + JSON output
  - [x] List creds: query creds registry, print table + JSON output
  - [x] List payloads: query payload.List(), print table + JSON output
  - [x] List keys: query ssh_keys.All(), print table + JSON output
  - [x] List vendors: aggregate all vendors from registry, print list + JSON output

### 3.9 Exploits Import File
- [x] Create `exploits/exploits.go` — package doc string
- [x] Create `exploits/imports.go` — blank imports for all exploit packages added in Phase 4+
- [ ] Create `exploits/generic/imports.go` — blank imports (not needed; all in imports.go)
- [ ] Create `exploits/routers/imports.go` — blank imports for router vendor sub-packages (deferred: empty dirs)
- [ ] Create `exploits/cameras/imports.go` — blank imports for camera vendor sub-packages (deferred: empty dirs)
- [ ] Create `exploits/misc/imports.go` — blank imports for misc vendor sub-packages (deferred: empty dirs)

### 3.10 Main Binary Integration
- [x] Add blank import to `cmds/goaccess/main.go`: `import _ "github.com/cookiengineer/goaccess/exploits"`
- [x] Build final binary: `CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/goaccess ./cmds/goaccess`
- [x] Verify binary works: `./bin/goaccess list exploits` (shows 4 exploits)
- [x] Verify `./bin/goaccess identify localhost` works
- [x] Run `go vet ./cmds/goaccess/...` and `go test ./cmds/goaccess/...`

### 3.11 Phase 3 Verification
- [ ] Run `make payloads` — verify all architectures compile (deferred: cross-compilation toolchain)
- [x] Run `make build` — verify main binary compiles
- [x] Run `go vet ./...` — verify no warnings
- [x] Run `go test ./...` — verify all tests pass (184 tests)
- [x] Test `./bin/goaccess` with each subcommand (identify, scan, access, list)

---

## Phase 4: Initial Exploit Modules + All Creds

### 4.1 Generic Exploits (7 packages — all done)
- [x] `exploits/generic/heartbleed/` — Heartbleed (TCP, CVE-2014-0160)
- [x] `exploits/generic/shellshock/` — ShellShock (HTTP, CVE-2014-6271)
- [x] `exploits/generic/tcp_32764/rce/` — TCP-32764 RCE (TCP, SerComm backdoor)
- [x] `exploits/generic/tcp_32764/info_disclosure/` — TCP-32764 Info Disclosure (TCP)
- [x] `exploits/generic/rom_0/` — RomPager ROM-0 (HTTP, CVE-2014-4019, LZS decompression)
- [x] `exploits/generic/gpon_home_gateway/` — GPON Home Gateway RCE (HTTP, CVE-2018-10561)
- [x] `exploits/generic/ssh_auth_keys/` — Merged into credentials/ssh_auth_keys.go (SSH)

### 4.2 Generic Creds Modules (9 packages — all done)
- [x] `exploits/generic/credentials/telnet_default.go` — TelnetDefault
- [x] `exploits/generic/credentials/ssh_default.go` — SSHDefault
- [x] `exploits/generic/credentials/ftp_default.go` — FTPDefault
- [x] `exploits/generic/credentials/http_basic_digest_default.go` — HTTPBasicDigestDefault
- [x] `exploits/generic/credentials/snmp_default.go` — SNMPDefault
- [x] `exploits/generic/credentials/ssh_auth_keys.go` — SSHAuthKeys (uses ssh_keys/ registry)
- [x] `exploits/generic/credentials/telnet_bruteforce.go` — TelnetBruteforce (username × password cartesian)
- [x] `exploits/generic/credentials/ssh_bruteforce.go` — SSHBruteforce
- [x] `exploits/generic/credentials/ftp_bruteforce.go` — FTPBruteforce
- [x] Unit test each creds module — credentials_test.go covers all 9 modules

### 4.3 D-Link Router Exploits — Priority Set (6 exploits)
- [x] `routers/dlink/dir_300_600_rce/` — DIR-300/600 HNAP RCE (HTTP + ExecuteExploit)
- [x] `routers/dlink/dir_300_645_815_upnp_rce/` — UPnP RCE (UDP + ExecuteExploit)
- [x] `routers/dlink/dir_8xx_password_disclosure/` — Password Disclosure (HTTP)
- [x] `routers/dlink/dir_825_path_traversal/` — Path Traversal (HTTP, authenticated)
- [x] `routers/dlink/multi_hnap_rce/` — Multi HNAP RCE (HTTP + ExecuteExploit)
- [x] `routers/dlink/dsl_2750b_rce/` — DSL-2750B RCE (HTTP + ExecuteExploit)

### 4.4 D-Link Router Creds (3 modules)
- [x] `routers/dlink/credentials/telnet_default.go` — admin:admin, 1234:1234, root:12345, root:root
- [x] `routers/dlink/credentials/ssh_default.go` — same wordlist
- [x] `routers/dlink/credentials/ftp_default.go` — admin:admin, root:root, anonymous:anonymous

### 4.5 TP-Link Router Exploits (1 exploit + creds)
- [x] `routers/tplink/archer_c2_c20i_rce/` — Archer C2/C20i blind command injection (HTTP + ExecuteExploit)
- [x] `routers/tplink/credentials/telnet_default.go` — admin:admin
- [x] `routers/tplink/credentials/ssh_default.go`
- [x] `routers/tplink/credentials/ftp_default.go`

### 4.6 MikroTik Router Exploits (1 exploit + creds)
- [x] `routers/mikrotik/winbox_auth_bypass_creds_disclosure/` — WinBox Auth Bypass (TCP binary, XOR-decrypt, MD5 keying)
- [x] `routers/mikrotik/credentials/telnet_default.go` — admin:admin
- [x] `routers/mikrotik/credentials/ssh_default.go`
- [x] `routers/mikrotik/credentials/ftp_default.go`
- [ ] `routers/mikrotik/credentials/api_ros_default.go` — RouterOS API defaults (future)

### 4.7 FortiNet Router Exploits (1 exploit + creds)
- [x] `routers/fortinet/fortigate_os_backdoor/` — FortiGate SSH Backdoor (SSH, SHA1 challenge-response)
- [x] `routers/fortinet/credentials/telnet_default.go` — admin:, maintainer:bcpb+serial#, maintainer:admin
- [x] `routers/fortinet/credentials/ssh_default.go`
- [x] `routers/fortinet/credentials/ftp_default.go`

### 4.8 Netcore Router Exploits (1 exploit + creds)
- [x] `routers/netcore/udp_53413_rce/` — UDP 53413 Backdoor RCE (UDP binary + ExecuteExploit)
- [x] `routers/netcore/credentials/telnet_default.go` — admin:admin, guest:guest
- [x] `routers/netcore/credentials/ssh_default.go`
- [x] `routers/netcore/credentials/ftp_default.go`

### 4.9 Camera Exploits — Multi (2 exploits)
- [x] `cameras/multi/cctv_dvr_rce/` — CCTV DVR RCE (HTTP + ExecuteExploit)
- [x] `cameras/multi/p2p_wificam_rce/` — P2P WiFiCam RCE (HTTP, two-stage: creds extraction + authenticated RCE)

### 4.10 Router Import Files
- [x] Update `exploits/imports.go` with all new imports (18 exploits + 24 creds)

### 4.11 Phase 4 Verification
- [x] Run `go vet ./exploits/...` — verify no warnings across all exploits
- [x] Run `go test ./exploits/...` — 271 tests pass
- [x] Run `CGO_ENABLED=0 go build -o bin/goaccess ./cmds/goaccess` — builds with all exploits
- [x] `./bin/goaccess list exploits` — 18 exploits listed across 7 vendors
- [x] `./bin/goaccess list creds` — 24 credentials modules listed across 6 vendors
- [x] Scanner integration: Identify/Scan/Access pipeline works with registered exploits

---

## Phase 5: Full Exploit Coverage — COMPLETE

### 5.1 D-Link Remaining Exploits (21 exploits)
- [x] `dlink/dcs_930l_auth_rce` — DCS-930L Auth RCE
- [x] `dlink/dgs_1510_add_user` — DGS-1510 Add User
- [x] `dlink/dir_300_320_600_615_info_disclosure` — Info Disclosure
- [x] `dlink/dir_300_320_615_auth_bypass` — Auth Bypass
- [x] `dlink/dir_645_815_rce` — DIR-645/815 RCE
- [x] `dlink/dir_645_password_disclosure` — Password Disclosure
- [x] `dlink/dir_655_866_652_rce` — DIR-655/866/652 RCE
- [x] `dlink/dir_815_850l_rce` — DIR-815/850L RCE
- [x] `dlink/dir_850l_creds_disclosure` — Creds Disclosure
- [x] `dlink/dns_320l_327l_rce` — DNS-320L/327L RCE
- [x] `dlink/dsl_2640b_dns_change` — DSL-2640B DNS Change
- [x] `dlink/dsl_2730_2750_path_traversal` — DSL-2730/2750 Path Traversal
- [x] `dlink/dsl_2730b_2780b_526b_dns_change` — DNS Change
- [x] `dlink/dsl_2740r_dns_change` — DNS Change
- [x] `dlink/dsl_2750b_info_disclosure` — Info Disclosure
- [x] `dlink/dsp_w110_rce` — DSP-W110 RCE
- [x] `dlink/dvg_n5402sp_path_traversal` — Path Traversal
- [x] `dlink/dwl_3200ap_password_disclosure` — Password Disclosure
- [x] `dlink/dwr_932_info_disclosure` — Info Disclosure
- [x] `dlink/dwr_932b_backdoor` — Backdoor RCE
- [x] `dlink/multi_hedwig_cgi_exec` — Multi hedwig.cgi RCE

### 5.2 Cisco Exploits (10 exploits)
- [x] `cisco/rv320_command_injection` — RV320 Command Injection
- [x] `cisco/catalyst_2960_rocem` — Catalyst 2960 ROCEM (TCP)
- [x] `cisco/dpc2420_info_disclosure` — DPC2420 Info Disclosure
- [x] `cisco/firepower_management60_path_traversal` — Path Traversal
- [x] `cisco/firepower_management60_rce` — RCE
- [x] `cisco/ios_http_authorization_bypass` — Auth Bypass
- [x] `cisco/secure_acs_bypass` — Secure ACS Bypass
- [x] `cisco/ucm_info_disclosure` — UCM Info Disclosure
- [x] `cisco/ucs_manager_rce` — UCS Manager RCE
- [x] `cisco/unified_multi_path_traversal` — Path Traversal

### 5.3 Netgear Exploits (10 exploits)
- [x] `netgear/dgn2200_dnslookup_cgi_rce` — DGN2200 dnslookup.cgi RCE
- [x] `netgear/dgn2200_ping_cgi_rce` — DGN2200 ping.cgi RCE
- [x] `netgear/jnr1010_path_traversal` — JNR1010 Path Traversal
- [x] `netgear/multi_password_disclosure_2017_5521` — Password Disclosure
- [x] `netgear/multi_rce` — Multi RCE
- [x] `netgear/n300_auth_bypass` — N300 Auth Bypass
- [x] `netgear/prosafe_rce` — ProSafe RCE
- [x] `netgear/r7000_r6400_rce` — R7000/R6400 RCE
- [x] `netgear/rax30_rce` — RAX30 RCE
- [x] `netgear/wnr500_612v3_jnr1010_2010_path_traversal` — Path Traversal

### 5.4 TP-Link Remaining (4 exploits)
- [x] `tplink/archer_c9_admin_password_reset` — Archer C9 Password Reset (CVE-2017-11519, glibc PRNG)
- [x] `tplink/wdr740nd_wdr740n_backdoor` — Backdoor RCE (ExecuteExploit)
- [x] `tplink/wdr740nd_wdr740n_path_traversal` — Path Traversal
- [x] `tplink/wdr842nd_wdr842n_configure_disclosure` — Configure Disclosure (DES decryption)

### 5.5 Linksys (5 exploits)
- [x] `linksys/1500_2500_rce`
- [x] `linksys/eseries_themoon_rce` (TheMoon worm exploit)
- [x] `linksys/smartwifi_password_disclosure`
- [x] `linksys/wap54gv3_rce`
- [x] `linksys/wrt100_110_rce`

### 5.6 ASUS (3 exploits)
- [x] `asus/asuswrt_lan_rce`
- [x] `asus/infosvr_backdoor_rce`
- [x] `asus/rt_n16_password_disclosure`

### 5.7 Belkin (6 exploits)
- [x] `belkin/auth_bypass`
- [x] `belkin/g_n150_password_disclosure`
- [x] `belkin/g_plus_info_disclosure`
- [x] `belkin/n150_path_traversal`
- [x] `belkin/n750_rce`
- [x] `belkin/play_max_prce`

### 5.8 ZyXEL (5 exploits)
- [x] `zyxel/d1000_rce`
- [x] `zyxel/d1000_wifi_password_disclosure`
- [x] `zyxel/p660hn_t_v1_rce`
- [x] `zyxel/p660hn_t_v2_rce`
- [x] `zyxel/zywall_usg_extract_hashes`

### 5.9 Huawei, 3Com, Technicolor, ZTE, IPFire, and Remaining Router Vendors
- [x] Complete all 30 remaining router exploits across 18 vendors — **DONE**
- [x] Each with exploit.go + exploit_test.go

### 5.10 Remaining Camera Exploits (15 exploits + 4 multi)
- [x] Complete all camera-specific exploits: brickcom (2), grandstream (2), acti (1), avigilon (1), beward (1), cisco (1), dlink (1), geuterbruck (1), honeywell (1), jovision (1), mvpower (1), siemens (1), xiongmai (1)
- [x] Camera multi: P2P_wificam_credential_disclosure, dvr_creds_disclosure, jvc_vanderbilt_honeywell_path_traversal, netwave_ip_camera_information_disclosure

### 5.11 Misc Device Exploits (4 exploits)
- [x] `misc/asus/b1m_projector_rce`
- [x] `misc/miele/pg8528_path_traversal`
- [x] `misc/watchguard/xcs_9_rce`
- [x] `misc/wepresent/wipg1000_rce`

### 5.12 Remaining Creds Modules
- [x] 27 router vendor credential sets (telnet, ssh, ftp per vendor) — 81 modules — **DONE**
- [x] 25 camera vendor credential sets (telnet, ssh, ftp per vendor) — 75 modules — **DONE**
- [x] Each creds module has vendor-specific default wordlist exported as Go var
- [x] 9 generic credentials modules (defaults + bruteforce + auth keys) — **DONE**

### 5.13 Import File Updates
- [x] Update `exploits/imports.go` with all 47 vendor credentials packages

### 5.14 Phase 5 Verification
- [x] Run `go test ./exploits/...` — 895 tests pass
- [x] `CGO_ENABLED=0 go build -o bin/goaccess ./cmds/goaccess` — builds with all modules
- [x] `./bin/goaccess list exploits` — 142 exploits across 43 vendors
- [x] `./bin/goaccess list credentials` — 165 credentials modules across 43 vendors
- [x] Full scanner integration works

---

## Phase 6: Advanced Features

### 6.1 Password Generators
- [x] Implement PasswordGenerator interface for known MAC-derived algorithms:
  - [x] D-Link WPA default key (last 8 chars of MAC, uppercase) — `routers/dlink/credentials/generator_wpa.go`
  - [x] D-Link Alphanetworks format patterns — `routers/dlink/credentials/generator_alphanet.go`
  - [x] TP-Link MD5-based generators — `routers/tplink/credentials/generator_md5.go`
  - [x] Thomson CPxxx patterns — `routers/thomson/credentials/generator.go`
  - [x] NETGEAR adjective+noun patterns — `routers/netgear/credentials/generator.go`
- [x] Implement generators in each vendor's `creds/` package
- [x] Integrate with Access pipeline: run generators before brute-force modules — wired in `scanner/scanner.go` via `testGeneratedCredentials()`

### 6.2 HTTP Form Brute-Force Module
- [x] `exploits/generic/credentials/http_form_default.go`
- [x] Parse HTML login forms, detect username/password fields, detect auth failure message
- [x] Support CSRF token extraction from forms
- [x] Support custom success/failure detection patterns

### 6.3 SNMP Brute-Force Module
- [x] `exploits/generic/credentials/snmp_bruteforce.go`
- [x] Full community string dictionary brute-force using wordlist module

### 6.4 HTTP Basic/Digest Brute-Force Module
- [x] `exploits/generic/credentials/http_basic_digest_bruteforce.go`
- [x] Full username+password dictionary brute-force

### 6.5 JSON Output & Report Generation
- [x] Full JSON output for all CLI commands (identify, scan, access, list)
- [x] Report struct with structured data (PrintScanResultsJSON, PrintScanResult now handles JSON)
- [x] Support piping output: stdout + JSON file simultaneously (--output flag on all commands)

### 6.6 Docker Cross-Compilation
- [x] Create Dockerfile for cross-compilation environment — multi-stage build with TARGETARCH support
- [x] CI pipeline: GitHub Actions to build all payloads on every release — `.github/workflows/build.yml`
- [x] Cache Go module dependencies between builds — `go mod download` before copy

### 6.7 Performance Optimization
- [x] Connection pooling for HTTP clients — `MaxIdleConns: 100, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30s`
- [x] Result deduplication — `deduplicateCredentials()` and `deduplicateVulnerabilities()` in scanner
- [x] Timeout calibration per protocol — each protocol client uses configurable Timeout from ScanConfig
- [ ] Memory profiling and optimization for large scans (future)

---

## Phase 7: Documentation & Polish

### 7.1 Documentation
- [x] `README.md` — Project overview, installation, usage examples
- [x] `docs/MASTERPLAN.md` — Architecture reference (already written)
- [x] `docs/EXPLOITS.md` — Exploit porting guide (already written)
- [x] `docs/TODO.md` — This file
- [x] `docs/CONTRIBUTING.md` — How to write new exploits, style guide
- [ ] GoDoc comments on all exported types and functions (future)

### 7.2 Polish
- [x] Consistent error messages and exit codes — all CLI commands use stderr for errors, os.Exit(1)
- [x] Progress bars for long-running scans — progress line shown during scan (every 10 results)
- [x] Color output theme consistency — report package handles all colorized output
- [x] Shell autocompletion script generation (bash/zsh) — `goaccess completion <bash|zsh>`

### 7.3 Security Review
- [x] Review all protocol clients for TLS/certificate validation — HTTP uses InsecureSkipVerify by design (IoT targets)
- [x] Review all exploits for safe command escaping — exploit modules use structured parameters
- [x] Review shell handler for proper cleanup — defer Close() on listeners
- [x] Ensure no hardcoded credentials in non-creds code — credentials only in wordlists + creds modules
- [x] Ensure rshell implant does not write to disk — runs /bin/sh from memory, no file writes

---

## Phase 6: Credential Extraction & Login Verification

### 6.1 CredentialedExploit Interface
- [x] Create `interfaces/credentialed.go` — CredentialedExploit interface (Credentials() *Credential, Login(Credential) error)
- [x] Interface extends Exploit for exploits that can extract and verify credentials

### 6.2 Parsers Package
- [x] Create `parsers/config.go` — XML regex parser, INI parser, key-value parser, password/username extractors, HTML form parser
- [x] Create `parsers/config_test.go` — 8 tests covering all parser functions

### 6.3 Credential Disclosure Exploits (30 exploits)
- [x] Implement Credentials() for all 30 password/credential disclosure exploits
- [x] Implement Login() using HTTP Basic Auth for web-based exploits
- [x] Add unit tests (TestCredentials + TestLogin) for each exploit
- [x] Examples: dlink/dir_8xx_password_disclosure, belkin/g_n150_password_disclosure, mikrotik/winbox_auth_bypass_creds_disclosure, technicolor/tc7200_password_disclosure, cameras/P2P_wificam_credential_disclosure, etc.

### 6.4 RCE Exploits (58 exploits)
- [x] Implement Credentials() using Execute("cat /etc/passwd") for command-execution exploits
- [x] Implement Login() using appropriate protocol (HTTP, SSH, Telnet)
- [x] Add unit tests for each exploit

### 6.5 Remaining Exploits (53 exploits)
- [x] Path traversal: Credentials() reads /etc/passwd via traversal endpoint
- [x] Info disclosure: Credentials() parses disclosed data
- [x] Auth bypass: Credentials() returns hardcoded/generated credentials
- [x] Config change/DNS: Credentials() returns nil where not applicable
- [x] UDP/TCP: Login() returns descriptive errors where not applicable

### 6.6 Documentation
- [x] Create `docs/EXPLOITS_STATUS.md` — Full status table for all 142 exploits (Implementation, Unit Test, Run, Credentials, Login)
- [x] All 142 exploits: ✓ Implementation, ✓ Unit Test, ✓ Run, ✓ Credentials, ✓ Login

### 6.7 Phase 6 Verification
- [x] `CGO_ENABLED=0 go build ./...` — builds with all new methods
- [x] `CGO_ENABLED=0 go test ./...` — 1,327 tests pass, 0 failures
- [x] 162 packages passing
- [x] All 142 exploits implement CredentialedExploit interface

---

## Phase 7: Future Enhancements
- [x] Payload cross-compilation (`make payloads`) for all 7 architectures — 14 binaries built (~2MB each)
- [x] Integration tests with podman containers (SSH/FTP/Telnet/SNMP) — `scanner/integration_test.go`
- [x] Password generators (MAC-derived, serial-derived per vendor) — 5 generators implemented
- [x] HTTP form brute-force with CSRF token handling — `http_form_default.go`
- [x] JSON output for all CLI commands — `--json` and `--output` flags on all commands
- [x] Docker cross-compilation — `Dockerfile` + `.github/workflows/build.yml`
- [x] Performance optimization — HTTP connection pooling, credential/vuln deduplication
- [x] README.md — project overview, installation, usage examples
- [x] CONTRIBUTING.md — exploit writing guide, code conventions, test patterns
- [x] Shell autocompletion — `goaccess completion <bash|zsh>`
- [x] Progress bars — scan progress line during long scans
- [x] Interactive shell mode with terminal emulation — `--shell` flag uses `shell.Interact()`
- [x] Plugin system for user-defined exploits (future)

---

## Phase 8: Drones Exploit Category — COMPLETE

### 8.1 Core Type Changes
- [x] Add `DeviceDrone DeviceType = "drone"` to `types/info.go`
- [x] Add `ProtocolVTwoSDK` to `types/protocol.go`
- [x] Add `"drone": 3` to `deviceTypeOrder` in `cmds/goaccess/list.go`

### 8.2 vtwo_sdk Protocol Package (`protocols/vtwo_sdk/`)
- [x] Implement `vtwo_sdk_types.go` — Packet, TLV structs, MsgType constants, Marshal/Unmarshal, malformed packet builders
- [x] Implement `vtwo_sdk.go` — Client struct (Target, Port, Timeout), Connect, SendPacket, RecvPacket, SendAndRecv, SessionInit, PullFile, PushFile, SessionClose, Close, IsConnected, IsSessionActive
- [x] Implement `vtwo_sdk_test.go` — 20 tests: packet framing, TLV packing/unpacking, session init, malformed packet construction, mock server integration
- [x] Run `go vet ./protocols/vtwo_sdk/...` and `go test ./protocols/vtwo_sdk/...` — 20 tests pass

### 8.3 Parrot Drone Exploits
- [x] `drones/parrot/ar_drone_telnet_root/` — Anonymous telnet root shell + AT command land/deactivate (Exploit, ExecuteExploit, CredentialedExploit) — 11 tests
- [x] `drones/parrot/ar_drone_ftp_anon/` — Anonymous FTP with config.ini credential extraction (Exploit, CredentialedExploit) — 12 tests
- [x] `drones/parrot/bebop_ftp_anon/` — Bebop FTP detection + anonymous access + config extraction (Exploit, CredentialedExploit) — 9 tests
- [x] `drones/parrot/credentials/` — telnet_default.go (4 creds), ftp_default.go (3 creds), http_default.go (3 creds) — tested centrally

### 8.4 DJI Drone Exploits
- [x] `drones/dji/http_media_api/` — CVE-2023-6949 unauthenticated media enumeration + download (Exploit, CredentialedExploit) — 11 tests
- [x] `drones/dji/vtwo_sdk_crash/` — CVE-2023-51452/53 malformed pull/push file crash vectors (Exploit, CredentialedExploit) — 9 tests
- [x] `drones/dji/vtwo_sdk_rce/` — CVE-2023-51454/55/56 OOB write/array/index vectors + land/deactivate (Exploit, ExecuteExploit, CredentialedExploit) — 10 tests
- [x] `drones/dji/ftp_diagnostic_dos/` — CVE-2023-6950 FTP SIZE command DoS detection (Exploit, CredentialedExploit) — 7 tests
- [x] `drones/dji/credentials/` — ftp_default.go (2 creds), http_default.go (3 creds) — tested centrally

### 8.5 Tello + DBPOWER Exploits
- [x] `drones/tello/udp_control_land/` — UDP flight control: SDK "command" activation, "land", "emergency" motor stop (Exploit, ExecuteExploit, CredentialedExploit) — 10 tests
- [x] `drones/tello/credentials/` — udp_default.go (1 cred: no auth required) — tested centrally
- [x] `drones/dbpower/u818a_ftp_anon/` — CVE-2017-3209 anonymous FTP with full FS read/write (Exploit, CredentialedExploit) — 7 tests

### 8.6 Generic Drone Modules
- [x] `drones/generic/drone_identify/` — Multi-vendor fingerprinting: MAC OUI lookup (DJI 60:60:1F, Parrot A0:14:3D/90:03:B7/00:26:7E, Ryze AC:3A:7A), HTTP banner matching — 10 tests
- [x] `drones/generic/drone_open_ports/` — Concurrent scanning of 8 drone-specific ports (21, 23, 80, 554, 5555, 8889, 10000, 11111) with vendor pattern analysis — 6 tests
- [x] `drones/generic/drone_creds/` — 9 known drone default credential combinations across Telnet(23)/FTP(21) — 9 tests

### 8.7 Integration
- [x] Create `exploits/drones/imports.go` with blank imports for all 15 drone packages
- [x] Create `exploits/drones/credentials_test.go` with centralized tests for all 6 credential modules
- [x] Update `exploits/imports.go` with `_ "github.com/cookiengineer/goaccess/exploits/drones"` import
- [x] Update `docs/MASTERPLAN.md` — drone directory structure + DeviceDrone + ProtocolVTwoSDK
- [x] Update `docs/EXPLOITS_STATUS.md` — drone exploit + credential status tables
- [x] Run `go vet ./...` — clean, no warnings
- [x] Run `go test ./...` — all packages pass (existing 1,365+ tests + new drone tests)
- [x] Run `CGO_ENABLED=0 go build -o bin/goaccess ./cmds/goaccess` — builds successfully
- [x] Run `./bin/goaccess list exploits --type drone` — 12 drone exploits listed across 4 vendors (dbpower, dji, generic, parrot, tello)
- [x] Run `./bin/goaccess list credentials --vendor parrot/dji/tello` — 6 credential modules verified

### Drone Exploits Summary

| Vendor | Exploits | Credential Modules | Tests |
|--------|----------|-------------------|-------|
| Parrot | 3 (telnet root, ftp anon, bebop ftp) | 3 (telnet, ftp, http) | 32 |
| DJI | 4 (http media, vtwo_sdk crash, vtwo_sdk rce, ftp dos) | 2 (ftp, http) | 37 |
| Tello | 1 (udp control land) | 1 (udp) | 10 |
| DBPOWER | 1 (u818a ftp) | — | 7 |
| Generic | 3 (identify, open ports, creds) | — | 25 |
| **Total** | **12** | **6** | **+ central creds test** |

**Combined with existing 142 exploits, total: 154 exploits, 1,365+ tests all passing.**

---

## Phase 9: Drone OUI Integration & Advanced Exploits — COMPLETE

### 9.1 Scanner Drone OUI Integration
- [x] Add drone ports (10000, 8889) to `CommonIOTPorts` in `scanner/portscan.go`
- [x] Add `DroneOUIs` map to `scanner/portscan.go` (DJI 60:60:1F/E0:4F:43/34:D2:62/28:E5:B6, Parrot A0:14:3D/90:03:B7/00:26:7E, Ryze AC:3A:7A)
- [x] Add `DroneServicePorts` map with port-to-description mappings
- [x] Add `IsDroneOUI()` function to detect drone vendors from MAC OUI
- [x] Add `DroneServiceHints()` function to generate hints from open ports
- [x] Integrate drone service detection in Identify Phase 1 (port scanning): append drone service hints
- [x] Integrate drone OUI detection in Identify Phase 2 (ARP probe): append drone vendor match, set Vendor field
- [x] Add `cleanMACForOUI()` helper to scanner

### 9.2 DJI Firmware Version Detection via vtwo_sdk
- [x] Extend `protocols/vtwo_sdk/` with exported `SequenceID` field
- [x] Create `drones/dji/vtwo_sdk_firmware_info/` — queries known version file paths via FileInfo requests, analyzes firmware content for model and version — 8 tests
- [x] Firmware model matching: 12 DJI model codes (WM160, WM220, WM230, WM245, WM247, WM1601, WM2408, WM1611, WM2405, WM2001, WM330A) with longest-prefix-first matching

### 9.3 DUMLRacer Root Access Exploit
- [x] Create `protocols/duml/` package:
  - Full DJI DUML protocol implementation (magic 0x55, protocol v4, packet format)
  - CRC-16 algorithm with 256-entry lookup table (seed 0x3692)
  - Packet constructors: BuildUpgradePacket (0xFC), BuildReportPacket (0x66), BuildFileSizePacket (0xB1), BuildHashPacket (0x8A), BuildCleanupPacket (0x33)
  - Device ID maps for AC, RC, GL targets with per-command source/target IDs
  - FTP defaults: 192.168.42.2:21 (nouser/nopass), upload path /upgrade/dji_system.bin
- [x] Create `drones/dji/dumlracer_root/` — full DUMLRacer exploit with:
  - FTP anonymous access detection + upgrade path check
  - vtwo_sdk service presence check (port 10000)
  - gzip-compressed tar payload construction with 100MB dummy file + symlink + ADB-enabling scripts
  - Stage 1: dummy + `jcase -> /data/` symlink + flag marker
  - Stage 2: dummy + `jcase/.bin/grep` (ADB root enabler) + `jcase/.bin/foo` (boot persistence) + wellhello marker
  - Exploit plan generation: full step-by-step race condition instructions
  - Implements Exploit, ExecuteExploit (FTP commands via Execute()), CredentialedExploit — 11 tests
- [x] All 13 DUML protocol tests pass

---

## Phase 9.5: HTTP Welcome Page Fingerprinting — COMPLETE

### 9.5.1 HTTPIndicator Type
- [x] Create `types/http_indicator.go` — HTTPIndicator struct with Headers, HeaderContent, Title, Content, TitleRegex, ContentRegex, MD5 fields
- [x] AND-across-fields, OR-within-fields semantics (Content uses AND to match Routeglass `body=X&&body=Y` patterns)

### 9.5.2 Embedded Indicator Database
- [x] Convert all ~300 Routeglass AdvancedRule entries to HTTPIndicator JSON format
- [x] Mechanical conversion: split `||` into separate indicators (cross-field OR), merge same-field OR into arrays
- [x] `scanner/http_indicators.json` — 405 entries covering 103 vendors, `go:embed` into the scanner package

### 9.5.3 Matching Engine
- [x] `scanner/http_indicators.go` — loadHTTPIndicators(), probeHTTPIndicators(), matchCompiledIndicator()
- [x] Regex pre-compilation at init time for performance
- [x] Path-based response caching (each unique path fetched once, shared across indicators)
- [x] First-match-wins at 0.95 confidence

### 9.5.4 Scanner Integration
- [x] Insert `probeHTTPIndicators()` as Phase 2 in Identify() pipeline, right after port scanning
- [x] Removed old `probeHTTP()` — superseded by the more thorough indicator-based scan
- [x] Phase renumbering: Port scan (1) → HTTP indicators (2) → ARP (3) → UPnP (4) → SNMP (5) → Exploit fingerprints (6)
- [x] Updated `scanner/fingerprint_test.go` — TestProbeHTTPIndicators_NoMatch

### 9.5.5 Documentation
- [x] Update `docs/MASTERPLAN.md` — new type docs, repository structure, identify pipeline diagram
- [x] Update `docs/PROGRESS.md` — scanner file listing, summary table
- [x] Update `docs/TODO.md` — this section

### 9.5.6 Verification
- [x] `CGO_ENABLED=0 go build ./...` — all packages compile
- [x] `go vet ./...` — no warnings
- [x] `go test ./...` — 1,365+ tests pass (0 failures)

---

## Phase 9.6: Firmware Version Extraction — COMPLETE

### 9.6.1 Type Changes
- [x] Add `FirmwareRegex` and `FirmwareGroup` fields to `types/http_indicator.go` HTTPIndicator struct
- [x] `FirmwareRegex`: optional regex with one capture group for the version string
- [x] `FirmwareGroup`: capture group index (1-based, default 1)

### 9.6.2 In-Band Firmware Extraction (GET)
- [x] When an HTTPIndicator matches, apply FirmwareRegex to the cached response body
- [x] Extract version into `FingerprintResult.Firmware`
- [x] Add firmware regex patterns to 93 indicators across 33 router vendors

### 9.6.3 Out-of-Band Firmware Probes (POST)
- [x] `firmwareProbes` registry in `http_indicators.go:init()` for POST-based endpoints
- [x] Sagemcom SAH probe: POST `/ws/DeviceInfo` with `Content-Type: application/x-sah-ws-4-call+json`
- [x] `probeFirmware()` called after Phase 2 if vendor is known and HTTP port is open

### 9.6.4 Server Header Fallback
- [x] Extract firmware from known server software version patterns in HTTP response headers
- [x] Patterns: `cisco-IOS/X.Y`, `uFOS/X.Y`, `RomPager/X.Y`, `GoAhead-Webs/X.Y`, `mini_httpd/X.Y`, `lighttpd/X.Y`, `thttpd/X.Y`, `Boa/X.Y`

### 9.6.5 Firmware Patterns Coverage (138 vendors)
- [x] Routers (58): ASUS, Aruba, Belkin, Billion, Buffalo, Cisco, Comtrend, D-Link, DD-WRT, DrayTek, Fortinet, FreshTomato, Gargoyle, Huawei, IPFire, Juniper, Linksys, MikroTik, NETGEAR, OpenWrt, OPNsense, Palo Alto, pfSense, Sagemcom, SonicWall, TP-Link, Technicolor, Thomson, Tomato, TRENDnet, Tenda, Ubiquiti, VyOS, ZTE, ZyXEL, and others
- [x] Cameras (28): ACTi, Arecont, Avigilon, Avtech, Axis, Basler, Beward, Brickcom, Canon, GeoVision, Geutebruck, Grandstream, Hikvision, Honeywell, IQinVision, JVC, Jovision, Mobotix, MVPower, Samsung, Sentry360, Speco, StarDot, Vacron, VideoIQ, XiongMai, and others
- [x] ISPs (14): AT&T, BT, Comcast/Xfinity, Orange/Livebox, Sky, Spectrum, Swisscom, Telstra, Virgin Media, Vodafone, KPN, StarHub, Beeline, and others
- [x] Industrial/Enterprise (20): Alcatel-Lucent, Calix, Cambium, Cradlepoint, Digi, Edimax, EnGenius, Extreme, FiberHome, Hitron, Lancom, Luxul, Motorola, Moxa, NetComm, Peplink, Ruckus, Sierra Wireless, Teltonika, Zhone, and others
- [x] Misc/IoT (8): Amazon/Eero, Google/Nest, GL.iNet, LG, Miele, Plume, WatchGuard, WePresent, Western Digital, Xiaomi
- [x] Legacy/Niche (10): 2wire, 3Com, Actiontec, Asmax, BEC, Bhu, Corega, Netsys, SMC, Shuttle, and others

### 9.6.6 Documentation
- [x] Update `docs/MASTERPLAN.md` — firmware extraction mechanisms in Identify pipeline
- [x] Update `docs/PROGRESS.md` — firmware patterns coverage list, drone probe section
- [x] Update `docs/TODO.md` — this section

---

## Phase 9.7: Drone Firmware Extraction — COMPLETE

### 9.7.1 DJI Drone Firmware
- [x] Create `scanner/drone_probes.go` — `probeDJIFirmware()` using vtwo_sdk protocol
- [x] Connect to port 10000, session init, FileInfo requests for known firmware paths
- [x] Regex extract from TLV payload values
- [x] Paths: `/etc/version`, `/etc/dji_version`, `/system/build.prop`, `/etc/os-release`, `/proc/version`

### 9.7.2 Parrot Drone Firmware
- [x] `probeParrotFirmware()` using telnet protocol (no auth root shell)
- [x] Connect to port 23, read banner, execute `uname -a`, `cat /etc/version`

### 9.7.3 HTTP Indicators for Drones
- [x] Add 2 DJI HTTP Media API indicators to `http_indicators.json`
- [x] GET `/` with title/body containing "DJI"
- [x] GET `/v2` with JSON response containing "path", "name"

### 9.7.4 Scanner Integration
- [x] Wire `probeDroneFirmware()` into Identify pipeline after Phase 2 firmware probe
- [x] Called when drone-relevant ports (10000, 23) are open

### 9.7.5 Verification
- [x] `go vet ./...` — clean
- [x] `go build ./...` — clean
- [x] `go test ./...` — all pass

---

## Phase 10: Future Enhancements
- [ ] Parrot Anafi MAVLink mission injection (CVE-2024-33844)
- [ ] Yuneec Mantis Q PX4-Autopilot command injection (CVE-2021-34125)
- [ ] Autel EVO Nano geo-fence bypass (CVE-2023-47335)

---

## Quick Reference: Build & Test Commands

```bash
# Build main binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/goaccess ./cmds/goaccess

# Build all payloads
make payloads

# Run all tests
CGO_ENABLED=0 go test ./...

# Run tests with coverage
CGO_ENABLED=0 go test -cover ./...

# Vet all packages
go vet ./...

# Vet + test + build (CI equivalent)
go vet ./... && go test ./... && CGO_ENABLED=0 go build ./cmds/goaccess

# Test a specific package
go test -v ./exploits/routers/dlink/dir_300_600_rce/

# Cross-compile a specific payload
GOOS=linux GOARCH=mips GOMIPS=softfloat CGO_ENABLED=0 go build -ldflags="-s -w" -o payload/mips/reverse_tcp cmds/rshell/main.go
```
