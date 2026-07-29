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

### 4.1 Generic Exploits (7 packages — 4 done, 3 remain)
- [x] `exploits/generic/heartbleed/` — Heartbleed (TCP, CVE-2014-0160)
  - [x] exploit.go — Send TLS heartbeat request, check for excessive data in response
  - [x] exploit_test.go — Mock heartbeat response, TLS ClientHello tests, interface compliance
- [x] `exploits/generic/shellshock/` — ShellShock (HTTP, CVE-2014-6271)
  - [x] exploit.go — Send HTTP request with `() { :; };` payload in User-Agent/Cookie/Referer headers
  - [x] exploit_test.go — Mock HTTP server echoing payload, vulnerable/not-vulnerable detection
- [x] `exploits/generic/tcp_32764/rce/` — TCP-32764 RCE (TCP, SerComm backdoor)
  - [x] exploit.go — Send "ABCDE" probe → detect endianness → send struct-packed command → read response
  - [x] exploit_test.go — Mock TCP server returning "MMcS"/"ScMM" signatures, backdoor detection test
- [x] `exploits/generic/tcp_32764/info_disclosure/` — TCP-32764 Info Disclosure (TCP)
  - [x] exploit.go — Same backdoor, command 0x01 for info retrieval
  - [x] exploit_test.go — Mock TCP server, backdoor detection test
- [ ] `exploits/generic/rom_0/` — RomPager ROM-0 (HTTP, CVE-2014-4019)
- [ ] `exploits/generic/gpon_home_gateway/` — GPON Home Gateway RCE (HTTP, CVE-2018-10561)
- [ ] `exploits/generic/ssh_auth_keys/` — SSH Authorized Keys (SSH)

### 4.2 Generic Creds Modules (9 packages — 5 done, 4 remain)
- [x] `exploits/generic/credentials/telnet_default.go` — TelnetDefault (implements CredentialsModule)
  - [x] Uses 10 default credential pairs
  - [x] CheckDefault: iterate credentials, attempt Telnet login
  - [x] Check: test if Telnet service is reachable
  - [x] Run: credential brute-force with results
- [x] `exploits/generic/credentials/ssh_default.go` — SSHDefault (10 pairs)
- [x] `exploits/generic/credentials/ftp_default.go` — FTPDefault (9 pairs incl. anonymous)
- [x] `exploits/generic/credentials/http_basic_digest_default.go` — HTTPBasicDigestDefault (9 pairs)
- [x] `exploits/generic/credentials/snmp_default.go` — SNMPDefault (10 community strings)
- [ ] `exploits/generic/credentials/ssh_auth_keys.go` — SSHAuthKeys (uses ssh_keys/ registry)
- [ ] `exploits/generic/credentials/telnet_bruteforce.go` — TelnetBruteforce (username × password cartesian)
- [ ] `exploits/generic/credentials/ssh_bruteforce.go` — SSHBruteforce
- [ ] `exploits/generic/credentials/ftp_bruteforce.go` — FTPBruteforce
- [x] Unit test each creds module — credentials_test.go covers all 5 modules

### 4.3 D-Link Router Exploits — Priority Set (6 exploits)
- [ ] `exploits/routers/dlink/dir_300_600_rce/` — DIR-300/600 HNAP RCE
  - [ ] exploit.go — POST to /HNAP1/ with command injection in SOAP header
  - [ ] exploit_test.go — Mock HNAP endpoint
  - [ ] fingerprints.go — URL patterns, UPnP patterns
- [ ] `exploits/routers/dlink/dir_300_645_815_upnp_rce/` — UPnP RCE
  - [ ] exploit.go — UDP-based: M-SEARCH with backtick command injection
  - [ ] exploit_test.go — Mock UDP server
- [ ] `exploits/routers/dlink/dir_8xx_password_disclosure/` — Password Disclosure
  - [ ] exploit.go — POST to /getcfg.php with newline-injected query params, regex parse XML
  - [ ] exploit_test.go — Mock PHP endpoint returning XML
- [ ] `exploits/routers/dlink/dir_825_path_traversal/` — Path Traversal
  - [ ] exploit.go — POST to /apply.cgi with html_response_page containing ../, Basic Auth
  - [ ] exploit_test.go — Mock CGI endpoint
- [ ] `exploits/routers/dlink/multi_hnap_rce/` — Multi HNAP RCE
  - [ ] exploit.go — SOAPAction header injection across multiple models
  - [ ] exploit_test.go — Mock HNAP endpoint
- [ ] `exploits/routers/dlink/dsl_2750b_rce/` — DSL-2750B RCE
  - [ ] exploit.go — Command injection via specific path
  - [ ] exploit_test.go

### 4.4 D-Link Router Creds (3 modules)
- [ ] `exploits/routers/dlink/creds/telnet_default.go` — D-Link Telnet defaults
  - [ ] Export `DLinkTelnetDefaults` with 4 credential pairs
- [ ] `exploits/routers/dlink/creds/ssh_default.go` — D-Link SSH defaults
- [ ] `exploits/routers/dlink/creds/ftp_default.go` — D-Link FTP defaults
- [ ] Create `exploits/routers/dlink/creds/imports.go`

### 4.5 TP-Link Router Exploits (1 exploit + creds)
- [ ] `exploits/routers/tplink/archer_c2_c20i_rce/` — Archer C2/C20i RCE
  - [ ] exploit.go — POST to /cgi?2 with IPPING_DIAG command injection, then POST to /cgi?7
  - [ ] exploit_test.go — Mock CGI endpoint
- [ ] `exploits/routers/tplink/creds/telnet_default.go` — TP-Link Telnet defaults
- [ ] `exploits/routers/tplink/creds/ssh_default.go`
- [ ] `exploits/routers/tplink/creds/ftp_default.go`
- [ ] Create `exploits/routers/tplink/creds/imports.go`
- [ ] Create `exploits/routers/tplink/imports.go`

### 4.6 MikroTik Router Exploits (1 exploit + creds)
- [ ] `exploits/routers/mikrotik/winbox_auth_bypass_creds_disclosure/` — WinBox Auth Bypass
  - [ ] exploit.go — TCP binary protocol: send crafted packet_a → parse response → send packet_b → parse user database → XOR decrypt passwords with MD5(user+key)
  - [ ] exploit_test.go — Mock TCP server returning binary WinBox responses
  - [ ] Complexity: HIGH — binary protocol parsing, XOR decryption, MD5 keying
- [ ] `exploits/routers/mikrotik/creds/telnet_default.go`
- [ ] `exploits/routers/mikrotik/creds/ssh_default.go`
- [ ] `exploits/routers/mikrotik/creds/ftp_default.go`
- [ ] `exploits/routers/mikrotik/creds/api_ros_default.go` — RouterOS API defaults
- [ ] Create `exploits/routers/mikrotik/creds/imports.go`
- [ ] Create `exploits/routers/mikrotik/imports.go`

### 4.7 FortiNet Router Exploits (1 exploit + creds)
- [ ] `exploits/routers/fortinet/fortigate_os_backdoor/` — FortiGate SSH Backdoor
  - [ ] exploit.go — SSH connect → auth_password blank → auth_interactive with SHA1(challenge+FGTAbc11*xy+Qqz27+salt) → base64 "AK1" prefix
  - [ ] exploit_test.go — Mock SSH server with interactive auth
  - [ ] Complexity: HIGH — custom SSH interactive auth, SHA1 challenge-response
- [ ] `exploits/routers/fortinet/creds/telnet_default.go`
- [ ] `exploits/routers/fortinet/creds/ssh_default.go`
- [ ] `exploits/routers/fortinet/creds/ftp_default.go`
- [ ] Create `exploits/routers/fortinet/creds/imports.go`
- [ ] Create `exploits/routers/fortinet/imports.go`

### 4.8 Netcore Router Exploits (1 exploit + creds)
- [ ] `exploits/routers/netcore/udp_53413_rce/` — UDP 53413 Backdoor RCE
  - [ ] exploit.go — Send 8 null bytes → check response signature → send AA\x00\x00AAAA<cmd>\x00 → parse response
  - [ ] exploit_test.go — Mock UDP server returning "\xD0\xA5Login:"
  - [ ] Complexity: MEDIUM — UDP binary protocol, response parsing
- [ ] `exploits/routers/netcore/creds/telnet_default.go`
- [ ] `exploits/routers/netcore/creds/ssh_default.go`
- [ ] `exploits/routers/netcore/creds/ftp_default.go`
- [ ] Create `exploits/routers/netcore/creds/imports.go`
- [ ] Create `exploits/routers/netcore/imports.go`

### 4.9 Camera Exploits — Multi (2 exploits)
- [ ] `exploits/cameras/multi/cctv_dvr_rce/` — CCTV DVR RCE
  - [ ] exploit.go — HTTP command injection in DVR web interface
  - [ ] exploit_test.go
- [ ] `exploits/cameras/multi/P2P_wificam_rce/` — P2P WiFiCam RCE
  - [ ] exploit.go — Credential extraction from /system.ini → authenticated command injection via /set_ftp.cgi
  - [ ] exploit_test.go
  - [ ] Complexity: HIGH — two-stage: info disclosure then authenticated RCE, 1275 device models

### 4.10 Router Import Files
- [ ] Update `exploits/routers/imports.go` with all implemented vendors
- [ ] Update `exploits/imports.go` with all new imports

### 4.11 Phase 4 Verification
- [ ] Run `go vet ./exploits/...` — verify no warnings across all exploits
- [ ] Run `go test ./exploits/...` — all exploit tests pass
- [ ] Run `CGO_ENABLED=0 go build -o bin/goaccess ./cmds/goaccess` — builds with all exploits
- [ ] Test `./bin/goaccess list exploits` — verify all 22 exploits listed
- [ ] Test `./bin/goaccess list creds` — verify all 34 creds modules listed
- [ ] Test scanner integration: create mock target, run identify/scan with registered exploits

---

## Phase 5: Full Exploit Coverage

### 5.1 D-Link Remaining Exploits (21 exploits)
- [ ] `dlink/dcs_930l_auth_rce` — DCS-930L Auth RCE
- [ ] `dlink/dgs_1510_add_user` — DGS-1510 Add User
- [ ] `dlink/dir_300_320_600_615_info_disclosure` — Info Disclosure
- [ ] `dlink/dir_300_320_615_auth_bypass` — Auth Bypass
- [ ] `dlink/dir_645_815_rce` — DIR-645/815 RCE
- [ ] `dlink/dir_645_password_disclosure` — Password Disclosure
- [ ] `dlink/dir_655_866_652_rce` — DIR-655/866/652 RCE
- [ ] `dlink/dir_815_850l_rce` — DIR-815/850L RCE
- [ ] `dlink/dir_850l_creds_disclosure` — Creds Disclosure
- [ ] `dlink/dns_320l_327l_rce` — DNS-320L/327L RCE
- [ ] `dlink/dsl_2640b_dns_change` — DSL-2640B DNS Change
- [ ] `dlink/dsl_2730_2750_path_traversal` — DSL-2730/2750 Path Traversal
- [ ] `dlink/dsl_2730b_2780b_526b_dns_change` — DNS Change
- [ ] `dlink/dsl_2740r_dns_change` — DNS Change
- [ ] `dlink/dsl_2750b_info_disclosure` — Info Disclosure
- [ ] `dlink/dsp_w110_rce` — DSP-W110 RCE
- [ ] `dlink/dvg_n5402sp_path_traversal` — Path Traversal
- [ ] `dlink/dwl_3200ap_password_disclosure` — Password Disclosure
- [ ] `dlink/dwr_932_info_disclosure` — Info Disclosure
- [ ] `dlink/dwr_932b_backdoor` — Backdoor RCE
- [ ] `dlink/multi_hedwig_cgi_exec` — Multi hedwig.cgi RCE

### 5.2 Cisco Exploits (10 exploits)
- [ ] `cisco/rv320_command_injection` — RV320 Command Injection
- [ ] `cisco/catalyst_2960_rocem` — Catalyst 2960 ROCEM (SNMP)
- [ ] `cisco/dpc2420_info_disclosure` — DPC2420 Info Disclosure
- [ ] `cisco/firepower_management60_path_traversal` — Path Traversal
- [ ] `cisco/firepower_management60_rce` — RCE
- [ ] `cisco/ios_http_authorization_bypass` — Auth Bypass
- [ ] `cisco/secure_acs_bypass` — Secure ACS Bypass
- [ ] `cisco/ucm_info_disclosure` — UCM Info Disclosure
- [ ] `cisco/ucs_manager_rce` — UCS Manager RCE
- [ ] `cisco/unified_multi_path_traversal` — Path Traversal

### 5.3 Netgear Exploits (10 exploits)
- [ ] `netgear/dgn2200_dnslookup_cgi_rce` — DGN2200 dnslookup.cgi RCE
- [ ] `netgear/dgn2200_ping_cgi_rce` — DGN2200 ping.cgi RCE
- [ ] `netgear/jnr1010_path_traversal` — JNR1010 Path Traversal
- [ ] `netgear/multi_password_disclosure_2017_5521` — Password Disclosure
- [ ] `netgear/multi_rce` — Multi RCE
- [ ] `netgear/n300_auth_bypass` — N300 Auth Bypass
- [ ] `netgear/prosafe_rce` — ProSafe RCE
- [ ] `netgear/r7000_r6400_rce` — R7000/R6400 RCE
- [ ] `netgear/rax30_rce` — RAX30 RCE
- [ ] `netgear/wnr500_612v3_jnr1010_2010_path_traversal` — Path Traversal

### 5.4 TP-Link Remaining (4 exploits)
- [ ] `tplink/archer_c9_admin_password_reset` — Archer C9 Password Reset
- [ ] `tplink/wdr740nd_wdr740n_backdoor` — Backdoor
- [ ] `tplink/wdr740nd_wdr740n_path_traversal` — Path Traversal
- [ ] `tplink/wdr842nd_wdr842n_configure_disclosure` — Config Disclosure

### 5.5 Linksys (5 exploits)
- [ ] `linksys/1500_2500_rce`
- [ ] `linksys/eseries_themoon_rce` (TheMoon worm exploit)
- [ ] `linksys/smartwifi_password_disclosure`
- [ ] `linksys/wap54gv3_rce`
- [ ] `linksys/wrt100_110_rce`

### 5.6 ASUS (3 exploits)
- [ ] `asus/asuswrt_lan_rce`
- [ ] `asus/infosvr_backdoor_rce`
- [ ] `asus/rt_n16_password_disclosure`

### 5.7 Belkin (6 exploits)
- [ ] `belkin/auth_bypass`
- [ ] `belkin/g_n150_password_disclosure`
- [ ] `belkin/g_plus_info_disclosure`
- [ ] `belkin/n150_path_traversal`
- [ ] `belkin/n750_rce`
- [ ] `belkin/play_max_prce`

### 5.8 ZyXEL (5 exploits)
- [ ] `zyxel/d1000_rce`
- [ ] `zyxel/d1000_wifi_password_disclosure`
- [ ] `zyxel/p660hn_t_v1_rce`
- [ ] `zyxel/p660hn_t_v2_rce`
- [ ] `zyxel/zywall_usg_extract_hashes`

### 5.9 Huawei, 3Com, Technicolor, ZTE, IPFire, and Remaining Router Vendors
- [ ] Complete all 30 remaining router exploits across 18 vendors
- [ ] Each with exploit.go + exploit_test.go + fingerprints.go (where applicable)

### 5.10 Remaining Camera Exploits (15 exploits)
- [ ] Complete all camera-specific exploits: brickcom (2), grandstream (2), acti (1), avigilon (1), beward (1), cisco (1), dlink (1), geuterbruck (1), honeywell (1), jovision (1), mvpower (1), siemens (1), xiongmai (1)

### 5.11 Misc Device Exploits (4 exploits)
- [ ] `misc/asus/b1m_projector_rce`
- [ ] `misc/miele/pg8528_path_traversal`
- [ ] `misc/watchguard/xcs_9_rce`
- [ ] `misc/wepresent/wipg1000_rce`

### 5.12 Remaining Creds Modules (~150 modules)
- [ ] Complete all 27 router vendor creds sets (telnet, ssh, ftp per vendor) — ~81 modules
- [ ] Complete all 25 camera vendor creds sets (telnet, ssh, ftp per vendor) — ~75 modules
- [ ] Each creds module has vendor-specific default wordlist exported as Go var

### 5.13 Import File Updates
- [ ] Update all `imports.go` files as exploits are added
- [ ] Verify the main `exploits/imports.go` compiles without duplicate imports

### 5.14 Phase 5 Verification
- [ ] Run `go test ./exploits/...` — ALL exploit tests pass
- [ ] Run `CGO_ENABLED=0 go build -o bin/goaccess ./cmds/goaccess` — builds with ALL exploits
- [ ] Test `./bin/goaccess list exploits` — verify count matches (142 exploits + 171 creds = 313 modules)
- [ ] Test `./bin/goaccess list exploits --vendor dlink` — verify 27 dlink exploits listed
- [ ] Full scanner test with mock targets for each vendor

---

## Phase 6: Advanced Features

### 6.1 Password Generators
- [ ] Implement PasswordGenerator interface for known MAC-derived algorithms:
  - [ ] D-Link WPA default key (last 8 chars of MAC, uppercase)
  - [ ] D-Link Alphanetworks format patterns
  - [ ] TP-Link MD5-based generators
  - [ ] Thomson CPxxx patterns
  - [ ] NETGEAR adjective+noun patterns
- [ ] Implement generators in each vendor's `creds/` package
- [ ] Integrate with Access pipeline: run generators before brute-force modules

### 6.2 HTTP Form Brute-Force Module
- [ ] `exploits/generic/creds/http_form_default.go`
- [ ] Parse HTML login forms, detect username/password fields, detect auth failure message
- [ ] Support CSRF token extraction from forms
- [ ] Support custom success/failure detection patterns

### 6.3 SNMP Brute-Force Module
- [ ] `exploits/generic/creds/snmp_bruteforce.go`
- [ ] Full community string dictionary brute-force using wordlist module

### 6.4 HTTP Basic/Digest Brute-Force Module
- [ ] `exploits/generic/creds/http_basic_digest_bruteforce.go`
- [ ] Full username+password dictionary brute-force

### 6.5 JSON Output & Report Generation
- [ ] Full JSON output for all CLI commands (identify, scan, access, list)
- [ ] Report struct with structured data
- [ ] Support piping output: stdout + JSON file simultaneously

### 6.6 Docker Cross-Compilation
- [ ] Create Dockerfile for cross-compilation environment
- [ ] CI pipeline: GitHub Actions to build all payloads on every release
- [ ] Cache Go module dependencies between builds

### 6.7 Performance Optimization
- [ ] Connection pooling for HTTP clients
- [ ] Timeout calibration per protocol
- [ ] Result deduplication (same creds found by multiple modules)
- [ ] Memory profiling and optimization for large scans

---

## Phase 7: Documentation & Polish

### 7.1 Documentation
- [ ] `README.md` — Project overview, installation, usage examples
- [ ] `docs/MASTERPLAN.md` — Architecture reference (already written)
- [ ] `docs/EXPLOITS.md` — Exploit porting guide (already written)
- [ ] `docs/TODO.md` — This file
- [ ] `docs/CONTRIBUTING.md` — How to write new exploits, style guide
- [ ] GoDoc comments on all exported types and functions

### 7.2 Polish
- [ ] Consistent error messages and exit codes
- [ ] Progress bars for long-running scans (optional)
- [ ] Color output theme consistency
- [ ] Shell autocompletion script generation (bash/zsh)

### 7.3 Security Review
- [ ] Review all protocol clients for TLS/certificate validation
- [ ] Review all exploits for safe command escaping
- [ ] Review shell handler for proper cleanup
- [ ] Ensure no hardcoded credentials in non-creds code
- [ ] Ensure rshell implant does not write to disk

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
