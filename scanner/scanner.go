package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/cookiengineer/goaccess/exploit"
	"github.com/cookiengineer/goaccess/interfaces"
	"github.com/cookiengineer/goaccess/oui"
	protocolarp "github.com/cookiengineer/goaccess/protocols/arp"
	"github.com/cookiengineer/goaccess/protocols/ftp"
	protocolhttp "github.com/cookiengineer/goaccess/protocols/http"
	"github.com/cookiengineer/goaccess/protocols/snmp"
	"github.com/cookiengineer/goaccess/protocols/ssh"
	"github.com/cookiengineer/goaccess/protocols/telnet"
	"github.com/cookiengineer/goaccess/protocols/udp"
	"github.com/cookiengineer/goaccess/types"
)

// Scanner orchestrates device identification, vulnerability scanning, and access exploitation.
type Scanner struct {
	config *types.ScanConfig

	// Channel-based job dispatch
	jobs    chan *job
	results chan *types.ScanResult
	done    chan struct{}

	// Thread-safe mutable state
	mutex          sync.RWMutex
	fingerprint    *types.FingerprintResult
	vulnerabilities []*types.VulnResult
	credentials    []*types.CredsResult
	errors         []error
}

type jobType int

const (
	jobCheck        jobType = iota // Exploit.Check()
	jobCheckDefault                // CredentialsModule.CheckDefault()
)

type job struct {
	exploit  interfaces.Exploit
	taskType jobType
}

// NewScanner creates a Scanner with the given configuration.
func NewScanner(config *types.ScanConfig) *Scanner {
	if config.Threads <= 0 {
		config.Threads = 8
	}
	if config.Timeout <= 0 {
		config.Timeout = 8 * time.Second
	}

	return &Scanner{
		config:  config,
		done:    make(chan struct{}),
	}
}

// Identify fingerprints a target device and returns vendor, model, firmware, and service information.
func (scanner *Scanner) Identify(target string, config *types.ScanConfig) (*types.FingerprintResult, error) {
	if config == nil {
		config = scanner.config
	}
	scanner.config = config

	result := &types.FingerprintResult{
		IP: target,
	}

	// Phase 1: Port scanning
	scanner.progress(config, "\r[*] Phase 1/6: Port scanning...")

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	openPorts := ScanPorts(target, CommonIOTPorts, timeout)
	result.Services = openPorts

	scanner.progress(config, "\r[*] Phase 1/6: Port scanning... done (%d ports open)\n", len(openPorts))

	// Phase 2: ARP probe
	scanner.progress(config, "\r[*] Phase 2/6: ARP probe...")

	macAddress := probeARP(target)
	if macAddress != "" {
		result.MAC = macAddress
		result.OUI = oui.Lookup(macAddress)
		if result.OUI != "" {
			result.Hints = append(result.Hints, fmt.Sprintf("MAC OUI: %s", result.OUI))
		}
	}

	scanner.progress(config, "\r[*] Phase 2/6: ARP probe... done (%s)\n",
		func() string { if macAddress != "" { return macAddress } else { return "not resolved" } }())

	// Phase 3: HTTP banner probe
	scanner.progress(config, "\r[*] Phase 3/6: HTTP banner probe...")

	httpResult := probeHTTP(target, timeout)
	if httpResult != nil {
		result.Hints = append(result.Hints, httpResult...)
	}

	scanner.progress(config, "\r[*] Phase 3/6: HTTP banner probe... done (%d hints)\n", len(httpResult))

	// Phase 4: UPnP SSDP probe
	scanner.progress(config, "\r[*] Phase 4/6: UPnP SSDP probe...")

	upnpResult := probeUPnP(target, timeout)
	if upnpResult != "" {
		result.Hints = append(result.Hints, fmt.Sprintf("UPnP: %s", upnpResult))
	}

	scanner.progress(config, "\r[*] Phase 4/6: UPnP SSDP probe... %s\n",
		func() string { if upnpResult != "" { return "done (found)" } else { return "nothing found" } }())

	// Phase 5: SNMP sysDescr probe
	scanner.progress(config, "\r[*] Phase 5/6: SNMP sysDescr probe...")

	community := "public"
	if config != nil && config.MACAddress != "" {
		// Use MAC-derived community? Not yet implemented.
	}
	snmpDesc := probeSNMP(target, community, timeout)
	if snmpDesc != "" {
		result.Hints = append(result.Hints, fmt.Sprintf("SNMP sysDescr: %s", snmpDesc))
	}

	scanner.progress(config, "\r[*] Phase 5/6: SNMP sysDescr probe... %s\n",
		func() string { if snmpDesc != "" { return "done (found)" } else { return "no response" } }())

	// Phase 6: Match fingerprints from registered exploits
	scanner.progress(config, "\r[*] Phase 6/6: Fingerprint matching...")

	vendor, model, confidence := matchFingerprints(target, result, timeout)
	if vendor != "" {
		result.Vendor = vendor
	}
	if model != "" {
		result.Model = model
	}
	result.Confidence = confidence

	scanner.progress(config, "\r[*] Phase 6/6: Fingerprint matching... done (%.1f%% confidence)\n", confidence*100)

	scanner.mutex.Lock()
	scanner.fingerprint = result
	scanner.mutex.Unlock()

	return result, nil
}

// Scan runs vulnerability checks and credential brute-force against a target.
// Results are streamed through the returned channel.
func (scanner *Scanner) Scan(target string, config *types.ScanConfig) (<-chan *types.ScanResult, error) {
	if config == nil {
		config = scanner.config
	}
	scanner.config = config

	// Run identify first
	fingerprint, err := scanner.Identify(target, config)
	if err != nil {
		return nil, fmt.Errorf("scan: identify failed: %w", err)
	}

	scanner.jobs = make(chan *job, 100)
	scanner.results = make(chan *types.ScanResult, 100)

	var workerGroup sync.WaitGroup

	// Start worker pool
	for index := 0; index < config.Threads; index++ {
		workerGroup.Add(1)
		go func(id int) {
			defer workerGroup.Done()
			scanner.worker(id)
		}(index)
	}

	// Start dispatch goroutine
	workerGroup.Add(1)
	go func() {
		defer workerGroup.Done()
		defer close(scanner.jobs)
		scanner.dispatchJobs(target, fingerprint, config)
	}()

	// Close results channel when all workers and dispatcher are done
	go func() {
		workerGroup.Wait()
		close(scanner.results)
	}()

	return scanner.results, nil
}

// Access actively exploits a target to gain shell or credentials.
func (scanner *Scanner) Access(target string, config *types.ScanConfig) (*types.AccessResult, error) {
	if config == nil {
		config = scanner.config
	}
	scanner.config = config

	result := &types.AccessResult{
		Target: target,
	}

	// Step 1: Identify
	scanner.logStep(result, types.StepIdentify, true, "Fingerprinting device")
	fingerprint, err := scanner.Identify(target, config)
	if err != nil {
		scanner.logStep(result, types.StepFailed, false, "Identify failed: "+err.Error())
		return result, nil
	}
	result.Vendor = fingerprint.Vendor
	result.Model = fingerprint.Model

	// Step 2: Credential recovery
	scanner.logStep(result, types.StepCredentials, true, "Recovering credentials")
	credsResult := scanner.recoverCredentials(target, fingerprint, config)
	if len(credsResult) > 0 {
		result.Credentials = credsResult
		scanner.logStep(result, types.StepCredentials, true,
			fmt.Sprintf("Found %d credential(s)", len(credsResult)))
	}

	// Step 3: Exploitation (priority-ordered)
	scanner.logStep(result, types.StepExploit, true, "Running exploits")
	exploitResults := scanner.runExploitChain(target, fingerprint, config)
	result.Exploits = exploitResults

	if len(exploitResults) > 0 {
		scanner.logStep(result, types.StepExploit, true,
			fmt.Sprintf("%d exploit(s) succeeded", len(exploitResults)))
	}

	// Step 4: Shell access
	if len(result.Credentials) > 0 || len(result.Exploits) > 0 {
		result.Success = true
		scanner.logStep(result, types.StepShell, true, "Access achieved")
	} else {
		scanner.logStep(result, types.StepFailed, false, "No access achieved")
	}

	return result, nil
}

func (scanner *Scanner) logStep(result *types.AccessResult, step types.AccessStep, success bool, detail string) {
	result.Steps = append(result.Steps, types.AccessStepLog{
		Step:    step,
		Success: success,
		Detail:  detail,
	})
}

func (scanner *Scanner) recoverCredentials(target string, fingerprint *types.FingerprintResult, config *types.ScanConfig) []*types.CredsResult {
	var creds []*types.CredsResult

	// Run password generators for the vendor
	generators := exploit.PasswordGeneratorsByVendor(fingerprint.Vendor)
	for _, generator := range generators {
		generated := generator.Generate(fingerprint.MAC, "", fingerprint.Model)
		scanner.testGeneratedCredentials(target, fingerprint.Services, generated, config.Timeout, &creds)
	}

	// Run credentials modules
	modules := exploit.CredentialsByVendor(fingerprint.Vendor)
	for _, module := range modules {
		opts := module.Options()
		opts.Target = target
		opts.Timeout = config.Timeout

		found, err := module.CheckDefault(target, opts)
		if err != nil {
			scanner.mutex.Lock()
			scanner.errors = append(scanner.errors, err)
			scanner.mutex.Unlock()
			continue
		}
		creds = append(creds, found...)
	}

	return deduplicateCredentials(creds)
}

func (scanner *Scanner) testGeneratedCredentials(target string, services []int, generated []types.Credential, timeout time.Duration, creds *[]*types.CredsResult) {
	if len(generated) == 0 {
		return
	}

	hasPort := func(port int) bool {
		for _, p := range services {
			if p == port {
				return true
			}
		}
		return false
	}

	for _, credential := range generated {
		if credential.Username == "" && credential.Password == "" {
			continue
		}

		if hasPort(23) {
			telnetClient := telnet.NewClient()
			telnetClient.Target = target
			telnetClient.Port = 23
			telnetClient.Timeout = timeout
			if telnetClient.Login(credential.Username, credential.Password) {
				*creds = append(*creds, &types.CredsResult{
					Target: target, Port: 23, Service: "telnet",
					Protocol: types.ProtocolTelnet, Username: credential.Username, Password: credential.Password,
				})
			}
			telnetClient.Close()
		}

		if hasPort(22) && credential.Username != "" {
			sshClient := ssh.NewClient()
			sshClient.Target = target
			sshClient.Port = 22
			sshClient.Timeout = timeout
			if err := sshClient.Login(credential.Username, credential.Password); err == nil {
				*creds = append(*creds, &types.CredsResult{
					Target: target, Port: 22, Service: "ssh",
					Protocol: types.ProtocolSSH, Username: credential.Username, Password: credential.Password,
				})
			}
			sshClient.Close()
		}

		if hasPort(21) && credential.Username != "" {
			ftpClient := ftp.NewClient()
			ftpClient.Target = target
			ftpClient.Port = 21
			ftpClient.Timeout = timeout
			if err := ftpClient.Login(credential.Username, credential.Password); err == nil {
				*creds = append(*creds, &types.CredsResult{
					Target: target, Port: 21, Service: "ftp",
					Protocol: types.ProtocolFTP, Username: credential.Username, Password: credential.Password,
				})
			}
			ftpClient.Close()
		}

		if hasPort(80) && credential.Username != "" {
			httpClient := protocolhttp.NewClient()
			httpClient.Target = target
			httpClient.Port = 80
			httpClient.Timeout = timeout
			httpClient.SetBasicAuth(credential.Username, credential.Password)
			if response, err := httpClient.Get("/", nil); err == nil {
				if response.StatusCode >= 200 && response.StatusCode < 400 && response.Headers.Get("WWW-Authenticate") == "" {
					*creds = append(*creds, &types.CredsResult{
						Target: target, Port: 80, Service: "http",
						Protocol: types.ProtocolHTTP, Username: credential.Username, Password: credential.Password,
					})
				}
			}
		}
	}
}

func (scanner *Scanner) runExploitChain(target string, fingerprint *types.FingerprintResult, config *types.ScanConfig) []*types.ExploitResult {
	var results []*types.ExploitResult

	// Priority 1: Credential disclosure exploits
	// Priority 2: Auth bypass exploits
	// Priority 3: RCE exploits
	// Priority 4: Path traversal / info disclosure

	exploits := exploit.ByVendor(fingerprint.Vendor)
	for _, exploitModule := range exploits {
		opts := exploitModule.Options()
		opts.Target = target
		opts.Timeout = config.Timeout

		exploitResult, err := exploitModule.Run(target, opts)
		if err != nil {
			scanner.mutex.Lock()
			scanner.errors = append(scanner.errors, err)
			scanner.mutex.Unlock()
			continue
		}
		if exploitResult != nil && exploitResult.Success {
			results = append(results, exploitResult)
		}
	}

	return results
}

func (scanner *Scanner) worker(id int) {
	for job := range scanner.jobs {
		opts := job.exploit.Options()
		opts.Target = scanner.config.Target
		opts.Timeout = scanner.config.Timeout
		opts.Verbose = scanner.config.Verbose

		result := &types.ScanResult{
			Exploit:   job.exploit.Info(),
			Timestamp: time.Now(),
		}

		info := job.exploit.Info()
		if info != nil {
			result.Module = info.Vendor + "/" + info.Name
		}

		switch job.taskType {
		case jobCheck:
			vuln, err := job.exploit.Check(opts.Target, opts)
			if err != nil {
				result.Error = err
			} else {
				result.Vulnerability = vuln
			}
		case jobCheckDefault:
			if credsModule, ok := job.exploit.(interfaces.CredentialsModule); ok {
				creds, err := credsModule.CheckDefault(opts.Target, opts)
				if err != nil {
					result.Error = err
				} else {
					result.Credentials = creds
				}
			}
		}

		scanner.results <- result
	}
}

func (scanner *Scanner) collector() {
	for result := range scanner.results {
		scanner.mutex.Lock()
		if result.Vulnerability != nil && result.Vulnerability.Confirmed {
			scanner.vulnerabilities = append(scanner.vulnerabilities, result.Vulnerability)
		}
		if len(result.Credentials) > 0 {
			scanner.credentials = append(scanner.credentials, result.Credentials...)
		}
		if result.Error != nil {
			scanner.errors = append(scanner.errors, result.Error)
		}
		scanner.mutex.Unlock()
	}
}

func (scanner *Scanner) dispatchJobs(target string, fingerprint *types.FingerprintResult, config *types.ScanConfig) {
	// Dispatch exploit checks
	if !config.SkipExploits {
		exploits := filterExploits(fingerprint.Vendor, config)
		for _, exploitModule := range exploits {
			scanner.jobs <- &job{exploit: exploitModule, taskType: jobCheck}
		}
	}

	// Dispatch credential checks
	if !config.SkipCredentials {
		credsModules := exploit.CredentialsByVendor(fingerprint.Vendor)
		for _, module := range credsModules {
			scanner.jobs <- &job{exploit: module, taskType: jobCheckDefault}
		}
	}
}

func filterExploits(vendor string, config *types.ScanConfig) []interfaces.Exploit {
	var exploits []interfaces.Exploit

	if vendor != "" {
		exploits = exploit.ByVendor(vendor)
	} else {
		exploits = exploit.All()
	}

	if config.VendorFilter != "" {
		exploits = exploit.ByVendor(config.VendorFilter)
	}

	if config.TypeFilter != "" {
		filtered := make([]interfaces.Exploit, 0)
		for _, exploitModule := range exploits {
			info := exploitModule.Info()
			if info != nil && info.DeviceType == config.TypeFilter {
				filtered = append(filtered, exploitModule)
			}
		}
		exploits = filtered
	}

	return exploits
}

func probeARP(target string) string {
	client := protocolarp.NewClient()
	mac, err := client.Resolve(target)
	if err != nil || mac == nil {
		return ""
	}
	return mac.String()
}

func probeHTTP(target string, timeout time.Duration) []string {
	var hints []string

	client := protocolhttp.NewClient()
	client.Target = target
	client.Timeout = timeout

	for _, port := range []int{80, 443, 8080} {
		client.Port = port
		client.SSL = (port == 443)

		response, err := client.Get("/", nil)
		if err != nil {
			continue
		}

		server := response.Headers.Get("Server")
		if server != "" {
			hints = append(hints, fmt.Sprintf("HTTP:%d Server: %s", port, server))
		}

		wwwAuth := response.Headers.Get("WWW-Authenticate")
		if wwwAuth != "" {
			hints = append(hints, fmt.Sprintf("HTTP:%d WWW-Authenticate: %s", port, wwwAuth))
		}

		if len(response.Body) > 0 {
			title := extractTitle(response.Body)
			if title != "" {
				hints = append(hints, fmt.Sprintf("HTTP:%d Title: %s", port, title))
			}
		}
		break // Only probe first reachable port
	}

	return hints
}

func probeUPnP(target string, timeout time.Duration) string {
	client := udp.NewClient()
	client.Target = target
	client.Port = 1900
	client.Timeout = timeout

	if err := client.Connect(); err != nil {
		return ""
	}
	defer client.Close()

	request := "M-SEARCH * HTTP/1.1\r\n" +
		"Host:239.255.255.250:1900\r\n" +
		"ST:upnp:rootdevice\r\n" +
		"Man:\"ssdp:discover\"\r\n" +
		"MX:2\r\n\r\n"

	if err := client.Send([]byte(request)); err != nil {
		return ""
	}

	response, err := client.Recv(4096)
	if err != nil {
		return ""
	}

	return string(response)
}

func probeSNMP(target, community string, timeout time.Duration) string {
	client := snmp.NewClient()
	client.Target = target
	client.Community = community
	client.Timeout = timeout

	result, err := client.Get("1.3.6.1.2.1.1.1.0")
	if err != nil {
		return ""
	}
	return result
}

func matchFingerprints(target string, result *types.FingerprintResult, timeout time.Duration) (string, string, float64) {
	bestVendor := ""
	bestModel := ""
	bestConfidence := 0.0

	allExploits := exploit.All()
	for _, exploitModule := range allExploits {
		fingerprints := exploitModule.Fingerprints()
		if len(fingerprints) == 0 {
			continue
		}

		info := exploitModule.Info()
		if info == nil {
			continue
		}

		for _, fingerprint := range fingerprints {
			confidence := testFingerprint(target, fingerprint, timeout)
			if confidence > bestConfidence {
				bestConfidence = confidence
				bestVendor = info.Vendor
				if len(info.Models) > 0 {
					bestModel = info.Models[0]
				}
			}
		}
	}

	return bestVendor, bestModel, bestConfidence
}

func testFingerprint(target string, fingerprint *types.Fingerprint, timeout time.Duration) float64 {
	if fingerprint.URL != "" {
		client := protocolhttp.NewClient()
		client.Target = target
		client.Timeout = timeout

		method := fingerprint.Method
		if method == "" {
			method = "GET"
		}

		response, err := client.Do(method, fingerprint.URL, nil, nil)
		if err != nil {
			return 0
		}

		matchCount := 0
		totalChecks := 0

		if fingerprint.Body != "" {
			totalChecks++
			if contains(string(response.Body), fingerprint.Body) {
				matchCount++
			}
		}

		for headerName, headerPattern := range fingerprint.Headers {
			totalChecks++
			if contains(response.Headers.Get(headerName), headerPattern) {
				matchCount++
			}
		}

		if totalChecks > 0 {
			return float64(matchCount) / float64(totalChecks)
		}
	}

	return 0
}

func extractTitle(html []byte) string {
	content := string(html)
	start := indexOf(content, "<title>")
	if start < 0 {
		start = indexOf(content, "<TITLE>")
	}
	if start < 0 {
		return ""
	}

	start += 7 // len("<title>")
	end := indexOf(content[start:], "</title>")
	if end < 0 {
		end = indexOf(content[start:], "</TITLE>")
	}
	if end < 0 {
		return ""
	}

	return content[start : start+end]
}

func contains(source, substring string) bool {
	return indexOf(source, substring) >= 0
}

func indexOf(source, substring string) int {
	if len(substring) == 0 {
		return 0
	}
	if len(substring) > len(source) {
		return -1
	}
	for index := 0; index <= len(source)-len(substring); index++ {
		match := true
		for offset := 0; offset < len(substring); offset++ {
			if source[index+offset] != substring[offset] {
				match = false
				break
			}
		}
		if match {
			return index
		}
	}
	return -1
}

func deduplicateCredentials(creds []*types.CredsResult) []*types.CredsResult {
	if len(creds) <= 1 {
		return creds
	}

	seen := make(map[string]bool)
	var unique []*types.CredsResult

	for _, cred := range creds {
		if cred == nil {
			continue
		}
		key := fmt.Sprintf("%s:%s@%s:%d", cred.Username, cred.Password, cred.Service, cred.Port)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, cred)
		}
	}

	return unique
}

func deduplicateVulnerabilities(vulns []*types.VulnResult) []*types.VulnResult {
	if len(vulns) <= 1 {
		return vulns
	}

	seen := make(map[string]bool)
	var unique []*types.VulnResult

	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		key := vuln.Details
		if !seen[key] {
			seen[key] = true
			unique = append(unique, vuln)
		}
	}

	return unique
}

func (scanner *Scanner) progress(config *types.ScanConfig, format string, arguments ...interface{}) {
	if config != nil && config.ProgressWriter != nil {
		fmt.Fprintf(config.ProgressWriter, format, arguments...)
	}
}
