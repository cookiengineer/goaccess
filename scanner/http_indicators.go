package scanner

import (
	"crypto/md5"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	protocolhttp "github.com/cookiengineer/goaccess/protocols/http"
	"github.com/cookiengineer/goaccess/types"
)

//go:embed http_indicators.json
var indicatorsJSON []byte

type compiledIndicator struct {
	types.HTTPIndicator
	compiledTitleRegex    []*regexp.Regexp
	compiledContentRegex  []*regexp.Regexp
	compiledFirmwareRegex *regexp.Regexp
}

var (
	indicatorRegistry []*compiledIndicator
	indicatorsLoaded  sync.Once
)

func loadHTTPIndicators() {
	indicatorsLoaded.Do(func() {
		var raw []types.HTTPIndicator
		if err := json.Unmarshal(indicatorsJSON, &raw); err != nil {
			panic("http_indicators: failed to parse embedded data: " + err.Error())
		}
		for index := range raw {
			ci := &compiledIndicator{HTTPIndicator: raw[index]}
			for _, pattern := range raw[index].TitleRegex {
				re, err := regexp.Compile(pattern)
				if err == nil {
					ci.compiledTitleRegex = append(ci.compiledTitleRegex, re)
				}
			}
			for _, pattern := range raw[index].ContentRegex {
				re, err := regexp.Compile(pattern)
				if err == nil {
					ci.compiledContentRegex = append(ci.compiledContentRegex, re)
				}
			}
			if raw[index].FirmwareRegex != "" {
				re, err := regexp.Compile(raw[index].FirmwareRegex)
				if err == nil {
					ci.compiledFirmwareRegex = re
				}
			}
			indicatorRegistry = append(indicatorRegistry, ci)
		}
	})
}

type httpResponseCache struct {
	title     string
	body      string
	headerStr string
	raw       []byte
}

func probeHTTPIndicators(target string, openPorts []int, timeout time.Duration, result *types.FingerprintResult) {
	loadHTTPIndicators()

	if len(indicatorRegistry) == 0 {
		return
	}

	candidatePorts := []int{80, 443, 8080}
	var httpPort int
	for _, port := range candidatePorts {
		for _, open := range openPorts {
			if open == port {
				httpPort = port
				break
			}
		}
		if httpPort != 0 {
			break
		}
	}
	if httpPort == 0 {
		return
	}

	pathSet := make(map[string]bool)
	for _, ci := range indicatorRegistry {
		p := ci.Path
		if p == "" {
			p = "/"
		}
		pathSet[p] = true
	}

	client := protocolhttp.NewClient()
	client.Target = target
	client.Port = httpPort
	client.SSL = (httpPort == 443)
	client.Timeout = timeout

	cache := make(map[string]*httpResponseCache)
	for path := range pathSet {
		resp, err := client.Get(path, nil)
		if err != nil {
			continue
		}

		bodyStr := string(resp.Body)
		title := extractTitle(resp.Body)

		headerStr := ""
		for key, values := range resp.Headers {
			headerStr += key + ": " + strings.Join(values, ", ") + "\n"
		}

		cache[path] = &httpResponseCache{
			title:     title,
			body:      bodyStr,
			headerStr: headerStr,
			raw:       resp.Body,
		}
	}

	for _, ci := range indicatorRegistry {
		path := ci.Path
		if path == "" {
			path = "/"
		}
		cached, ok := cache[path]
		if !ok {
			continue
		}

		if matchCompiledIndicator(ci, cached) {
			result.Vendor = strings.ToLower(ci.Vendor)
			result.Confidence = 0.95

			hint := fmt.Sprintf("HTTP:%d Matched: %s %s (path=%s)", httpPort, ci.Vendor, ci.Product, path)
			result.Hints = append(result.Hints, hint)

			if ci.compiledFirmwareRegex != nil {
				matches := ci.compiledFirmwareRegex.FindStringSubmatch(cached.body)
				group := ci.FirmwareGroup
				if group <= 0 || group >= len(matches) {
					group = 1
				}
				if group < len(matches) {
					result.Firmware = matches[group]
					result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d Firmware: %s", httpPort, result.Firmware))
				}
			}

			if cached.title != "" {
				result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d Title: %s", httpPort, cached.title))
			}
			return
		}
	}

	for path, cached := range cache {
		if cached.title != "" {
			result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d Title: %s", httpPort, cached.title))
		} else if path == "/" && len(cached.body) > 0 {
			server := extractHeaderValue(cached.headerStr, "Server")
			if server != "" {
				result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d Server: %s", httpPort, server))
			}
			wwwAuth := extractHeaderValue(cached.headerStr, "Www-Authenticate")
			if wwwAuth != "" {
				result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d WWW-Authenticate: %s", httpPort, wwwAuth))
			}
		}
	}
}

func matchCompiledIndicator(ci *compiledIndicator, cached *httpResponseCache) bool {
	hasCriteria := ci.MD5 != "" || len(ci.Headers) > 0 || len(ci.HeaderContent) > 0 ||
		len(ci.Title) > 0 || len(ci.Content) > 0 ||
		len(ci.compiledTitleRegex) > 0 || len(ci.compiledContentRegex) > 0

	if !hasCriteria {
		return false
	}

	if ci.MD5 != "" {
		hash := md5.Sum(cached.raw)
		if hex.EncodeToString(hash[:]) == ci.MD5 {
			return true
		}
		return false
	}

	if len(ci.Headers) > 0 {
		for name, value := range ci.Headers {
			if !headerContains(cached.headerStr, name, value) {
				return false
			}
		}
	}

	if len(ci.HeaderContent) > 0 {
		anyMatch := false
		for _, hc := range ci.HeaderContent {
			if strings.Contains(cached.headerStr, hc) {
				anyMatch = true
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	if len(ci.Title) > 0 {
		anyMatch := false
		for _, t := range ci.Title {
			if strings.Contains(cached.title, t) {
				anyMatch = true
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	if len(ci.Content) > 0 {
		for _, c := range ci.Content {
			if !strings.Contains(cached.body, c) {
				return false
			}
		}
	}

	if len(ci.compiledTitleRegex) > 0 {
		anyMatch := false
		for _, re := range ci.compiledTitleRegex {
			if re.MatchString(cached.title) {
				anyMatch = true
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	if len(ci.compiledContentRegex) > 0 {
		anyMatch := false
		for _, re := range ci.compiledContentRegex {
			if re.MatchString(cached.body) {
				anyMatch = true
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	return true
}

func headerContains(headerStr, name, value string) bool {
	lower := strings.ToLower(headerStr)
	nameLower := strings.ToLower(name)
	index := strings.Index(lower, nameLower+":")
	if index < 0 {
		return false
	}
	lineEnd := strings.IndexByte(lower[index:], '\n')
	lineContent := lower[index:]
	if lineEnd >= 0 {
		lineContent = lower[index : index+lineEnd]
	}
	return strings.Contains(lineContent, strings.ToLower(value))
}

func extractHeaderValue(headerStr, name string) string {
	lower := strings.ToLower(headerStr)
	nameLower := strings.ToLower(name)
	index := strings.Index(lower, nameLower+":")
	if index < 0 {
		return ""
	}
	start := index + len(nameLower) + 1
	lineEnd := strings.IndexByte(lower[start:], '\n')
	if lineEnd < 0 {
		return strings.TrimSpace(lower[start:])
	}
	return strings.TrimSpace(lower[start : start+lineEnd])
}

// firmwareProbeEntry defines a POST-based endpoint that reveals firmware version.
type firmwareProbeEntry struct {
	path        string
	contentType string
	body        string
	regex       *regexp.Regexp
	group       int
}

var firmwareProbes []firmwareProbeEntry

func init() {
	firmwareProbes = []firmwareProbeEntry{
		// Sagemcom SAH DeviceInfo endpoint
		{
			path:        "/ws/DeviceInfo",
			contentType: "application/x-sah-ws-4-call+json",
			body:        `{"service":"DeviceInfo","method":"get","parameters":""}`,
			regex:       regexp.MustCompile(`"SoftwareVersion"\s*:\s*"([^"]+)"`),
			group:       1,
		},
	}
}

// probeFirmware tries known POST endpoints and header patterns
// to extract firmware version. Called from the Identify pipeline after vendor is determined.
func probeFirmware(target string, vendor string, httpPort int, timeout time.Duration, result *types.FingerprintResult) bool {
	if vendor == "" || httpPort == 0 {
		return false
	}

	// 1. Try POST-based firmware probes (e.g. Sagemcom SAH)
	for _, probe := range firmwareProbes {
		client := protocolhttp.NewClient()
		client.Target = target
		client.Port = httpPort
		client.Timeout = timeout

		resp, err := client.Post(probe.path, []byte(probe.body), map[string]string{
			"Content-Type": probe.contentType,
		})
		if err != nil {
			continue
		}

		matches := probe.regex.FindStringSubmatch(string(resp.Body))
		if probe.group < len(matches) {
			result.Firmware = matches[probe.group]
			result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d Firmware: %s (from POST %s)", httpPort, result.Firmware, probe.path))
			return true
		}
	}

	// 2. Try Server header firmware extraction
	if result.Firmware == "" {
		for _, hint := range result.Hints {
			if strings.HasPrefix(hint, "HTTP:") && strings.Contains(hint, "Server:") {
				fw := extractFirmwareFromServer(hint)
				if fw != "" {
					result.Firmware = fw
					result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d Firmware: %s (from Server header)", httpPort, fw))
					return true
				}
			}
		}
	}

	return false
}

var serverFirmwarePatterns = []*regexp.Regexp{
	regexp.MustCompile(`cisco-IOS/([0-9.()A-Za-z]+)`),
	regexp.MustCompile(`uFOS/([0-9.]+)`),
	regexp.MustCompile(`RomPager/([0-9.]+)`),
	regexp.MustCompile(`mini_httpd/([0-9.]+)`),
	regexp.MustCompile(`lighttpd/([0-9.]+)`),
	regexp.MustCompile(`thttpd/([0-9.]+)`),
	regexp.MustCompile(`Boa/([0-9.]+)`),
	regexp.MustCompile(`GoAhead-Webs/([0-9.]+)`),
}

func extractFirmwareFromServer(hint string) string {
	for _, pattern := range serverFirmwarePatterns {
		matches := pattern.FindStringSubmatch(hint)
		if len(matches) >= 2 {
			return matches[1]
		}
	}
	return ""
}
