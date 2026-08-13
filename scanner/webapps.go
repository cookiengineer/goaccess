package scanner

import (
	"fmt"
	"time"

	"github.com/cookiengineer/goaccess/libs/webapp"
	protocolhttp "github.com/cookiengineer/goaccess/protocols/http"
	"github.com/cookiengineer/goaccess/types"
)

// probeWebApps fingerprints the target's HTTP root page for known web
// application platforms (CMS, frameworks, application servers) and records the
// match in the fingerprint result. It runs as part of the identify pipeline
// after IoT-specific HTTP indicator matching.
func probeWebApps(target string, openPorts []int, timeout time.Duration, result *types.FingerprintResult) {
	for _, port := range webAppPorts(openPorts) {
		if probeWebAppOnPort(target, port, port == 443, timeout, result) {
			return
		}
	}
}

// probeWebAppOnPort fetches the root page on a single HTTP(S) port and, if the
// response matches a known platform, records it in the result. It returns true
// when a match was found.
func probeWebAppOnPort(target string, port int, ssl bool, timeout time.Duration, result *types.FingerprintResult) bool {
	client := protocolhttp.NewClient()
	client.Target = target
	client.Port = port
	client.SSL = ssl
	client.Timeout = timeout

	response, err := client.Get("/", nil)
	if err != nil {
		return false
	}

	server := response.Headers.Get("Server")
	app := webapp.Detect(response.Body, server)
	if app == webapp.AppUnknown {
		return false
	}

	result.Vendor = string(app)
	result.Confidence = 0.9
	result.Hints = append(result.Hints, fmt.Sprintf("HTTP:%d WebApp: %s", port, app))
	return true
}

// webAppPorts returns the HTTP(S) ports to probe for web application detection,
// preferring ports discovered open during the port scan.
func webAppPorts(openPorts []int) []int {
	var ports []int
	for _, candidate := range []int{80, 443, 8080} {
		for _, open := range openPorts {
			if open == candidate {
				ports = append(ports, candidate)
				break
			}
		}
	}
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	return ports
}
