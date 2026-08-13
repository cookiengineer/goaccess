package scanner

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cookiengineer/goaccess/types"
)

func TestWebAppPorts_Open(t *testing.T) {
	ports := webAppPorts([]int{22, 80, 443})
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Errorf("webAppPorts = %v, want [80 443]", ports)
	}
}

func TestWebAppPorts_Fallback(t *testing.T) {
	ports := webAppPorts([]int{22, 25})
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Errorf("webAppPorts = %v, want fallback [80 443]", ports)
	}
}

func TestHTTPFingerprintPorts(t *testing.T) {
	ports := httpFingerprintPorts([]int{21, 443, 8080})
	found8080 := false
	for _, p := range ports {
		if p == 8080 {
			found8080 = true
		}
	}
	if !found8080 {
		t.Errorf("httpFingerprintPorts = %v, want to include 8080", ports)
	}
}

func TestProbeWebAppOnPort_WordPress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress 5.8" /></head>
			<body><a href="/wp-content/theme.css">x</a></body></html>`))
	}))
	defer server.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	result := &types.FingerprintResult{IP: host}
	if !probeWebAppOnPort(host, port, false, 2*time.Second, result) {
		t.Fatal("expected web app match")
	}
	if result.Vendor != "wordpress" {
		t.Errorf("Vendor = %q, want wordpress", result.Vendor)
	}
	if len(result.Hints) == 0 {
		t.Error("expected at least one hint")
	}
}

func TestProbeWebAppOnPort_NoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>plain site</body></html>"))
	}))
	defer server.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	result := &types.FingerprintResult{IP: host}
	if probeWebAppOnPort(host, port, false, 2*time.Second, result) {
		t.Error("expected no web app match")
	}
}
