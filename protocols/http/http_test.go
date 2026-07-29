package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient()
	if client.Timeout != 10*time.Second {
		t.Errorf("default timeout = %v, want 10s", client.Timeout)
	}
	if client.httpClient != nil {
		t.Error("httpClient should be nil until first request")
	}
}

func TestGetTargetURL(t *testing.T) {
	tests := []struct {
		target   string
		port     int
		ssl      bool
		path     string
		expected string
	}{
		{"192.168.1.1", 80, false, "/test", "http://192.168.1.1:80/test"},
		{"192.168.1.1", 0, false, "/", "http://192.168.1.1:80/"},
		{"192.168.1.1", 443, true, "/admin", "https://192.168.1.1:443/admin"},
		{"192.168.1.1", 0, true, "/", "https://192.168.1.1:443/"},
		{"192.168.1.1", 8080, false, "/api", "http://192.168.1.1:8080/api"},
	}

	for _, test := range tests {
		client := &Client{Target: test.target, Port: test.port, SSL: test.ssl}
		result := client.GetTargetURL(test.path)
		if result != test.expected {
			t.Errorf("GetTargetURL(%q) = %q, want %q", test.path, result, test.expected)
		}
	}
}

func TestDo_Get(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/test" {
			t.Errorf("expected /test, got %s", r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte("response body"))
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	response, err := client.Do("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("Do(GET) failed: %v", err)
	}
	if response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", response.StatusCode)
	}
	if !strings.Contains(string(response.Body), "response body") {
		t.Errorf("Body missing expected content: %q", string(response.Body))
	}
}

func TestGet_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	response, err := client.Get("/nonexistent", nil)
	if err != nil {
		t.Fatalf("GET returned error: %v", err)
	}
	if response.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", response.StatusCode)
	}
}

func TestPost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	_, err := client.Post("/submit", []byte("data"), nil)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
}

func TestHead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	response, err := client.Head("/", nil)
	if err != nil {
		t.Fatalf("HEAD failed: %v", err)
	}
	if response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", response.StatusCode)
	}
}

func TestSetBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	client.SetBasicAuth("admin", "secret")
	response, err := client.Get("/", nil)
	if err != nil {
		t.Fatalf("GET with auth failed: %v", err)
	}
	if response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", response.StatusCode)
	}
}

func TestDo_ConnectionRefused(t *testing.T) {
	client := &Client{
		Target:  "127.0.0.1",
		Port:    19999, // unlikely to be open
		Timeout: 100 * time.Millisecond,
	}
	_, err := client.Get("/", nil)
	if err == nil {
		t.Error("Expected connection error, got nil")
	}
}
