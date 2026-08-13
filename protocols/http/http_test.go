package http

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestHostHeaderOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "attacker.example.com" {
			t.Errorf("Host = %q, want attacker.example.com", r.Host)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://"), Host: "attacker.example.com"}
	if _, err := client.Get("/", nil); err != nil {
		t.Fatalf("GET failed: %v", err)
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

func TestCookieJar_PersistsSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/"})
			w.WriteHeader(200)
		case "/admin":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "abc123" {
				w.WriteHeader(403)
				return
			}
			w.WriteHeader(200)
		}
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	if _, err := client.Get("/login", nil); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if !client.HasCookies() {
		t.Fatal("expected session cookie to be stored")
	}
	response, err := client.Get("/admin", nil)
	if err != nil {
		t.Fatalf("admin request failed: %v", err)
	}
	if response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200 (cookie not forwarded)", response.StatusCode)
	}
}

func TestClearCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Path: "/"})
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	if _, err := client.Get("/", nil); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if !client.HasCookies() {
		t.Fatal("expected cookie to be set")
	}
	client.ClearCookies()
	if client.HasCookies() {
		t.Error("expected cookies to be cleared")
	}
}

func TestFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Write([]byte("landing"))
		}
	}))
	defer server.Close()

	// Default: redirects are not followed.
	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	response, err := client.Get("/start", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if response.StatusCode != 302 {
		t.Errorf("default: StatusCode = %d, want 302 (redirect not followed)", response.StatusCode)
	}

	// Enabled: redirects are followed.
	follow := &Client{Target: strings.TrimPrefix(server.URL, "http://"), FollowRedirects: true}
	response, err = follow.Get("/start", nil)
	if err != nil {
		t.Fatalf("Get with redirects failed: %v", err)
	}
	if response.StatusCode != 200 || !strings.Contains(string(response.Body), "landing") {
		t.Errorf("follow: StatusCode = %d body = %q, want 200 with 'landing'", response.StatusCode, string(response.Body))
	}
}

func TestPostForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Errorf("Content-Type = %q, want url-encoded", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm error: %v", err)
		}
		if r.PostForm.Get("user") != "admin" || r.PostForm.Get("pass") != "secret" {
			t.Errorf("form values = %v, want user=admin pass=secret", r.PostForm)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	form := url.Values{"user": {"admin"}, "pass": {"secret"}}
	if _, err := client.PostForm("/login", form, nil); err != nil {
		t.Fatalf("PostForm failed: %v", err)
	}
}

func TestPostMultipart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm error: %v", err)
			return
		}
		if r.FormValue("command") != "deploy" {
			t.Errorf("field command = %q, want deploy", r.FormValue("command"))
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			t.Errorf("FormFile error: %v", err)
			return
		}
		data := make([]byte, 4)
		if _, err := file.Read(data); err != nil {
			t.Errorf("read file error: %v", err)
		}
		if string(data) != "test" {
			t.Errorf("file content = %q, want test", string(data))
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	client := &Client{Target: strings.TrimPrefix(server.URL, "http://")}
	response, err := client.PostMultipart("/upload", map[string]string{"command": "deploy"},
		[]FileUpload{{FieldName: "file", Filename: "x.jsp", Content: []byte("test")}}, nil)
	if err != nil {
		t.Fatalf("PostMultipart failed: %v", err)
	}
	if response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", response.StatusCode)
	}
}
