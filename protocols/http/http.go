package http

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides HTTP/HTTPS communication with a target device.
// Embed this struct into exploit modules that communicate over HTTP.
type Client struct {
	Target  string
	Port    int
	SSL     bool
	Timeout time.Duration
	Verbose bool

	httpClient    *http.Client
	basicAuthUser string
	basicAuthPass string
}

// Response wraps an HTTP response for convenience.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// NewClient creates an HTTP client with sensible defaults.
func NewClient() *Client {
	return &Client{
		Timeout: 10 * time.Second,
	}
}

func (client *Client) ensureHTTPClient() *http.Client {
	if client.httpClient != nil {
		return client.httpClient
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client.httpClient = &http.Client{
		Timeout:   client.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client.httpClient
}

// SetBasicAuth sets HTTP Basic authentication credentials.
func (client *Client) SetBasicAuth(username, password string) {
	client.basicAuthUser = username
	client.basicAuthPass = password
}

// GetTargetURL constructs the full URL for a given path.
func (client *Client) GetTargetURL(path string) string {
	scheme := "http"
	if client.SSL {
		scheme = "https"
	}

	host := client.Target
	defaultPort := 80
	if client.SSL {
		defaultPort = 443
	}

	if client.Port > 0 && !hasPort(host) {
		host = fmt.Sprintf("%s:%d", host, client.Port)
	} else if client.Port == 0 && !hasPort(host) {
		host = fmt.Sprintf("%s:%d", host, defaultPort)
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func hasPort(host string) bool {
	for index := len(host) - 1; index >= 0; index-- {
		if host[index] == ':' {
			return true
		}
		if host[index] < '0' || host[index] > '9' {
			return false
		}
	}
	return false
}

// Get sends an HTTP GET request to the given path.
func (client *Client) Get(path string, headers map[string]string) (*Response, error) {
	return client.Do("GET", path, nil, headers)
}

// Post sends an HTTP POST request with the given body to the given path.
func (client *Client) Post(path string, body []byte, headers map[string]string) (*Response, error) {
	return client.Do("POST", path, body, headers)
}

// Head sends an HTTP HEAD request to the given path.
func (client *Client) Head(path string, headers map[string]string) (*Response, error) {
	return client.Do("HEAD", path, nil, headers)
}

// Do sends an HTTP request with the given method, path, body, and headers.
func (client *Client) Do(method string, path string, body []byte, headers map[string]string) (*Response, error) {
	targetURL := client.GetTargetURL(path)
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("http: invalid URL %q: %w", targetURL, err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	request, err := http.NewRequest(method, parsedURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("http: request creation failed: %w", err)
	}

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	if client.basicAuthUser != "" || client.basicAuthPass != "" {
		request.SetBasicAuth(client.basicAuthUser, client.basicAuthPass)
	}

	response, err := client.ensureHTTPClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("http: request failed: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("http: reading response body failed: %w", err)
	}

	return &Response{
		StatusCode: response.StatusCode,
		Headers:    response.Header,
		Body:       responseBody,
	}, nil
}
