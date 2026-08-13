package http

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
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

	// FollowRedirects enables automatic redirect following (default false).
	// Web application exploits typically enable this to follow login 302s.
	FollowRedirects bool

	// Host overrides the HTTP Host header sent in requests. When empty, the
	// Host header is derived from Target. Used by host-header injection exploits.
	Host string

	httpClient    *http.Client
	jar           *cookiejar.Jar
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
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     30 * time.Second,
	}
	client.jar, _ = cookiejar.New(nil)
	client.httpClient = &http.Client{
		Timeout:   client.Timeout,
		Transport: transport,
		Jar:       client.jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if client.FollowRedirects {
				return nil
			}
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

// FileUpload describes a single file to attach to a multipart/form-data request.
type FileUpload struct {
	// FieldName is the form field name, e.g. "file" or "image".
	FieldName string
	// Filename is the client-provided filename sent to the server.
	Filename string
	// Content is the raw file content.
	Content []byte
	// ContentType is the MIME type; defaults to application/octet-stream when empty.
	ContentType string
}

// PostForm sends an application/x-www-form-urlencoded POST request built from
// the given values. Any extra headers (e.g. Referer, X-Requested-With) are
// merged with the default Content-Type header.
func (client *Client) PostForm(path string, form url.Values, headers map[string]string) (*Response, error) {
	merged := make(map[string]string, len(headers)+1)
	for key, value := range headers {
		merged[key] = value
	}
	merged["Content-Type"] = "application/x-www-form-urlencoded"
	return client.Do("POST", path, []byte(form.Encode()), merged)
}

// PostMultipart sends a multipart/form-data POST request containing the given
// text fields and files. Useful for file-upload exploits (e.g. WAR/JSP upload).
func (client *Client) PostMultipart(path string, fields map[string]string, files []FileUpload, headers map[string]string) (*Response, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, fmt.Errorf("http: writing multipart field failed: %w", err)
		}
	}

	for _, file := range files {
		contentType := file.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		part, err := writer.CreateFormFile(file.FieldName, file.Filename)
		if err != nil {
			return nil, fmt.Errorf("http: creating multipart file failed: %w", err)
		}
		if _, err := part.Write(file.Content); err != nil {
			return nil, fmt.Errorf("http: writing multipart file failed: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("http: closing multipart writer failed: %w", err)
	}

	merged := make(map[string]string, len(headers)+1)
	for key, value := range headers {
		merged[key] = value
	}
	merged["Content-Type"] = writer.FormDataContentType()

	return client.Do("POST", path, body.Bytes(), merged)
}

// UploadFile is a convenience wrapper around PostMultipart for a single file.
func (client *Client) UploadFile(path, fieldName, filename string, content []byte, headers map[string]string) (*Response, error) {
	return client.PostMultipart(path, nil, []FileUpload{
		{FieldName: fieldName, Filename: filename, Content: content},
	}, headers)
}

// ClearCookies drops the client's stored session cookies (resets the session).
func (client *Client) ClearCookies() {
	if client.jar != nil {
		// The jar is reset lazily on the next request by rebuilding the client.
		client.httpClient = nil
		client.jar = nil
	}
}

// HasCookies reports whether the client currently holds session cookies.
func (client *Client) HasCookies() bool {
	if client.jar == nil {
		return false
	}
	return len(client.jar.Cookies(client.sessionURL())) > 0
}

func (client *Client) sessionURL() *url.URL {
	parsed, _ := url.Parse(client.GetTargetURL("/"))
	return parsed
}

// String returns a short description of the client target for logging.
func (client *Client) String() string {
	return strings.TrimSpace(client.GetTargetURL("/"))
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

	if client.Host != "" {
		request.Host = client.Host
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
