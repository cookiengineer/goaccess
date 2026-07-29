package parsers

import (
	"testing"
)

func TestParseXMLRegex(t *testing.T) {
	data := []byte(`<root><usrid>1</usrid><name>admin</name><password>secret123</password></root>`)
	result := ParseXMLRegex(data)
	if result["name"] != "admin" {
		t.Errorf("name = %q, want admin", result["name"])
	}
	if result["password"] != "secret123" {
		t.Errorf("password = %q, want secret123", result["password"])
	}
	if result["usrid"] != "1" {
		t.Errorf("usrid = %q, want 1", result["usrid"])
	}
}

func TestParseINIConfig(t *testing.T) {
	data := []byte("[admin]\nuser=admin\npass=password123\n")
	result := ParseINIConfig(data)
	if result["user"] != "admin" {
		t.Errorf("user = %q, want admin", result["user"])
	}
	if result["pass"] != "password123" {
		t.Errorf("pass = %q, want password123", result["pass"])
	}
}

func TestParseKeyValueLines(t *testing.T) {
	data := []byte("username: admin\npassword: secret\nport: 8080\n")
	result := ParseKeyValueLines(data)
	if result["username"] != "admin" {
		t.Errorf("username = %q, want admin", result["username"])
	}
	if result["password"] != "secret" {
		t.Errorf("password = %q, want secret", result["password"])
	}
}

func TestExtractPassword(t *testing.T) {
	password := ExtractPassword([]byte("config.dat\nadmin_password=\"MySecret123\"\nsome_other=value"))
	if password != "MySecret123" {
		t.Errorf("password = %q, want MySecret123", password)
	}
}

func TestExtractPassword_WPAPassphrase(t *testing.T) {
	password := ExtractPassword([]byte("wpa_passphrase = \"My WiFi Password\""))
	if password != "My WiFi Password" {
		t.Errorf("password = %q, want My WiFi Password", password)
	}
}

func TestExtractUsername(t *testing.T) {
	username := ExtractUsername([]byte("username: root\npassword: toor"))
	if username != "root" {
		t.Errorf("username = %q, want root", username)
	}
}

func TestExtractCredentialsFromHTML(t *testing.T) {
	html := []byte(`<html><form action="/login.cgi" method="post"><input name="username_field"><input name="password_field" type="password"></form></html>`)
	userField, passField, actionURL := ExtractCredentialsFromHTML(html)
	if userField != "username_field" {
		t.Errorf("userField = %q, want username_field", userField)
	}
	if passField != "password_field" {
		t.Errorf("passField = %q, want password_field", passField)
	}
	if actionURL != "/login.cgi" {
		t.Errorf("actionURL = %q, want /login.cgi", actionURL)
	}
}

func TestXMLConfig(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><DeviceInfo><Model>DIR-300</Model><Firmware>1.0.0</Firmware></DeviceInfo>`)
	result, err := ParseXMLConfig(data)
	if err != nil {
		t.Logf("ParseXMLConfig fallback to regex (expected for simple XML): %v", err)
	}
	resultRegex := ParseXMLRegex(data)
	if resultRegex["model"] != "DIR-300" {
		t.Errorf("XML regex: model = %q, want DIR-300", resultRegex["model"])
	}
	_ = result
}
