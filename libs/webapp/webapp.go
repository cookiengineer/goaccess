// Package webapp provides generic helpers for detecting and interacting with
// web applications: fingerprinting known CMS/framework platforms, parsing HTML
// login forms, and evaluating login outcomes. It is transport-agnostic and
// used by server/web-application exploit modules.
package webapp

import (
	"regexp"
	"strings"
)

// App identifies a known web application platform.
type App string

const (
	AppUnknown    App = ""
	AppWordPress  App = "wordpress"
	AppJoomla     App = "joomla"
	AppDrupal     App = "drupal"
	AppTomcat     App = "tomcat"
	AppJenkins    App = "jenkins"
	AppJBoss      App = "jboss"
	AppMagento    App = "magento"
	AppOpenCart   App = "opencart"
	AppPrestaShop App = "prestashop"
	AppSAP        App = "sap"
)

// appSignature associates a fingerprint marker with an App. The marker is
// matched case-insensitively against the HTML body or the Server header.
type appSignature struct {
	app    App
	marker string
}

var appSignatures = []appSignature{
	{AppWordPress, "wp-content"},
	{AppWordPress, "wp-includes"},
	{AppWordPress, `content="WordPress`},
	{AppWordPress, "wp-login.php"},
	{AppJoomla, "com_content"},
	{AppJoomla, `content="Joomla`},
	{AppJoomla, "mosConfig"},
	{AppDrupal, "Drupal.settings"},
	{AppDrupal, `content="Drupal`},
	{AppDrupal, "X-Generator: Drupal"},
	{AppTomcat, "Apache Tomcat"},
	{AppTomcat, "/manager/html"},
	{AppTomcat, "Apache-Coyote"},
	{AppJenkins, "X-Jenkins"},
	{AppJenkins, "[Jenkins]"},
	{AppJenkins, "jenkins"},
	{AppJBoss, "JBoss"},
	{AppJBoss, "jboss.css"},
	{AppJBoss, "Welcome to JBoss"},
	{AppMagento, "mage/"},
	{AppMagento, "Magento"},
	{AppMagento, "adminhtml"},
	{AppOpenCart, "route=common/home"},
	{AppOpenCart, "OpenCart"},
	{AppOpenCart, "catalog/view/theme"},
	{AppPrestaShop, "PrestaShop"},
	{AppPrestaShop, "prestashop"},
	{AppSAP, "SAP NetWeaver"},
	{AppSAP, "/sap/bc/gui/sap/its/webgui"},
	{AppSAP, "SAPGUI"},
}

// Detect fingerprints the web application platform from an HTML body and the
// value of the HTTP Server header. Returns AppUnknown when nothing matches.
func Detect(body []byte, serverHeader string) App {
	haystack := strings.ToLower(string(body) + "\n" + serverHeader)
	for _, signature := range appSignatures {
		if strings.Contains(haystack, strings.ToLower(signature.marker)) {
			return signature.app
		}
	}
	return AppUnknown
}

// GeneratorVersion extracts the version string from an HTML generator meta tag,
// e.g. `<meta name="generator" content="WordPress 4.9.8" />` → "4.9.8".
// Returns an empty string when the version cannot be determined.
func GeneratorVersion(body []byte) string {
	pattern := regexp.MustCompile(`(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	match := pattern.FindStringSubmatch(string(body))
	if len(match) < 2 {
		return ""
	}
	content := match[1]
	// Strip a leading application name, keeping the trailing version tokens.
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return ""
	}
	// If the first token looks like a name and a numeric version follows, return
	// the version part.
	for index, field := range fields {
		if len(field) > 0 && field[0] >= '0' && field[0] <= '9' {
			return strings.Join(fields[index:], " ")
		}
	}
	return content
}

// LoginForm describes a parsed HTML login form.
type LoginForm struct {
	// Action is the form submission URL (may be empty, meaning same page).
	Action string
	// UsernameField is the name of the username/login input field.
	UsernameField string
	// PasswordField is the name of the password input field.
	PasswordField string
	// HiddenFields contains hidden inputs (e.g. CSRF tokens) that must be
	// replayed when submitting the form.
	HiddenFields map[string]string
}

var (
	formActionPattern = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["']`)
	inputPattern      = regexp.MustCompile(`(?i)<input[^>]*>`)
	nameAttrPattern   = regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
	valueAttrPattern  = regexp.MustCompile(`(?i)value=["']([^"']*)["']`)
	typeAttrPattern   = regexp.MustCompile(`(?i)type=["']([^"']+)["']`)
)

// ParseLoginForm extracts a login form's action URL, username/password field
// names, and hidden fields from an HTML page.
func ParseLoginForm(body []byte) *LoginForm {
	form := &LoginForm{HiddenFields: make(map[string]string)}
	content := string(body)

	if match := formActionPattern.FindStringSubmatch(content); len(match) > 1 {
		form.Action = match[1]
	}

	for _, input := range inputPattern.FindAllString(content, -1) {
		name := attrValue(input, nameAttrPattern)
		if name == "" {
			continue
		}
		inputType := strings.ToLower(attrValue(input, typeAttrPattern))
		lower := strings.ToLower(name)

		switch {
		case inputType == "hidden":
			form.HiddenFields[name] = attrValue(input, valueAttrPattern)
		case form.UsernameField == "" && (strings.Contains(lower, "user") || strings.Contains(lower, "log") || strings.Contains(lower, "name") || strings.Contains(lower, "email")):
			form.UsernameField = name
		case form.PasswordField == "" && (strings.Contains(lower, "pass") || strings.Contains(lower, "pwd")):
			form.PasswordField = name
		}
	}

	return form
}

func attrValue(input string, pattern *regexp.Regexp) string {
	match := pattern.FindStringSubmatch(input)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// loginFailureMarkers are substrings commonly present on a failed login page.
var loginFailureMarkers = []string{
	"incorrect password",
	"incorrect username",
	"invalid credentials",
	"invalid login",
	"invalid username",
	"wrong password",
	"login failed",
	"authentication failed",
	"access denied",
	"user not found",
	"unable to log in",
}

// LoginFailed reports whether a response body indicates a failed login attempt.
func LoginFailed(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, marker := range loginFailureMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// ContainsAny reports whether the body contains any of the given markers
// (case-insensitive).
func ContainsAny(body []byte, markers ...string) bool {
	lower := strings.ToLower(string(body))
	for _, marker := range markers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

// ContainsAll reports whether the body contains every one of the given markers
// (case-insensitive).
func ContainsAll(body []byte, markers ...string) bool {
	lower := strings.ToLower(string(body))
	for _, marker := range markers {
		if !strings.Contains(lower, strings.ToLower(marker)) {
			return false
		}
	}
	return true
}
