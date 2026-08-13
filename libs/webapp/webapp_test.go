package webapp

import "testing"

func TestDetect_WordPress(t *testing.T) {
	body := []byte(`<html><head><meta name="generator" content="WordPress 4.9.8" /></head>
		<body><a href="http://example.com/wp-content/theme.css"></a></body></html>`)
	if app := Detect(body, "Apache"); app != AppWordPress {
		t.Errorf("Detect() = %q, want %q", app, AppWordPress)
	}
}

func TestDetect_Tomcat_ServerHeader(t *testing.T) {
	if app := Detect([]byte("<html></html>"), "Apache-Coyote/1.1"); app != AppTomcat {
		t.Errorf("Detect() = %q, want %q", app, AppTomcat)
	}
}

func TestDetect_Drupal(t *testing.T) {
	body := []byte(`<script>Drupal.settings = {};</script>`)
	if app := Detect(body, "nginx"); app != AppDrupal {
		t.Errorf("Detect() = %q, want %q", app, AppDrupal)
	}
}

func TestDetect_Unknown(t *testing.T) {
	if app := Detect([]byte("<html>hello</html>"), "nginx"); app != AppUnknown {
		t.Errorf("Detect() = %q, want empty", app)
	}
}

func TestGeneratorVersion(t *testing.T) {
	body := []byte(`<meta name="generator" content="WordPress 4.9.8" />`)
	if version := GeneratorVersion(body); version != "4.9.8" {
		t.Errorf("GeneratorVersion() = %q, want %q", version, "4.9.8")
	}
}

func TestGeneratorVersion_Empty(t *testing.T) {
	if version := GeneratorVersion([]byte("<html></html>")); version != "" {
		t.Errorf("GeneratorVersion() = %q, want empty", version)
	}
}

func TestParseLoginForm(t *testing.T) {
	body := []byte(`<html><form method="post" action="/wp-login.php">
		<input type="hidden" name="redirect_to" value="/wp-admin/" />
		<input type="text" name="log" />
		<input type="password" name="pwd" />
		<input type="submit" value="Log In" />
		</form></html>`)

	form := ParseLoginForm(body)
	if form.Action != "/wp-login.php" {
		t.Errorf("Action = %q, want /wp-login.php", form.Action)
	}
	if form.UsernameField != "log" {
		t.Errorf("UsernameField = %q, want log", form.UsernameField)
	}
	if form.PasswordField != "pwd" {
		t.Errorf("PasswordField = %q, want pwd", form.PasswordField)
	}
	if form.HiddenFields["redirect_to"] != "/wp-admin/" {
		t.Errorf("HiddenFields = %v, want redirect_to", form.HiddenFields)
	}
}

func TestParseLoginForm_Empty(t *testing.T) {
	form := ParseLoginForm([]byte("<html></html>"))
	if form.UsernameField != "" || form.PasswordField != "" {
		t.Errorf("expected empty form fields, got %q / %q", form.UsernameField, form.PasswordField)
	}
}

func TestLoginFailed(t *testing.T) {
	if !LoginFailed([]byte("Error: incorrect password for user admin")) {
		t.Error("expected login failure detected")
	}
	if LoginFailed([]byte("Welcome back!")) {
		t.Error("expected no login failure")
	}
}

func TestContainsAny(t *testing.T) {
	if !ContainsAny([]byte("Hello World"), "world") {
		t.Error("expected contains")
	}
	if ContainsAny([]byte("Hello World"), "xyz") {
		t.Error("expected not contains")
	}
}

func TestContainsAll(t *testing.T) {
	if !ContainsAll([]byte("foo bar baz"), "foo", "baz") {
		t.Error("expected contains all")
	}
	if ContainsAll([]byte("foo bar baz"), "foo", "qux") {
		t.Error("expected not contains all")
	}
}
