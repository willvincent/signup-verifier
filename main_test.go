package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestIsValidEmail(t *testing.T) {
	valid := []string{
		"test@example.com",
		"foo.bar+123@sub.domain.co.uk",
		"user_name@domain.io",
		"u@x.co",
	}
	invalid := []string{
		"",
		"plainaddress",
		"@no-local-part.com",
		"user@.com",
		"user@localhost",
		"user@domain..com",
	}

	for _, email := range valid {
		if !isValidEmail(email) {
			t.Errorf("Expected valid email: %q", email)
		}
	}

	for _, email := range invalid {
		if isValidEmail(email) {
			t.Errorf("Expected invalid email: %q", email)
		}
	}
}

func TestExtractDomain(t *testing.T) {
	cases := map[string]string{
		"test@example.com":        "example.com",
		"user@sub.domain.co.uk":   "sub.domain.co.uk",
		"missing-at-symbol":       "",
		"@no-user-part.com":       "no-user-part.com",
		"user@":                   "",
		"user@invalid..domain":    "invalid..domain",
		"user@@double.at.com":     "double.at.com",
	}

	for input, expected := range cases {
		got := extractDomain(input)
		if got != expected {
			t.Errorf("extractDomain(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestHasMXRecord(t *testing.T) {
	t.Run("valid domain", func(t *testing.T) {
		if !hasMXRecord("gmail.com") {
			t.Error("Expected gmail.com to have MX record")
		}
	})

	t.Run("nonexistent domain", func(t *testing.T) {
		if hasMXRecord("this-domain-should-not-exist-xyz123.com") {
			t.Error("Expected nonexistent domain to not have MX record")
		}
	})
}

func TestGetIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.0.1:12345"

	// no XFF header
	if ip := getIP(req); ip != "192.168.0.1:12345" {
		t.Errorf("expected remote addr, got %s", ip)
	}

	// with XFF header
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if ip := getIP(req); ip != "203.0.113.9" {
		t.Errorf("expected X-Forwarded-For IP, got %s", ip)
	}
}

func TestHoneypotTrap(t *testing.T) {
	form := url.Values{}
	form.Set("email", "user@example.com")
	form.Set("nickname", "bot")

	req := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	if req.FormValue("nickname") == "" {
		t.Error("honeypot should be populated for this test")
	}
}
