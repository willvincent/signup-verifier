package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

func TestLoadConfig(t *testing.T) {
	tmp := []byte(`
listenAddress: ":8080"
route: "/signup"
thankYouURL: "/thanks"
onError: "json"
requiredFields: ["email"]
allowedFields: ["email"]
forward:
  method: "POST"
  url: "http://localhost/fake"
`)
	path := "test_config.yaml"
	if err := os.WriteFile(path, tmp, 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}
	defer os.Remove(path)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.ListenAddress != ":8080" {
		t.Errorf("Expected :8080, got %s", cfg.ListenAddress)
	}
}

func TestIsDisposable(t *testing.T) {
	cfg := &Config{}
	cfg.DisposableDomains.Domains = map[string]struct{}{
		"mailinator.com": {},
		"tempmail.com":   {},
	}

	if !IsDisposable(cfg, "mailinator.com") {
		t.Error("Expected mailinator.com to be disposable")
	}
	if IsDisposable(cfg, "gmail.com") {
		t.Error("Expected gmail.com to NOT be disposable")
	}
}

func TestLoadDisposableDomains_LocalFallback(t *testing.T) {
	path := "test_disposables.txt"
	os.WriteFile(path, []byte("disposable.com\n# comment\n\n temp.com"), 0644)
	defer os.Remove(path)

	cfg := &Config{}
	cfg.DisposableDomains.LocalFile = path

	count, err := LoadDisposableDomains(cfg)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 valid domains, got %d", count)
	}
}

func TestLoadDisposableDomains_RemoteFails_ThenLocal(t *testing.T) {
	path := "test_fallback.txt"
	os.WriteFile(path, []byte("a.com\nb.com"), 0644)
	defer os.Remove(path)

	cfg := &Config{}
	cfg.DisposableDomains.RemoteURL = "http://localhost:9999/404"
	cfg.DisposableDomains.LocalFile = path

	count, err := LoadDisposableDomains(cfg)
	if err != nil {
		t.Fatalf("load fallback failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 fallback domains, got %d", count)
	}
}

func TestLoadDisposableDomains_NothingPresent(t *testing.T) {
	cfg := &Config{}
	count, err := LoadDisposableDomains(cfg)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 domains, got %d", count)
	}
}

func TestLoadDisposableDomains_LocalMissingFile(t *testing.T) {
	cfg := &Config{}
	cfg.DisposableDomains.LocalFile = "does_not_exist.txt"

	count, err := LoadDisposableDomains(cfg)
	if err == nil {
		t.Error("Expected error opening nonexistent file")
	}
	if count != 0 {
		t.Errorf("Expected 0 domains, got %d", count)
	}
}

func TestLoadDisposableDomains_RemoteScannerError(t *testing.T) {
	// Create a handler that returns a body that will trigger a scan error
	brokenReader := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write something invalid that makes Scanner choke (no newline etc)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0xff, 0xfe, 0xfd}) // Invalid UTF-8
	})

	s := httptest.NewServer(brokenReader)
	defer s.Close()

	cfg := &Config{}
	cfg.DisposableDomains.RemoteURL = s.URL

	_, err := LoadDisposableDomains(cfg)
	if err != nil {
		t.Errorf("expected graceful fallback, got error: %v", err)
	}
}

func TestParseDisposableDomains_Success(t *testing.T) {
	input := strings.NewReader("a.com\nb.com\n# comment\n\nc.com")
	domains, err := parseDisposableDomains(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 3 {
		t.Errorf("expected 3 domains, got %d", len(domains))
	}
}

func TestParseDisposableDomains_Error(t *testing.T) {
	r := iotest.ErrReader(fmt.Errorf("scan fail"))
	_, err := parseDisposableDomains(r)
	if err == nil {
		t.Errorf("expected scanner error")
	}
}
