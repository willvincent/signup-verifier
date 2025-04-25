//go:build test

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/willvincent/signup-verifier/internal/config"
	"github.com/willvincent/signup-verifier/internal/ratelimit"
	"github.com/willvincent/signup-verifier/internal/verifier"
)

// dummyVerifier is a mock verifier for testing.
type dummyVerifier struct {
	valid bool
	err   error
}

func (d *dummyVerifier) Verify(email string) (bool, error) {
	return d.valid, d.err
}

// mockVerifier for timeout testing.
type mockVerifier struct {
	verifyFunc func(string) (bool, error)
}

func (m *mockVerifier) Verify(email string) (bool, error) {
	return m.verifyFunc(email)
}

func TestMain(m *testing.M) {
	verifier.Register("dummy", func(apiKey string) verifier.Verifier {
		return &dummyVerifier{valid: true}
	})
	// Enable debug logging for tests
	Debug = true
	os.Exit(m.Run())
}

func basicTestConfig() *config.Config {
	return &config.Config{
		ListenAddress: ":8080",
		Route:         "/signup",
		ThankYouURL:   "/thanks",
		HoneypotField: "",
		RequiredFields: []string{"email"},
		AllowedFields:  []string{"email"},
		Health: struct {
			Route string `yaml:"route"`
		}{Route: "/health"},
		Metrics: struct {
			Enabled bool   `yaml:"enabled"`
			Address string `yaml:"address"`
			Route   string `yaml:"route"`
		}{
			Enabled: false,
		},
		Forward: struct {
			Method string `yaml:"method"`
			URL    string `yaml:"url"`
		}{
			Method: "POST",
			URL:    "http://localhost/fake",
		},
		RateLimit: struct {
			Enabled        bool `yaml:"enabled"`
			RequestsPerMin int  `yaml:"requestsPerMinute"`
			Burst          int  `yaml:"burst"`
		}{},
		EmailVerifier: config.EmailVerifierConfig{},
		DisposableDomains: struct {
			LocalFile      string              `yaml:"localFile"`
			RemoteURL      string              `yaml:"remoteURL"`
			CacheTTLMin    int                 `yaml:"cacheTTLMinutes"`
			LastLoadedTime time.Time           `yaml:"-"`
			Domains        map[string]struct{} `yaml:"-"`
		}{
			Domains: make(map[string]struct{}),
		},
		OnError: struct {
			Method      string `yaml:method`
			ForwardData bool   `yaml:forwardData`
			Action      string `yaml:action`
		}{
			Action:      "json",
			Method:      "",
			ForwardData: false,
		},
	}
}

func TestPing(t *testing.T) {
	t.Log("Ping test running")
}

func TestRun(t *testing.T) {
	t.Log("Running TestRun")
	tests := []struct {
		name        string
		cfg         *config.Config
		setup       func(*App)
		expectError bool
	}{
		{
			name: "successful setup",
			cfg:  basicTestConfig(),
		},
		{
			name: "rate limiter enabled",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.RateLimit.Enabled = true
				cfg.RateLimit.RequestsPerMin = 10
				cfg.RateLimit.Burst = 2
				return cfg
			}(),
		},
		{
			name: "disposable domains enabled",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.CheckDisposable = true
				cfg.DisposableDomains.Domains = map[string]struct{}{"example.com": {}}
				return cfg
			}(),
		},
		{
			name: "email verifier enabled",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.EmailVerifier.Provider = "dummy"
				return cfg
			}(),
		},
		{
			name: "unknown verifier provider",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.EmailVerifier.Provider = "fakeprovider"
				return cfg
			}(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running subtest: %s", tt.name)
			app := NewApp(tt.cfg)
			if tt.setup != nil {
				tt.setup(app)
			}

			server, err := app.Run()
			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Run failed: %v", err)
			}
			if server == nil {
				t.Fatal("Expected non-nil server")
			}
			if server.Addr != tt.cfg.ListenAddress {
				t.Errorf("Expected server.Addr %q, got %q", tt.cfg.ListenAddress, server.Addr)
			}
		})
	}
}

func Test_handleSignup(t *testing.T) {
	t.Log("Running Test_handleSignup")
	tests := []struct {
		name           string
		cfg            *config.Config
		method         string
		formValues     url.Values
		headers        map[string]string
		setup          func(*testing.T, *App)
		expectedStatus int
		expectedBody   string
		expectedMetric string
	}{
		{
			name:           "non-POST method",
			cfg:            basicTestConfig(),
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed\n",
		},
		{
			name: "rate limit exceeded",
			cfg:  basicTestConfig(),
			setup: func(t *testing.T, app *App) {
				app.Config.RateLimit.Enabled = true
				app.Config.RateLimit.RequestsPerMin = 1
				app.Config.RateLimit.Burst = 1
				app.Limiter = ratelimit.New(1, 1)
				app.Limiter.Allow("1.2.3.4")
			},
			method:         http.MethodPost,
			headers:        map[string]string{"X-Forwarded-For": "1.2.3.4"},
			expectedStatus: http.StatusTooManyRequests,
			expectedBody:   `{"error": "Rate limit exceeded"}`,
			expectedMetric: "rate_limited",
		},
		{
			name:           "invalid form",
			cfg:            basicTestConfig(),
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"invalid@@example.com"}},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   `{"error": "Invalid email format"}`,
			expectedMetric: "invalid_email_format",
		},
		{
			name: "honeypot triggered",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.HoneypotField = "botfield"
				return cfg
			}(),
			method:         http.MethodPost,
			formValues:     url.Values{"botfield": {"bot"}, "email": {"test@example.com"}},
			expectedStatus: http.StatusFound,
			expectedBody:   "",
			expectedMetric: "bot_trap",
		},
		{
			name:           "missing required field",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.RequiredFields = []string{"email"}
				return cfg
			}(),
			method:         http.MethodPost,
			formValues:     url.Values{},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   `{"error": "Missing required fields: email"}`,
			expectedMetric: "missing_fields",
		},
		{
			name:           "invalid email format",
			cfg:            basicTestConfig(),
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"bademail"}},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   `{"error": "Invalid email format"}`,
			expectedMetric: "invalid_email_format",
		},
		{
			name:           "invalid email with no domain",
			cfg:            basicTestConfig(),
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"user@"}},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   `{"error": "Invalid email format"}`,
			expectedMetric: "invalid_email_format",
		},
		{
			name: "no MX record",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.CheckMX = true
				return cfg
			}(),
			setup: func(t *testing.T, app *App) {
				app.LookupMXFunc = func(domain string) ([]*net.MX, error) {
					return nil, fmt.Errorf("no MX records")
				}
			},
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"user@bad.com"}},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   `{"error": "Email domain has no MX record"}`,
			expectedMetric: "mx_failed",
		},
		{
			name: "disposable domain",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.CheckDisposable = true
				cfg.DisposableDomains = struct {
					LocalFile      string              `yaml:"localFile"`
					RemoteURL      string              `yaml:"remoteURL"`
					CacheTTLMin    int                 `yaml:"cacheTTLMinutes"`
					LastLoadedTime time.Time           `yaml:"-"`
					Domains        map[string]struct{} `yaml:"-"`
				}{
					Domains: map[string]struct{}{"example.com": {}},
				}
				return cfg
			}(),
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"user@example.com"}},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   `{"error": "Disposable email not allowed"}`,
			expectedMetric: "disposable_email",
		},
		{
			name: "email verification failure",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.EmailVerifier.Provider = "dummy"
				cfg.EmailVerifier.FailOpen = false
				return cfg
			}(),
			setup: func(t *testing.T, app *App) {
				app.Verifier = &dummyVerifier{valid: false}
			},
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"user@example.com"}},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedBody:   `{"error": "Email failed verification"}`,
			expectedMetric: "email_invalid",
		},
		{
			name: "email verification error with fail open",
			cfg: func() *config.Config {
				cfg := basicTestConfig()
				cfg.EmailVerifier.Provider = "dummy"
				cfg.EmailVerifier.FailOpen = true
				return cfg
			}(),
			setup: func(t *testing.T, app *App) {
				app.Verifier = &dummyVerifier{err: fmt.Errorf("verifier error")}
			},
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"user@example.com"}},
			expectedStatus: http.StatusFound,
			expectedBody:   "",
			expectedMetric: "success",
		},
		{
			name: "successful signup with forwarding",
			cfg:  basicTestConfig(),
			setup: func(t *testing.T, app *App) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(server.Close)
				app.Config.Forward.URL = server.URL
			},
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"user@example.com"}},
			expectedStatus: http.StatusFound,
			expectedBody:   "",
			expectedMetric: "success",
		},
		{
			name: "forwarding error",
			cfg:  basicTestConfig(),
			setup: func(t *testing.T, app *App) {
				app.HTTPClient = &http.Client{
					Transport: &http.Transport{
						DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
							return nil, fmt.Errorf("connection refused")
						},
					},
				}
			},
			method:         http.MethodPost,
			formValues:     url.Values{"email": {"user@example.com"}},
			expectedStatus: http.StatusBadGateway,
			expectedBody:   `{"error": "Failed to forward submission"}`,
			expectedMetric: "forward_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running subtest: %s", tt.name)
			app := NewApp(tt.cfg)
			if tt.setup != nil {
				tt.setup(t, app)
			}
			t.Cleanup(func() {
				app.Limiter = nil
				app.Verifier = nil
			})

			req := httptest.NewRequest(tt.method, tt.cfg.Route, strings.NewReader(tt.formValues.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()

			app.handleSignup(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
			if w.Body.String() != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, w.Body.String())
			}
			if tt.expectedStatus == http.StatusFound {
				if loc := w.Header().Get("Location"); loc != tt.cfg.ThankYouURL {
					t.Errorf("Expected redirect to %q, got %q", tt.cfg.ThankYouURL, loc)
				}
			}
		})
	}
}

func Test_redirectThankYou(t *testing.T) {
	t.Log("Running Test_redirectThankYou")
	cfg := basicTestConfig()
	app := NewApp(cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)

	app.redirectThankYou(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
	}
	if loc := w.Header().Get("Location"); loc != cfg.ThankYouURL {
		t.Errorf("Expected redirect to %q, got %q", cfg.ThankYouURL, loc)
	}
	// Allow empty body, as some Go versions may not write the HTML redirect body
	if w.Body.String() != "" && w.Body.String() != "<a href=\"/thanks\">Found</a>.\n\n" {
		t.Errorf("Expected body \"\" or \"<a href=\\\"/thanks\\\">Found</a>.\\n\\n\", got %q", w.Body.String())
	}
}

func Test_handleError(t *testing.T) {
	t.Log("Running Test_handleError")
	tests := []struct {
		name           string
		onError        struct {
			Method      string `yaml:method`
			ForwardData bool   `yaml:forwardData`
			Action      string `yaml:action`
		}
		msg            string
		status         int
		formValues     url.Values
		expectedBody   string
		expectedCode   int
		expectedURL    string
	}{
		{
			name: "json error",
			onError: struct {
				Method      string `yaml:method`
				ForwardData bool   `yaml:forwardData`
				Action      string `yaml:action`
			}{
				Action:      "json",
				Method:      "",
				ForwardData: false,
			},
			msg:          "Test error",
			status:       http.StatusBadRequest,
			expectedBody: `{"error": "Test error"}`,
			expectedCode: http.StatusBadRequest,
		},
		{
			name: "redirect error default",
			onError: struct {
				Method      string `yaml:method`
				ForwardData bool   `yaml:forwardData`
				Action      string `yaml:action`
			}{
				Action:      "redirect",
				Method:      "POST",
				ForwardData: false,
			},
			msg:          "Test error",
			status:       http.StatusBadRequest,
			expectedBody: "", // Allow empty body
			expectedCode: http.StatusFound,
			expectedURL:  "/thanks",
		},
		{
			name: "redirect error GET no data",
			onError: struct {
				Method      string `yaml:method`
				ForwardData bool   `yaml:forwardData`
				Action      string `yaml:action`
			}{
				Action:      "redirect",
				Method:      "GET",
				ForwardData: false,
			},
			msg:          "Test error",
			status:       http.StatusBadRequest,
			expectedBody: "", // Allow empty body
			expectedCode: http.StatusFound,
			expectedURL:  "/thanks",
		},
		{
			name: "redirect error GET with data",
			onError: struct {
				Method      string `yaml:method`
				ForwardData bool   `yaml:forwardData`
				Action      string `yaml:action`
			}{
				Action:      "redirect",
				Method:      "GET",
				ForwardData: true,
			},
			msg:          "Test error",
			status:       http.StatusBadRequest,
			formValues:   url.Values{"email": {"test@example.com"}, "name": {"Test"}},
			expectedBody: "", // Allow empty body
			expectedCode: http.StatusFound,
			expectedURL:  "/thanks?email=test%40example.com&name=Test",
		},
		{
			name: "missing fields error",
			onError: struct {
				Method      string `yaml:method`
				ForwardData bool   `yaml:forwardData`
				Action      string `yaml:action`
			}{
				Action:      "json",
				Method:      "",
				ForwardData: false,
			},
			msg:          "Missing required fields: email, name",
			status:       http.StatusUnprocessableEntity,
			expectedBody: `{"error": "Missing required fields: email, name"}`,
			expectedCode: http.StatusUnprocessableEntity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running subtest: %s", tt.name)
			cfg := basicTestConfig()
			cfg.OnError = tt.onError
			app := NewApp(cfg)
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/signup", nil)
			req.Form = tt.formValues

			app.handleError(w, req, tt.msg, tt.status)

			if w.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, w.Code)
			}
			if w.Body.String() != tt.expectedBody && (tt.expectedBody != "" || w.Body.String() != "<a href=\""+tt.expectedURL+"\">Found</a>.\n\n") {
				t.Errorf("Expected body %q or redirect HTML, got %q", tt.expectedBody, w.Body.String())
			}
			if tt.onError.Action == "redirect" {
				if loc := w.Header().Get("Location"); loc != tt.expectedURL {
					t.Errorf("Expected redirect to %q, got %q", tt.expectedURL, loc)
				}
			}
		})
	}
}




func Test_isValidEmail(t *testing.T) {
	t.Log("Running Test_isValidEmail")
	app := NewApp(basicTestConfig())
	tests := map[string]bool{
		"valid@example.com": true,
		"bademail":          false,
		"missing@domain":    false,
		"user@domain.com":   true,
	}

	for email, expected := range tests {
		t.Run(email, func(t *testing.T) {
			t.Logf("Running subtest: %s", email)
			if got := app.isValidEmail(email); got != expected {
				t.Errorf("isValidEmail(%q) = %v, want %v", email, got, expected)
			}
		})
	}
}

func Test_extractDomain(t *testing.T) {
	t.Log("Running Test_extractDomain")
	app := NewApp(basicTestConfig())
	tests := map[string]string{
		"valid@example.com": "example.com",
		"user@sub.domain":   "sub.domain",
		"invalid":           "",
		"user@":             "",
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			t.Logf("Running subtest: %s", input)
			if got := app.extractDomain(input); got != expected {
				t.Errorf("extractDomain(%q) = %q, want %q", input, got, expected)
			}
		})
	}
}

func Test_getIP(t *testing.T) {
	t.Log("Running Test_getIP")
	app := NewApp(basicTestConfig())
	tests := []struct {
		name     string
		req      *http.Request
		expected string
	}{
		{
			name: "remote addr",
			req: func() *http.Request {
				req := httptest.NewRequest("POST", "/", nil)
				req.RemoteAddr = "1.2.3.4:5678"
				return req
			}(),
			expected: "1.2.3.4:5678",
		},
		{
			name: "X-Forwarded-For",
			req: func() *http.Request {
				req := httptest.NewRequest("POST", "/", nil)
				req.Header.Set("X-Forwarded-For", "9.9.9.9")
				return req
			}(),
			expected: "9.9.9.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running subtest: %s", tt.name)
			if got := app.getIP(tt.req); got != tt.expected {
				t.Errorf("getIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func Test_hasMXRecord(t *testing.T) {
	t.Log("Running Test_hasMXRecord")
	tests := []struct {
		name      string
		domain    string
		lookupMX  func(string) ([]*net.MX, error)
		expected  bool
	}{
		{
			name:   "has MX record",
			domain: "good.com",
			lookupMX: func(domain string) ([]*net.MX, error) {
				return []*net.MX{{Host: "mail.good.com"}}, nil
			},
			expected: true,
		},
		{
			name:   "no MX record",
			domain: "bad.com",
			lookupMX: func(domain string) ([]*net.MX, error) {
				return nil, fmt.Errorf("no MX records")
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running subtest: %s", tt.name)
			app := NewApp(basicTestConfig())
			app.LookupMXFunc = tt.lookupMX
			if got := app.hasMXRecord(tt.domain); got != tt.expected {
				t.Errorf("hasMXRecord(%q) = %v, want %v", tt.domain, got, tt.expected)
			}
		})
	}
}

func Test_verifyWithRetries(t *testing.T) {
	t.Log("Running Test_verifyWithRetries")
	tests := []struct {
		name          string
		verifier      verifier.Verifier
		settings      config.EmailVerifierConfig
		expectedValid bool
		expectedErr   error
	}{
		{
			name:          "successful verification",
			verifier:      &dummyVerifier{valid: true},
			settings:      config.EmailVerifierConfig{TimeoutSec: 1, MaxRetries: 0},
			expectedValid: true,
			expectedErr:   nil,
		},
		{
			name:     "verifier error with retries",
			verifier: &dummyVerifier{err: fmt.Errorf("verifier error")},
			settings: config.EmailVerifierConfig{TimeoutSec: 1, MaxRetries: 1},
			expectedValid: false,
			expectedErr:   fmt.Errorf("verifier error"),
		},
		{
			name: "timeout",
			verifier: &mockVerifier{
				verifyFunc: func(email string) (bool, error) {
					time.Sleep(2 * time.Second)
					return true, nil
				},
			},
			settings:      config.EmailVerifierConfig{TimeoutSec: 1, MaxRetries: 1},
			expectedValid: false,
			expectedErr:   context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Running subtest: %s", tt.name)
			app := NewApp(basicTestConfig())
			valid, err := app.verifyWithRetries(tt.verifier, "test@example.com", tt.settings)
			if valid != tt.expectedValid {
				t.Errorf("Expected valid %v, got %v", tt.expectedValid, valid)
			}
			if err != tt.expectedErr && (err == nil || tt.expectedErr == nil || err.Error() != tt.expectedErr.Error()) {
				t.Errorf("Expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestServerEndToEnd(t *testing.T) {
	t.Log("Running TestServerEndToEnd")
	cfg := basicTestConfig()
	app := NewApp(cfg)
	server, err := app.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	defer server.Close()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
	resp, err := client.PostForm("http://localhost:8080/signup", url.Values{"email": {"test@example.com"}})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != cfg.ThankYouURL {
		t.Errorf("Expected redirect to %q, got %q", cfg.ThankYouURL, loc)
	}
}

func Test_loadDisposables(t *testing.T) {
	t.Log("Running Test_loadDisposables")
	cfg := basicTestConfig()
	cfg.CheckDisposable = true
	cfg.DisposableDomains = struct {
		LocalFile      string              `yaml:"localFile"`
		RemoteURL      string              `yaml:"remoteURL"`
		CacheTTLMin    int                 `yaml:"cacheTTLMinutes"`
		LastLoadedTime time.Time           `yaml:"-"`
		Domains        map[string]struct{} `yaml:"-"`
	}{
		Domains: map[string]struct{}{"example.com": {}},
	}
	app := NewApp(cfg)
	err := app.loadDisposables()
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
}

func Test_startMetrics(t *testing.T) {
	t.Log("Running Test_startMetrics")
	cfg := basicTestConfig()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = ":0" // Ephemeral port
	cfg.Metrics.Route = "/metrics"
	app := NewApp(cfg)
	err := app.startMetrics()
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
}