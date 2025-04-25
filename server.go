//go:build !test || test

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/willvincent/signup-verifier/internal/config"
	"github.com/willvincent/signup-verifier/internal/metrics"
	"github.com/willvincent/signup-verifier/internal/ratelimit"
	"github.com/willvincent/signup-verifier/internal/verifier"
)

// App holds the application state and dependencies.
type App struct {
	Config       *config.Config
	Limiter      *ratelimit.Limiter
	Verifier     verifier.Verifier
	HTTPClient   *http.Client
	LookupMXFunc func(string) ([]*net.MX, error)
}

// NewApp creates a new App with default dependencies.
func NewApp(cfg *config.Config) *App {
	return &App{
		Config:       cfg,
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		LookupMXFunc: net.LookupMX,
	}
}

// Run sets up and returns an HTTP server.
func (app *App) Run() (*http.Server, error) {
	if err := app.setupRateLimiter(); err != nil {
		return nil, err
	}
	if err := app.loadDisposables(); err != nil {
		return nil, err
	}
	if err := app.setupEmailVerifier(); err != nil {
		return nil, err
	}
	if err := app.startMetrics(); err != nil {
		return nil, err
	}

	mux := app.setupMux()

	server := &http.Server{
		Addr:    app.Config.ListenAddress,
		Handler: mux,
	}

	return server, nil
}

func (app *App) setupRateLimiter() error {
	if !app.Config.RateLimit.Enabled {
		return nil
	}
	app.Limiter = ratelimit.New(app.Config.RateLimit.RequestsPerMin, app.Config.RateLimit.Burst)
	log.Println("Rate limiting enabled")
	return nil
}

func (app *App) loadDisposables() error {
	if !app.Config.CheckDisposable {
		return nil
	}
	count, err := config.LoadDisposableDomains(app.Config)
	if err != nil {
		return fmt.Errorf("load disposable domains: %w", err)
	}
	log.Printf("Loaded %d disposable domains\n", count)
	return nil
}

func (app *App) setupEmailVerifier() error {
	if app.Config.EmailVerifier.Provider == "" {
		return nil
	}
	var err error
	app.Verifier, err = verifier.NewFromProvider(app.Config.EmailVerifier.Provider, app.Config.EmailVerifier.APIKey)
	if err != nil {
		return fmt.Errorf("load email verifier: %w", err)
	}
	log.Printf("Using %s for email verification", app.Config.EmailVerifier.Provider)
	return nil
}

func (app *App) startMetrics() error {
	if !app.Config.Metrics.Enabled {
		return nil
	}
	metrics.Init()
	mux := http.NewServeMux()
	mux.Handle(app.Config.Metrics.Route, promhttp.Handler())
	log.Printf("Serving metrics at %s%s\n", app.Config.Metrics.Address, app.Config.Metrics.Route)
	go func() {
		if err := http.ListenAndServe(app.Config.Metrics.Address, mux); err != nil {
			log.Fatalf("Metrics server error: %v", err)
		}
	}()
	return nil
}

func (app *App) setupMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(app.Config.Route, app.handleSignup)
	mux.HandleFunc(app.Config.Health.Route, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/thanks", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<h1>Thank You!</h1>")
	})
	log.Printf("Health check available at %s\n", app.Config.Health.Route)
	log.Printf("Main server listening on %s\n", app.Config.ListenAddress)
	return mux
}

func (app *App) handleSignup(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer metrics.SignupDuration.Observe(time.Since(start).Seconds())

	if debug {
		log.Printf("Handling signup request: method=%s, remoteAddr=%s, headers=%v, form=%v", r.Method, r.RemoteAddr, r.Header, r.Form)
	}

	if r.Method != http.MethodPost {
		if debug {
			log.Printf("Invalid method: %s", r.Method)
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := app.getIP(r)
	if app.Config.RateLimit.Enabled && app.Limiter != nil && !app.Limiter.Allow(ip) {
		metrics.SignupAttempts.WithLabelValues("rate_limited").Inc()
		if debug {
			log.Printf("Rate limit exceeded for IP: %s", ip)
		}
		app.handleError(w, r, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		metrics.SignupAttempts.WithLabelValues("bad_form").Inc()
		if debug {
			log.Printf("Invalid form submission: %v", err)
		}
		app.handleError(w, r, "Invalid form submission", http.StatusBadRequest)
		return
	}

	if app.Config.HoneypotField != "" && r.FormValue(app.Config.HoneypotField) != "" {
		metrics.SignupAttempts.WithLabelValues("bot_trap").Inc()
		if debug {
			log.Printf("Honeypot triggered: field=%s, value=%s", app.Config.HoneypotField, r.FormValue(app.Config.HoneypotField))
		}
		app.redirectThankYou(w, r)
		return
	}

	missing := []string{}
	for _, field := range app.Config.RequiredFields {
		if r.FormValue(field) == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		metrics.SignupAttempts.WithLabelValues("missing_fields").Inc()
		errMsg := fmt.Sprintf("Missing required fields: %s", strings.Join(missing, ", "))
		if debug {
			log.Printf("Missing required fields: %v", missing)
		}
		app.handleError(w, r, errMsg, http.StatusUnprocessableEntity)
		return
	}

	email := r.FormValue("email")
	if !app.isValidEmail(email) {
		metrics.SignupAttempts.WithLabelValues("invalid_email_format").Inc()
		if debug {
			log.Printf("Invalid email format: %s", email)
		}
		app.handleError(w, r, "Invalid email format", http.StatusUnprocessableEntity)
		return
	}
	domain := app.extractDomain(email)
	if domain == "" {
		metrics.SignupAttempts.WithLabelValues("email_domain_parse_error").Inc()
		if debug {
			log.Printf("Could not extract domain from email: %s", email)
		}
		app.handleError(w, r, "Could not extract domain", http.StatusUnprocessableEntity)
		return
	}

	if app.Config.CheckMX && !app.hasMXRecord(domain) {
		metrics.SignupAttempts.WithLabelValues("mx_failed").Inc()
		if debug {
			log.Printf("Email domain has no MX record: %s", domain)
		}
		app.handleError(w, r, "Email domain has no MX record", http.StatusUnprocessableEntity)
		return
	}

	if app.Config.CheckDisposable && config.IsDisposable(app.Config, domain) {
		metrics.SignupAttempts.WithLabelValues("disposable_email").Inc()
		if debug {
			log.Printf("Disposable email not allowed: %s", domain)
		}
		app.handleError(w, r, "Disposable email not allowed", http.StatusUnprocessableEntity)
		return
	}

	if app.Verifier != nil {
		valid, err := app.verifyWithRetries(app.Verifier, email, app.Config.EmailVerifier)
		if err != nil {
			metrics.SignupAttempts.WithLabelValues("verifier_error").Inc()
			metrics.VerifierResults.WithLabelValues(app.Config.EmailVerifier.Provider, "error").Inc()
			if debug {
				log.Printf("Email verification failed: %v", err)
			}
			if !app.Config.EmailVerifier.FailOpen {
				app.handleError(w, r, "Email verification failed", http.StatusBadGateway)
				return
			}
		} else if !valid {
			metrics.SignupAttempts.WithLabelValues("email_invalid").Inc()
			metrics.VerifierResults.WithLabelValues(app.Config.EmailVerifier.Provider, "invalid").Inc()
			if debug {
				log.Printf("Email failed verification: %s", email)
			}
			app.handleError(w, r, "Email failed verification", http.StatusUnprocessableEntity)
			return
		} else {
			metrics.VerifierResults.WithLabelValues(app.Config.EmailVerifier.Provider, "valid").Inc()
			if debug {
				log.Printf("Email verified successfully: %s", email)
			}
		}
	}

	payload := make(url.Values)
	for _, field := range app.Config.AllowedFields {
		if val := r.FormValue(field); val != "" {
			payload.Set(field, val)
		}
	}

	if app.Config.Forward.Method == "POST" {
		resp, err := app.HTTPClient.PostForm(app.Config.Forward.URL, payload)
		if err != nil {
			metrics.SignupAttempts.WithLabelValues("forward_error").Inc()
			if debug {
				log.Printf("Failed to forward submission: %v", err)
			}
			app.handleError(w, r, "Failed to forward submission", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if debug {
			log.Printf("Successfully forwarded submission to %s", app.Config.Forward.URL)
		}
	}

	metrics.SignupAttempts.WithLabelValues("success").Inc()
	if debug {
		log.Printf("Signup successful for email: %s, initiating redirect to %s", email, app.Config.ThankYouURL)
	}
	app.redirectThankYou(w, r)
}

func (app *App) isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z_+])*@(([0-9a-zA-Z][-\w]*\.)+[a-zA-Z]{2,9})$`)
	return re.MatchString(email)
}

func (app *App) extractDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at+1 >= len(email) {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

func (app *App) redirectThankYou(w http.ResponseWriter, r *http.Request) {
	if debug {
		log.Printf("Attempting redirect to thank you page: URL=%s, client headers=%v", app.Config.ThankYouURL, r.Header)
	}

	// Validate ThankYouURL
	if app.Config.ThankYouURL == "" {
		if debug {
			log.Printf("ThankYouURL is empty, returning error response")
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error": "Thank you page URL not configured"}`)
		return
	}

	// Parse URL to ensure it’s valid
	parsedURL, err := url.ParseRequestURI(app.Config.ThankYouURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		if debug {
			log.Printf("Invalid ThankYouURL: %s, error: %v", app.Config.ThankYouURL, err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error": "Invalid thank you page URL"}`)
		return
	}

	// Set the redirect and log details
	w.Header().Set("Location", app.Config.ThankYouURL)
	if debug {
		log.Printf("Redirecting client to %s with GET, status=%d, Location header=%s", app.Config.ThankYouURL, http.StatusFound, w.Header().Get("Location"))
	}
	http.Redirect(w, r, app.Config.ThankYouURL, http.StatusFound)
}

func (app *App) hasMXRecord(domain string) bool {
	mx, err := app.LookupMXFunc(domain)
	return err == nil && len(mx) > 0
}

func (app *App) getIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return xff
	}
	return r.RemoteAddr
}

func (app *App) handleError(w http.ResponseWriter, r *http.Request, msg string, status int) {
	if debug {
		log.Printf("Handling error: msg=%s, status=%d, onError=%s", msg, status, app.Config.OnError)
	}

	if app.Config.OnError.Action == "redirect" {
		if app.Config.OnError.Method == "GET" {
			// Redirect with GET, optionally forwarding data if configured
			url := app.Config.ThankYouURL
			if app.Config.OnError.ForwardData && r.Form != nil {
				query := r.Form.Encode()
				if query != "" {
					if strings.Contains(url, "?") {
						url += "&" + query
					} else {
						url += "?" + query
					}
				}
			}
			http.Redirect(w, r, url, http.StatusFound)
		} else {
			// Default to original redirect behavior (POST data included)
			http.Redirect(w, r, app.Config.ThankYouURL, http.StatusFound)
		}
		return
	}

	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"error": %q}`, msg)
}

func (app *App) verifyWithRetries(v verifier.Verifier, email string, settings config.EmailVerifierConfig) (bool, error) {
	timeout := time.Duration(settings.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	retries := settings.MaxRetries
	var lastErr error

	for attempt := 0; attempt <= retries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		resultCh := make(chan struct {
			valid bool
			err   error
		}, 1)

		go func() {
			valid, err := v.Verify(email)
			resultCh <- struct {
				valid bool
				err   error
			}{valid, err}
		}()

		select {
		case res := <-resultCh:
			if res.err != nil {
				lastErr = res.err
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return res.valid, nil
		case <-ctx.Done():
			lastErr = ctx.Err()
		}
	}

	return false, lastErr
}

// Run is a top-level function to maintain compatibility with main.go.
func Run(cfg *config.Config) (*http.Server, error) {
	app := NewApp(cfg)
	return app.Run()
}