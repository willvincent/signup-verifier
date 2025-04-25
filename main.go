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

	"github.com/willvincent/signup-verifier/internal/config"
	"github.com/willvincent/signup-verifier/internal/metrics"
	"github.com/willvincent/signup-verifier/internal/ratelimit"
	"github.com/willvincent/signup-verifier/internal/verifier"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var cfg *config.Config
var limiter *ratelimit.Limiter
var activeVerifier verifier.Verifier

func main() {
	var err error
	cfg, err = config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if cfg.RateLimit.Enabled {
		limiter = ratelimit.New(cfg.RateLimit.RequestsPerMin, cfg.RateLimit.Burst)
		log.Println("Rate limiting enabled")
	}

	if cfg.CheckDisposable {
		count, err := config.LoadDisposableDomains(cfg)
		if err != nil {
			log.Fatalf("Failed to load disposable domains: %v", err)
		}
		log.Printf("Loaded %d disposable domains\n", count)
	}

	if cfg.EmailVerifier.Provider != "" {
		activeVerifier, err = verifier.NewFromProvider(cfg.EmailVerifier.Provider, cfg.EmailVerifier.APIKey)
		if err != nil {
			log.Fatalf("Failed to load email verifier: %v", err)
		}
		log.Printf("Using %s for email verification", cfg.EmailVerifier.Provider)
	}

	// Setup metrics if enabled
	if cfg.Metrics.Enabled {
		metrics.Init()

		go func() {
			mux := http.NewServeMux()
			mux.Handle(cfg.Metrics.Route, promhttp.Handler())
			log.Printf("Serving metrics at %s%s\n", cfg.Metrics.Address, cfg.Metrics.Route)
			err := http.ListenAndServe(cfg.Metrics.Address, mux)
			if err != nil {
				log.Fatalf("Metrics server error: %v", err)
			}
		}()
	}

	// Main app mux
	mainMux := http.NewServeMux()
	mainMux.HandleFunc(cfg.Route, handleSignup)

	mainMux.HandleFunc(cfg.Health.Route, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	log.Printf("Health check available at %s\n", cfg.Health.Route)
	log.Printf("Main server listening on %s\n", cfg.ListenAddress)

	err = http.ListenAndServe(cfg.ListenAddress, mainMux)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer metrics.SignupDuration.Observe(time.Since(start).Seconds())

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getIP(r)
	if cfg.RateLimit.Enabled && !limiter.Allow(ip) {
		metrics.SignupAttempts.WithLabelValues("rate_limited").Inc()
		handleError(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		metrics.SignupAttempts.WithLabelValues("bad_form").Inc()
		handleError(w, "Invalid form submission", http.StatusBadRequest)
		return
	}

	// Honeypot
	if cfg.HoneypotField != "" && r.FormValue(cfg.HoneypotField) != "" {
		metrics.SignupAttempts.WithLabelValues("bot_trap").Inc()
		redirectThankYou(w, r)
		return
	}

	// Required fields
	missing := []string{}
	for _, field := range cfg.RequiredFields {
		if r.FormValue(field) == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		metrics.SignupAttempts.WithLabelValues("missing_fields").Inc()
		handleError(w, "Missing required fields", http.StatusUnprocessableEntity)
		return
	}

	// Email format
	email := r.FormValue("email")
	if !isValidEmail(email) {
		metrics.SignupAttempts.WithLabelValues("invalid_email_format").Inc()
		handleError(w, "Invalid email format", http.StatusUnprocessableEntity)
		return
	}
	domain := extractDomain(email)
	if domain == "" {
		metrics.SignupAttempts.WithLabelValues("email_domain_parse_error").Inc()
		handleError(w, "Could not extract domain", http.StatusUnprocessableEntity)
		return
	}

	// MX check
	if cfg.CheckMX && !hasMXRecord(domain) {
		metrics.SignupAttempts.WithLabelValues("mx_failed").Inc()
		handleError(w, "Email domain has no MX record", http.StatusUnprocessableEntity)
		return
	}

	// Disposable domain
	if cfg.CheckDisposable && config.IsDisposable(cfg, domain) {
		metrics.SignupAttempts.WithLabelValues("disposable_email").Inc()
		handleError(w, "Disposable email not allowed", http.StatusUnprocessableEntity)
		return
	}

	// External verifier
	if activeVerifier != nil {
		valid, err := verifyWithRetries(activeVerifier, email, cfg.EmailVerifier)
		if err != nil {
			metrics.SignupAttempts.WithLabelValues("verifier_error").Inc()
			metrics.VerifierResults.WithLabelValues(cfg.EmailVerifier.Provider, "error").Inc()
			if !cfg.EmailVerifier.FailOpen {
				handleError(w, "Email verification failed", http.StatusBadGateway)
				return
			}
		} else if !valid {
			metrics.SignupAttempts.WithLabelValues("email_invalid").Inc()
			metrics.VerifierResults.WithLabelValues(cfg.EmailVerifier.Provider, "invalid").Inc()
			handleError(w, "Email failed verification", http.StatusUnprocessableEntity)
			return
		} else {
			metrics.VerifierResults.WithLabelValues(cfg.EmailVerifier.Provider, "valid").Inc()
		}
	}

	// Allowed field filtering
	payload := make(url.Values)
	for _, field := range cfg.AllowedFields {
		if val := r.FormValue(field); val != "" {
			payload.Set(field, val)
		}
	}

	// Forward
	if cfg.Forward.Method == "POST" {
		resp, err := http.PostForm(cfg.Forward.URL, payload)
		if err != nil {
			metrics.SignupAttempts.WithLabelValues("forward_error").Inc()
			handleError(w, "Failed to forward submission", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
	}

	metrics.SignupAttempts.WithLabelValues("success").Inc()
	redirectThankYou(w, r)
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+$`)
	return re.MatchString(email)
}

func extractDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at+1 >= len(email) {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

func redirectThankYou(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, cfg.ThankYouURL, http.StatusFound)
}

func hasMXRecord(domain string) bool {
	mx, err := net.LookupMX(domain)
	return err == nil && len(mx) > 0
}

func getIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return xff
	}
	ip := r.RemoteAddr
	return ip
}

func handleError(w http.ResponseWriter, msg string, status int) {
	if cfg.OnError == "redirect" {
		http.Redirect(w, nil, cfg.ThankYouURL, http.StatusFound)
		return
	}
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"error": %q}`, msg)
}

func verifyWithRetries(v verifier.Verifier, email string, settings config.EmailVerifierConfig) (bool, error) {
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
