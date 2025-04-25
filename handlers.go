package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/willvincent/signup-verifier/internal/config"
	"github.com/willvincent/signup-verifier/internal/metrics"
)

type webhookPayload struct {
	Email     string `json:"email"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}

func (app *App) handleSignup(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer metrics.SignupDuration.Observe(time.Since(start).Seconds())

	if Debug {
		log.Printf("Handling signup request: method=%s, remoteAddr=%s, headers=%v, form=%v", r.Method, r.RemoteAddr, r.Header, r.Form)
	}

	if r.Method != http.MethodPost {
		if Debug {
			log.Printf("Invalid method: %s", r.Method)
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := app.getIP(r)
	if app.Config.RateLimit.Enabled && app.Limiter != nil && !app.Limiter.Allow(ip) {
		metrics.SignupAttempts.WithLabelValues("rate_limited").Inc()
		if Debug {
			log.Printf("Rate limit exceeded for IP: %s", ip)
		}
		app.fireWebhook("", "failed", "Rate limit exceeded")
		app.handleError(w, r, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		metrics.SignupAttempts.WithLabelValues("bad_form").Inc()
		if Debug {
			log.Printf("Invalid form submission: %v", err)
		}
		app.fireWebhook("", "failed", "Invalid form submission")
		app.handleError(w, r, "Invalid form submission", http.StatusBadRequest)
		return
	}

	if app.Config.HoneypotField != "" && r.FormValue(app.Config.HoneypotField) != "" {
		metrics.SignupAttempts.WithLabelValues("bot_trap").Inc()
		if Debug {
			log.Printf("Honeypot triggered: field=%s, value=%s", app.Config.HoneypotField, r.FormValue(app.Config.HoneypotField))
		}
		app.fireWebhook("", "failed", "Honeypot triggered")
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
		if Debug {
			log.Printf("Missing required fields: %v", missing)
		}
		app.fireWebhook("", "failed", errMsg)
		app.handleError(w, r, errMsg, http.StatusUnprocessableEntity)
		return
	}

	email := r.FormValue("email")
	if !app.isValidEmail(email) {
		metrics.SignupAttempts.WithLabelValues("invalid_email_format").Inc()
		if Debug {
			log.Printf("Invalid email format: %s", email)
		}
		app.fireWebhook(email, "failed", "Invalid email format")
		app.handleError(w, r, "Invalid email format", http.StatusUnprocessableEntity)
		return
	}
	domain := app.extractDomain(email)
	if domain == "" {
		metrics.SignupAttempts.WithLabelValues("email_domain_parse_error").Inc()
		if Debug {
			log.Printf("Could not extract domain from email: %s", email)
		}
		app.fireWebhook(email, "failed", "Could not extract domain")
		app.handleError(w, r, "Could not extract domain", http.StatusUnprocessableEntity)
		return
	}

	if app.Config.CheckMX && !app.hasMXRecord(domain) {
		metrics.SignupAttempts.WithLabelValues("mx_failed").Inc()
		if Debug {
			log.Printf("Email domain has no MX record: %s", domain)
		}
		app.fireWebhook(email, "failed", "Email domain has no MX record")
		app.handleError(w, r, "Email domain has no MX record", http.StatusUnprocessableEntity)
		return
	}

	if app.Config.CheckDisposable && config.IsDisposable(app.Config, domain) {
		metrics.SignupAttempts.WithLabelValues("disposable_email").Inc()
		if Debug {
			log.Printf("Disposable email not allowed: %s", domain)
		}
		app.fireWebhook(email, "failed", "Disposable email not allowed")
		app.handleError(w, r, "Disposable email not allowed", http.StatusUnprocessableEntity)
		return
	}

	if app.Verifier != nil {
		valid, err := app.verifyWithRetries(app.Verifier, email, app.Config.EmailVerifier)
		if err != nil {
			metrics.SignupAttempts.WithLabelValues("verifier_error").Inc()
			metrics.VerifierResults.WithLabelValues(app.Config.EmailVerifier.Provider, "error").Inc()
			if Debug {
				log.Printf("Email verification failed: %v", err)
			}
			app.fireWebhook(email, "failed", "Email verification failed")
			if !app.Config.EmailVerifier.FailOpen {
				app.handleError(w, r, "Email verification failed", http.StatusBadGateway)
				return
			}
		} else if !valid {
			metrics.SignupAttempts.WithLabelValues("email_invalid").Inc()
			metrics.VerifierResults.WithLabelValues(app.Config.EmailVerifier.Provider, "invalid").Inc()
			if Debug {
				log.Printf("Email failed verification: %s", email)
			}
			app.fireWebhook(email, "failed", "Email failed verification")
			app.handleError(w, r, "Email failed verification", http.StatusUnprocessableEntity)
			return
		} else {
			metrics.VerifierResults.WithLabelValues(app.Config.EmailVerifier.Provider, "valid").Inc()
			if Debug {
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
			if Debug {
				log.Printf("Failed to forward submission: %v", err)
			}
			app.fireWebhook(email, "failed", "Failed to forward submission")
			app.handleError(w, r, "Failed to forward submission", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if Debug {
			log.Printf("Successfully forwarded submission to %s", app.Config.Forward.URL)
		}
	}

	metrics.SignupAttempts.WithLabelValues("success").Inc()
	if Debug {
		log.Printf("Signup successful for email: %s, initiating redirect to %s", email, app.Config.ThankYouURL)
	}
	app.fireWebhook(email, "success", "")
	app.redirectThankYou(w, r)
}

func (app *App) handleError(w http.ResponseWriter, r *http.Request, msg string, status int) {
	if Debug {
		log.Printf("Handling error: msg=%s, status=%d, onError=%s, onErrorMethod=%s, onErrorForwardData=%v",
			msg, status, app.Config.OnError.Action, app.Config.OnError.Method, app.Config.OnError.ForwardData)
	}

	if app.Config.OnError.Action == "redirect" {
		url := app.Config.ThankYouURL
		if app.Config.OnError.Method == "GET" && r.Form != nil {
			if app.Config.OnError.ForwardData {
				query := r.Form.Encode()
				if query != "" {
					if strings.Contains(url, "?") {
						url += "&" + query
					} else {
						url += "?" + query
					}
				}
			}
			if Debug {
				log.Printf("Redirecting to %s with GET, forwardData=%v", url, app.Config.OnError.ForwardData)
			}
			w.Header().Set("Location", url)
			http.Redirect(w, r, url, http.StatusFound)
			return
		}
		if Debug {
			log.Printf("Redirecting to %s with POST", url)
		}
		w.Header().Set("Location", url)
		http.Redirect(w, r, url, http.StatusFound)
		return
	}

	if Debug {
		log.Printf("Returning JSON error response: %s", msg)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error": %q}`, msg)
}

func (app *App) redirectThankYou(w http.ResponseWriter, r *http.Request) {
	if Debug {
		log.Printf("Attempting redirect to thank you page: URL=%s, client headers=%v", app.Config.ThankYouURL, r.Header)
	}

	// Validate ThankYouURL
	if app.Config.ThankYouURL == "" {
		if Debug {
			log.Printf("ThankYouURL is empty, returning error response")
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error": "Thank you page URL not configured"}`)
		return
	}

	// Allow relative URLs (e.g., /thanks) or full URLs
	parsedURL, err := url.ParseRequestURI(app.Config.ThankYouURL)
	if err != nil || (parsedURL.Scheme == "" && parsedURL.Host == "" && !strings.HasPrefix(app.Config.ThankYouURL, "/")) {
		if Debug {
			log.Printf("Invalid ThankYouURL: %s, error: %v", app.Config.ThankYouURL, err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error": "Invalid thank you page URL"}`)
		return
	}

	// Set the redirect and log details
	w.Header().Set("Location", app.Config.ThankYouURL)
	if Debug {
		log.Printf("Redirecting client to %s with GET, status=%d, Location header=%s", app.Config.ThankYouURL, http.StatusFound, w.Header().Get("Location"))
	}
	http.Redirect(w, r, app.Config.ThankYouURL, http.StatusFound)
}

func (app *App) fireWebhook(email, status, errorMsg string) {
	var webhookURL string
	if status == "success" {
		webhookURL = app.Config.Webhook.SuccessURL
	} else {
		webhookURL = app.Config.Webhook.FailureURL
	}

	if webhookURL == "" {
		if Debug {
			log.Printf("No webhook URL configured for %s status", status)
		}
		return
	}

	payload := webhookPayload{
		Email:     email,
		Status:    status,
		Error:     errorMsg,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		if Debug {
			log.Printf("Failed to marshal webhook payload: %v", err)
		}
		return
	}

	go func() {
		if Debug {
			log.Printf("Sending webhook to %s: payload=%s", webhookURL, string(body))
		}
		resp, err := app.HTTPClient.Post(webhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			if Debug {
				log.Printf("Webhook request to %s failed: %v", webhookURL, err)
			}
			return
		}
		defer resp.Body.Close()
		if Debug {
			log.Printf("Webhook request to %s returned status: %d", webhookURL, resp.StatusCode)
		}
	}()
}