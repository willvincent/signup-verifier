//go:build !test || test

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
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

// Run is a top-level function to maintain compatibility with main.go.
func Run(cfg *config.Config) (*http.Server, error) {
	app := NewApp(cfg)
	return app.Run()
}