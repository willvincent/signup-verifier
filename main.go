//go:build !test

package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/willvincent/signup-verifier/internal/config"
)

func main() {
	flag.Parse()
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	server, err := Run(cfg)
	if err != nil {
		log.Fatalf("Startup error: %v", err)
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}