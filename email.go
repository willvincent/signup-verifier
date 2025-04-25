package main

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/willvincent/signup-verifier/internal/config"
	"github.com/willvincent/signup-verifier/internal/verifier"
)

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

func (app *App) hasMXRecord(domain string) bool {
	mx, err := app.LookupMXFunc(domain)
	return err == nil && len(mx) > 0
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