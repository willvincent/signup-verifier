package config

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var disposableLock sync.RWMutex

// LoadDisposableDomains populates cfg.DisposableDomains.Domains
func LoadDisposableDomains(cfg *Config) (int, error) {
	domains := map[string]struct{}{}

	// Prefer remote if available
	if cfg.DisposableDomains.RemoteURL != "" {
		resp, err := http.Get(cfg.DisposableDomains.RemoteURL)
		if err == nil {
			defer resp.Body.Close()
			domains, err = parseDisposableDomains(resp.Body)
			if err != nil {
				log.Printf("Remote scanner error: %v", err)
			} else {
				log.Println("Loaded disposable domains from remote")
			}
		} else {
			log.Printf("Failed to load remote list: %v", err)
		}
	}
	
	// Fall back to local file
	if cfg.DisposableDomains.LocalFile != "" && len(domains) == 0 {
		file, err := os.Open(cfg.DisposableDomains.LocalFile)
		if err != nil {
			return 0, err
		}
		defer file.Close()
	
		localDomains, err := parseDisposableDomains(file)
		if err != nil {
			return 0, err
		}
		domains = localDomains
		log.Println("Loaded disposable domains from local file")
	}

	disposableLock.Lock()
	defer disposableLock.Unlock()
	cfg.DisposableDomains.Domains = domains
	cfg.DisposableDomains.LastLoadedTime = time.Now()

	return len(domains), nil
}

func IsDisposable(cfg *Config, domain string) bool {
	disposableLock.RLock()
	defer disposableLock.RUnlock()
	_, exists := cfg.DisposableDomains.Domains[domain]
	return exists
}

func parseDisposableDomains(r io.Reader) (map[string]struct{}, error) {
	scanner := bufio.NewScanner(r)
	domains := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" && !strings.HasPrefix(line, "#") {
			domains[line] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}
