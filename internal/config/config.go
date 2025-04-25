package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type EmailVerifierConfig struct {
	Provider    string `yaml:"provider"`
	APIKey      string `yaml:"apiKey"`
	TimeoutSec  int    `yaml:"timeoutSeconds"`
	MaxRetries  int    `yaml:"maxRetries"`
	FailOpen    bool   `yaml:"failOpen"`
}

type Config struct {
	ListenAddress      string   `yaml:"listenAddress"`
	Route              string   `yaml:"route"`
	RequiredFields     []string `yaml:"requiredFields"`
	AllowedFields      []string `yaml:"allowedFields"`
	HoneypotField      string   `yaml:"honeypotField"`
	CheckMX            bool     `yaml:"checkMX"`
	CheckDisposable    bool     `yaml:"checkDisposable"`
	ThankYouURL        string   `yaml:"thankYouURL"`

	OnError struct {
		Method      string `yaml:method`
		ForwardData bool   `yaml:forwardData`
		Action      string `yaml:Action`
	}

	Health struct {
		Route string `yaml:"route"`
	} `yaml:"health"`

	Metrics struct {
		Enabled bool   `yaml:"enabled"`
		Address string `yaml:"address"`
		Route   string `yaml:"route"`
	} `yaml:"metrics"`
	
	DisposableDomains struct {
		LocalFile      string        `yaml:"localFile"`
		RemoteURL      string        `yaml:"remoteURL"`
		CacheTTLMin    int           `yaml:"cacheTTLMinutes"`
		LastLoadedTime time.Time     `yaml:"-"`
		Domains        map[string]struct{} `yaml:"-"`
	} `yaml:"disposableDomains"`

	RateLimit struct {
		Enabled          bool `yaml:"enabled"`
		RequestsPerMin   int  `yaml:"requestsPerMinute"`
		Burst            int  `yaml:"burst"`
	} `yaml:"rateLimit"`

	EmailVerifier EmailVerifierConfig `yaml:"emailVerifier"`

	Forward struct {
		Method string `yaml:"method"`
		URL    string `yaml:"url"`
	} `yaml:"forward"`
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(raw, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
