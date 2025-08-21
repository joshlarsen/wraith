package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Firestore FirestoreConfig `yaml:"firestore"`
	LLM       LLMConfig       `yaml:"llm"`
	OSV       OSVConfig       `yaml:"osv"`
}

type FirestoreConfig struct {
	ProjectID  string `yaml:"project_id"`
	Database   string `yaml:"database"`
	Collection string `yaml:"collection"`
}

type LLMConfig struct {
	Model   string `yaml:"model"`
	APIKey  string `yaml:"api_key"`
	BaseURL string `yaml:"base_url,omitempty"` // Optional: custom base URL, defaults to "https://api.openai.com/v1"
}

type OSVConfig struct {
	ModifiedCSVURL string `yaml:"modified_csv_url"`
	APIURL         string `yaml:"api_url"`
	Ecosystem      string `yaml:"ecosystem,omitempty"` // Optional: filter by ecosystem
	CacheDir       string `yaml:"cache_dir,omitempty"` // Optional: cache directory for CSV files
	CacheTTL       int    `yaml:"cache_ttl,omitempty"` // Optional: cache TTL in hours, 0 = no expiration
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Set defaults
	if cfg.OSV.ModifiedCSVURL == "" {
		cfg.OSV.ModifiedCSVURL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
	}

	if cfg.OSV.APIURL == "" {
		cfg.OSV.APIURL = "https://api.osv.dev/v1"
	}
	if cfg.Firestore.Collection == "" {
		cfg.Firestore.Collection = "vulnerability_classifications"
	}
	if cfg.Firestore.Database == "" {
		cfg.Firestore.Database = "(default)"
	}
	if cfg.OSV.CacheDir == "" {
		cfg.OSV.CacheDir = ".cache/osv"
	}
	if cfg.OSV.CacheTTL == 0 {
		cfg.OSV.CacheTTL = 24 // Default 24 hours
	}

	return &cfg, nil
}
