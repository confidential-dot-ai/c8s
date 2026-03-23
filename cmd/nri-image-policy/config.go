package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the plugin configuration.
type Config struct {
	Whitelist  WhitelistConfig  `yaml:"whitelist"`
	Containerd ContainerdConfig `yaml:"containerd"`
	Policy     PolicyConfig     `yaml:"policy"`
	Logging    LoggingConfig    `yaml:"logging"`
}

// WhitelistConfig contains KBS connection settings for whitelist retrieval.
type WhitelistConfig struct {
	URL     string        `yaml:"url"`     // KBS service URL
	Timeout time.Duration `yaml:"timeout"` // Per-request timeout (default: 30s)
}

// ContainerdConfig contains containerd connection settings for tag-to-digest resolution.
type ContainerdConfig struct {
	Socket    string `yaml:"socket"`
	Namespace string `yaml:"namespace"`
}

// PolicyConfig contains policy enforcement settings.
type PolicyConfig struct {
	Mode                  string   `yaml:"mode"`                    // fail-closed, audit
	EnforceExisting       bool     `yaml:"enforce_existing"`        // kill non-whitelisted containers on startup
	DenyMissingAnnotation bool     `yaml:"deny_missing_annotation"` // deny containers without image annotation
	ExemptNamespaces      []string `yaml:"exempt_namespaces"`
}

// LoggingConfig contains logging settings.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// LoadConfig loads configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{
		// Defaults for optional fields only.
		// Required fields come from the config file templated by Ansible.
		Whitelist: WhitelistConfig{
			Timeout: 30 * time.Second,
		},
		Containerd: ContainerdConfig{
			Socket:    "/run/containerd/containerd.sock",
			Namespace: "k8s.io",
		},
		Policy: PolicyConfig{
			Mode:                  "fail-closed",
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Whitelist.URL == "" {
		return fmt.Errorf("whitelist.url must be set")
	}
	if c.Whitelist.Timeout <= 0 {
		return fmt.Errorf("whitelist.timeout must be positive")
	}
	if c.Policy.Mode != "fail-closed" && c.Policy.Mode != "audit" {
		return fmt.Errorf("policy.mode must be 'fail-closed' or 'audit'")
	}
	return nil
}
