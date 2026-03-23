package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		Whitelist: WhitelistConfig{
			URL:     "http://localhost:8080",
			Timeout: 30 * time.Second,
		},
		Policy: PolicyConfig{
			Mode: "fail-closed",
		},
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_AuditMode(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Mode = "audit"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingURL(t *testing.T) {
	cfg := validConfig()
	cfg.Whitelist.URL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestValidate_ZeroTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Whitelist.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestValidate_NegativeTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Whitelist.Timeout = -1 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Mode = "permissive"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid policy mode")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	yaml := `
whitelist:
  url: http://localhost:8080
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Whitelist.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %s", cfg.Whitelist.Timeout)
	}
	if cfg.Policy.Mode != "fail-closed" {
		t.Errorf("expected default mode fail-closed, got %s", cfg.Policy.Mode)
	}
	if cfg.Containerd.Socket != "/run/containerd/containerd.sock" {
		t.Errorf("expected default socket, got %s", cfg.Containerd.Socket)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(":::bad"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
