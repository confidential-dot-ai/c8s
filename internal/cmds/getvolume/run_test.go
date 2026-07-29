package getvolume

import (
	"strings"
	"testing"
	"time"
)

func TestParseVolumeSpec(t *testing.T) {
	got, err := parseVolumeSpec("weights=/tenant-a/volumes/weights")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Name != "weights" || got.Path != "/tenant-a/volumes/weights" {
		t.Fatalf("got %+v", got)
	}

	for _, spec := range []string{
		"",                              // no pair
		"weights",                       // no path
		"=/tenant-a/volumes/weights",    // no name
		"WEIGHTS=/tenant-a/vol",         // not a dns-1123 label
		"we/ights=/tenant-a/vol",        // a path, not a name
		"thirteenchars=/tenant-a/vol",   // longer than a serial holds
		"weights=tenant-a/volumes/w",    // path is not absolute
		"weights=/tenant-a/../etc/pass", // path escapes
	} {
		if _, err := parseVolumeSpec(spec); err == nil {
			t.Errorf("accepted %q", spec)
		}
	}
}

// The name rides in a virtio serial, so the cap the daemon enforces has to be
// the one admission and the sidecar enforce.
func TestParseVolumeSpecAcceptsTheLongestServableName(t *testing.T) {
	name := strings.Repeat("a", 12)
	if _, err := parseVolumeSpec(name + "=/tenant-a/volumes/x"); err != nil {
		t.Fatalf("rejected a 12-character name: %v", err)
	}
}

func validConfig() config {
	return config{
		CDSURL:            "https://cds.example",
		AttestationApiURL: "http://127.0.0.1:8400",
		SocketDir:         "/run/c8s/workload-claims",
		Volumes:           []volumeRequest{{Name: "weights", Path: "/tenant-a/volumes/weights"}},
		Attempts:          60,
		RetryInterval:     5 * time.Second,
		RequestTimeout:    10 * time.Second,
		InventoryTimeout:  5 * time.Second,
	}
}

func TestValidate(t *testing.T) {
	cfg := validConfig()
	if err := validate(&cfg); err != nil {
		t.Fatalf("rejected a complete config: %v", err)
	}

	for name, mutate := range map[string]func(*config){
		"cds url":           func(c *config) { c.CDSURL = "" },
		"plaintext cds url": func(c *config) { c.CDSURL = "http://cds.example" },
		"attestation api":   func(c *config) { c.AttestationApiURL = "" },
		"no volumes":        func(c *config) { c.Volumes = nil },
		"socket dir":        func(c *config) { c.SocketDir = "" },
		"attempts":          func(c *config) { c.Attempts = 0 },
		"retry interval":    func(c *config) { c.RetryInterval = 0 },
		"request timeout":   func(c *config) { c.RequestTimeout = 0 },
		"inventory timeout": func(c *config) { c.InventoryTimeout = 0 },
		"repeated name": func(c *config) {
			c.Volumes = append(c.Volumes, volumeRequest{Name: "weights", Path: "/tenant-a/volumes/other"})
		},
	} {
		cfg := validConfig()
		mutate(&cfg)
		if err := validate(&cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateTrimsURL(t *testing.T) {
	cfg := validConfig()
	cfg.CDSURL = "https://cds.example/"
	if err := validate(&cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.CDSURL != "https://cds.example" {
		t.Fatalf("CDSURL = %q, want the trailing slash gone", cfg.CDSURL)
	}
}

func TestNewCmdHasTheSidecarFlags(t *testing.T) {
	cmd := NewCmd()
	for _, flag := range []string{"cds-url", "attestation-api-url", "cert", "key", "volume", "socket-dir", "attempts"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("missing --%s", flag)
		}
	}
}
