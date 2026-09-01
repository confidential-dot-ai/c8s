package attestproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readNodeImageFile(t *testing.T, parts ...string) string {
	t.Helper()
	pathParts := append([]string{"..", "..", "..", "node-guest-image", "c8s", "mkosi.extra"}, parts...)
	data, err := os.ReadFile(filepath.Join(pathParts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestNodeImageAttestationSocketWiring is the measured-image contract for
// node mode. The TCP listener is private. The root service publishes one
// fixed, group-readable socket before RKE2 starts.
func TestNodeImageAttestationSocketWiring(t *testing.T) {
	config := readNodeImageFile(t, "etc", "attestation-api", "config.toml")
	if !strings.Contains(config, `bind = "127.0.0.1:8400"`) {
		t.Fatalf("node attestation API does not bind loopback:\n%s", config)
	}
	for _, unsafe := range []string{`bind = "0.0.0.0:8400"`, `bind = "[::]:8400"`} {
		if strings.Contains(config, unsafe) {
			t.Fatalf("node attestation API contains unsafe bind %q", unsafe)
		}
	}

	unit := readNodeImageFile(t, "etc", "systemd", "system", "attestation-api-proxy.service")
	for _, want := range []string{
		"After=attestation-api.service",
		"Requires=attestation-api.service",
		"Before=rke2-server.service rke2-agent.service",
		"User=root",
		"Group=root",
		"ExecStartPre=/bin/sh -c 'test -d /var/run/nri-image-policy'",
		"ExecStart=/usr/local/bin/c8s attest-proxy --socket=/var/run/nri-image-policy/attestation-api.sock --socket-gid=65532 --upstream=http://127.0.0.1:8400",
		"/usr/local/bin/c8s attest-proxy healthcheck --socket=/var/run/nri-image-policy/attestation-api.sock",
		"Restart=on-failure",
		"ReadWritePaths=/var/run/nri-image-policy",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("attestation proxy unit missing %q\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "BindsTo=attestation-api.service") {
		t.Errorf("proxy must stay active and return 502 during an upstream restart\n%s", unit)
	}

	tmpfiles := readNodeImageFile(t, "etc", "tmpfiles.d", "confos-rke2.conf")
	if !strings.Contains(tmpfiles, "d /run/nri-image-policy 0755 root root") {
		t.Fatalf("node image does not create the proxy socket directory as root:\n%s", tmpfiles)
	}
	preset := readNodeImageFile(t, "usr", "lib", "systemd", "system-preset", "50-rke2.preset")
	if !strings.Contains(preset, "enable attestation-api-proxy.service") {
		t.Fatalf("node image does not enable the attestation proxy service:\n%s", preset)
	}
}
