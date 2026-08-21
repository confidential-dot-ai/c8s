//go:build !c8s_node

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubClusterDNSService points the lookup at a canned Service list for the
// duration of the test.
func stubClusterDNSService(t *testing.T, out string, err error) {
	t.Helper()
	prev := fetchClusterDNSServiceJSON
	t.Cleanup(func() { fetchClusterDNSServiceJSON = prev })
	fetchClusterDNSServiceJSON = func(context.Context) ([]byte, error) { return []byte(out), err }
}

// The chart default is the c8s node image's cluster-dns, so on any other
// cluster the carve-out names an address no pod resolves against and every
// confidential workload loses DNS.
func TestClusterDNSServiceIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		list    string
		want    string
		wantErr string
	}{
		{
			name: "rke2 names the Service differently but labels it the same",
			list: `{"items":[{"metadata":{"name":"rke2-coredns-rke2-coredns"},"spec":{"clusterIP":"10.43.0.10","clusterIPs":["10.43.0.10"]}}]}`,
			want: "10.43.0.10",
		},
		{
			name: "a headless sibling is not a resolver",
			list: `{"items":[
				{"metadata":{"name":"kube-dns-headless"},"spec":{"clusterIP":"None"}},
				{"metadata":{"name":"kube-dns"},"spec":{"clusterIP":"10.96.0.10"}}]}`,
			want: "10.96.0.10",
		},
		{
			name:    "no match leaves nothing to scope the carve-out to",
			list:    `{"items":[]}`,
			wantErr: "no Service in kube-system",
		},
		{
			name: "two resolvers name both rather than pick one",
			list: `{"items":[
				{"metadata":{"name":"kube-dns"},"spec":{"clusterIP":"10.96.0.10"}},
				{"metadata":{"name":"kube-dns-upstream"},"spec":{"clusterIP":"10.96.0.11"}}]}`,
			wantErr: "kube-dns (10.96.0.10), kube-dns-upstream (10.96.0.11)",
		},
		{
			// iptables-sync validates before it writes a rule, so a value it
			// rejects leaves the node with no cw egress guard at all.
			name:    "an unparseable ClusterIP is not a resolver",
			list:    `{"items":[{"metadata":{"name":"kube-dns"},"spec":{"clusterIP":"0.0.0.0"}}]}`,
			wantErr: "no Service in kube-system",
		},
		{
			name:    "malformed payload",
			list:    `not json`,
			wantErr: "parse service list",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubClusterDNSService(t, tc.list, nil)
			got, err := clusterDNSServiceIP(t.Context())
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ip = %q, want an error: a wrong carve-out address is indistinguishable from no carve-out", got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ip = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClusterDNSServiceIPSurfacesKubectlFailure(t *testing.T) {
	stubClusterDNSService(t, "", fmt.Errorf("connection refused"))
	if _, err := clusterDNSServiceIP(t.Context()); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error = %v, want kubectl's own failure", err)
	}
}

// A dual-stack resolver still yields its primary address; the chart carries
// one, so the operator is told which family goes unguarded.
func TestClusterDNSServiceIPTakesThePrimaryOfADualStackResolver(t *testing.T) {
	stubClusterDNSService(t, `{"items":[{"metadata":{"name":"kube-dns"},"spec":{"clusterIP":"10.96.0.10","clusterIPs":["10.96.0.10","fd00::a"]}}]}`, nil)
	got, err := clusterDNSServiceIP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.96.0.10" {
		t.Fatalf("ip = %q, want the primary ClusterIP", got)
	}
}

func TestResolveClusterDNSIP(t *testing.T) {
	list := `{"items":[{"metadata":{"name":"kube-dns"},"spec":{"clusterIP":"10.43.0.10"}}]}`

	t.Run("host mode derives", func(t *testing.T) {
		stubClusterDNSService(t, list, nil)
		got, err := resolveClusterDNSIP(t.Context(), "node", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != "10.43.0.10" {
			t.Fatalf("ip = %q, want the cluster's own resolver", got)
		}
	})

	// --cvm-mode=pod renders ratlsMesh.enabled=false, so the value is inert
	// and a cluster it cannot be read on must not fail the install.
	t.Run("pod mode reads nothing", func(t *testing.T) {
		stubClusterDNSService(t, "", fmt.Errorf("must not be called"))
		got, err := resolveClusterDNSIP(t.Context(), "pod", nil)
		if err != nil || got != "" {
			t.Fatalf("ip = %q, err = %v, want the host mesh's value left alone", got, err)
		}
	})

	// The computed values are helm's last -f, so deriving over an operator's
	// file would override it.
	t.Run("a values file that sets the key owns it", func(t *testing.T) {
		stubClusterDNSService(t, "", fmt.Errorf("must not be called"))
		f := filepath.Join(t.TempDir(), "values.yaml")
		if err := os.WriteFile(f, []byte("ratlsMesh:\n  clusterDNSIP: 10.0.0.53\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolveClusterDNSIP(t.Context(), "node", []string{f})
		if err != nil || got != "" {
			t.Fatalf("ip = %q, err = %v, want the operator's file left alone", got, err)
		}
	})

	t.Run("a values file that does not set the key still derives", func(t *testing.T) {
		stubClusterDNSService(t, list, nil)
		f := filepath.Join(t.TempDir(), "values.yaml")
		if err := os.WriteFile(f, []byte("ratlsMesh:\n  certTtl: 8h\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolveClusterDNSIP(t.Context(), "node", []string{f})
		if err != nil {
			t.Fatal(err)
		}
		if got != "10.43.0.10" {
			t.Fatalf("ip = %q, want the cluster's own resolver", got)
		}
	})

	t.Run("an underivable cluster fails the install", func(t *testing.T) {
		stubClusterDNSService(t, `{"items":[]}`, nil)
		_, err := resolveClusterDNSIP(t.Context(), "node", nil)
		if err == nil {
			t.Fatal("installed with the chart default: every confidential workload would lose DNS")
		}
		if !strings.Contains(err.Error(), "ratlsMesh.clusterDNSIP") {
			t.Fatalf("error = %v, want it to name the override", err)
		}
	})
}
