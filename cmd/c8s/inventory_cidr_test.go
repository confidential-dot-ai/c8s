package main

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// An explicit --node-cidr is taken as given: an operator with a separate node
// network can express it as a range, which survives scale-up.
func TestResolveInventoryCIDRsPrefersExplicit(t *testing.T) {
	got, err := resolveInventoryCIDRs(t.Context(), []string{"10.0.1.0/24"}, "node")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "10.0.1.0/24" {
		t.Fatalf("cidrs = %v, want the operator's value untouched", got)
	}
}

// With no --node-cidr nothing is rendered — CDS derives the bound from the
// live node list — but the install still preflights the cluster so an
// unusable one fails here rather than refusing sandbox tokens at runtime.
func TestResolveInventoryCIDRsPreflightsCluster(t *testing.T) {
	prev := fetchNodeJSON
	t.Cleanup(func() { fetchNodeJSON = prev })

	t.Run("separable nodes render nothing and pass", func(t *testing.T) {
		fetchNodeJSON = func(context.Context) ([]byte, error) {
			return []byte(`{"items":[{"metadata":{"name":"a"},"spec":{"podCIDR":"10.244.0.0/24"},
				"status":{"addresses":[{"type":"InternalIP","address":"10.0.1.4"}]}}]}`), nil
		}
		got, err := resolveInventoryCIDRs(t.Context(), nil, "node")
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("cidrs = %v, want nil — CDS derives the bound, not the chart", got)
		}
	})

	// Where the cluster populates podCIDR we can prove node and pod addresses
	// are not separable; installing anyway would bound the callback to pods.
	t.Run("node inside the pod range fails the install", func(t *testing.T) {
		fetchNodeJSON = func(context.Context) ([]byte, error) {
			return []byte(`{"items":[{"metadata":{"name":"a"},"spec":{"podCIDR":"10.0.1.0/24"},
				"status":{"addresses":[{"type":"InternalIP","address":"10.0.1.4"}]}}]}`), nil
		}
		_, err := resolveInventoryCIDRs(t.Context(), nil, "node")
		if err == nil {
			t.Fatal("accepted a node address inside the pod range: the callback bound would admit pod IPs")
		}
		if !strings.Contains(err.Error(), "not separable") {
			t.Fatalf("error = %v, want it to explain why no bound is possible", err)
		}
	})

	t.Run("no usable address is an error, not an empty bound", func(t *testing.T) {
		for _, body := range []string{
			`{"items":[]}`,
			`{"items":[{"metadata":{"name":"a"},"status":{"addresses":[{"type":"Hostname","address":"a"}]}}]}`,
			`{"items":[{"metadata":{"name":"a"},"status":{"addresses":[{"type":"InternalIP","address":"127.0.0.1"}]}}]}`,
		} {
			fetchNodeJSON = func(context.Context) ([]byte, error) { return []byte(body), nil }
			if _, err := resolveInventoryCIDRs(t.Context(), nil, "node"); err == nil {
				t.Fatalf("accepted a node list with no routable InternalIP: %s", body)
			}
		}
	})

	// A cluster that cannot be read fails the install rather than proceeding
	// with the callback unbounded — which would install cleanly and leave
	// sandbox identity off.
	t.Run("unreadable cluster fails and names the fix", func(t *testing.T) {
		fetchNodeJSON = func(context.Context) ([]byte, error) { return nil, errNoCluster }
		_, err := resolveInventoryCIDRs(t.Context(), nil, "node")
		if err == nil {
			t.Fatal("install proceeded without checking the sandbox-digests bound")
		}
		if !strings.Contains(err.Error(), "--node-cidr") {
			t.Fatalf("error = %v, want it to name the flag that fixes it", err)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		fetchNodeJSON = func(context.Context) ([]byte, error) { return []byte("not json"), nil }
		if _, err := resolveInventoryCIDRs(t.Context(), nil, "node"); err == nil {
			t.Fatal("accepted malformed node JSON")
		}
	})
}

// Under --cvm-mode=pod the inventory answers from inside each kata guest on
// the guest's pod IP, so the callback is pinned to the pod range(s) rather
// than left to CDS's live node-host derivation (which would refuse every
// sandbox token).
func TestResolveInventoryCIDRsPodModeUsesPodRanges(t *testing.T) {
	prev := fetchNodeJSON
	t.Cleanup(func() { fetchNodeJSON = prev })

	fetchNodeJSON = func(context.Context) ([]byte, error) {
		return []byte(`{"items":[
			{"metadata":{"name":"a"},"spec":{"podCIDR":"10.42.0.0/24","podCIDRs":["10.42.0.0/24","fd00:42::/64"]},
			 "status":{"addresses":[{"type":"InternalIP","address":"10.0.1.4"}]}},
			{"metadata":{"name":"b"},"spec":{"podCIDR":"10.42.1.0/24","podCIDRs":["10.42.1.0/24"]},
			 "status":{"addresses":[{"type":"InternalIP","address":"10.0.1.5"}]}}
		]}`), nil
	}
	got, err := resolveInventoryCIDRs(t.Context(), nil, "pod")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.42.0.0/24", "fd00:42::/64", "10.42.1.0/24"}
	if !slices.Equal(got, want) {
		t.Fatalf("cidrs = %v, want the pod ranges %v, not node host routes", got, want)
	}

	// The same cluster under node mode still renders nothing (live bound).
	got, err = resolveInventoryCIDRs(t.Context(), nil, "node")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("node mode cidrs = %v, want nil", got)
	}

	// A CNI with its own IPAM leaves podCIDR empty: fail closed and name the flag.
	fetchNodeJSON = func(context.Context) ([]byte, error) {
		return []byte(`{"items":[{"metadata":{"name":"a"},"status":{"addresses":[
			{"type":"InternalIP","address":"10.0.1.4"}]}}]}`), nil
	}
	_, err = resolveInventoryCIDRs(t.Context(), nil, "pod")
	if err == nil {
		t.Fatal("pod mode with no podCIDR proceeded with the callback bounded to nothing useful")
	}
	if !strings.Contains(err.Error(), "--node-cidr") {
		t.Fatalf("error = %v, want it to name the flag that fixes it", err)
	}

	// An unreadable cluster fails in pod mode too.
	fetchNodeJSON = func(context.Context) ([]byte, error) { return nil, errNoCluster }
	if _, err := resolveInventoryCIDRs(t.Context(), nil, "pod"); err == nil {
		t.Fatal("pod mode install proceeded without reading the pod ranges")
	}

	// Explicit --node-cidr wins in pod mode too.
	got, err = resolveInventoryCIDRs(t.Context(), []string{"10.42.0.0/16"}, "pod")
	if err != nil || !slices.Equal(got, []string{"10.42.0.0/16"}) {
		t.Fatalf("explicit pod-mode cidrs = %v err=%v, want the operator's value untouched", got, err)
	}
}

var errNoCluster = errTestCluster("no cluster")

type errTestCluster string

func (e errTestCluster) Error() string { return string(e) }
