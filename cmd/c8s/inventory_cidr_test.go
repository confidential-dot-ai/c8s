package main

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestInventoryCIDRsFromNodeJSON(t *testing.T) {
	t.Run("one host route per node, deduplicated", func(t *testing.T) {
		got, err := inventoryCIDRsFromNodeJSON([]byte(`{"items":[
			{"metadata":{"name":"a"},"status":{"addresses":[
				{"type":"Hostname","address":"a"},
				{"type":"InternalIP","address":"10.0.1.4"},
				{"type":"ExternalIP","address":"203.0.113.7"}]}},
			{"metadata":{"name":"b"},"status":{"addresses":[
				{"type":"InternalIP","address":"10.0.1.5"}]}}
		]}`))
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"10.0.1.4/32", "10.0.1.5/32"}
		if !slices.Equal(got, want) {
			t.Fatalf("cidrs = %v, want %v (InternalIP only, as host routes)", got, want)
		}
	})

	// A /32 is what keeps a pod in the node's own subnet out. A covering range
	// would not, which is the whole reason this emits host routes.
	t.Run("a node route does not admit its subnet", func(t *testing.T) {
		got, err := inventoryCIDRsFromNodeJSON([]byte(`{"items":[
			{"metadata":{"name":"a"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.1.4"}]}}]}`))
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != "10.0.1.4/32" {
			t.Fatalf("cidr = %q, want a host route", got[0])
		}
	})

	// Where the cluster populates podCIDR we can prove the two are separable.
	// Where it does not — the CNI owns IPAM — the check simply does not run.
	t.Run("node inside the pod range is refused", func(t *testing.T) {
		_, err := inventoryCIDRsFromNodeJSON([]byte(`{"items":[
			{"metadata":{"name":"a"},"spec":{"podCIDR":"10.0.1.0/24"},
			 "status":{"addresses":[{"type":"InternalIP","address":"10.0.1.4"}]}}]}`))
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
			if _, err := inventoryCIDRsFromNodeJSON([]byte(body)); err == nil {
				t.Fatalf("accepted a node list with no routable InternalIP: %s", body)
			}
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		if _, err := inventoryCIDRsFromNodeJSON([]byte("not json")); err == nil {
			t.Fatal("accepted malformed node JSON")
		}
	})
}

// An explicit --node-cidr is taken as given: an operator with a separate node
// network can express it as a range, which survives scale-up.
func TestResolveInventoryCIDRsPrefersExplicit(t *testing.T) {
	got, err := resolveInventoryCIDRs(t.Context(), []string{"10.0.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"10.0.1.0/24"}) {
		t.Fatalf("cidrs = %v, want the operator's value untouched", got)
	}
}

// With no --node-cidr the value is read from the cluster, and a cluster that
// cannot be read fails the install rather than proceeding with the callback
// unbounded — which would install cleanly and leave sandbox identity off.
func TestResolveInventoryCIDRsInfersFromCluster(t *testing.T) {
	prev := fetchNodeJSON
	t.Cleanup(func() { fetchNodeJSON = prev })

	fetchNodeJSON = func(context.Context) ([]byte, error) {
		return []byte(`{"items":[{"metadata":{"name":"a"},"status":{"addresses":[
			{"type":"InternalIP","address":"10.0.1.4"}]}}]}`), nil
	}
	got, err := resolveInventoryCIDRs(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"10.0.1.4/32"}) {
		t.Fatalf("cidrs = %v, want the node's host route", got)
	}

	fetchNodeJSON = func(context.Context) ([]byte, error) {
		return nil, errNoCluster
	}
	_, err = resolveInventoryCIDRs(t.Context(), nil)
	if err == nil {
		t.Fatal("install proceeded with the sandbox-digests callback unbounded")
	}
	if !strings.Contains(err.Error(), "--node-cidr") {
		t.Fatalf("error = %v, want it to name the flag that fixes it", err)
	}
}

var errNoCluster = errTestCluster("no cluster")

type errTestCluster string

func (e errTestCluster) Error() string { return string(e) }
