package nriimagepolicy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	pushDigestA = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	pushDigestB = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
	pushDigestC = "sha256:0000000000000000000000000000000000000000000000000000000000000003"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// anyAllowlist builds an allowlist with one any-argv entry per digest, named
// "w-" plus the first 12 hex digits of the digest.
func anyAllowlist(digests map[string]string) *allowlist.Allowlist {
	al := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{}}
	for d, image := range digests {
		al.Workloads["w-"+d[len("sha256:"):][:12]] = allowlist.Workload{Label: image, Containers: []allowlist.Container{{
			Digest:  mustDigestOrPanic(d),
			Image:   image,
			Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		}}}
	}
	return al
}

func mustDigestOrPanic(s string) types.Digest {
	d, err := types.ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

// admitsDigest mirrors the plugin's admission order: always_allow first, then
// the served index.
func admitsDigest(store *policyStore, digest string) bool {
	snap := store.current()
	return store.alwaysAllows(digest) || (snap != nil && snap.index.AdmitsDigest(digest))
}

func TestStartupSourceMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config
		want string
	}{
		{
			name: "pull",
			cfg: &config{Allowlist: allowlistConfig{
				Pull: pullConfig{URL: "https://cds.example"},
			}},
			want: "pull",
		},
		{
			name: "always allow only",
			cfg: &config{Allowlist: allowlistConfig{
				AlwaysAllow: map[string]string{pushDigestA: "image-a"},
			}},
			want: "always_allow",
		},
		{
			name: "label rules only",
			cfg: &config{Policy: policyConfig{
				LabelRules: []labelRule{{Name: "require-tenant"}},
			}},
			want: "label_rules",
		},
		{
			name: "static and label rules",
			cfg: &config{
				Allowlist: allowlistConfig{
					AlwaysAllow: map[string]string{pushDigestA: "image-a"},
				},
				Policy: policyConfig{
					LabelRules: []labelRule{{Name: "require-tenant"}},
				},
			},
			want: "always_allow+label_rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startupSourceMode(tt.cfg); got != tt.want {
				t.Fatalf("startupSourceMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- policyStore ---

// The store applies whatever the verified state names, in either direction:
// the statement is signed by the authority and fetched over the attested pull
// channel, so there is no local counter for a withheld or rolled-back CDS to
// trip over. always_allow is checked ahead of every snapshot, so a swap never
// drops the bootstrap floor.
func TestPolicyStoreAppliesWhateverTheStateNames(t *testing.T) {
	store := newPolicyStore(map[string]string{pushDigestA: "bootstrap"})

	fifth := anyAllowlist(map[string]string{pushDigestB: "v5"})
	store.apply(fifth, 5, policyDigest(t, fifth))
	if store.current().version != 5 || !admitsDigest(store, pushDigestB) {
		t.Fatalf("applied = (%d, %s), want version 5 admitting the pulled digest",
			store.current().version, store.current().digest)
	}

	third := anyAllowlist(map[string]string{pushDigestC: "v3"})
	store.apply(third, 3, policyDigest(t, third))
	if store.current().version != 3 || !admitsDigest(store, pushDigestC) {
		t.Fatalf("applied = (%d, %s), want the version-3 policy the state named",
			store.current().version, store.current().digest)
	}
	if admitsDigest(store, pushDigestB) {
		t.Fatal("the superseded policy still admits its digest")
	}
	if !admitsDigest(store, pushDigestA) {
		t.Fatal("a swap dropped the always_allow floor")
	}
}
