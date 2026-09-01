package cds

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// anyPolicy is the loosest argv policy — the fixtures here exercise matching
// topology, not argv semantics (pkg/allowlist owns those).
var anyPolicy = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}

// namedEntry builds a one-main-container entry admitting any argv.
func namedEntry(t *testing.T, mainDigests ...string) pkgallowlist.Workload {
	t.Helper()
	var w pkgallowlist.Workload
	for _, d := range mainDigests {
		w.Containers = append(w.Containers, pkgallowlist.Container{Digest: wlDigest(t, d), Command: anyPolicy, Args: anyPolicy})
	}
	return w
}

// containersView builds the per-container inventory view with empty argv.
func containersView(digests ...string) []workloadclaims.SandboxContainer {
	out := make([]workloadclaims.SandboxContainer, 0, len(digests))
	for _, d := range digests {
		out = append(out, workloadclaims.SandboxContainer{Digest: d})
	}
	return out
}

// issueWithInventory drives a full token-bearing /attest against the given
// store and inventory answer and returns the parsed leaf.
func issueWithInventory(t *testing.T, store policyStore, digests []string, containers []workloadclaims.SandboxContainer, tune func(*AttestHandler)) *ratls.MatchedWorkload {
	t.Helper()
	leaf := leafFromInventory(t, store, digests, containers, tune)
	matched, err := ratls.MatchedWorkloadFromCert(leaf)
	if err != nil {
		t.Fatalf("MatchedWorkloadFromCert: %v", err)
	}
	return matched
}

func leafFromInventory(t *testing.T, store policyStore, digests []string, containers []workloadclaims.SandboxContainer, tune func(*AttestHandler)) *x509.Certificate {
	t.Helper()
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL)
	h.AllowlistStore = store
	h.SandboxDigests = fakeDigests{
		digests:    map[string][]string{testSandboxID: digests},
		containers: map[string][]workloadclaims.SandboxContainer{testSandboxID: containers},
		key:        signer.PublicKey(),
	}
	if tune != nil {
		tune(&h)
	}
	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	return leafFromAttestResponse(t, w)
}

// completeAPIStore is a store whose "api" entry is exactly the one workload
// digest — a complete pod reporting it matches uniquely.
func completeAPIStore(t *testing.T) fakeStore {
	return fakeStore{
		floor:     map[string]bool{wlDigestC: true},
		workloads: map[string]pkgallowlist.Workload{"api": namedEntry(t, wlDigestA)},
	}
}

func TestAttest_MatchedWorkload_StampsUniqueMatch(t *testing.T) {
	store := completeAPIStore(t)
	matched := issueWithInventory(t, store, []string{wlDigestA}, containersView(wlDigestA), nil)
	if matched == nil {
		t.Fatal("complete pod got no matched-workload stamp")
	}
	if matched.Name != "api" {
		t.Fatalf("name = %q, want api", matched.Name)
	}
	if matched.AllowlistVersion != "1" {
		t.Fatalf("allowlist version = %q, want 1", matched.AllowlistVersion)
	}
	al, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := al.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(matched.AllowlistDigest, wantDigest) {
		t.Fatalf("allowlist digest = %x, want %x", matched.AllowlistDigest, wantDigest)
	}
}

// The platform's injected sidecar (floor digest + injected entrypoint) is
// dropped before matching — the same drop set secrets release uses — so a pod
// running its workload plus the cert sidecar still matches its entry.
func TestAttest_MatchedWorkload_DropsInjectedContainers(t *testing.T) {
	store := completeAPIStore(t)
	containers := []workloadclaims.SandboxContainer{
		{Digest: wlDigestA},
		{Digest: wlDigestC, Argv: []string{"get-cert", "--renew-interval=6h"}},
	}
	matched := issueWithInventory(t, store, []string{wlDigestA, wlDigestC}, containers, nil)
	if matched == nil || matched.Name != "api" {
		t.Fatalf("matched = %+v, want api", matched)
	}
}

// A useful c8s helper is not hidden by its floor digest or /c8s entrypoint. An
// extra workload-proxy with attacker settings prevents a named certificate.
func TestAttest_MatchedWorkload_RejectsExtraC8SHelperArguments(t *testing.T) {
	store := completeAPIStore(t)
	entry := store.workloads["api"]
	entry.Containers[0].Name = "app"
	entry.InitContainers = []pkgallowlist.Container{{
		Name:    "c8s-cert",
		Digest:  wlDigest(t, wlDigestC),
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"get-cert", "--renew-interval=6h"}},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
	}}
	store.workloads["api"] = entry
	containers := []workloadclaims.SandboxContainer{
		{Name: "app", Role: pkgallowlist.ContainerRoleMain, Digest: wlDigestA},
		{Name: "c8s-cert", Role: pkgallowlist.ContainerRoleInit, Digest: wlDigestC, Argv: []string{"get-cert", "--renew-interval=6h"}},
		{Digest: wlDigestC, Argv: []string{"/c8s", "workload-proxy", "--upstream=http://attacker.invalid"}},
	}
	matched := issueWithInventory(t, store, []string{wlDigestA, wlDigestC}, containers, nil)
	if matched != nil {
		t.Fatalf("attacker-configured c8s helper received named certificate: %+v", matched)
	}
}

// A control-plane author cannot hide a second proxy under the broad `/c8s`
// entrypoint. It remains in the inventory, makes the pod differ from its exact
// named policy, and therefore cannot receive a named workload certificate.
func TestAttest_MatchedWorkload_HiddenC8sProxyGetsNoNamedIdentity(t *testing.T) {
	store := completeAPIStore(t)
	containers := []workloadclaims.SandboxContainer{
		{Digest: wlDigestA},
		{Digest: wlDigestC, Argv: []string{"/c8s", "get-cert", "--renew-interval=6h"}},
		{Digest: wlDigestC, Argv: []string{"/c8s", "workload-proxy", "--mode=client", "--peer-policy=sglang-router"}},
	}
	matched := issueWithInventory(t, store, []string{wlDigestA, wlDigestC}, containers, nil)
	if matched != nil {
		t.Fatalf("hidden /c8s workload-proxy received named identity %+v", matched)
	}
}

// Every failure to establish a name issues the membership-only leaf unnamed —
// never a refusal, never a wrong name.
func TestAttest_MatchedWorkload_UnnamedCases(t *testing.T) {
	for name, tc := range map[string]struct {
		store      fakeStore
		digests    []string
		containers []workloadclaims.SandboxContainer
	}{
		"old inventory without containers view": {
			store:   completeAPIStore(t),
			digests: []string{wlDigestA},
		},
		"views disagree": {
			store:      completeAPIStore(t),
			digests:    []string{wlDigestA},
			containers: containersView(wlDigestA, wlDigestC),
		},
		"malformed container digest": {
			store:      completeAPIStore(t),
			digests:    []string{wlDigestA},
			containers: []workloadclaims.SandboxContainer{{Digest: "not-a-digest"}},
		},
		"incomplete pod (missing main)": {
			store: fakeStore{
				floor:     map[string]bool{wlDigestC: true},
				workloads: map[string]pkgallowlist.Workload{"api": namedEntry(t, wlDigestA, wlDigestB)},
			},
			digests:    []string{wlDigestA},
			containers: containersView(wlDigestA),
		},
		"ambiguous match": {
			store: fakeStore{
				workloads: map[string]pkgallowlist.Workload{
					"api": namedEntry(t, wlDigestA),
					"web": namedEntry(t, wlDigestA),
				},
			},
			digests:    []string{wlDigestA},
			containers: containersView(wlDigestA),
		},
		"only injected containers": {
			store:      completeAPIStore(t),
			digests:    []string{wlDigestC},
			containers: []workloadclaims.SandboxContainer{{Digest: wlDigestC, Argv: []string{"get-cert"}}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			matched := issueWithInventory(t, tc.store, tc.digests, tc.containers, nil)
			if matched != nil {
				t.Fatalf("expected an unnamed leaf, got stamp %+v", matched)
			}
		})
	}
}

// racedStore returns one document to the issuance's single LoadAll and a
// different one afterwards, modeling an operator write racing issuance. The
// stamp must be internally consistent — name, version, and digest all from the
// snapshot the decision actually used.
type racedStore struct {
	first fakeStore
	later fakeStore
	calls *int
}

func (s racedStore) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	*s.calls++
	if *s.calls == 1 {
		al, _, err := s.first.LoadAll()
		return al, "1", err
	}
	al, _, err := s.later.LoadAll()
	return al, "2", err
}

func TestAttest_MatchedWorkload_RacedPolicyStampsOneSnapshot(t *testing.T) {
	first := completeAPIStore(t)
	later := fakeStore{workloads: map[string]pkgallowlist.Workload{"renamed": namedEntry(t, wlDigestA)}}
	calls := 0
	store := racedStore{first: first, later: later, calls: &calls}

	matched := issueWithInventory(t, store, []string{wlDigestA}, containersView(wlDigestA), nil)
	if matched == nil {
		t.Fatal("no stamp")
	}
	if calls != 1 {
		t.Fatalf("LoadAll called %d times during issuance, want exactly 1", calls)
	}
	if matched.Name != "api" || matched.AllowlistVersion != "1" {
		t.Fatalf("stamp = %+v, want the first snapshot's name and version", matched)
	}
	al, _, err := first.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := al.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(matched.AllowlistDigest, wantDigest) {
		t.Fatalf("stamp digest is not the first snapshot's canonical digest")
	}
}

// A named leaf gets the dedicated shorter TTL; a membership-only leaf keeps
// the ordinary one.
func TestAttest_MatchedWorkload_NamedLeafTTL(t *testing.T) {
	store := completeAPIStore(t)
	tune := func(h *AttestHandler) {
		h.CertTTL = 12 * time.Hour
		h.NamedCertTTL = 2 * time.Hour
	}

	named := leafFromInventory(t, store, []string{wlDigestA}, containersView(wlDigestA), tune)
	if got := named.NotAfter.Sub(named.NotBefore); got > 3*time.Hour {
		t.Fatalf("named leaf validity = %v, want capped at ~2h", got)
	}

	unnamed := leafFromInventory(t, store, []string{wlDigestA}, nil, tune)
	if got := unnamed.NotAfter.Sub(unnamed.NotBefore); got < 11*time.Hour {
		t.Fatalf("unnamed leaf validity = %v, want the ordinary ~12h", got)
	}
}

// issuer.MaxNamedLeafTTL is a ceiling on the stamp's staleness bound, not a
// default: NamedCertTTL can only shorten it. A handler configured above it — or
// with the zero value — must still cap at the ceiling.
func TestAttest_MatchedWorkload_NamedLeafTTLCeiling(t *testing.T) {
	store := completeAPIStore(t)
	for name, namedTTL := range map[string]time.Duration{
		"above the ceiling": 24 * time.Hour,
		"zero":              0,
		"negative":          -time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			leaf := leafFromInventory(t, store, []string{wlDigestA}, containersView(wlDigestA), func(h *AttestHandler) {
				h.CertTTL = 24 * time.Hour
				h.NamedCertTTL = namedTTL
			})
			if got := leaf.NotAfter.Sub(leaf.NotBefore); got > issuer.MaxNamedLeafTTL {
				t.Fatalf("named leaf validity = %v, want capped at MaxNamedLeafTTL %v", got, issuer.MaxNamedLeafTTL)
			}
		})
	}
}
