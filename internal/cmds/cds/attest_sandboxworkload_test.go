package cds

import (
	"bytes"
	"net/http"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	wlDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wlDigestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	wlDigestC = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// fakeStore is an allowlistGate over a floor set and named workload entries.
type fakeStore struct {
	floor     map[string]bool
	workloads map[string]pkgallowlist.Workload
}

// floorStore admits the given digests as floor entries (no combination policy).
func floorStore(digests ...string) fakeStore {
	f := make(map[string]bool, len(digests))
	for _, d := range digests {
		f[d] = true
	}
	return fakeStore{floor: f}
}

func (s fakeStore) Contains(d types.Digest) (bool, error) {
	if s.floor[d.String()] {
		return true, nil
	}
	for _, w := range s.workloads {
		for _, cd := range w.Digests() {
			if cd.String() == d.String() {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s fakeStore) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	digs := map[string]string{}
	for d := range s.floor {
		digs[d] = ""
	}
	return &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Digests: digs, Workloads: s.workloads}, "1", nil
}

func wlDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

// workloadEntry builds a named entry whose init/main containers are the given
// digests.
func workloadEntry(t *testing.T, initDigests, mainDigests []string) pkgallowlist.Workload {
	t.Helper()
	var w pkgallowlist.Workload
	for _, d := range initDigests {
		w.InitContainers = append(w.InitContainers, pkgallowlist.Container{Digest: wlDigest(t, d)})
	}
	for _, d := range mainDigests {
		w.Containers = append(w.Containers, pkgallowlist.Container{Digest: wlDigest(t, d)})
	}
	return w
}

// A sandbox running only allowlisted floor images is issued a leaf. The
// requester sent no image list: everything checked here came from the inventory
// the token named.
func TestAttest_SandboxWorkload_AllowsFloorOnlySandbox(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = floorStore(wlDigestA, wlDigestB)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// An image the inventory reports but the allowlist does not admit blocks
// issuance — the gate now runs on every token-bearing request, including the
// first one, where a self-reported claim used to be empty.
func TestAttest_SandboxWorkload_RejectsUnallowlistedImage(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// An inventory that does not know the sandbox is fail-closed: CDS cannot
// establish what the pod runs, which is exactly when it must not issue.
func TestAttest_SandboxWorkload_UnreachableInventoryFailsClosed(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{}, key: signer.PublicKey()} // knows no sandbox

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// An inventory reporting an empty sandbox is fail-closed. "No containers" is
// not "nothing to check": looping over it would pass the gate vacuously, and a
// sandbox always runs at least the sidecar that is asking. The kata inventory
// reaches this state legitimately while it is still syncing, so issuance must
// wait rather than proceed unchecked.
func TestAttest_SandboxWorkload_EmptySandboxFailsClosed(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// Without a store or a callback client CDS cannot check what the sandbox runs,
// so a token-bearing request is refused rather than issued unchecked.
func TestAttest_SandboxWorkload_RejectsWhenGateUnwired(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire func(h *AttestHandler)
	}{
		{"no allowlist store", func(h *AttestHandler) { h.AllowlistStore = nil }},
		{"no digests client", func(h *AttestHandler) { h.SandboxDigests = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockAttestationApi(t, "deadbeef")
			h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
			tc.wire(&h)

			csrPEM, _ := generateCSR(t)
			challenge := issueChallenge(t, h)
			w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
			}
		})
	}
}

// Issuance happens at arbitrary points in the pod lifecycle, and in most of
// them the running set is a strict subset of what the pod declares. Every one
// of these must still get a certificate: gating on the whole declared set would
// deny ordinary states, and permanently so once completed init containers are
// reaped (the running set never equals init+main again).
func TestAttest_SandboxWorkload_PartialLifecycleStatesIssue(t *testing.T) {
	store := fakeStore{
		floor: map[string]bool{wlDigestC: true}, // the injected c8s-cert sidecar
		workloads: map[string]pkgallowlist.Workload{
			"api": workloadEntry(t, []string{wlDigestA}, []string{wlDigestB}),
		},
	}

	for _, tc := range []struct {
		name    string
		running []string
	}{
		{"only the injected sidecar (first issuance)", []string{wlDigestC}},
		{"user init container running", []string{wlDigestC, wlDigestA}},
		{"init done, main coming up", []string{wlDigestC, wlDigestB}},
		{"fully started", []string{wlDigestC, wlDigestA, wlDigestB}},
		{"a container transiently evicted while restarting", []string{wlDigestA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockAttestationApi(t, "deadbeef")
			h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
			h.AllowlistStore = store
			h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: tc.running}, key: signer.PublicKey()}

			csrPEM, _ := generateCSR(t)
			challenge := issueChallenge(t, h)
			w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
			}
		})
	}
}

// Relaxing the whole-set match must not relax membership: an image no entry
// admits still blocks issuance, in every lifecycle state.
func TestAttest_SandboxWorkload_MembershipStillBitesMidLifecycle(t *testing.T) {
	store := fakeStore{
		floor:     map[string]bool{wlDigestC: true},
		workloads: map[string]pkgallowlist.Workload{"api": workloadEntry(t, []string{wlDigestA}, nil)},
	}
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = store
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestC, wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// A request with no sandbox token is issued without a sandbox ID and without
// the workload gate: it gets a leaf no workload authorizer will accept.
func TestAttest_SandboxWorkload_NoTokenSkipsGate(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = floorStore() // admits nothing
	h.SandboxDigests = fakeDigests{digests: map[string][]string{}}

	csrPEM, _ := generateCSR(t)
	w := postAttestSandbox(t, h, issueChallenge(t, h), csrPEM, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// Dev mode: an empty measurement allowlist must not disable sandbox identity.
// CDS still verifies the token and still gates on the inventory's answer — it
// just accepts any RA-TLS-attested inventory rather than a pinned one, matching
// what an empty allowlist already means for /attest itself. Losing the whole
// flow here would break issuance for every workload on an unpinned cluster.
func TestAttest_SandboxWorkload_UnpinnedMeasurementsStillIssue(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.Measurements = nil // dev: --measurements empty
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	leaf := leafFromAttestResponse(t, w)
	id, err := ratls.SandboxIDFromCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if id != testSandboxID {
		t.Fatalf("sandbox ID = %q, want %q", id, testSandboxID)
	}
}

// The allowlist gate still bites on an unpinned cluster: dropping the
// measurement pin must not also drop the image check.
func TestAttest_SandboxWorkload_UnpinnedStillEnforcesAllowlist(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.Measurements = nil
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA, wlDigestB}}, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// sandboxContainers is the per-container detail a current inventory reports for
// the test sandbox: each running (digest, argv) pair.
func sandboxContainers(pairs ...workloadclaims.SandboxContainer) map[string][]workloadclaims.SandboxContainer {
	return map[string][]workloadclaims.SandboxContainer{testSandboxID: pairs}
}

func digestsOf(cs map[string][]workloadclaims.SandboxContainer) map[string][]string {
	out := map[string][]string{}
	for id, list := range cs {
		for _, c := range list {
			out[id] = append(out[id], c.Digest)
		}
	}
	return out
}

func anyArgv() pkgallowlist.ArgvPolicy {
	return pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
}

func exactArgs(argv ...string) pkgallowlist.ArgvPolicy {
	return pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: argv}
}

// stampFromResponse issues against h with a sandbox token and returns the
// leaf's matched-workload stamp (nil when the leaf carries none).
func stampFromResponse(t *testing.T, h AttestHandler, signer *workloadclaims.SandboxTokenSigner) *ratls.MatchedWorkload {
	t.Helper()
	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	leaf := leafFromAttestResponse(t, w)
	matched, err := ratls.MatchedWorkloadFromCert(leaf)
	if err != nil {
		t.Fatalf("matched-workload from leaf: %v", err)
	}
	return matched
}

// Two entries sharing the same image digest but pinning different exact argv
// are told apart by the container's actual command: the stamp names exactly
// the one entry the argv satisfies, unambiguous. This is what the digest-only
// match could never do.
func TestAttest_SandboxWorkload_ArgvDisambiguatesSameDigestEntries(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	store := fakeStore{
		floor: map[string]bool{wlDigestC: true},
		workloads: map[string]pkgallowlist.Workload{
			"kimi-k3":    {Containers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: exactArgs("--model", "kimi-k3")}}},
			"sglang-dev": {Containers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: exactArgs("--model", "qwen3-0.6b")}}},
		},
	}
	containers := sandboxContainers(
		workloadclaims.SandboxContainer{Digest: wlDigestC},
		workloadclaims.SandboxContainer{Digest: wlDigestA, Argv: []string{"--model", "kimi-k3"}},
	)
	h.AllowlistStore = store
	h.SandboxDigests = fakeDigests{digests: digestsOf(containers), containers: containers, key: signer.PublicKey()}

	matched := stampFromResponse(t, h, signer)
	if matched == nil {
		t.Fatal("leaf carries no matched-workload stamp")
	}
	if len(matched.Names) != 1 || matched.Names[0] != "kimi-k3" {
		t.Fatalf("argv must resolve the same-digest entries to exactly kimi-k3, got %v", matched.Names)
	}
	if matched.Ambiguous() {
		t.Fatal("an argv-resolved single entry must not be stamped ambiguous")
	}
	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	want, err := doc.WorkloadEntriesDigest(matched.Names)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(matched.EntriesDigest, want) {
		t.Fatalf("stamped digest %x is not WorkloadEntriesDigest(%v) = %x", matched.EntriesDigest, matched.Names, want)
	}
}

// When the running argv satisfies BOTH entries — here both carry an "any"
// policy over the same image — the stamp must name the whole set sorted and
// mark it ambiguous, rather than asserting an identity the evidence does not
// establish. Its digest must be recomputable from the allowlist document.
func TestAttest_SandboxWorkload_StampsAmbiguousWhenArgvSatisfiesBoth(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	store := fakeStore{
		workloads: map[string]pkgallowlist.Workload{
			"kimi-k3":    {Containers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: anyArgv()}}},
			"sglang-dev": {Containers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: anyArgv()}}},
		},
	}
	containers := sandboxContainers(workloadclaims.SandboxContainer{Digest: wlDigestA, Argv: []string{"--model", "kimi-k3"}})
	h.AllowlistStore = store
	h.SandboxDigests = fakeDigests{digests: digestsOf(containers), containers: containers, key: signer.PublicKey()}

	matched := stampFromResponse(t, h, signer)
	if matched == nil {
		t.Fatal("leaf carries no matched-workload stamp")
	}
	if len(matched.Names) != 2 || matched.Names[0] != "kimi-k3" || matched.Names[1] != "sglang-dev" {
		t.Fatalf("stamp must name BOTH argv-compatible entries sorted, got %v", matched.Names)
	}
	if !matched.Ambiguous() {
		t.Fatal("entries the argv cannot distinguish must be stamped ambiguous")
	}
	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	want, err := doc.WorkloadEntriesDigest(matched.Names)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(matched.EntriesDigest, want) {
		t.Fatalf("stamped digest %x is not WorkloadEntriesDigest(%v) = %x", matched.EntriesDigest, matched.Names, want)
	}
}

// A unique-digest entry stamps exactly one name, unambiguous.
func TestAttest_SandboxWorkload_StampsSingleEntry(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	store := fakeStore{
		floor: map[string]bool{wlDigestC: true},
		workloads: map[string]pkgallowlist.Workload{
			"web": {
				InitContainers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: anyArgv()}},
				Containers:     []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestB), Command: anyArgv(), Args: anyArgv()}},
			},
		},
	}
	containers := sandboxContainers(
		workloadclaims.SandboxContainer{Digest: wlDigestC},
		workloadclaims.SandboxContainer{Digest: wlDigestA, Argv: []string{"init"}},
		workloadclaims.SandboxContainer{Digest: wlDigestB, Argv: []string{"serve"}},
	)
	h.AllowlistStore = store
	h.SandboxDigests = fakeDigests{digests: digestsOf(containers), containers: containers, key: signer.PublicKey()}

	matched := stampFromResponse(t, h, signer)
	if matched == nil {
		t.Fatal("leaf carries no matched-workload stamp")
	}
	if len(matched.Names) != 1 || matched.Names[0] != "web" || matched.Ambiguous() {
		t.Fatalf("stamp = %+v, want exactly [web], unambiguous", matched)
	}
}

// A floor-only pod matches no workload entry: it must be admitted (existing
// behavior) and carry NO matched-workload stamp — absence is the truthful
// statement, not an empty stamp.
func TestAttest_SandboxWorkload_NoStampForFloorOnlyPod(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	containers := sandboxContainers(workloadclaims.SandboxContainer{Digest: wlDigestA, Argv: []string{"sh"}})
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{digests: digestsOf(containers), containers: containers, key: signer.PublicKey()}

	if matched := stampFromResponse(t, h, signer); matched != nil {
		t.Fatalf("floor-only pod must carry no stamp, got %+v", matched)
	}
}

// An inventory too old to report per-container detail cannot support an argv
// match: the flat digest gate still runs, and the leaf carries no stamp —
// degradation, not failure, so a node-image skew cannot brick issuance.
func TestAttest_SandboxWorkload_NoContainerDetailIssuesWithoutStamp(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = fakeStore{
		workloads: map[string]pkgallowlist.Workload{
			"api": {Containers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: anyArgv()}}},
		},
	}
	h.SandboxDigests = fakeDigests{digests: map[string][]string{testSandboxID: {wlDigestA}}, key: signer.PublicKey()}

	if matched := stampFromResponse(t, h, signer); matched != nil {
		t.Fatalf("a digests-only inventory must not produce a stamp, got %+v", matched)
	}
}

// A non-floor container whose argv satisfies no entry's policy refuses
// issuance outright. This restores the combination enforcement #168 dropped —
// containers from different entries (or off-policy commands) cannot be mixed
// into an unauthorized pod — and it is strictly stronger than the pre-#168
// digest-set match because the digests here ARE admitted; only the argv is not.
func TestAttest_SandboxWorkload_ArgvMatchingNoEntryRefuses(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = fakeStore{
		workloads: map[string]pkgallowlist.Workload{
			"kimi-k3": {Containers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: exactArgs("--model", "kimi-k3")}}},
		},
	}
	containers := sandboxContainers(workloadclaims.SandboxContainer{Digest: wlDigestA, Argv: []string{"--model", "exfiltrator"}})
	h.SandboxDigests = fakeDigests{digests: digestsOf(containers), containers: containers, key: signer.PublicKey()}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// A container reported WITH per-container detail but WITHOUT argv means the
// argv was never recorded (mixed-version skew during the inventory upgrade
// window), not that the process runs argv-less — OCI requires argv[0]. Its
// true argv is unknown, so an exact-policy entry can neither be matched nor
// refuted: degrade exactly like a detail-less inventory (flat gate already
// passed, no stamp) instead of refusing renewal of an admitted pod.
func TestAttest_SandboxWorkload_EmptyArgvDetailIssuesWithoutStamp(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = fakeStore{
		workloads: map[string]pkgallowlist.Workload{
			"kimi-k3": {Containers: []pkgallowlist.Container{{Digest: wlDigest(t, wlDigestA), Command: anyArgv(), Args: exactArgs("--model", "kimi-k3")}}},
		},
	}
	containers := sandboxContainers(workloadclaims.SandboxContainer{Digest: wlDigestA}) // detail present, argv absent
	h.SandboxDigests = fakeDigests{digests: digestsOf(containers), containers: containers, key: signer.PublicKey()}

	if matched := stampFromResponse(t, h, signer); matched != nil {
		t.Fatalf("argv-less container detail must degrade to no stamp, got %+v", matched)
	}
}

// An inventory whose per-container detail names a digest its flat set does not
// is reporting two different sandboxes in one response. Even with every
// individual digest allowlisted, the divergence refuses issuance — gating on
// one view and stamping from the other would let the difference slip through
// whichever check only saw its half.
func TestAttest_SandboxWorkload_ContainerOutsideDigestSetRefuses(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = floorStore(wlDigestA, wlDigestB)
	h.SandboxDigests = fakeDigests{
		digests:    map[string][]string{testSandboxID: {wlDigestA}},
		containers: sandboxContainers(workloadclaims.SandboxContainer{Digest: wlDigestA}, workloadclaims.SandboxContainer{Digest: wlDigestB}),
		key:        signer.PublicKey(),
	}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// The mirror image: a flat digest with no per-container detail is a container
// the argv matching would never see. Same refusal.
func TestAttest_SandboxWorkload_DigestWithoutDetailRefuses(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.AllowlistStore = floorStore(wlDigestA, wlDigestB)
	h.SandboxDigests = fakeDigests{
		digests:    map[string][]string{testSandboxID: {wlDigestA, wlDigestB}},
		containers: sandboxContainers(workloadclaims.SandboxContainer{Digest: wlDigestA}),
		key:        signer.PublicKey(),
	}

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}
