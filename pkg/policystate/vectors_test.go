package policystate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update rewrites testdata/vectors.json instead of comparing against it. Run
// `go test ./pkg/policystate -run TestVectors -update` after a deliberate
// protocol change, and review the diff: every changed line is a value another
// implementation has to change with you.
var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

// vector is one cross-language test case: the canonical bytes of a fixed
// input and whatever is derived from them.
type vector struct {
	Name      string `json:"name"`
	Domain    string `json:"domain,omitempty"`
	Canonical string `json:"canonical,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// vectorFile is testdata/vectors.json: the fixed keys plus every case.
type vectorFile struct {
	Protocol     string   `json:"protocol"`
	Ed25519Seed  string   `json:"ed25519_seed"`
	AuthorityKey string   `json:"authority_key"`
	Authority    string   `json:"authority"`
	BootKey      string   `json:"boot_key"`
	BootID       string   `json:"boot_id"`
	Nonce        string   `json:"challenge_nonce"`
	Vectors      []vector `json:"vectors"`
}

// vectorNonce is the fixed challenge nonce; the vectors would not be
// reproducible with a random one.
var vectorNonce = bytes.Repeat([]byte{0x2a}, MinNonceLen)

// vectorPolicy stands in for a published allowlist document: the vectors pin a
// content address over exact bytes, not the allowlist schema.
var vectorPolicy = []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`)

func TestVectors(t *testing.T) {
	got := buildVectors(t)
	if *update {
		writeVectors(t, got)
		t.Logf("wrote %s", vectorsPath)
		return
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%s) = _, %v, want no error (run with -update to create it)", vectorsPath, err)
	}
	var want vectorFile
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("json.Unmarshal(%s) = %v, want no error", vectorsPath, err)
	}

	for _, f := range []struct{ name, got, want string }{
		{"protocol", got.Protocol, want.Protocol},
		{"ed25519_seed", got.Ed25519Seed, want.Ed25519Seed},
		{"authority_key", got.AuthorityKey, want.AuthorityKey},
		{"authority", got.Authority, want.Authority},
		{"boot_key", got.BootKey, want.BootKey},
		{"boot_id", got.BootID, want.BootID},
		{"challenge_nonce", got.Nonce, want.Nonce},
	} {
		if f.got != f.want {
			t.Errorf("vectors.%s = %s, want %s", f.name, f.got, f.want)
		}
	}

	byName := make(map[string]vector, len(want.Vectors))
	for _, v := range want.Vectors {
		byName[v.Name] = v
	}
	for _, g := range got.Vectors {
		w, ok := byName[g.Name]
		if !ok {
			t.Errorf("vectors[%q] = %+v, want it to be absent (run with -update to add it)", g.Name, g)
			continue
		}
		delete(byName, g.Name)
		if g != w {
			t.Errorf("vectors[%q] = %+v, want %+v", g.Name, g, w)
		}
	}
	for name := range byName {
		t.Errorf("vectors[%q] = missing, want the stored vector (run with -update to drop it)", name)
	}
}

// buildVectors recomputes every vector from its fixed input.
func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	authorityKey, err := EncodeAuthorityKey(testPub())
	if err != nil {
		t.Fatalf("EncodeAuthorityKey(pub) = _, %v, want no error", err)
	}
	out := vectorFile{
		Protocol:     Protocol,
		Ed25519Seed:  base64.RawURLEncoding.EncodeToString(testSeed),
		AuthorityKey: authorityKey,
		Authority:    testAuthority,
		BootKey:      EncodeBootKey(testPub()),
		BootID:       BootID(testPub()),
		Nonce:        base64.RawURLEncoding.EncodeToString(vectorNonce),
	}
	add := func(v vector) { out.Vectors = append(out.Vectors, v) }

	// Canonical encoding: escaping, unicode, nested key order, explicit null
	// and an integer at the counter ceiling.
	type nested struct {
		Zebra string `json:"zebra"`
		Apple string `json:"apple"`
	}
	add(vector{
		Name: "canonical/escaping",
		Canonical: canonicalOf(t, map[string]any{
			"html":    "<a> & </a>",
			"unicode": "héllo … 日本 \U0001f512",
			"control": "tab\tnewline\nquote\"backslash\\\x01",
			"nested":  nested{Zebra: "z", Apple: "a"},
			"count":   MaxCounter - 1,
		}),
	})
	add(vector{Name: "canonical/state-quiet", Canonical: canonicalOf(t, quietState())})
	add(vector{Name: "canonical/state-update", Canonical: canonicalOf(t, testState())})

	// One hash per domain over identical bytes: the values must all differ.
	for _, domain := range []string{DomainState, DomainChallenge, DomainAck} {
		canonical := []byte(`{"a":1}`)
		add(vector{
			Name:      "hash/" + domain,
			Domain:    domain,
			Canonical: string(canonical),
			Hash:      FormatHash(Hash(domain, canonical)),
		})
	}

	// A policy object: a content address over exact bytes, not a
	// domain-separated hash.
	add(vector{Name: "object/policy", Canonical: string(vectorPolicy), Hash: ContentDigest(vectorPolicy)})

	// The journal chain: first policy, a publication that removes permissions,
	// and the drain that closes it.
	entries, digests := testChain(t)
	for i, e := range entries {
		add(vector{
			Name:      "journal/entry-" + string(rune('1'+i)),
			Canonical: canonicalOf(t, e),
			Hash:      digests[i],
		})
	}

	// Signed state and its challenge binding.
	stateHash, err := StateHash(testState())
	if err != nil {
		t.Fatalf("StateHash(testState()) = _, %v, want no error", err)
	}
	signed, err := SignState(testKey(), testState())
	if err != nil {
		t.Fatalf("SignState(priv, testState()) = _, %v, want no error", err)
	}
	add(vector{
		Name:      "state/signed",
		Domain:    DomainState,
		Canonical: canonicalOf(t, signed.Statement),
		Hash:      stateHash,
		Signature: signed.Signature,
	})
	challenged, err := SignChallenge(testKey(), signed, vectorNonce)
	if err != nil {
		t.Fatalf("SignChallenge(priv, signed, nonce) = _, %v, want no error", err)
	}
	add(vector{
		Name:      "state/challenge",
		Domain:    DomainChallenge,
		Canonical: canonicalOf(t, challenged.Challenge),
		Signature: challenged.ChallengeSignature,
	})

	// A participant message in its signed envelope.
	ack := Ack{
		Protocol:     Protocol,
		BootID:       BootID(testPub()),
		Version:      4,
		TargetDigest: digestOf('d'),
		Retired:      2,
	}
	env, err := SignMessage(testKey(), DomainAck, ack)
	if err != nil {
		t.Fatalf("SignMessage(priv, DomainAck, ack) = _, %v, want no error", err)
	}
	add(vector{Name: "participant/ack", Domain: DomainAck, Canonical: canonicalOf(t, ack), Signature: env.Signature})

	return out
}

func canonicalOf(t *testing.T, v any) string {
	t.Helper()
	b, err := Canonical(v)
	if err != nil {
		t.Fatalf("Canonical(%T) = _, %v, want no error", v, err)
	}
	return string(b)
}

func writeVectors(t *testing.T, f vectorFile) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
		t.Fatalf("os.MkdirAll(testdata) = %v, want no error", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatalf("encode vectors = %v, want no error", err)
	}
	if err := os.WriteFile(vectorsPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("os.WriteFile(%s) = %v, want no error", vectorsPath, err)
	}
}
