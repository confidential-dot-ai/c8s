package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

const (
	// The two policies a test moves between: P is the source, Q the target.
	testDigestP = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testDigestQ = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeDeployment is the CDS read surface the router publishes on its own
// origin: the signed state, the challenge, and the content-addressed journal
// entries. Fields are knobs a test sets before dialing.
type fakeDeployment struct {
	t       *testing.T
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	objects map[string][]byte

	// head and position track the journal this deployment serves.
	head     string
	position uint64

	// current is what the state and challenge endpoints answer with. It
	// defaults to the statement the responder bound.
	current policystate.State
	// challengeNonce, when set, replaces the nonce in the signed binding, so
	// a test can forge an answer to another challenge.
	challengeNonce []byte
}

func newFakeDeployment(t *testing.T) *fakeDeployment {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeDeployment{t: t, priv: priv, pub: pub, objects: map[string][]byte{}}
}

func (f *fakeDeployment) authority() string {
	f.t.Helper()
	fingerprint, err := policystate.AuthorityFingerprint(f.pub)
	if err != nil {
		f.t.Fatal(err)
	}
	return fingerprint
}

// start serves the endpoints over TLS and returns the config and evidence a
// verifier run would hold: the URL, and the fingerprint of the certificate the
// attestation bound.
func (f *fakeDeployment) start() (config, *evidence) {
	mux := http.NewServeMux()
	mux.HandleFunc(policystate.PathState, func(w http.ResponseWriter, _ *http.Request) {
		signed, err := policystate.SignState(f.priv, f.current)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(signed)
	})
	mux.HandleFunc(policystate.PathChallenge, func(w http.ResponseWriter, r *http.Request) {
		var req policystate.ChallengeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if f.challengeNonce != nil {
			nonce = f.challengeNonce
		}
		signed, err := policystate.SignState(f.priv, f.current)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		challenged, err := policystate.SignChallenge(f.priv, signed, nonce)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(challenged)
	})
	mux.HandleFunc(policystate.PathObjectPrefix, func(w http.ResponseWriter, r *http.Request) {
		body, ok := f.objects[strings.TrimPrefix(r.URL.Path, policystate.PathObjectPrefix)]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	ts := httptest.NewTLSServer(mux)
	f.t.Cleanup(ts.Close)

	sum := sha256.Sum256(ts.Certificate().Raw)
	return config{url: ts.URL, timeout: 5 * time.Second},
		&evidence{stateFetchCert: hex.EncodeToString(sum[:])}
}

// publish appends one journal entry, stores it under its content address, and
// advances the head this deployment serves.
func (f *fakeDeployment) publish(typ policystate.EventType, payload any) string {
	f.t.Helper()
	var prev *policystate.Entry
	if f.head != "" {
		var entry policystate.Entry
		if err := policystate.Decode(f.objects[strings.TrimPrefix(f.head, "sha256:")], &entry); err != nil {
			f.t.Fatal(err)
		}
		prev = &entry
	}
	entry, err := policystate.NewEntryAt(prev, f.head, f.authority(), typ, payload, time.Now())
	if err != nil {
		f.t.Fatal(err)
	}
	canonical, err := policystate.Canonical(entry)
	if err != nil {
		f.t.Fatal(err)
	}
	digest := policystate.ContentDigest(canonical)
	f.objects[strings.TrimPrefix(digest, "sha256:")] = canonical
	f.head, f.position = digest, entry.Position
	return digest
}

// state is a valid statement at the journal head this deployment serves.
func (f *fakeDeployment) state(active string, update *policystate.Update) policystate.State {
	f.t.Helper()
	head, position := f.head, f.position
	if head == "" {
		head, position = "sha256:"+strings.Repeat("a", 64), 1
	}
	return policystate.State{
		Protocol:      policystate.Protocol,
		DeploymentID:  "c8s-test",
		Authority:     f.authority(),
		LogHead:       head,
		LogPosition:   position,
		ActiveVersion: 2,
		ActiveDigest:  active,
		Update:        update,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

// bind makes the evidence carry s as the statement the responder committed,
// exactly as the attest-pq parser would have built it.
func (f *fakeDeployment) bind(ev *evidence, s policystate.State) {
	f.t.Helper()
	signed, err := policystate.SignState(f.priv, s)
	if err != nil {
		f.t.Fatal(err)
	}
	hash, err := policystate.StateHash(s)
	if err != nil {
		f.t.Fatal(err)
	}
	ev.bindingVersion = "c8s/attest-pq/v1"
	ev.state = &boundState{signed: signed, hash: hash, envelope: policystate.Bound(s)}
	f.current = s
}

// draining is the update a publication that removes permissions advertises.
func draining(switched bool) *policystate.Update {
	return &policystate.Update{
		Version:       3,
		SourceDigest:  testDigestP,
		TargetDigest:  testDigestQ,
		RequiresDrain: true,
		Switched:      switched,
	}
}

// verifiedOutcome is a verdict that has passed hardware verification, which is
// what the state policy is allowed to demote.
func verifiedOutcome() Outcome { return Outcome{Verified: true} }

func runStatePolicy(t *testing.T, cfg config, ev *evidence, policy *statePolicy) Outcome {
	t.Helper()
	oc := verifiedOutcome()
	applyStatePolicy(context.Background(), &oc, cfg, &verifyPlan{state: policy}, ev)
	return oc
}

// An evidence source that binds no policy state leaves an unasked verdict
// standing with a note, and fails one that asked for a policy decision.
func TestStatePolicyBindingNotOffered(t *testing.T) {
	tests := []struct {
		name     string
		policy   *statePolicy
		verified bool
	}{
		{"nothing asked for", &statePolicy{}, true},
		{"--allowlist-pin", &statePolicy{pins: map[string]bool{testDigestP: true}}, false},
		{"--follow", &statePolicy{follow: true}, false},
		{"--authority", &statePolicy{authority: testDigestP}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &evidence{stateNote: "policy state: not bound by this evidence source"}
			oc := runStatePolicy(t, config{}, ev, tt.policy)
			if oc.Verified != tt.verified {
				t.Fatalf("verified = %t, want %t (error %q)", oc.Verified, tt.verified, oc.Error)
			}
			if oc.StateBindingNote != ev.stateNote {
				t.Errorf("state binding note = %q, want %q", oc.StateBindingNote, ev.stateNote)
			}
		})
	}
}

// The authority is what the verifier decides to trust. A pin that does not
// match the statement's signer fails; an unpinned run learns the fingerprint
// over the attested channel and says so.
func TestStatePolicyAuthorityTrust(t *testing.T) {
	t.Run("learned over the attested channel", func(t *testing.T) {
		dep := newFakeDeployment(t)
		cfg, ev := dep.start()
		dep.bind(ev, dep.state(testDigestP, nil))

		oc := runStatePolicy(t, cfg, ev, &statePolicy{fresh: true})
		if !oc.Verified {
			t.Fatalf("verified = false, want true: %s", oc.Error)
		}
		if oc.State.Authority != dep.authority() {
			t.Errorf("authority = %q, want %q", oc.State.Authority, dep.authority())
		}
		if !strings.Contains(oc.State.AuthorityTrust, "trust on first use") {
			t.Errorf("authority trust = %q, want it rendered as trust on first use", oc.State.AuthorityTrust)
		}
		if !strings.Contains(oc.State.Freshness, "proven current") {
			t.Errorf("freshness = %q, want it proven by the challenge", oc.State.Freshness)
		}
	})

	t.Run("pinned to another authority", func(t *testing.T) {
		dep := newFakeDeployment(t)
		cfg, ev := dep.start()
		dep.bind(ev, dep.state(testDigestP, nil))

		oc := runStatePolicy(t, cfg, ev, &statePolicy{authority: "sha256:" + strings.Repeat("f", 64)})
		if oc.Verified || !strings.Contains(oc.Error, "--authority pins") {
			t.Fatalf("verified = %t, error = %q, want an authority mismatch", oc.Verified, oc.Error)
		}
	})

	t.Run("the deployment signs with another key", func(t *testing.T) {
		dep := newFakeDeployment(t)
		cfg, ev := dep.start()
		bound := dep.state(testDigestP, nil)
		dep.bind(ev, bound)

		// The responder bound a statement from a different authority than the
		// one the deployment answers for.
		other := newFakeDeployment(t)
		stale := bound
		stale.Authority = other.authority()
		signed, err := policystate.SignState(other.priv, stale)
		if err != nil {
			t.Fatal(err)
		}
		ev.state.signed = signed

		oc := runStatePolicy(t, cfg, ev, &statePolicy{pins: map[string]bool{testDigestP: true}})
		if oc.Verified || !strings.Contains(oc.Error, "the deployment signs with") {
			t.Fatalf("verified = %t, error = %q, want the authority disagreement", oc.Verified, oc.Error)
		}
	})
}

// The challenge is what proves the bound statement is current. A nonce that
// does not come back and a journal that went backwards are different failures,
// and neither may pass.
func TestStatePolicyFreshness(t *testing.T) {
	t.Run("nonce not echoed", func(t *testing.T) {
		dep := newFakeDeployment(t)
		cfg, ev := dep.start()
		dep.bind(ev, dep.state(testDigestP, nil))
		dep.challengeNonce = make([]byte, stateNonceBytes)

		oc := runStatePolicy(t, cfg, ev, &statePolicy{fresh: true, pins: map[string]bool{testDigestP: true}})
		if oc.Verified || !strings.Contains(oc.Error, "nonce") {
			t.Fatalf("verified = %t, error = %q, want a nonce failure", oc.Verified, oc.Error)
		}
	})

	// An acknowledgement moves the head without changing what the session may
	// reach, so an answer ahead of the bound statement is still current.
	t.Run("the head moved on", func(t *testing.T) {
		dep := newFakeDeployment(t)
		cfg, ev := dep.start()
		bound := dep.state(testDigestP, nil)
		dep.bind(ev, bound)
		advanced := bound
		advanced.LogPosition = bound.LogPosition + 1
		advanced.LogHead = "sha256:" + strings.Repeat("b", 64)
		dep.current = advanced

		oc := runStatePolicy(t, cfg, ev, &statePolicy{fresh: true, pins: map[string]bool{testDigestP: true}})
		if !oc.Verified {
			t.Fatalf("verified = false, want true: %s", oc.Error)
		}
	})

	t.Run("the journal went backwards", func(t *testing.T) {
		dep := newFakeDeployment(t)
		cfg, ev := dep.start()
		bound := dep.state(testDigestP, nil)
		bound.LogPosition = 9
		dep.bind(ev, bound)
		rewound := bound
		rewound.LogPosition = 3
		dep.current = rewound

		oc := runStatePolicy(t, cfg, ev, &statePolicy{fresh: true, pins: map[string]bool{testDigestP: true}})
		if oc.Verified || !strings.Contains(oc.Error, "state_race") {
			t.Fatalf("verified = %t, error = %q, want state_race", oc.Verified, oc.Error)
		}
	})
}

// The verifier decides on the session's envelope, not on the active policy: a
// pin set that does not cover every digest the session may operate under is
// REFUSED, whatever the deployment considers active.
func TestStatePolicyOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		active      string
		update      *policystate.Update
		pins        []string
		follow      bool
		wantOutcome string
		wantVerdict bool
		wantNote    string
	}{
		{
			name:   "settled deployment with its policy pinned",
			active: testDigestP, pins: []string{testDigestP},
			wantOutcome: "PROCEED", wantVerdict: true,
		},
		{
			name:   "both policies pinned ahead of the rollout",
			active: testDigestP, update: draining(false), pins: []string{testDigestP, testDigestQ},
			wantOutcome: "PROCEED", wantVerdict: true,
		},
		{
			name:   "the source alone pinned during an update",
			active: testDigestP, update: draining(false), pins: []string{testDigestP},
			wantOutcome: "REFUSED", wantNote: testDigestQ,
		},
		{
			name:   "the target alone pinned during an update",
			active: testDigestP, update: draining(true), pins: []string{testDigestQ},
			wantOutcome: "REFUSED", wantNote: testDigestP,
		},
		{
			name:   "the target alone pinned once the update drained",
			active: testDigestQ, pins: []string{testDigestQ},
			wantOutcome: "PROCEED", wantVerdict: true,
		},
		{
			name:   "follow proceeds",
			active: testDigestP, update: draining(false), follow: true,
			wantOutcome: "PROCEED", wantVerdict: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := newFakeDeployment(t)
			cfg, ev := dep.start()
			dep.bind(ev, dep.state(tt.active, tt.update))

			policy := &statePolicy{follow: tt.follow, pins: map[string]bool{}}
			for _, digest := range tt.pins {
				policy.pins[digest] = true
			}
			oc := runStatePolicy(t, cfg, ev, policy)
			if oc.State == nil {
				t.Fatalf("no state summary: %s", oc.Error)
			}
			if oc.State.Outcome != tt.wantOutcome {
				t.Errorf("outcome = %q, want %q", oc.State.Outcome, tt.wantOutcome)
			}
			if oc.Verified != tt.wantVerdict {
				t.Fatalf("verified = %t, want %t (error %q)", oc.Verified, tt.wantVerdict, oc.Error)
			}
			if tt.wantNote != "" && !strings.Contains(oc.State.OutcomeNote, tt.wantNote) {
				t.Errorf("outcome note = %q, want it to name the unapproved %s", oc.State.OutcomeNote, tt.wantNote)
			}
		})
	}
}

// Without pins and without --follow the state is reported, not judged: a run
// that selected no policy must not invent one.
func TestStatePolicyWithoutASelectionReportsOnly(t *testing.T) {
	dep := newFakeDeployment(t)
	cfg, ev := dep.start()
	dep.bind(ev, dep.state(testDigestP, nil))

	oc := runStatePolicy(t, cfg, ev, &statePolicy{})
	if !oc.Verified {
		t.Fatalf("verified = false, want true: %s", oc.Error)
	}
	if oc.State.Outcome != "" {
		t.Errorf("outcome = %q, want none", oc.State.Outcome)
	}
	if !strings.Contains(oc.State.OutcomeNote, "no policy selected") {
		t.Errorf("outcome note = %q", oc.State.OutcomeNote)
	}
}

// The flags that select a policy are parsed once, before anything is dialed.
func TestBuildStatePolicyFlags(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr string
		check   func(*testing.T, *statePolicy)
	}{
		{
			name: "pins feed one set",
			cfg:  config{allowlistPins: []string{testDigestP, "  " + testDigestQ + "  ", ""}},
			check: func(t *testing.T, p *statePolicy) {
				if len(p.pins) != 2 || !p.pins[testDigestP] || !p.pins[testDigestQ] {
					t.Fatalf("pins = %v, want both digests", p.pins)
				}
			},
		},
		{
			name:    "follow and pins are exclusive",
			cfg:     config{follow: true, allowlistPins: []string{testDigestP}},
			wantErr: "--follow cannot be combined",
		},
		{
			name:    "a malformed pin is a usage error",
			cfg:     config{allowlistPins: []string{"deadbeef"}},
			wantErr: "--allowlist-pin",
		},
		{
			name:    "a malformed authority is a usage error",
			cfg:     config{authority: "not-a-digest"},
			wantErr: "--authority",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := buildStatePolicy(tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one mentioning %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, policy)
		})
	}
}
