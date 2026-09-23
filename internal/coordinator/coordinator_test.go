package coordinator_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/coordinator"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	_ "modernc.org/sqlite"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// policy renders a canonical document admitting one container per named
// workload, which is enough for Removed to see an entry appear or vanish.
func policy(t *testing.T, workloads map[string]string) []byte {
	t.Helper()
	entries := make([]string, 0, len(workloads))
	for _, name := range slices.Sorted(maps.Keys(workloads)) {
		entries = append(entries, fmt.Sprintf(
			`%q:{"initContainers":[],"containers":[{"digest":%q,"command":{"policy":"any"},"args":{"policy":"any"}}]}`,
			name, workloads[name]))
	}
	raw := fmt.Sprintf(`{"schema":%q,"workloads":{%s}}`, allowlist.Schema, strings.Join(entries, ","))
	doc, err := allowlist.ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseJSON(%s) = _, %v, want no error", raw, err)
	}
	canonical, err := doc.Canonical()
	if err != nil {
		t.Fatalf("Canonical() = _, %v, want no error", err)
	}
	return canonical
}

func open(t *testing.T) *coordinator.Coordinator {
	t.Helper()
	c, err := coordinator.OpenInMemory(coordinator.Options{DeploymentID: "test-deployment"})
	if err != nil {
		t.Fatalf("OpenInMemory() = _, %v, want no error", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// seeded opens a coordinator whose version 1 admits one workload.
func seeded(t *testing.T) *coordinator.Coordinator {
	t.Helper()
	c := open(t)
	publish(t, c, policy(t, map[string]string{"api": digestA}))
	return c
}

func publish(t *testing.T, c *coordinator.Coordinator, canonical []byte) coordinator.Publication {
	t.Helper()
	result, err := c.Publish(canonical, "operator-keys:test")
	if err != nil {
		t.Fatalf("Publish() = _, %v, want no error", err)
	}
	return result
}

// participant is one enrolled boot, with the key it signs every message under.
type participant struct {
	id  string
	key ed25519.PrivateKey
}

func enroll(t *testing.T, c *coordinator.Coordinator, name string) participant {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() = _, _, %v, want no error", err)
	}
	p := participant{id: policystate.BootID(pub), key: priv}
	msg := policystate.Enrollment{
		Protocol:      policystate.Protocol,
		BootID:        p.id,
		Name:          name,
		BootKey:       policystate.EncodeBootKey(pub),
		AppliedDigest: state(t, c).Statement.ActiveDigest,
	}
	if err := c.Enroll(sign(t, priv, msg)); err != nil {
		t.Fatalf("Enroll(%s) = %v, want no error", name, err)
	}
	return p
}

func sign[T any](t *testing.T, key ed25519.PrivateKey, msg T) policystate.Envelope[T] {
	t.Helper()
	env, err := policystate.SignMessage(key, policystate.DomainAck, msg)
	if err != nil {
		t.Fatalf("SignMessage() = _, %v, want no error", err)
	}
	return env
}

func (p participant) ack(t *testing.T, c *coordinator.Coordinator, version uint64, target string, retired uint64) error {
	t.Helper()
	return c.Ack(sign(t, p.key, policystate.Ack{
		Protocol: policystate.Protocol, BootID: p.id, Version: version, TargetDigest: target, Retired: retired,
	}))
}

func (p participant) complete(t *testing.T, c *coordinator.Coordinator, version uint64, target string) error {
	t.Helper()
	return c.Complete(sign(t, p.key, policystate.Completion{
		Protocol: policystate.Protocol, BootID: p.id, Version: version, TargetDigest: target,
	}))
}

func state(t *testing.T, c *coordinator.Coordinator) policystate.SignedState {
	t.Helper()
	s, err := c.State()
	if err != nil {
		t.Fatalf("State() = _, %v, want no error", err)
	}
	if err := policystate.VerifySignedState(s); err != nil {
		t.Fatalf("VerifySignedState() = %v, want no error", err)
	}
	return s
}

func TestFirstPublicationIsActiveAtOnce(t *testing.T) {
	c := open(t)
	canonical := policy(t, map[string]string{"api": digestA})
	result := publish(t, c, canonical)

	if result.Version != 1 || result.RequiresDrain {
		t.Errorf("Publish() = %+v, want version 1 with no drain", result)
	}
	s := state(t, c).Statement
	if s.Update != nil {
		t.Errorf("state update = %+v, want nil: nothing was enrolled to wait for", s.Update)
	}
	if s.ActiveVersion != 1 || s.ActiveDigest != result.PolicyDigest {
		t.Errorf("active = (%d, %s), want (1, %s)", s.ActiveVersion, s.ActiveDigest, result.PolicyDigest)
	}
	if got := policystate.Bound(s); len(got) != 1 || got[0] != result.PolicyDigest {
		t.Errorf("Bound() = %v, want [%s]", got, result.PolicyDigest)
	}
	if _, _, version, _, err := c.Active(); err != nil || version != 1 {
		t.Errorf("Active() = _, _, %d, _, %v, want 1 and no error", version, err)
	}
}

func TestAckGatesTheSwitchAndCompletionGatesTheDrain(t *testing.T) {
	c := seeded(t)
	one, two := enroll(t, c, "node-1"), enroll(t, c, "node-2")

	// Dropping the only workload removes its rule, so the bound must cover both
	// policies until every participant reports it retired.
	target := publish(t, c, policy(t, map[string]string{}))
	if !target.RequiresDrain {
		t.Fatalf("Publish() = %+v, want requires_drain for a removal", target)
	}

	s := state(t, c).Statement
	if s.ActiveVersion != 1 {
		t.Errorf("active version = %d, want 1: publication does not switch", s.ActiveVersion)
	}
	if s.Update == nil || s.Update.Switched {
		t.Fatalf("state update = %+v, want an outstanding unswitched update", s.Update)
	}
	if got := policystate.Bound(s); len(got) != 2 {
		t.Errorf("Bound() = %v, want both policies", got)
	}

	if err := one.ack(t, c, target.Version, target.PolicyDigest, 1); err != nil {
		t.Fatalf("Ack(node-1) = %v, want no error", err)
	}
	if s := state(t, c).Statement; s.Update.Switched {
		t.Fatal("update switched with node-2 still outstanding")
	}
	if err := two.ack(t, c, target.Version, target.PolicyDigest, 0); err != nil {
		t.Fatalf("Ack(node-2) = %v, want no error", err)
	}
	s = state(t, c).Statement
	if !s.Update.Switched || s.ActiveVersion != 2 {
		t.Fatalf("after the last ack: switched=%v active=%d, want true and 2", s.Update.Switched, s.ActiveVersion)
	}
	if got := policystate.Bound(s); len(got) != 2 {
		t.Errorf("Bound() = %v, want both policies until the drain", got)
	}

	if err := one.complete(t, c, target.Version, target.PolicyDigest); err != nil {
		t.Fatalf("Complete(node-1) = %v, want no error", err)
	}
	if s := state(t, c).Statement; s.Update == nil {
		t.Fatal("update cleared with node-2 still outstanding")
	}
	if err := two.complete(t, c, target.Version, target.PolicyDigest); err != nil {
		t.Fatalf("Complete(node-2) = %v, want no error", err)
	}

	s = state(t, c).Statement
	if s.Update != nil {
		t.Errorf("state update = %+v, want nil after the last completion", s.Update)
	}
	if got := policystate.Bound(s); len(got) != 1 || got[0] != target.PolicyDigest {
		t.Errorf("Bound() = %v, want the target alone", got)
	}
	if got := entryTypes(t, c); fmt.Sprint(got) != "[published published drained]" {
		t.Errorf("journal = %v, want a drain closing the removal", got)
	}
}

func TestAdditionsOnlyNeverDrain(t *testing.T) {
	c := seeded(t)
	node := enroll(t, c, "node-1")

	target := publish(t, c, policy(t, map[string]string{"api": digestA, "web": digestB}))
	if target.RequiresDrain {
		t.Fatalf("Publish() = %+v, want no drain: nothing was removed", target)
	}
	s := state(t, c).Statement
	if got := policystate.Bound(s); len(got) != 1 || got[0] != target.PolicyDigest {
		t.Errorf("Bound() = %v, want the target alone from publication", got)
	}
	if err := node.ack(t, c, target.Version, target.PolicyDigest, 0); err != nil {
		t.Fatalf("Ack() = %v, want no error", err)
	}
	if err := node.complete(t, c, target.Version, target.PolicyDigest); err != nil {
		t.Fatalf("Complete() = %v, want no error", err)
	}
	if got := entryTypes(t, c); fmt.Sprint(got) != "[published published]" {
		t.Errorf("journal = %v, want no drain entry", got)
	}
}

func TestOneUpdateAtATime(t *testing.T) {
	c := seeded(t)
	node := enroll(t, c, "node-1")
	target := publish(t, c, policy(t, map[string]string{"web": digestB}))

	if err := c.CanPublish(); !errors.Is(err, coordinator.ErrConflict) {
		t.Errorf("CanPublish() during a rollout = %v, want ErrConflict", err)
	}
	if _, err := c.Publish(policy(t, map[string]string{"api": digestA}), "operator-keys:test"); !errors.Is(err, coordinator.ErrConflict) {
		t.Errorf("Publish() during a rollout = %v, want ErrConflict", err)
	}
	if head := c.Head(); head.Version != target.Version {
		t.Errorf("publication head = %d, want %d: the refused publish recorded nothing", head.Version, target.Version)
	}

	if err := node.ack(t, c, target.Version, target.PolicyDigest, 0); err != nil {
		t.Fatalf("Ack() = %v, want no error", err)
	}
	if err := node.complete(t, c, target.Version, target.PolicyDigest); err != nil {
		t.Fatalf("Complete() = %v, want no error", err)
	}
	if err := c.CanPublish(); err != nil {
		t.Errorf("CanPublish() after completion = %v, want no error", err)
	}
}

func TestEnrollmentDuringAnUpdateIsRefused(t *testing.T) {
	c := seeded(t)
	first := enroll(t, c, "node-1")
	target := publish(t, c, policy(t, map[string]string{"web": digestB}))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	joiner := policystate.Enrollment{
		Protocol: policystate.Protocol, BootID: policystate.BootID(pub), Name: "node-2",
		BootKey: policystate.EncodeBootKey(pub), AppliedDigest: target.PolicyDigest,
	}
	if err := c.Enroll(sign(t, priv, joiner)); !errors.Is(err, coordinator.ErrConflict) {
		t.Fatalf("Enroll() during a rollout = %v, want ErrConflict", err)
	}

	// The frozen set is the one publication captured, so the update still
	// switches on the participant that was there.
	if err := first.ack(t, c, target.Version, target.PolicyDigest, 0); err != nil {
		t.Fatalf("Ack() = %v, want no error", err)
	}
	if s := state(t, c).Statement; !s.Update.Switched {
		t.Error("update did not switch on the frozen participant's ack")
	}
}

func TestParticipantMessagesAreAuthenticated(t *testing.T) {
	c := seeded(t)
	node := enroll(t, c, "node-1")
	target := publish(t, c, policy(t, map[string]string{"web": digestB}))

	_, impostor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := participant{id: node.id, key: impostor}
	if err := forged.ack(t, c, target.Version, target.PolicyDigest, 0); !errors.Is(err, coordinator.ErrUnauthenticated) {
		t.Errorf("Ack() under the wrong key = %v, want ErrUnauthenticated", err)
	}
	if err := node.ack(t, c, target.Version+7, target.PolicyDigest, 0); !errors.Is(err, coordinator.ErrConflict) {
		t.Errorf("Ack() for another version = %v, want ErrConflict", err)
	}
	if err := node.complete(t, c, target.Version, target.PolicyDigest); !errors.Is(err, coordinator.ErrConflict) {
		t.Errorf("Complete() before the switch = %v, want ErrConflict", err)
	}
}

func TestReEnrollment(t *testing.T) {
	c := seeded(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := policystate.Enrollment{
		Protocol: policystate.Protocol, BootID: policystate.BootID(pub), Name: "node-1",
		BootKey: policystate.EncodeBootKey(pub), AppliedDigest: state(t, c).Statement.ActiveDigest,
	}
	if err := c.Enroll(sign(t, priv, msg)); err != nil {
		t.Fatalf("Enroll() = %v, want no error", err)
	}
	if err := c.Enroll(sign(t, priv, msg)); err != nil {
		t.Errorf("re-Enroll() with the same key = %v, want no error", err)
	}

	other, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stolen := msg
	stolen.BootKey = policystate.EncodeBootKey(other)
	if err := c.Enroll(sign(t, otherPriv, stolen)); !errors.Is(err, coordinator.ErrInvalid) {
		t.Errorf("Enroll() with a boot id that does not name its key = %v, want ErrInvalid", err)
	}
}

func TestChallengeBindsTheNonce(t *testing.T) {
	c := seeded(t)
	nonce := make([]byte, policystate.MinNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	challenged, err := c.Challenge(nonce)
	if err != nil {
		t.Fatalf("Challenge() = _, %v, want no error", err)
	}
	if err := policystate.VerifyChallengedState(challenged, nonce); err != nil {
		t.Errorf("VerifyChallengedState() = %v, want no error", err)
	}
	other := append([]byte(nil), nonce...)
	other[0]++
	if err := policystate.VerifyChallengedState(challenged, other); err == nil {
		t.Error("VerifyChallengedState() accepted another nonce")
	}
	if challenged.Statement.Authority != c.Authority() {
		t.Errorf("challenge authority = %q, want %q", challenged.Statement.Authority, c.Authority())
	}
}

func TestObjectsServeTheExactPublishedBytes(t *testing.T) {
	c := seeded(t)
	canonical := policy(t, map[string]string{"api": digestA})
	digest := policystate.ContentDigest(canonical)

	got, err := c.Object(digest)
	if err != nil {
		t.Fatalf("Object(%s) = _, %v, want no error", digest, err)
	}
	if string(got) != string(canonical) {
		t.Errorf("Object() = %s, want %s", got, canonical)
	}
	if _, err := c.Object("sha256:" + strings.Repeat("0", 64)); !errors.Is(err, coordinator.ErrNotFound) {
		t.Errorf("Object(unknown) = _, %v, want ErrNotFound", err)
	}
	if _, err := c.Object("not-a-digest"); !errors.Is(err, coordinator.ErrInvalid) {
		t.Errorf("Object(malformed) = _, %v, want ErrInvalid", err)
	}
}

func TestPublishRejectsNonCanonicalBytes(t *testing.T) {
	c := open(t)
	canonical := policy(t, map[string]string{"api": digestA})
	spaced := append([]byte(" "), canonical...)
	if _, err := c.Publish(spaced, "operator-keys:test"); !errors.Is(err, coordinator.ErrInvalid) {
		t.Errorf("Publish(non-canonical) = _, %v, want ErrInvalid", err)
	}
	if _, err := c.Publish(canonical, ""); !errors.Is(err, coordinator.ErrInvalid) {
		t.Errorf("Publish() with no authority = _, %v, want ErrInvalid", err)
	}
}

func TestReopenVerifiesTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator.db")
	opts := coordinator.Options{DeploymentID: "test-deployment"}

	first, err := coordinator.Open(path, opts)
	if err != nil {
		t.Fatalf("Open() = _, %v, want no error", err)
	}
	publish(t, first, policy(t, map[string]string{"api": digestA}))
	head := publish(t, first, policy(t, map[string]string{"api": digestA, "web": digestB}))
	authority := first.Authority()
	if err := first.Close(); err != nil {
		t.Fatalf("Close() = %v, want no error", err)
	}

	second, err := coordinator.Open(path, opts)
	if err != nil {
		t.Fatalf("reopen = _, %v, want no error", err)
	}
	defer second.Close()
	if got := second.Head(); got.Version != 2 || got.PolicyDigest != head.PolicyDigest || got.LogHead != head.LogHead {
		t.Errorf("head after reopen = %+v, want version 2 at %s", got, head.LogHead)
	}
	// A restart is a new authority: the key is never written down, so every
	// verifier must re-anchor.
	if second.Authority() == authority {
		t.Error("authority survived a restart, but the signing key is never persisted")
	}
	if second.DeploymentID() != "test-deployment" {
		t.Errorf("deployment id = %q, want the recorded one", second.DeploymentID())
	}
	if _, err := coordinator.Open(path, coordinator.Options{DeploymentID: "other"}); err == nil {
		t.Error("Open() accepted a deployment id that differs from the recorded one")
	}
}

func TestReopenRefusesATamperedJournal(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "entry bytes edited",
			sql:  `UPDATE objects SET bytes = replace(CAST(bytes AS TEXT), '"position":2', '"position":9') WHERE digest = (SELECT digest FROM journal WHERE position = 2)`,
			want: "hashes to",
		},
		{
			name: "entry dropped",
			sql:  "DELETE FROM journal WHERE position = 1",
			want: "gap",
		},
		{
			name: "entry object dropped",
			sql:  "DELETE FROM objects WHERE digest = (SELECT digest FROM journal WHERE position = 2)",
			want: "not found",
		},
		{
			name: "update row points at no publication",
			sql:  `UPDATE "update" SET version = 9 WHERE id = 1`,
			want: "newest publication",
		},
		{
			name: "update row rewrites the source",
			sql:  `UPDATE "update" SET source = 'sha256:` + strings.Repeat("c", 64) + `' WHERE id = 1`,
			want: "names source",
		},
		{
			name: "update row drops the drain requirement",
			sql:  `UPDATE "update" SET requires_drain = 0 WHERE id = 1`,
			want: "requires_drain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "coordinator.db")
			opts := coordinator.Options{DeploymentID: "test-deployment"}
			c, err := coordinator.Open(path, opts)
			if err != nil {
				t.Fatalf("Open() = _, %v, want no error", err)
			}
			publish(t, c, policy(t, map[string]string{"api": digestA}))
			enroll(t, c, "node-1")
			// A removal, so the outstanding update carries requires_drain.
			publish(t, c, policy(t, map[string]string{"web": digestB}))
			if err := c.Close(); err != nil {
				t.Fatalf("Close() = %v, want no error", err)
			}

			exec(t, path, tc.sql)
			_, err = coordinator.Open(path, opts)
			if err == nil {
				t.Fatalf("Open() accepted a database with %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), path) {
				t.Errorf("Open() = %v, want an error naming %q and the path", err, tc.want)
			}
		})
	}
}

// entryTypes walks the journal backwards from the head by parent link and
// returns the event types in order, which is what a verifier holding a
// checkpoint does.
func entryTypes(t *testing.T, c *coordinator.Coordinator) []policystate.EventType {
	t.Helper()
	var types []policystate.EventType
	for digest := c.Head().LogHead; digest != ""; {
		raw, err := c.Object(digest)
		if err != nil {
			t.Fatalf("Object(%s) = _, %v, want no error", digest, err)
		}
		var entry policystate.Entry
		if err := policystate.Decode(raw, &entry); err != nil {
			t.Fatalf("Decode(%s) = %v, want no error", digest, err)
		}
		types = append([]policystate.EventType{entry.Type}, types...)
		digest = entry.Parent
	}
	return types
}

// exec runs one statement against a closed coordinator database, which is how
// these tests stand in for an operator editing the file.
func exec(t *testing.T, path, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() = _, %v, want no error", err)
	}
	defer db.Close()
	if _, err := db.Exec(statement); err != nil {
		t.Fatalf("Exec(%s) = %v, want no error", statement, err)
	}
}
