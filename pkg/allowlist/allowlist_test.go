package allowlist

import (
	"bytes"
	"strings"
	"testing"
)

const digestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const digestC = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func TestParseJSON_Minimal(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"cds"}}`)
	if al.Digests[digestA] != "cds" {
		t.Fatalf("floor digest not parsed: %#v", al.Digests)
	}
}

func TestParseJSON_RejectsUnknownSchema(t *testing.T) {
	_, err := ParseJSON([]byte(`{"schema":"other","digests":{}}`))
	if err == nil || !strings.Contains(err.Error(), "unknown schema") {
		t.Fatalf("expected unknown schema error, got %v", err)
	}
}

func TestParseJSON_RejectsUnknownFields(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","surprise":1}`)); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestJSONParsersRequireEOF(t *testing.T) {
	allowlistBody := `{"schema":"` + Schema + `","workloads":{}}`
	workloadBody := `{"containers":[{"digest":"` + digestA + `"}]}`
	for _, tc := range []struct {
		name  string
		parse func([]byte) error
		body  string
	}{
		{"operator allowlist", func(b []byte) error { _, err := ParseJSON(b); return err }, allowlistBody},
		{"served allowlist", func(b []byte) error { _, err := ParseServedJSON(b); return err }, allowlistBody},
		{"workload", func(b []byte) error { _, err := ParseWorkloadJSON(b); return err }, workloadBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.parse([]byte(tc.body + " \n\t")); err != nil {
				t.Fatalf("trailing whitespace was rejected: %v", err)
			}
			for _, suffix := range []string{` {}`, ` true`, ` trailing`} {
				if err := tc.parse([]byte(tc.body + suffix)); err == nil {
					t.Fatalf("accepted trailing data %q", suffix)
				}
			}
		})
	}
}

func TestParseRejectsDuplicateContainerNameAcrossRoles(t *testing.T) {
	body := `{"schema":"` + Schema + `","workloads":{"w":{"initContainers":[{"name":"same","digest":"` + digestA + `"}],"containers":[{"name":"same","digest":"` + digestB + `"}]}}}`
	if _, err := ParseJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "declared more than once") {
		t.Fatalf("duplicate init/main name error = %v", err)
	}
}

func TestParseJSON_RejectsBadFloorDigest(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","digests":{"sha256:zz":"x"}}`)); err == nil {
		t.Fatal("expected invalid digest error")
	}
}

func TestParseJSON_AbsentPolicyDefaultsToDeny(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"`+digestA+`"}]}}}`)
	c := al.Workloads["w"].Containers[0]
	if c.Command.Policy != PolicyDeny || c.Args.Policy != PolicyDeny {
		t.Fatalf("absent policies should default to deny, got %#v", c)
	}
}

func TestParseJSON_ExactRequiresArgv(t *testing.T) {
	_, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + digestA + `","args":{"policy":"exact"}}]}}}`))
	if err == nil || !strings.Contains(err.Error(), "exact policy requires") {
		t.Fatalf("expected exact-needs-argv error, got %v", err)
	}
}

func TestParseJSON_DenyRejectsArgv(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + digestA + `","args":{"policy":"deny","argv":["x"]}}]}}}`)); err == nil {
		t.Fatal("expected deny-takes-no-argv error")
	}
}

func TestParseJSON_PathValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"relative", `"read":["etc/x"]`, false},
		{"dotdot", `"read":["/a/../b"]`, false},
		{"midglob", `"read":["/a/*/b"]`, false},
		{"subtree", `"read":["/a/**"]`, true},
		{"literal", `"read":["/secret"]`, true},
		{"write with read", `"read":["/r"],"write":["/secret"]`, true},
		{"write without read", `"write":["/secret"]`, false},
	} {
		body := `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` +
			digestA + `"}],"secrets":{"policy":"allow",` + tc.body + `}}}}`
		_, err := ParseJSON([]byte(body))
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestCanonical_OrderIndependent(t *testing.T) {
	a := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestB+`","args":{"policy":"any"}},
		{"digest":"`+digestA+`","args":{"policy":"any"}}]}}}`)
	b := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","args":{"policy":"any"}},
		{"digest":"`+digestB+`","args":{"policy":"any"}}]}}}`)
	da, _ := a.Canonical()
	db, _ := b.Canonical()
	if !bytes.Equal(da, db) {
		t.Fatal("canonical form depends on container order")
	}
}

func TestCanonical_FormattingIndependent(t *testing.T) {
	compact := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"x"}}`)
	spaced := mustParse(t, "{\n  \"schema\": \"c8s.allowlist/v1\",\n  \"digests\": {\""+digestA+"\": \"x\"}\n}")
	dc, _ := compact.Canonical()
	ds, _ := spaced.Canonical()
	if !bytes.Equal(dc, ds) {
		t.Fatal("canonical form depends on source formatting")
	}
}

func TestRoundTripCanonical(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"cds"},
		"workloads":{"w":{"label":"img","containers":[
		{"digest":"`+digestB+`","command":{"policy":"exact","argv":["/app"]},
		 "args":{"policy":"any"}}],"secrets":{"policy":"allow","read":["/s/**"]}}}}`)
	canon, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseJSON(canon)
	if err != nil {
		t.Fatalf("re-parse canonical: %v", err)
	}
	c2, _ := again.Canonical()
	if !bytes.Equal(canon, c2) {
		t.Fatalf("canonical form not stable across round-trip:\n%s\n%s", canon, c2)
	}
}

// Order independence alone would pass even if both parses sorted descending;
// pin the absolute ascending order.
func TestSortContainers_AscendingByDigest(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestB+`","args":{"policy":"any"}},
		{"digest":"`+digestA+`","args":{"policy":"any"}}]}}}`)
	cs := al.Workloads["w"].Containers
	if cs[0].Digest.String() != digestA || cs[1].Digest.String() != digestB {
		t.Fatalf("containers not sorted ascending by digest: %s, %s", cs[0].Digest, cs[1].Digest)
	}
}

func TestSortContainers_PolicyTieBreakAscending(t *testing.T) {
	// Same digest, distinct args policies; "any" sorts before "exact".
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","args":{"policy":"exact","argv":["x"]}},
		{"digest":"`+digestA+`","args":{"policy":"any"}}]}}}`)
	cs := al.Workloads["w"].Containers
	if cs[0].Args.Policy != PolicyAny || cs[1].Args.Policy != PolicyExact {
		t.Fatalf("policy tie-break wrong: %q, %q", cs[0].Args.Policy, cs[1].Args.Policy)
	}
}

func TestSortContainers_StableOnFullTie(t *testing.T) {
	// Image is not part of the sort key; a full tie must keep input order.
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","image":"zzz","args":{"policy":"any"}},
		{"digest":"`+digestA+`","image":"aaa","args":{"policy":"any"}}]}}}`)
	cs := al.Workloads["w"].Containers
	if cs[0].Image != "zzz" || cs[1].Image != "aaa" {
		t.Fatalf("tied containers reordered: %q, %q", cs[0].Image, cs[1].Image)
	}
}

func TestValidWorkloadName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"a", true},
		{"z", true},
		{"A", true},
		{"Z", true},
		{"0", true},
		{"9", true},
		{"a.b_c-d9", true},
		{"x.", true},
		{"x_", true},
		{"x-", true},
		{"", false},
		// Bytes adjacent to each accepted range.
		{"`", false},
		{"{", false},
		{"@", false},
		{"[", false},
		{"/", false},
		{":", false},
		// Separators are only valid after the first byte.
		{".x", false},
		{"_x", false},
		{"-x", false},
		{"a b", false},
		{"a/b", false},
	} {
		if got := ValidWorkloadName(tc.name); got != tc.ok {
			t.Errorf("ValidWorkloadName(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestParseJSON_RejectsBadWorkloadName(t *testing.T) {
	body := `{"schema":"c8s.allowlist/v1","workloads":{"a/b":{"containers":[{"digest":"` + digestA + `"}]}}}`
	if _, err := ParseJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "workload name") {
		t.Fatalf("expected workload name error, got %v", err)
	}
}

func TestWorkloadIdentityDefaultsAndValidation(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"api-v1":{"identity":"api","containers":[{"digest":"`+digestA+`"}]},
		"api-v2":{"identity":"api","containers":[{"digest":"`+digestB+`"}]},
		"router":{"containers":[{"digest":"`+digestC+`"}]}
	}}`)
	if got := WorkloadIdentity("api-v1", al.Workloads["api-v1"]); got != "api" {
		t.Fatalf("explicit identity = %q, want api", got)
	}
	if got := WorkloadIdentity("router", al.Workloads["router"]); got != "router" {
		t.Fatalf("default identity = %q, want router", got)
	}
	if WorkloadIdentity("api-v1", al.Workloads["api-v1"]) != WorkloadIdentity("api-v2", al.Workloads["api-v2"]) {
		t.Fatal("operator-authored rollout entries did not share their stable identity")
	}

	bad := `{"schema":"c8s.allowlist/v1","workloads":{"api-v1":{"identity":"api/other","containers":[{"digest":"` + digestA + `"}]}}}`
	if _, err := ParseJSON([]byte(bad)); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("invalid identity accepted: %v", err)
	}
	if _, err := ParseWorkloadJSON([]byte(`{"identity":"api/other","containers":[{"digest":"` + digestA + `"}]}`)); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("invalid identity accepted on single-entry write: %v", err)
	}
}

func TestParseWorkloadJSON(t *testing.T) {
	w, err := ParseWorkloadJSON([]byte(`{"initContainers":[{"digest":"` + digestC + `"}],"containers":[
		{"digest":"` + digestB + `"},{"digest":"` + digestA + `"}]}`))
	if err != nil {
		t.Fatalf("ParseWorkloadJSON: %v", err)
	}
	if w == nil {
		t.Fatal("ParseWorkloadJSON returned nil workload without error")
	}
	if w.Containers[0].Digest.String() != digestA || w.Containers[1].Digest.String() != digestB {
		t.Fatalf("containers not sorted: %s, %s", w.Containers[0].Digest, w.Containers[1].Digest)
	}
	if w.InitContainers[0].Command.Policy != PolicyDeny {
		t.Fatalf("absent policy should default to deny, got %q", w.InitContainers[0].Command.Policy)
	}
}

func TestParseWorkloadJSON_Rejects(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown field", `{"containers":[],"surprise":1}`},
		{"init missing digest", `{"initContainers":[{"image":"x"}]}`},
		{"container missing digest", `{"containers":[{"image":"x"}]}`},
	} {
		if w, err := ParseWorkloadJSON([]byte(tc.body)); err == nil {
			t.Errorf("%s: expected error, got workload %#v", tc.name, w)
		}
	}
}

func TestWorkloadDigests(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{
		"initContainers":[{"digest":"`+digestC+`"}],
		"containers":[{"digest":"`+digestA+`"},{"digest":"`+digestB+`"}]}}}`)
	got := al.Workloads["w"].Digests()
	want := []string{digestC, digestA, digestB}
	if len(got) != len(want) {
		t.Fatalf("Digests() returned %d digests, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("Digests()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestLegacyUnnamedIdenticalInitMainNeedsNamedMigration(t *testing.T) {
	body := `{"schema":"c8s.allowlist/v1","workloads":{"legacy":{
		"initContainers":[{"digest":"` + digestA + `"}],
		"containers":[{"digest":"` + digestA + `"}]}}}`
	if _, err := ParseJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "re-derive it with container names") {
		t.Fatalf("ambiguous legacy role migration error = %v", err)
	}
	if _, err := ParseServedJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "re-derive it with container names") {
		t.Fatalf("served ambiguous legacy role migration error = %v", err)
	}
}

func mustParse(t *testing.T, s string) *Allowlist {
	t.Helper()
	al, err := ParseJSON([]byte(s))
	if err != nil {
		t.Fatalf("ParseJSON: %v\n%s", err, s)
	}
	return al
}

// The 63-byte bound arrived after entries could already be stored. A served
// document carrying one over-long legacy name must still parse — failing it
// would break every allowlist pull and every `c8s verify --allowlist` in the
// cluster over an entry nobody can reach — while the write path still refuses
// to create such a name.
func TestWorkloadNameBoundIsWritePathOnly(t *testing.T) {
	long := strings.Repeat("a", MaxWorkloadNameLen+1)
	body := `{"schema":"c8s.allowlist/v1","workloads":{
		"` + long + `":{"containers":[{"digest":"` + digestA + `"}]},
		"ok":{"containers":[{"digest":"` + digestB + `"}]}}}`

	if _, err := ParseJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "workload name") {
		t.Fatalf("ParseJSON accepted an over-long name: %v", err)
	}

	al, err := ParseServedJSON([]byte(body))
	if err != nil {
		t.Fatalf("ParseServedJSON failed the whole document over one legacy name: %v", err)
	}
	if _, ok := al.Workloads["ok"]; !ok {
		t.Fatal("the in-bound entry was lost")
	}
	// Dropped, not carried: it can never be stamped on a leaf, and leaving its
	// digests admitted would be the fail-open direction.
	if _, ok := al.Workloads[long]; ok {
		t.Fatal("the over-long entry survived a served parse")
	}
	if !ValidWorkloadName("ok") || ValidWorkloadName(long) {
		t.Fatal("ValidWorkloadName must still apply the bound")
	}
}

// The grammar itself is not relaxed on either path: the name is a URL path
// segment.
func TestParseServedJSON_StillRejectsBadWorkloadNameGrammar(t *testing.T) {
	body := `{"schema":"c8s.allowlist/v1","workloads":{"a/b":{"containers":[{"digest":"` + digestA + `"}]}}}`
	if _, err := ParseServedJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "workload name") {
		t.Fatalf("expected workload name error, got %v", err)
	}
}
