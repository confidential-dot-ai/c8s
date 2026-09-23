package allowlist

import "testing"

// ruleDoc builds a one-entry allowlist around a container body, which is what
// the narrowing cases vary.
func ruleDoc(container, secrets string) string {
	if secrets != "" {
		secrets = `,"secrets":` + secrets
	}
	return `{"schema":"c8s.allowlist/v1","workloads":{"api":{"label":"example.com/api:1",` +
		`"initContainers":[],"containers":[` + container + `]` + secrets + `}}}`
}

const (
	ruleWideArgv = `{"digest":"` + digestA + `","image":"example.com/api:1",` +
		`"command":{"policy":"any"},"args":{"policy":"any"},` +
		`"mounts":{"policy":"exact","destinations":["/a","/b"]},"env":{"policy":"any"}}`
	rulePinnedArgv = `{"digest":"` + digestA + `","image":"example.com/api:1",` +
		`"command":{"policy":"exact","argv":["/bin/api"]},"args":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","destinations":["/a","/b"]},"env":{"policy":"any"}}`
	ruleNarrowMounts = `{"digest":"` + digestA + `","image":"example.com/api:1",` +
		`"command":{"policy":"exact","argv":["/bin/api"]},"args":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","destinations":["/a"]},"env":{"policy":"any"}}`
	ruleNarrowEnv = `{"digest":"` + digestA + `","image":"example.com/api:1",` +
		`"command":{"policy":"exact","argv":["/bin/api"]},"args":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","destinations":["/a","/b"]},"env":{"policy":"exact","values":{"MODE":"prod"}}}`

	ruleSecretsWide   = `{"policy":"allow","read":["/team/**"]}`
	ruleSecretsNarrow = `{"policy":"allow","read":["/team/api"]}`

	emptyDoc = `{"schema":"c8s.allowlist/v1","workloads":{}}`
)

func TestRules(t *testing.T) {
	got := Rules(mustParse(t, ruleDoc(rulePinnedArgv, ruleSecretsWide)))
	if len(got) != 1 {
		t.Fatalf("len(Rules(allowlist)) = %d, want 1", len(got))
	}
	r := got[0]
	if r.Workload != "api" || r.Role != RoleMain {
		t.Errorf("Rules(allowlist)[0] = {%q, %q}, want {%q, %q}", r.Workload, r.Role, "api", RoleMain)
	}
	if r.Secrets == nil || len(r.Secrets.Read) != 1 {
		t.Errorf("Rules(allowlist)[0].Secrets = %v, want the entry grant", r.Secrets)
	}
	if rules := Rules(nil); rules != nil {
		t.Errorf("Rules(nil) = %v, want nil", rules)
	}
}

// TestRulesAreOrderedByKey keeps two implementations enumerating the same set
// in the same order, whatever the map iteration order was.
func TestRulesAreOrderedByKey(t *testing.T) {
	doc := `{"schema":"c8s.allowlist/v1","workloads":{` +
		`"api":{"initContainers":[],"containers":[` + rulePinnedArgv + `]},` +
		`"web":{"initContainers":[` + ruleNarrowEnv + `],"containers":[` + ruleNarrowMounts + `]}}}`
	a := mustParse(t, doc)
	first := Rules(a)
	if len(first) != 3 {
		t.Fatalf("len(Rules(allowlist)) = %d, want 3", len(first))
	}
	var prev string
	for i, r := range first {
		key := RuleKey(r)
		if key <= prev {
			t.Errorf("RuleKey(rules[%d]) = %s, want it to sort after %s", i, key, prev)
		}
		prev = key
	}
	for range 5 {
		again := Rules(a)
		for j := range again {
			if RuleKey(again[j]) != RuleKey(first[j]) {
				t.Fatalf("Rules(allowlist)[%d] = %+v, want %+v", j, again[j], first[j])
			}
		}
	}
}

func TestRuleKeyDistinguishesRoleAndWorkload(t *testing.T) {
	base := Rule{Workload: "api", Role: RoleMain}
	byRole := base
	byRole.Role = RoleInit
	byWorkload := base
	byWorkload.Workload = "web"

	seen := map[string]string{}
	for name, r := range map[string]Rule{"base": base, "role": byRole, "workload": byWorkload} {
		key := RuleKey(r)
		if other, dup := seen[key]; dup {
			t.Errorf("RuleKey(%s) = %s, want it to differ from RuleKey(%s)", name, key, other)
		}
		seen[key] = name
	}
}

// TestRuleKeyIsStable pins the exact digest of one rule: it is the name an
// enforcer and CDS must agree on, so a change here is a protocol change.
func TestRuleKeyIsStable(t *testing.T) {
	rules := Rules(mustParse(t, ruleDoc(rulePinnedArgv, ruleSecretsWide)))
	if len(rules) != 1 {
		t.Fatalf("len(Rules(allowlist)) = %d, want 1", len(rules))
	}
	want := "sha256:6a8a392137f68ca9e5cb687ed430cb070c0217adfb0a674e721448be91c73785"
	if got := RuleKey(rules[0]); got != want {
		t.Errorf("RuleKey(rule) = %s, want %s", got, want)
	}
}

// TestRemoved covers the case the design singles out: a narrowing that leaves
// the image digest untouched still retires the old rule.
func TestRemoved(t *testing.T) {
	tests := []struct {
		name    string
		old     string
		updated string
		want    int
	}{
		{"identical policy", ruleDoc(rulePinnedArgv, ""), ruleDoc(rulePinnedArgv, ""), 0},
		{"narrowed argv", ruleDoc(ruleWideArgv, ""), ruleDoc(rulePinnedArgv, ""), 1},
		{"narrowed mounts", ruleDoc(rulePinnedArgv, ""), ruleDoc(ruleNarrowMounts, ""), 1},
		{"narrowed env", ruleDoc(rulePinnedArgv, ""), ruleDoc(ruleNarrowEnv, ""), 1},
		{"narrowed secrets", ruleDoc(rulePinnedArgv, ruleSecretsWide), ruleDoc(rulePinnedArgv, ruleSecretsNarrow), 1},
		{"revoked secrets", ruleDoc(rulePinnedArgv, ruleSecretsWide), ruleDoc(rulePinnedArgv, ""), 1},
		{"removed workload", ruleDoc(rulePinnedArgv, ""), emptyDoc, 1},
		{"added workload", emptyDoc, ruleDoc(rulePinnedArgv, ""), 0},
		{"granted secrets", ruleDoc(rulePinnedArgv, ""), ruleDoc(rulePinnedArgv, ruleSecretsWide), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Removed(mustParse(t, tc.old), mustParse(t, tc.updated)); len(got) != tc.want {
				t.Errorf("len(Removed(old, updated)) = %d, want %d", len(got), tc.want)
			}
		})
	}
}

// TestRemovedDigestOnlyChange checks the ordinary case still works: a new
// image digest retires the rule that named the old one.
func TestRemovedDigestOnlyChange(t *testing.T) {
	updated := ruleDoc(`{"digest":"`+digestB+`","image":"example.com/api:2",`+
		`"command":{"policy":"exact","argv":["/bin/api"]},"args":{"policy":"deny"},`+
		`"mounts":{"policy":"exact","destinations":["/a","/b"]},"env":{"policy":"any"}}`, "")
	got := Removed(mustParse(t, ruleDoc(rulePinnedArgv, "")), mustParse(t, updated))
	if len(got) != 1 || got[0].Container.Digest.String() != digestA {
		t.Errorf("Removed(old, updated) = %v, want the rule naming %s", got, digestA)
	}
}
