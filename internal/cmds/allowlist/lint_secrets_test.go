package allowlist

import (
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func secretsLintWarnings(t *testing.T, doc string) []string {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return lintSecretsGrants(al)
}

func TestLintGrantsRequireExactArgv(t *testing.T) {
	warnings := secretsLintWarnings(t, `{"schema":"c8s.allowlist/v1",
		"workloads":{"w":{"containers":[
			{"digest":"`+digA+`","command":{"policy":"any"},"args":{"policy":"exact","argv":["run"]},
			 "paths":{"policy":"allow","read":["/secrets/model/**"]}}]}}}`)
	if !anyContains(warnings, "not exact+exact") {
		t.Fatalf("expected an argv warning, got: %v", warnings)
	}
}

func TestLintGrantsOutsideSecretsRoot(t *testing.T) {
	warnings := secretsLintWarnings(t, `{"schema":"c8s.allowlist/v1",
		"workloads":{"w":{"containers":[
			{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
			 "paths":{"policy":"allow","read":["/etc/ssl/key"]}}]}}}`)
	if !anyContains(warnings, "outside /secrets/") {
		t.Fatalf("expected a root warning, got: %v", warnings)
	}
}

func TestLintIdenticalSetEntriesWithGrants(t *testing.T) {
	entry := func(read string) string {
		return `{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
			"paths":{"policy":"allow","read":["` + read + `"]}}`
	}
	warnings := secretsLintWarnings(t, `{"schema":"c8s.allowlist/v1",
		"workloads":{
			"a":{"containers":[`+entry("/secrets/a")+`]},
			"b":{"containers":[`+entry("/secrets/b")+`]}}}`)
	if !anyContains(warnings, "identical container set") {
		t.Fatalf("expected an ambiguity warning, got: %v", warnings)
	}
}

func TestLintIdenticalSetWithoutGrantsIsQuiet(t *testing.T) {
	entry := `{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}`
	warnings := secretsLintWarnings(t, `{"schema":"c8s.allowlist/v1",
		"workloads":{
			"a":{"containers":[`+entry+`]},
			"b":{"containers":[`+entry+`]}}}`)
	if anyContains(warnings, "identical container set") {
		t.Fatalf("grant-free identical sets must not warn, got: %v", warnings)
	}
}

func TestLintSameEntryDuplicateWidenedToAny(t *testing.T) {
	warnings := secretsLintWarnings(t, `{"schema":"c8s.allowlist/v1",
		"workloads":{"w":{"containers":[
			{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
			 "paths":{"policy":"allow","read":["/secrets/a"]}},
			{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app","--debug"]},"args":{"policy":"deny"},
			 "paths":{"policy":"any"}}]}}}`)
	if !anyContains(warnings, "widens paths to 'any'") {
		t.Fatalf("expected a widening warning, got: %v", warnings)
	}
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
