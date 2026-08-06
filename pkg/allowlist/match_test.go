package allowlist

import (
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	dApp     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dSidecar = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dInit    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	dOther   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

func dig(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

// exactly builds a container pinned to one digest and argv.
func exactly(t *testing.T, digest string, argv ...string) Container {
	t.Helper()
	c := Container{Digest: dig(t, digest), Command: ArgvPolicy{Policy: PolicyAny}, Args: ArgvPolicy{Policy: PolicyAny}}
	if len(argv) > 0 {
		c.Command = ArgvPolicy{Policy: PolicyExact, Argv: argv}
		c.Args = ArgvPolicy{Policy: PolicyDeny}
	}
	return c
}

func run(digest string, argv ...string) RunningContainer {
	return RunningContainer{Digest: digest, Argv: argv}
}

func TestMatchWorkload(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"api": {
			InitContainers: []Container{exactly(t, dInit, "/migrate")},
			Containers:     []Container{exactly(t, dApp, "/serve"), exactly(t, dSidecar, "/proxy")},
		},
	}}

	for _, tc := range []struct {
		name    string
		running []RunningContainer
		want    string
		wantErr error
	}{
		{
			name:    "every main present",
			running: []RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy")},
			want:    "api",
		},
		{
			// A declared init container that has not been reaped is not foreign.
			name:    "lingering init is admitted",
			running: []RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy"), run(dInit, "/migrate")},
			want:    "api",
		},
		{
			name:    "missing main is refused",
			running: []RunningContainer{run(dApp, "/serve")},
			wantErr: ErrNoMatch,
		},
		{
			// The whole point: an extra image, even one that has since stopped,
			// means this pod is not the entry.
			name:    "foreign container is refused",
			running: []RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy"), run(dOther, "/sh")},
			wantErr: ErrNoMatch,
		},
		{
			name:    "wrong argv on a declared digest is refused",
			running: []RunningContainer{run(dApp, "/bin/sh", "-c", "cat /run/secrets/*"), run(dSidecar, "/proxy")},
			wantErr: ErrNoMatch,
		},
		{
			name:    "empty running set is refused",
			running: nil,
			wantErr: ErrNoMatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, _, err := al.MatchWorkload(tc.running)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if name != tc.want {
				t.Fatalf("matched %q, want %q", name, tc.want)
			}
		})
	}
}

// Two entries that the running set cannot tell apart are refused rather than
// resolved by iteration order.
func TestMatchWorkloadAmbiguous(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"a": {Containers: []Container{exactly(t, dApp, "/serve")}},
		"b": {Containers: []Container{exactly(t, dApp, "/serve")}},
	}}
	if _, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve")}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous", err)
	}
}

// Two entries sharing a digest but pinning different argv are distinguishable
// here, even though Index admits either argv for that digest (a union across
// entries). That difference is the reason argv is matched per entry.
func TestMatchWorkloadDistinguishesByArgv(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"model-a": {Containers: []Container{exactly(t, dApp, "/serve", "--model", "a")}},
		"model-b": {Containers: []Container{exactly(t, dApp, "/serve", "--model", "b")}},
	}}
	name, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve", "--model", "b")})
	if err != nil || name != "model-b" {
		t.Fatalf("matched %q (%v), want model-b", name, err)
	}

	idx := al.BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: dApp, Argv: []string{"/serve", "--model", "a"}}) {
		t.Fatal("precondition: Index should admit either argv for the shared digest")
	}
}

// A digest declared with an "any" command in one entry does not let that entry
// swallow a pod whose real workload is another entry.
func TestMatchWorkloadWideEntryDoesNotStealNarrowPod(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"prod":  {Containers: []Container{exactly(t, dApp, "/serve"), exactly(t, dSidecar, "/proxy")}},
		"debug": {Containers: []Container{exactly(t, dApp)}}, // command: any
	}}
	// The sidecar is foreign to "debug", so only "prod" matches.
	name, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy")})
	if err != nil || name != "prod" {
		t.Fatalf("matched %q (%v), want prod", name, err)
	}
}

func TestMatchWorkloadEmptyAllowlist(t *testing.T) {
	al := &Allowlist{Schema: Schema}
	if _, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve")}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestDigestConstantsAreWellFormed(t *testing.T) {
	for _, d := range []string{dApp, dSidecar, dInit, dOther} {
		if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
			t.Fatalf("malformed test digest %q", d)
		}
	}
}
