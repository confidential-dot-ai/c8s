package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// buildJournal appends n published entries and returns their digests in
// ascending position order. The entries are real: the verifier re-hashes every
// one it walks.
func (f *fakeDeployment) buildJournal(n int) []string {
	f.t.Helper()
	digests := make([]string, 0, n)
	for i := range n {
		digests = append(digests, f.publish(policystate.EventPublished, policystate.PublishedPayload{
			Version:      uint64(i + 1),
			TargetDigest: testDigestP,
			AuthorizedBy: policystate.AuthorizedBySeed,
		}))
	}
	return digests
}

// checkpointFile writes cp to a temp file and returns its path. A nil cp means
// "no file yet".
func checkpointFile(t *testing.T, cp *stateCheckpoint) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if cp == nil {
		return path
	}
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readCheckpointFile(t *testing.T, path string) stateCheckpoint {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cp stateCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatal(err)
	}
	return cp
}

// A first run has nothing to compare against: it records the head it saw, and
// says so rather than claiming continuity it cannot have checked.
func TestCheckpointFirstRunRecordsTheHead(t *testing.T) {
	dep := newFakeDeployment(t)
	cfg, ev := dep.start()
	dep.buildJournal(3)
	state := dep.state(testDigestP, nil)
	dep.bind(ev, state)
	path := checkpointFile(t, nil)

	oc := runStatePolicy(t, cfg, ev, &statePolicy{checkpoint: path, pins: map[string]bool{testDigestP: true}})
	if !oc.Verified {
		t.Fatalf("verified = false, want true: %s", oc.Error)
	}
	if !strings.Contains(oc.State.Continuity, "first run") {
		t.Errorf("continuity = %q, want it to say this is the first run", oc.State.Continuity)
	}
	if got := readCheckpointFile(t, path); got.LogHead != state.LogHead || got.LogPosition != state.LogPosition || got.Authority != dep.authority() {
		t.Fatalf("checkpoint = %+v, want the head the verdict accepted", got)
	}
}

// The walk follows each entry's parent from the head back to the checkpointed
// entry, and the checkpoint advances only when the whole verdict survived.
func TestCheckpointContinuityWalksTheJournal(t *testing.T) {
	dep := newFakeDeployment(t)
	cfg, ev := dep.start()
	digests := dep.buildJournal(2)
	stored := &stateCheckpoint{Authority: dep.authority(), LogHead: digests[0], LogPosition: 1}
	dep.buildJournal(3)
	state := dep.state(testDigestP, nil)
	dep.bind(ev, state)
	path := checkpointFile(t, stored)

	oc := runStatePolicy(t, cfg, ev, &statePolicy{checkpoint: path, pins: map[string]bool{testDigestP: true}})
	if !oc.Verified {
		t.Fatalf("verified = false, want true: %s", oc.Error)
	}
	if !strings.Contains(oc.State.Continuity, "without a gap or a fork") {
		t.Errorf("continuity = %q, want an unbroken chain", oc.State.Continuity)
	}
	if got := readCheckpointFile(t, path); got.LogPosition != state.LogPosition {
		t.Fatalf("checkpoint position = %d, want the new head at %d", got.LogPosition, state.LogPosition)
	}
}

func TestCheckpointFailures(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(dep *fakeDeployment) *stateCheckpoint
		wantErr string
	}{
		{
			// A deployment that no longer serves an entry the chain runs
			// through cannot show it continued the history it was checkpointed
			// at.
			name: "a journal entry is missing",
			setup: func(dep *fakeDeployment) *stateCheckpoint {
				digests := dep.buildJournal(1)
				stored := &stateCheckpoint{Authority: dep.authority(), LogHead: digests[0], LogPosition: 1}
				dep.buildJournal(2)
				delete(dep.objects, strings.TrimPrefix(dep.head, "sha256:"))
				return stored
			},
			wantErr: "fetch journal entry",
		},
		{
			name: "the authority changed",
			setup: func(dep *fakeDeployment) *stateCheckpoint {
				digests := dep.buildJournal(2)
				return &stateCheckpoint{
					Authority:   "sha256:" + strings.Repeat("e", 64),
					LogHead:     digests[0],
					LogPosition: 1,
				}
			},
			wantErr: "authority changed",
		},
		{
			name: "history forked at the checkpointed position",
			setup: func(dep *fakeDeployment) *stateCheckpoint {
				dep.buildJournal(3)
				return &stateCheckpoint{
					Authority:   dep.authority(),
					LogHead:     "sha256:" + strings.Repeat("d", 64),
					LogPosition: 1,
				}
			},
			wantErr: "history forked",
		},
		{
			name: "the journal went backwards",
			setup: func(dep *fakeDeployment) *stateCheckpoint {
				digests := dep.buildJournal(2)
				return &stateCheckpoint{Authority: dep.authority(), LogHead: digests[1], LogPosition: 9}
			},
			wantErr: "went backwards",
		},
		{
			name: "the checkpoint file is incomplete",
			setup: func(dep *fakeDeployment) *stateCheckpoint {
				dep.buildJournal(1)
				return &stateCheckpoint{Authority: dep.authority()}
			},
			wantErr: "is incomplete",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := newFakeDeployment(t)
			cfg, ev := dep.start()
			stored := tt.setup(dep)
			dep.bind(ev, dep.state(testDigestP, nil))
			path := checkpointFile(t, stored)

			oc := runStatePolicy(t, cfg, ev, &statePolicy{checkpoint: path, pins: map[string]bool{testDigestP: true}})
			if oc.Verified || !strings.Contains(oc.Error, tt.wantErr) {
				t.Fatalf("verified = %t, error = %q, want one mentioning %q", oc.Verified, oc.Error, tt.wantErr)
			}
		})
	}
}
