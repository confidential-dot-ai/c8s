package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// stateCheckpoint is the history a previous successful run observed. It is not
// an approval: it records where the journal was, so the next run can tell a
// deployment that moved forward from one that forked or restarted.
type stateCheckpoint struct {
	Authority   string `json:"authority"`
	LogHead     string `json:"log_head"`
	LogPosition uint64 `json:"log_position"`
}

// applyCheckpoint connects the bound statement to the stored checkpoint and,
// on success, advances it. A missing entry, a position that does not line up,
// or a different authority fails: each one means this is not the history the
// last run saw continuing.
func applyCheckpoint(ctx context.Context, oc *Outcome, policy *statePolicy, summary *StateSummary, statement policystate.State, channel *stateChannel, channelErr error) {
	if policy.checkpoint == "" {
		return
	}
	if channelErr != nil {
		failVerdict(oc, "cannot check history continuity: %v", channelErr)
		return
	}
	stored, err := readCheckpoint(policy.checkpoint)
	if err != nil {
		failVerdict(oc, "%v", err)
		return
	}
	if stored != nil {
		if err := checkContinuity(ctx, *stored, statement, channel); err != nil {
			failVerdict(oc, "%v", err)
			return
		}
		summary.Continuity = fmt.Sprintf("the journal extends the checkpoint at position %d without a gap or a fork", stored.LogPosition)
	} else {
		summary.Continuity = "first run: no checkpoint to compare against, the current head is recorded"
	}
	// Only a verdict that survived every check earns a new checkpoint:
	// recording a head this run rejected would let the next run accept it as
	// history it had already seen.
	if !oc.Verified {
		return
	}
	next := stateCheckpoint{
		Authority:   statement.Authority,
		LogHead:     statement.LogHead,
		LogPosition: statement.LogPosition,
	}
	if err := writeCheckpoint(policy.checkpoint, next); err != nil {
		failVerdict(oc, "%v", err)
	}
}

// checkpointAuthority is the authority a stored checkpoint anchors, or "" when
// there is no checkpoint to read. It runs before the continuity walk, because
// which authority may sign the statement decides whether the walk is worth
// starting.
func checkpointAuthority(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	stored, err := readCheckpoint(path)
	if err != nil || stored == nil {
		return "", err
	}
	return stored.Authority, nil
}

// readCheckpoint loads the file, or returns nil when there is none yet.
func readCheckpoint(path string) (*stateCheckpoint, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read --state-checkpoint: %w", err)
	}
	var cp stateCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("--state-checkpoint %s is not a checkpoint file: %w", path, err)
	}
	if cp.Authority == "" || cp.LogHead == "" || cp.LogPosition == 0 {
		return nil, fmt.Errorf("--state-checkpoint %s is incomplete: it needs authority, log_head and log_position", path)
	}
	return &cp, nil
}

// writeCheckpoint replaces the file atomically, so an interrupted run leaves
// the previous checkpoint rather than a truncated one.
func writeCheckpoint(path string, cp stateCheckpoint) error {
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write --state-checkpoint: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write --state-checkpoint: %w", err)
	}
	return nil
}

// checkContinuity walks the journal backwards from the head the statement
// names, following each entry's parent, and requires it to reach the
// checkpointed head at the checkpointed position. Every entry is fetched by
// digest and re-hashed by the client, so the chain is authenticated by content
// address rather than by the hop it arrived over.
//
// The walk is bounded by the distance between the two positions: a deployment
// that serves a longer chain than its own counters claim is answering for a
// history it does not admit to.
func checkContinuity(ctx context.Context, stored stateCheckpoint, statement policystate.State, channel *stateChannel) error {
	if stored.Authority != statement.Authority {
		return fmt.Errorf("authority changed: %s -> %s; re-anchor", stored.Authority, statement.Authority)
	}
	if statement.LogPosition < stored.LogPosition {
		return fmt.Errorf("the journal went backwards: the checkpoint is at position %d and the responder bound position %d", stored.LogPosition, statement.LogPosition)
	}
	if statement.LogPosition == stored.LogPosition {
		if statement.LogHead != stored.LogHead {
			return fmt.Errorf("history forked: position %d hashes to %s here and to %s in the checkpoint", stored.LogPosition, statement.LogHead, stored.LogHead)
		}
		return nil
	}

	digest, position := statement.LogHead, statement.LogPosition
	for position > stored.LogPosition {
		entry, err := channel.client.Entry(ctx, digest)
		if err != nil {
			return fmt.Errorf("fetch journal entry %s at position %d: %w", digest, position, err)
		}
		if entry.Position != position {
			return fmt.Errorf("journal entry %s reports position %d, and the chain from the head puts it at %d", digest, entry.Position, position)
		}
		if entry.Parent == "" {
			return fmt.Errorf("the journal starts at position %d, before the checkpoint at position %d: this is not the history the checkpoint recorded", entry.Position, stored.LogPosition)
		}
		digest, position = entry.Parent, position-1
	}
	if digest != stored.LogHead {
		return fmt.Errorf("history forked: position %d hashes to %s here and to %s in the checkpoint", stored.LogPosition, digest, stored.LogHead)
	}
	return nil
}
