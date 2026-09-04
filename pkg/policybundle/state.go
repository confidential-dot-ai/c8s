package policybundle

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Node-side paths. c8s-policy-measure writes the policy directory once per
// boot; cred-release, the NRI plugin and CDS read it through ReadDir.
const (
	// NodeStateDir is the tmpfs the measured image keeps its boot state in:
	// the policy directory and the attestation-api unix socket. Binds from
	// it classify as allowlist.SourceNodeState.
	NodeStateDir = "/run/confai"
	// DefaultPolicyDir holds ModeFile (always), DigestFile and one file per
	// bundle member (static boots only).
	DefaultPolicyDir = NodeStateDir + "/policy"

	// ModeFile holds StaticMode or DynamicMode plus a newline; the measurer
	// writes it last, so a reader that finds it finds every other file too.
	ModeFile = "mode"
	// DigestFile holds the lowercase hex of the bundle's IndexDigest.
	DigestFile = "digest"

	// StaticMode and DynamicMode are the two values ModeFile carries.
	StaticMode  = "static"
	DynamicMode = "dynamic"

	// OperatorPubkeyPath is where the measured initrd stages the operator
	// public key it read off the opkeydata disk and hashed into RTMR[3] on a
	// dynamic boot. The initrd is the single measured reader of that disk;
	// c8s-policy-measure, cred-release and the NRI plugin read the staged
	// file.
	OperatorPubkeyPath = "/etc/confai/operator-pubkey"
)

// State is what a consumer reads back from the policy directory.
type State struct {
	// Mode is StaticMode or DynamicMode.
	Mode string
	// Bundle is the attached bundle, re-indexed from the member files;
	// ReadDir checked its IndexDigest against DigestFile. Zero on a dynamic
	// boot.
	Bundle Bundle
}

// ReadDir loads the measurer's output from dir. A missing or unknown mode
// is an error, never a default: a consumer that starts without the
// measurer's verdict must not guess one. On a static boot every other
// regular file is a member, read under the Load bounds, and the members'
// index digest must equal DigestFile, so a member rewritten after the
// measurement is refused before any register comparison.
func ReadDir(dir string) (State, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ModeFile))
	if err != nil {
		return State{}, fmt.Errorf("policy mode: %w (did c8s-policy-measure.service run?)", err)
	}
	mode := strings.TrimSpace(string(raw))
	switch mode {
	case DynamicMode:
		return State{Mode: mode}, nil
	case StaticMode:
	default:
		return State{}, fmt.Errorf("%s holds %q: the policy mode is neither %s nor %s", filepath.Join(dir, ModeFile), mode, StaticMode, DynamicMode)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return State{}, fmt.Errorf("policy dir: %w", err)
	}
	if len(entries) > MaxMembers+2 {
		return State{}, fmt.Errorf("policy dir %s has %d entries, max %d members", dir, len(entries), MaxMembers)
	}
	members := make(map[string][]byte, len(entries))
	for _, e := range entries {
		name := e.Name()
		if name == ModeFile || name == DigestFile {
			continue
		}
		if !e.Type().IsRegular() {
			return State{}, fmt.Errorf("policy dir: %s is not a regular file", filepath.Join(dir, name))
		}
		data, err := ReadMember(filepath.Join(dir, name))
		if err != nil {
			return State{}, err
		}
		members[name] = data
	}
	bundle, err := FromMembers(members)
	if err != nil {
		return State{}, err
	}
	recorded, err := os.ReadFile(filepath.Join(dir, DigestFile))
	if err != nil {
		return State{}, fmt.Errorf("policy digest: %w", err)
	}
	sum := bundle.IndexDigest()
	if got := strings.TrimSpace(string(recorded)); got != hex.EncodeToString(sum[:]) {
		return State{}, fmt.Errorf("policy dir %s: members index to %x, %s says %s", dir, sum, DigestFile, got)
	}
	return State{Mode: mode, Bundle: bundle}, nil
}
