package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/tdxrtmr"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// operatorPubkeyPath is where the measured initrd stages the operator public
// key on a dynamic boot; the same path cred-release reads. A var so tests
// point it at a temp file.
var operatorPubkeyPath = "/etc/confai/operator-pubkey"

// poweroff powers the node off after a sealed-mode fatal condition. The plugin
// is a containerd child, not a unit, so no FailureAction= applies to it. A var
// so tests inject a recorder instead of powering off the test host.
var poweroff = systemPoweroff

// selfAttestTimeout bounds the own-quote round trip at startup; the socket
// is local, so a slow answer means the verifier is not serving. It exceeds
// containerd's plugin_registration_timeout, so Run registers the stub before
// it attests (see pinOwnTuple).
const selfAttestTimeout = 30 * time.Second

// pinOwnTuple derives the CDS pins from the node's own quote. A var so tests
// observe when Run calls it relative to stub registration.
var pinOwnTuple = ownTuplePins

// sealedPolicy is what a static boot pins the plugin to: the linted document,
// the register that commits to it, and the values env From rules resolve
// against that no NRI message carries.
type sealedPolicy struct {
	doc   *allowlist.Allowlist
	rtmr3 [runtimemeasure.Size]byte
	// hostIP is what nri-node-ip.service wrote for this node; nodeName is
	// the node name the kubelet derives from the hostname. The kubelet
	// injects both through fieldRefs.
	hostIP   string
	nodeName string
}

// nodeIP is the address the node-ip file under workload_claims.socket_dir
// holds: nri-node-ip.service writes it on the node image, the chart's
// installer elsewhere. false when no socket dir is configured or the file is
// absent; the file's only readers fall back to another source then.
func nodeIP(cfg *config) (string, bool) {
	if cfg.WorkloadClaims.SocketDir == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// kubeletNodeName is the node name the kubelet (and RKE2, which passes it
// as hostname-override) forms from the kernel hostname: trimmed and
// lowercased, so a spec.nodeName fieldRef injects that form.
func kubeletNodeName(hostname string) string {
	return strings.ToLower(strings.TrimSpace(hostname))
}

// systemPoweroff asks systemd first, which flushes journals, and falls back
// to the syscall when systemd is not answering.
func systemPoweroff() error {
	if err := exec.Command("systemctl", "poweroff", "--force", "--force").Run(); err == nil {
		return nil
	}
	unix.Sync()
	return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

// loadSealed proves the running register commits to exactly the bundle
// policybundle.ReadDir found (members re-indexed against the digest file):
// strict parse and sealed lint of the allowlist member, then sysfs RTMR[3]
// must equal ForStaticAllowlist(index).
func loadSealed(bundle policybundle.Bundle) (*sealedPolicy, error) {
	raw := bundle.Members[policybundle.MemberStaticAllowlist]
	if err := allowlist.LintSealed(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", policybundle.MemberStaticAllowlist, err)
	}
	doc, err := allowlist.ParseJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", policybundle.MemberStaticAllowlist, err)
	}
	own, err := tdxrtmr.Read(3)
	if err != nil {
		return nil, err
	}
	want := bundle.RTMR3()
	if own != want {
		return nil, fmt.Errorf("RTMR[3] is %s, want %s = ForStaticAllowlist(index) (was the bundle replaced after the measurement?)",
			hex.EncodeToString(own[:]), hex.EncodeToString(want[:]))
	}
	return &sealedPolicy{doc: doc, rtmr3: own}, nil
}

// checkDynamicRegister proves a dynamic boot left RTMR[3] at ForDynamic(seed):
// the node plugin never extends the register itself, so anything else means
// the static events, or something foreign, went in. The seed is the
// initrd-staged operator key when one was launched with, else Zero.
func checkDynamicRegister(pubkeyPath string) error {
	seed := runtimemeasure.Zero
	pub, err := os.ReadFile(pubkeyPath)
	switch {
	case err == nil && len(pub) > 0:
		seed = runtimemeasure.ForOperatorKey(pub)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("read operator pubkey: %w", err)
	}
	own, err := tdxrtmr.Read(3)
	if err != nil {
		return err
	}
	if want := runtimemeasure.ForDynamic(seed); own != want {
		return fmt.Errorf("RTMR[3] is %s, want %s = ForDynamic(seed) on a dynamic boot", hex.EncodeToString(own[:]), hex.EncodeToString(want[:]))
	}
	return nil
}

// ownTuplePins pins the CDS peer to this node's own image tuple {MRTD,
// RTMR1, RTMR2, RTMR3} as the attestation-api reports it from a fresh quote,
// so no installer writes pins into the measured config. The reported RTMR[3]
// must be the one the sealed load proved, or the verifier is not looking at
// this node.
func ownTuplePins(ctx context.Context, attestationAPIURL string, rtmr3 [runtimemeasure.Size]byte) (ratls.Pins, error) {
	ctx, cancel := context.WithTimeout(ctx, selfAttestTimeout)
	defer cancel()

	entry, err := attestationclient.NewClient(attestationAPIURL).OwnTupleEntry(ctx)
	if err != nil {
		return ratls.Pins{}, err
	}
	if got := entry.RTMRs[3]; !bytes.Equal(got, rtmr3[:]) {
		return ratls.Pins{}, fmt.Errorf("the verifier reports RTMR[3] %x, the sealed register is %x", got, rtmr3[:])
	}
	return ratls.Pins{Entries: []measurements.Entry{entry}}, nil
}

// oomScoreAdjPath is where the plugin lowers its own OOM score in sealed
// mode: containerd launches it with no unit to carry OOMScoreAdjust=, and a
// plugin the kernel kills mid-request admits that request. A var for tests.
var oomScoreAdjPath = "/proc/self/oom_score_adj"

func protectFromOOM(logger *slog.Logger) {
	if err := os.WriteFile(oomScoreAdjPath, []byte("-1000\n"), 0); err != nil {
		logger.Warn("cannot lower the plugin's OOM score; an OOM kill mid-request admits that request", "path", oomScoreAdjPath, "error", err)
	}
}
