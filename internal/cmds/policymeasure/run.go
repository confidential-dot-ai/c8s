package policymeasure

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/tdxrtmr"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// extendRTMR3 is the register extend; a var so tests substitute a fake that
// folds into the sysfs fixture (a plain file cannot fold on write).
var extendRTMR3 = func(event [runtimemeasure.Size]byte) error {
	return tdxrtmr.Extend(3, event)
}

// Run measures the boot's policy mode. Every failure is returned; the unit's
// FailureAction turns it into a power-off.
func Run(cfg Config) error {
	platform := ratls.NormalizePlatform(cfg.Platform)
	if platform == "" {
		return errors.New("--platform is required")
	}
	if err := ratls.ValidatePlatform(platform); err != nil {
		return fmt.Errorf("--platform: %w", err)
	}
	if err := os.MkdirAll(cfg.PolicyDir, 0o755); err != nil {
		return fmt.Errorf("policy dir: %w", err)
	}
	if err := refuseMeasured(cfg.PolicyDir); err != nil {
		return err
	}
	policyAttached, err := exists(cfg.PolicyDisk)
	if err != nil {
		return err
	}

	// Only TDX has a runtime register. An SNP boot is always dynamic, and a
	// policydata disk it cannot measure is refused rather than ignored, or
	// the launcher would believe the node is sealed.
	if platform != "tdx" {
		if policyAttached {
			return fmt.Errorf("policydata disk %s is attached but platform %s has no runtime register to measure it into: static mode is TDX-only", cfg.PolicyDisk, platform)
		}
		return writeMode(cfg.PolicyDir, policybundle.DynamicMode)
	}

	seed, err := launchSeed(cfg.OperatorPubkey)
	if err != nil {
		return err
	}
	reg, err := tdxrtmr.Read(3)
	if err != nil {
		return err
	}
	if reg != seed {
		return fmt.Errorf("RTMR[3] is %s before the mode event, want %s (Zero, or ForOperatorKey of %s when staged): the register was extended before this unit ran",
			hex.EncodeToString(reg[:]), hex.EncodeToString(seed[:]), cfg.OperatorPubkey)
	}

	if !policyAttached {
		want := runtimemeasure.ForDynamic(seed)
		if err := extendAndVerify([][runtimemeasure.Size]byte{runtimemeasure.ModeDynamic}, want); err != nil {
			return err
		}
		return writeMode(cfg.PolicyDir, policybundle.DynamicMode)
	}
	return measureStatic(cfg, seed)
}

// launchSeed returns the register the initrd left: ForOperatorKey of the
// staged pubkey, or Zero when no key was staged. Requiring the two to agree
// refuses a pubkey file written after boot that the initrd never measured.
func launchSeed(pubkeyPath string) ([runtimemeasure.Size]byte, error) {
	pub, err := os.ReadFile(pubkeyPath)
	if errors.Is(err, os.ErrNotExist) {
		return runtimemeasure.Zero, nil
	}
	if err != nil {
		return runtimemeasure.Zero, fmt.Errorf("operator pubkey: %w", err)
	}
	if len(pub) == 0 {
		return runtimemeasure.Zero, fmt.Errorf("operator pubkey %s is empty", pubkeyPath)
	}
	return runtimemeasure.ForOperatorKey(pub), nil
}

// measureStatic is the static branch: the register must be Zero (a static
// node has no operator key), the bundle is read off the disk and linted,
// the members and digest are published, then the two events are extended
// and the register must read back as the bundle's RTMR3. mode is written
// last so a consumer that finds mode=static finds every other file too.
func measureStatic(cfg Config, seed [runtimemeasure.Size]byte) error {
	opkeyAttached, err := exists(cfg.OpkeyDisk)
	if err != nil {
		return err
	}
	if opkeyAttached {
		return fmt.Errorf("both %s and %s are attached: a static node has no operator key", cfg.PolicyDisk, cfg.OpkeyDisk)
	}
	if seed != runtimemeasure.Zero {
		return fmt.Errorf("operator pubkey %s is staged on a static boot: a static node has no operator key", cfg.OperatorPubkey)
	}

	members, err := readBundleDisk(cfg.PolicyDisk, filepath.Dir(cfg.PolicyDir))
	if err != nil {
		return err
	}
	bundle, err := policybundle.FromMembers(members)
	if err != nil {
		return err
	}
	// LintSealed parses strictly (unknown fields refused) and requires the
	// bytes to be canonical, so what is measured is what was reviewed.
	if err := allowlist.LintSealed(bundle.Members[policybundle.MemberStaticAllowlist]); err != nil {
		return fmt.Errorf("%s: %w", policybundle.MemberStaticAllowlist, err)
	}

	for name, data := range bundle.Members {
		if err := writeFile(cfg.PolicyDir, name, data); err != nil {
			return err
		}
	}
	sum := bundle.IndexDigest()
	if err := writeFile(cfg.PolicyDir, policybundle.DigestFile, []byte(hex.EncodeToString(sum[:]))); err != nil {
		return err
	}

	events := [][runtimemeasure.Size]byte{runtimemeasure.ModeStatic, runtimemeasure.PolicyEvent(bundle.Index())}
	if err := extendAndVerify(events, bundle.RTMR3()); err != nil {
		return err
	}
	return writeMode(cfg.PolicyDir, policybundle.StaticMode)
}

// extendAndVerify folds events into RTMR[3] and reads the register back:
// the value the verifiers recompute must be what the hardware holds, not
// what this process believes it wrote.
func extendAndVerify(events [][runtimemeasure.Size]byte, want [runtimemeasure.Size]byte) error {
	for _, ev := range events {
		if err := extendRTMR3(ev); err != nil {
			return err
		}
	}
	got, err := tdxrtmr.Read(3)
	if err != nil {
		return fmt.Errorf("read back RTMR[3]: %w", err)
	}
	if got != want {
		return fmt.Errorf("RTMR[3] reads back as %s after the mode event, want %s", hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}
	return nil
}
