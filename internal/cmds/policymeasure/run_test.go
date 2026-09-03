package policymeasure

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/tdxrtmr"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// sealedAllowlist is a canonical document LintSealed accepts.
func sealedAllowlist(t *testing.T) []byte {
	t.Helper()
	doc := `{"schema":"c8s.allowlist/v1","digests":{},"workloads":{"web":{"containers":[{"digest":"` + digestA + `",` +
		`"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","destinations":["/etc/hosts"],"rules":{"/etc/hosts":{"source":"platform"}}},` +
		`"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}}}]}}}`
	al, err := allowlist.ParseJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

// fixture is one boot: a fake sysfs, fake disks (directories the fake
// mount copies from), a policy dir, and recorders for the extends and
// unmounts that happened.
type fixture struct {
	cfg      Config
	sysfs    string
	extended [][runtimemeasure.Size]byte
	mounted  []string
	unmounts int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	fx := &fixture{
		sysfs: filepath.Join(root, "sysfs"),
		cfg: Config{
			Platform:       "tdx",
			PolicyDir:      filepath.Join(root, "run", "confai", "policy"),
			OpkeyDisk:      filepath.Join(root, "disks", "opkeydata"),
			PolicyDisk:     filepath.Join(root, "disks", "policydata"),
			OperatorPubkey: filepath.Join(root, "etc", "operator-pubkey"),
		},
	}
	for _, d := range []string{fx.sysfs, filepath.Dir(fx.cfg.PolicyDir), filepath.Join(root, "disks"), filepath.Join(root, "etc")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	origRoot, origExtend, origMount, origUnmount := tdxrtmr.SysfsRoot, extendRTMR3, mountISO, unmountISO
	tdxrtmr.SysfsRoot = fx.sysfs
	// The fake sysfs node folds like the TSM node does.
	extendRTMR3 = func(event [runtimemeasure.Size]byte) error {
		fx.extended = append(fx.extended, event)
		reg, err := tdxrtmr.Read(3)
		if err != nil {
			return err
		}
		next := runtimemeasure.Extend(reg, event)
		return os.WriteFile(tdxrtmr.Path(3), next[:], 0o600)
	}
	// A "disk" is a directory; mounting copies its entries into the target.
	mountISO = func(dev, target string) error {
		fx.mounted = append(fx.mounted, target)
		entries, err := os.ReadDir(dev)
		if err != nil {
			return err
		}
		for _, e := range entries {
			src, dst := filepath.Join(dev, e.Name()), filepath.Join(target, e.Name())
			switch {
			case e.Type()&os.ModeSymlink != 0:
				link, err := os.Readlink(src)
				if err != nil {
					return err
				}
				if err := os.Symlink(link, dst); err != nil {
					return err
				}
			case e.IsDir():
				if err := os.Mkdir(dst, 0o755); err != nil {
					return err
				}
			default:
				data, err := os.ReadFile(src)
				if err != nil {
					return err
				}
				if err := os.WriteFile(dst, data, 0o444); err != nil {
					return err
				}
			}
		}
		return nil
	}
	unmountISO = func(target string) error {
		fx.unmounts++
		return os.RemoveAll(target)
	}
	t.Cleanup(func() {
		tdxrtmr.SysfsRoot, extendRTMR3, mountISO, unmountISO = origRoot, origExtend, origMount, origUnmount
	})
	return fx
}

func (fx *fixture) setRegister(t *testing.T, reg [runtimemeasure.Size]byte) {
	t.Helper()
	if err := os.WriteFile(tdxrtmr.Path(3), reg[:], 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fx *fixture) register(t *testing.T) [runtimemeasure.Size]byte {
	t.Helper()
	reg, err := tdxrtmr.Read(3)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// attachPolicy builds the policydata "disk" from members; a value of nil
// makes a subdirectory instead of a file.
func (fx *fixture) attachPolicy(t *testing.T, members map[string][]byte) {
	t.Helper()
	if err := os.Mkdir(fx.cfg.PolicyDisk, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range members {
		path := filepath.Join(fx.cfg.PolicyDisk, name)
		if data == nil {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (fx *fixture) stageOperatorKey(t *testing.T) []byte {
	t.Helper()
	pub := []byte("-----BEGIN PUBLIC KEY-----\noperator\n-----END PUBLIC KEY-----\n")
	if err := os.WriteFile(fx.cfg.OperatorPubkey, pub, 0o644); err != nil {
		t.Fatal(err)
	}
	return pub
}

func (fx *fixture) readPolicy(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fx.cfg.PolicyDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func (fx *fixture) policyFileAbsent(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(fx.cfg.PolicyDir, name)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("os.Stat(%s/%s) = %v, want not-exist", fx.cfg.PolicyDir, name, err)
	}
}

func TestRunDynamic(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(t *testing.T, fx *fixture) (seed [runtimemeasure.Size]byte)
	}{
		{"no operator key", func(t *testing.T, fx *fixture) [runtimemeasure.Size]byte {
			fx.setRegister(t, runtimemeasure.Zero)
			return runtimemeasure.Zero
		}},
		{"operator key measured by the initrd", func(t *testing.T, fx *fixture) [runtimemeasure.Size]byte {
			seed := runtimemeasure.ForOperatorKey(fx.stageOperatorKey(t))
			fx.setRegister(t, seed)
			return seed
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			seed := tc.stage(t, fx)
			if err := Run(fx.cfg); err != nil {
				t.Fatalf("Run(dynamic) = %v, want nil", err)
			}
			if got, want := fx.register(t), runtimemeasure.ForDynamic(seed); got != want {
				t.Errorf("RTMR[3] after Run = %x, want ForDynamic(seed) %x", got, want)
			}
			if got := string(fx.readPolicy(t, policybundle.ModeFile)); got != "dynamic\n" {
				t.Errorf("mode = %q, want %q", got, "dynamic\n")
			}
			fx.policyFileAbsent(t, policybundle.DigestFile)
			fx.policyFileAbsent(t, policybundle.MemberStaticAllowlist)
			if len(fx.mounted) != 0 {
				t.Errorf("mounted %v on a dynamic boot, want nothing", fx.mounted)
			}
		})
	}
}

func TestRunStatic(t *testing.T) {
	fx := newFixture(t)
	fx.setRegister(t, runtimemeasure.Zero)
	doc := sealedAllowlist(t)
	fx.attachPolicy(t, map[string][]byte{
		policybundle.MemberStaticAllowlist: doc,
		// KubeVirt's AtomicWriter layout: a versioned directory and a link.
		"..2026_09_03": nil,
	})
	if err := os.Symlink("..2026_09_03", filepath.Join(fx.cfg.PolicyDisk, "..data")); err != nil {
		t.Fatal(err)
	}
	bundle, err := policybundle.FromMembers(map[string][]byte{policybundle.MemberStaticAllowlist: doc})
	if err != nil {
		t.Fatal(err)
	}

	if err := Run(fx.cfg); err != nil {
		t.Fatalf("Run(static) = %v, want nil", err)
	}
	if got, want := fx.register(t), bundle.RTMR3(); got != want {
		t.Errorf("RTMR[3] after Run = %x, want bundle RTMR3 %x", got, want)
	}
	if want := [][runtimemeasure.Size]byte{runtimemeasure.ModeStatic, runtimemeasure.PolicyEvent(bundle.Index())}; len(fx.extended) != 2 || fx.extended[0] != want[0] || fx.extended[1] != want[1] {
		t.Errorf("extended events = %x, want ModeStatic then PolicyEvent(index)", fx.extended)
	}
	if got := string(fx.readPolicy(t, policybundle.ModeFile)); got != "static\n" {
		t.Errorf("mode = %q, want %q", got, "static\n")
	}
	sum := bundle.IndexDigest()
	if got, want := string(fx.readPolicy(t, policybundle.DigestFile)), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("digest = %q, want %q", got, want)
	}
	if got := fx.readPolicy(t, policybundle.MemberStaticAllowlist); !bytes.Equal(got, doc) {
		t.Errorf("published member differs from the attached bytes")
	}
	for _, name := range []string{policybundle.ModeFile, policybundle.DigestFile, policybundle.MemberStaticAllowlist} {
		info, err := os.Stat(filepath.Join(fx.cfg.PolicyDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Errorf("%s mode = %o, want 0444", name, info.Mode().Perm())
		}
	}
	if fx.unmounts != 1 {
		t.Errorf("unmounts = %d, want 1", fx.unmounts)
	}
	if entries, _ := os.ReadDir(filepath.Dir(fx.cfg.PolicyDir)); len(entries) != 1 {
		t.Errorf("mountpoint left behind under %s: %v", filepath.Dir(fx.cfg.PolicyDir), entries)
	}

	state, err := policybundle.ReadDir(fx.cfg.PolicyDir)
	if err != nil {
		t.Fatalf("policybundle.ReadDir after Run = %v, want nil", err)
	}
	if state.Mode != policybundle.StaticMode || state.Bundle.RTMR3() != bundle.RTMR3() {
		t.Errorf("policybundle.ReadDir = %+v, want static with the measured bundle", state)
	}
}

func TestRunSNP(t *testing.T) {
	t.Run("dynamic without touching a register", func(t *testing.T) {
		fx := newFixture(t)
		fx.cfg.Platform = "snp"
		// No sysfs node at all: SNP has none, and the run must not need one.
		if err := Run(fx.cfg); err != nil {
			t.Fatalf("Run(snp) = %v, want nil", err)
		}
		if got := string(fx.readPolicy(t, policybundle.ModeFile)); got != "dynamic\n" {
			t.Errorf("mode = %q, want %q", got, "dynamic\n")
		}
		if len(fx.extended) != 0 {
			t.Errorf("extended %d events on SNP, want 0", len(fx.extended))
		}
	})
	t.Run("policydata attached is fatal", func(t *testing.T) {
		fx := newFixture(t)
		fx.cfg.Platform = "sev-snp"
		fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: sealedAllowlist(t)})
		err := Run(fx.cfg)
		if err == nil || !strings.Contains(err.Error(), "TDX-only") {
			t.Fatalf("Run(snp, policydata) = %v, want TDX-only error", err)
		}
		fx.policyFileAbsent(t, policybundle.ModeFile)
	})
}

// TestRunFailsClosed walks every refusal. Each case leaves no mode file, so
// a consumer ordered after the unit cannot find a verdict the register does
// not back.
func TestRunFailsClosed(t *testing.T) {
	staticBoot := func(t *testing.T, fx *fixture) {
		fx.setRegister(t, runtimemeasure.Zero)
		fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: sealedAllowlist(t)})
	}
	for _, tc := range []struct {
		name  string
		stage func(t *testing.T, fx *fixture)
		want  string
	}{
		{"platform missing", func(t *testing.T, fx *fixture) { fx.cfg.Platform = "" }, "--platform is required"},
		{"platform unknown", func(t *testing.T, fx *fixture) { fx.cfg.Platform = "sgx" }, "--platform"},
		{"sysfs register absent", func(t *testing.T, fx *fixture) {}, "is this a TDX guest"},
		{"register already extended", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.ForDynamic(runtimemeasure.Zero))
		}, "before the mode event"},
		{"operator key staged but not measured", func(t *testing.T, fx *fixture) {
			fx.stageOperatorKey(t)
			fx.setRegister(t, runtimemeasure.Zero)
		}, "before the mode event"},
		{"operator key file empty", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			if err := os.WriteFile(fx.cfg.OperatorPubkey, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "is empty"},
		{"already measured this boot", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			if err := os.MkdirAll(fx.cfg.PolicyDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := writeMode(fx.cfg.PolicyDir, policybundle.DynamicMode); err != nil {
				t.Fatal(err)
			}
		}, "measured earlier this boot"},
		{"dynamic extend fails", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			extendRTMR3 = func([runtimemeasure.Size]byte) error { return errors.New("EACCES") }
		}, "EACCES"},
		{"dynamic read-back mismatch", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			extendRTMR3 = func([runtimemeasure.Size]byte) error { return nil } // the node ignored the write
		}, "reads back as"},
		{"static with opkeydata attached", func(t *testing.T, fx *fixture) {
			staticBoot(t, fx)
			if err := os.WriteFile(fx.cfg.OpkeyDisk, []byte("iso"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "a static node has no operator key"},
		{"static with an operator key measured", func(t *testing.T, fx *fixture) {
			seed := runtimemeasure.ForOperatorKey(fx.stageOperatorKey(t))
			fx.setRegister(t, seed)
			fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: sealedAllowlist(t)})
		}, "a static node has no operator key"},
		{"mount fails", func(t *testing.T, fx *fixture) {
			staticBoot(t, fx)
			mountISO = func(string, string) error { return errors.New("EINVAL: not an iso9660 image") }
		}, filepath.Join("disks", "policydata") + ": EINVAL"},
		{"unmount fails", func(t *testing.T, fx *fixture) {
			staticBoot(t, fx)
			unmountISO = func(string) error { return errors.New("EBUSY") }
		}, "unmount"},
		{"bundle without static-allowlist.json", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			fx.attachPolicy(t, map[string][]byte{"README": []byte("x")})
		}, "no static-allowlist.json member"},
		{"unknown member", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: sealedAllowlist(t), "routes.json": []byte("{}")})
		}, "is unknown"},
		{"subdirectory on the disk", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: sealedAllowlist(t), "sub": nil})
		}, "not a regular file"},
		{"member over the size bound", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: bytes.Repeat([]byte("{"), policybundle.MaxMemberSize+1)})
		}, "over"},
		{"allowlist not sealed", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			doc := `{"schema":"c8s.allowlist/v1","digests":null,"workloads":{"web":{"initContainers":null,"containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"},"env":{"policy":"any"}}]}}}`
			fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: []byte(doc)})
		}, "sealed allowlist"},
		{"allowlist not canonical", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: append(sealedAllowlist(t), '\n')})
		}, "canonical"},
		{"allowlist not JSON", func(t *testing.T, fx *fixture) {
			fx.setRegister(t, runtimemeasure.Zero)
			fx.attachPolicy(t, map[string][]byte{policybundle.MemberStaticAllowlist: []byte("not json")})
		}, "static-allowlist.json"},
		{"static extend fails", func(t *testing.T, fx *fixture) {
			staticBoot(t, fx)
			extendRTMR3 = func([runtimemeasure.Size]byte) error { return errors.New("EACCES") }
		}, "EACCES"},
		{"static read-back mismatch", func(t *testing.T, fx *fixture) {
			staticBoot(t, fx)
			extendRTMR3 = func([runtimemeasure.Size]byte) error { return nil }
		}, "reads back as"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			tc.stage(t, fx)
			err := Run(fx.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
			if tc.name != "already measured this boot" {
				fx.policyFileAbsent(t, policybundle.ModeFile)
			}
			if fx.unmounts != len(fx.mounted) && !strings.Contains(tc.name, "unmount") {
				t.Errorf("mounted %d, unmounted %d: the disk stays mounted after a failure", len(fx.mounted), fx.unmounts)
			}
		})
	}
}
