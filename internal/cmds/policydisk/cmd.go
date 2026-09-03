// Package policydisk implements `c8s policy-disk`: it builds the policydata
// ISO a static-allowlist node boots with from the reviewed bundle members,
// and prints the index digest and RTMR[3] the node will report so the
// reviewer can pin them before the node exists.
package policydisk

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

// VolumeLabel is the ISO9660 volume label the node image looks the policy
// bundle up by (/dev/disk/by-label/policydata).
const VolumeLabel = "policydata"

// isoTools are the ISO9660 authoring tools tried in order; the first on PATH
// wins. They share the option set the node image's own test harness uses.
var isoTools = []string{"xorrisofs", "genisoimage", "mkisofs"}

// Config is what one run takes.
type Config struct {
	// Members are the files that make up the bundle; each becomes a member
	// named by its basename.
	Members []string
	// Output is the ISO path to write.
	Output string
	// KubeVirtSecret, when set, names a Secret to emit on stdout that KubeVirt
	// turns into the same disk (a secret volume with volumeLabel policydata).
	KubeVirtSecret string
}

// NewCmd returns the cobra subcommand.
func NewCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "policy-disk --member <file>... -o <iso>",
		Short: "Build the policydata disk a static-allowlist node boots with",
		Long: `Builds the policydata ISO from the reviewed bundle members and prints the
index digest and the RTMR[3] a node sealed to it reports. static-allowlist.json
is required and is linted as a sealed document first: its bytes are what the
node measures, so it must be canonical and complete.

Attach the ISO to the node at launch with volume label policydata (libvirt:
a CD-ROM device). On KubeVirt pass --kubevirt-secret <name>: the command then
writes a Secret holding the members, plus the volume to add to the
VirtualMachine, to stdout, and the digest lines to stderr.

Requires xorrisofs, genisoimage or mkisofs on PATH.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return Run(cmd.Context(), cfg, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&cfg.Members, "member", nil, "bundle member file; repeatable. The basename is the member name and static-allowlist.json is required")
	f.StringVarP(&cfg.Output, "output", "o", "", "ISO path to write (required)")
	f.StringVar(&cfg.KubeVirtSecret, "kubevirt-secret", "", "also write a Secret of this name holding the members, and the KubeVirt volume that mounts it as the policydata disk, to stdout")
	_ = cmd.MarkFlagRequired("member")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

// Run builds the bundle, writes the ISO and prints the measurements. The
// digest lines go to stdout, or to stderr when the KubeVirt manifest takes
// stdout, so `> volume.yaml` captures exactly one document stream.
func Run(ctx context.Context, cfg Config, stdout, stderr io.Writer) error {
	bundle, err := loadMembers(cfg.Members)
	if err != nil {
		return err
	}
	if err := pkgallowlist.LintSealed(bundle.Members[policybundle.MemberStaticAllowlist]); err != nil {
		return fmt.Errorf("%s: %w", policybundle.MemberStaticAllowlist, err)
	}
	tool, err := findISOTool()
	if err != nil {
		return err
	}
	if err := writeISO(ctx, tool, bundle, cfg.Output); err != nil {
		return err
	}

	report := stdout
	if cfg.KubeVirtSecret != "" {
		report = stderr
		manifest, err := kubeVirtManifest(cfg.KubeVirtSecret, bundle)
		if err != nil {
			return err
		}
		if _, err := stdout.Write(manifest); err != nil {
			return err
		}
	}
	digest := bundle.IndexDigest()
	rtmr3 := bundle.RTMR3()
	fmt.Fprintf(report, "index-digest: sha256:%s\n", hex.EncodeToString(digest[:]))
	fmt.Fprintf(report, "rtmr3: %s\n", hex.EncodeToString(rtmr3[:]))
	return nil
}

// loadMembers reads each member file. Two paths with one basename would
// silently drop one, so that is an error.
func loadMembers(paths []string) (policybundle.Bundle, error) {
	members := make(map[string][]byte, len(paths))
	for _, path := range paths {
		name := filepath.Base(path)
		if _, dup := members[name]; dup {
			return policybundle.Bundle{}, fmt.Errorf("--member %s: a member named %q was already given", path, name)
		}
		data, err := policybundle.ReadMember(path)
		if err != nil {
			return policybundle.Bundle{}, fmt.Errorf("--member: %w", err)
		}
		members[name] = data
	}
	return policybundle.FromMembers(members)
}

// findISOTool returns the first ISO authoring tool on PATH.
func findISOTool() (string, error) {
	for _, tool := range isoTools {
		if path, err := exec.LookPath(tool); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no ISO9660 tool on PATH: install one of %s", strings.Join(isoTools, ", "))
}

// writeISO stages the members in a temporary directory and runs the tool
// over it, so members given from different directories land flat under
// their bundle names. Joliet and Rock Ridge are both written: the node
// mounts iso9660 and reads the names the index was computed over.
func writeISO(ctx context.Context, tool string, bundle policybundle.Bundle, out string) error {
	stage, err := os.MkdirTemp("", "policydata-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, data := range bundle.Members {
		if err := os.WriteFile(filepath.Join(stage, name), data, 0o444); err != nil {
			return fmt.Errorf("stage %s: %w", name, err)
		}
	}
	cmd := exec.CommandContext(ctx, tool, "-V", VolumeLabel, "-J", "-R", "-o", out, stage)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w\n%s", filepath.Base(tool), err, strings.TrimSpace(output.String()))
	}
	return nil
}

// kubeVirtManifest renders the Secret KubeVirt serves as the policydata disk
// and, as comments after it, the disk and volume entries the VirtualMachine
// needs. Comments keep `kubectl apply -f` to the one document it can apply.
func kubeVirtManifest(name string, bundle policybundle.Bundle) ([]byte, error) {
	secret := corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Data:       bundle.Members,
	}
	doc, err := sigsyaml.Marshal(secret)
	if err != nil {
		return nil, fmt.Errorf("encode secret: %w", err)
	}
	var b bytes.Buffer
	b.Write(doc)
	fmt.Fprintf(&b, `---
# Add to the VirtualMachine's spec.template.spec (no opkeydata disk: a static
# node has no operator key):
#   domain.devices.disks:
#     - name: %[1]s
#       disk:
#         bus: virtio
#   volumes:
#     - name: %[1]s
#       secret:
#         secretName: %[2]s
#         volumeLabel: %[1]s
`, VolumeLabel, name)
	return b.Bytes(), nil
}
