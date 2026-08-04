package volume

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

type createConfig struct {
	name      string
	source    string
	out       string
	path      string
	escrowOut string
	node      string
	workDir   string
	dryRun    bool

	// run executes the build tools. Not a flag: tests set it so the whole
	// create flow is exercised without erofs-utils and cryptsetup installed.
	run Runner
}

func newCreateCmd(o *options) *cobra.Command {
	var cfg createConfig
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Build an encrypted volume and store its key",
		Long: `Package --source into an encrypted image at --out and store its key at --path
in the CDS secret store.

The image is written as ciphertext and can travel by any means, including
through the untrusted host. Attach it to the node as a raw block device whose
virtio serial is c8s-vol-<name>.

The key is generated here and exists in exactly two places: the CDS process, and
the escrow file. A CDS restart empties the store, and without the escrow file
the volume is unopenable — keep it somewhere durable and access-controlled.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(cmd, o, cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.name, "name", "", "volume name; forms the device serial c8s-vol-<name> (required, max 12 chars)")
	f.StringVar(&cfg.source, "source", "", "directory whose contents become the volume (required)")
	f.StringVar(&cfg.out, "out", "", "where to write the encrypted image; must not exist (required)")
	f.StringVar(&cfg.path, "path", "", "secret-store path for the key, e.g. /tenant-a/volumes/weights (required)")
	f.StringVar(&cfg.escrowOut, "escrow-out", "", "where to write the key blob you must keep (required)")
	f.StringVar(&cfg.node, "node", "", "node holding the device; emitted as a nodeSelector on the printed annotations")
	f.StringVar(&cfg.workDir, "work-dir", "", "directory for build intermediates (default: a temp dir); they are removed either way")
	f.BoolVar(&cfg.dryRun, "dry-run", false, "build the image and write escrow, but do not call CDS")
	return cmd
}

func runCreate(cmd *cobra.Command, o *options, cfg createConfig) error {
	path, err := validateCreate(&cfg)
	if err != nil {
		return err
	}
	if !cfg.dryRun {
		if err := o.Validate(); err != nil {
			return err
		}
	}

	key, err := GenerateKey()
	if err != nil {
		return err
	}
	verity, err := Build(cmdsutil.CmdCtx(cmd), BuildConfig{
		Source: cfg.source, Out: cfg.out, Key: key, WorkDir: cfg.workDir, Run: cfg.run,
	})
	if err != nil {
		return err
	}
	blob, err := NewBlob(key, verity)
	if err != nil {
		return err
	}

	// Escrow before CDS. The image already exists at this point, so a key that
	// reached neither the operator's disk nor the store would leave ciphertext
	// nothing can ever open.
	if err := writeEscrow(cfg.escrowOut, blob); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if cfg.dryRun {
		fmt.Fprintf(out, "built %s (%d data blocks); key escrowed to %s; CDS not called\n",
			cfg.out, verity.DataBlocks, cfg.escrowOut)
		return nil
	}

	signer, err := o.Signer()
	if err != nil {
		return err
	}
	hc, err := o.HTTPClient(cmdsutil.CmdCtx(cmd))
	if err != nil {
		return err
	}
	if err := putBlob(cmdsutil.CmdCtx(cmd), hc, cmdsutil.TrimSlash(o.URL), path, blob, signer); err != nil {
		return err
	}

	printResult(out, cfg, path, verity)
	return nil
}

func validateCreate(cfg *createConfig) (string, error) {
	switch {
	case cfg.name == "":
		return "", fmt.Errorf("--name is required")
	case cfg.source == "":
		return "", fmt.Errorf("--source is required")
	case cfg.out == "":
		return "", fmt.Errorf("--out is required")
	case cfg.escrowOut == "":
		return "", fmt.Errorf("--escrow-out is required: it is the only copy of the key outside CDS")
	}
	if err := ValidVolumeName(cfg.name); err != nil {
		return "", fmt.Errorf("--name: %w", err)
	}
	path, err := pkgallowlist.CanonicalSecretPath(cfg.path)
	if err != nil {
		return "", fmt.Errorf("--path: %w", err)
	}
	return path, nil
}

// writeEscrow saves the blob, O_EXCL and 0600. It is the whole key: an operator
// who loses it and restarts CDS has ciphertext and nothing that opens it.
func writeEscrow(dest string, blob Blob) error {
	raw, err := blob.Marshal()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("--escrow-out: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("write escrow: %w", err)
	}
	return nil
}

func printResult(w io.Writer, cfg createConfig, path string, v Verity) {
	fmt.Fprintf(w, "+ %s (%d data blocks)\n", cfg.out, v.DataBlocks)
	fmt.Fprintf(w, "+ key stored at %s\n", path)
	fmt.Fprintf(w, "+ key escrowed to %s — keep it; a CDS restart needs it\n\n", cfg.escrowOut)

	fmt.Fprintf(w, "Attach %s to the node as a raw block device with serial %s%s.\n\n", cfg.out, SerialPrefix, cfg.name)

	fmt.Fprintf(w, "Pod annotations:\n")
	fmt.Fprintf(w, "  confidential.ai/cw: <workload-id>\n")
	fmt.Fprintf(w, "  confidential.ai/c8s-volumes: %q\n", cfg.name+"="+path)
	if cfg.node != "" {
		fmt.Fprintf(w, "\nPod nodeSelector (the device is on one node):\n")
		fmt.Fprintf(w, "  kubernetes.io/hostname: %s\n", cfg.node)
	}

	fmt.Fprintf(w, "\nAllowlist grant for the workload entry (read-only, exact path):\n")
	fmt.Fprintf(w, "  \"secrets\": {\"policy\": \"allow\", \"read\": [%q]}\n", path)
	fmt.Fprintf(w, "\nA subtree grant would cover every volume beneath it, so this names one path.\n")
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
