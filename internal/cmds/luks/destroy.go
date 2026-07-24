package luks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newDestroyCmd() *cobra.Command {
	var (
		bf              baoFlags
		workload, name  string
		driver          string
		force           bool
		localBackingDir string
		namespace       string
	)
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Delete a LUKS volume's openbao entry and backing device",
		Long: "destroy removes the KV entry and the backing device: the loop " +
			"device + backing file for --driver local, the PersistentVolumeClaim " +
			"for --driver pvc. Refuses without --force while the volume looks " +
			"in use (local: the loop device is held by an open LUKS mapping; " +
			"pvc: a pod mounts the claim) — the KV entry is left intact on " +
			"refusal. Deleting the KV passphrase is the crypto-shred: without " +
			"it the LUKS data is unrecoverable. Removing the backing device " +
			"is cleanup, not a wipe.",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := bf.client()
			if err != nil {
				return err
			}
			return runDestroy(cmd.Context(), c, destroyCfg{
				workload: workload, name: name, driver: driver,
				force: force, localBackingDir: localBackingDir,
				namespace: namespace,
			})
		},
	}
	bf.bind(cmd)
	cmd.Flags().StringVar(&workload, "workload", "", "confidential.ai/cw workload id (required)")
	cmd.Flags().StringVar(&name, "name", "", "volume name (required)")
	cmd.Flags().StringVar(&driver, "driver", "local", "backing driver that provisioned it (local | pvc | csi)")
	cmd.Flags().BoolVar(&force, "force", false, "proceed even if the volume looks in use (held loop device / mounted claim)")
	cmd.Flags().StringVar(&localBackingDir, "local-dir", "/var/lib/c8s/luks",
		"host directory where the local driver stores backing .img files")
	cmd.Flags().StringVar(&namespace, "namespace", "default",
		"claim namespace for --driver pvc")
	return cmd
}

type destroyCfg struct {
	workload, name  string
	driver          string
	force           bool
	localBackingDir string
	namespace       string
}

func runDestroy(ctx context.Context, c *bao, cfg destroyCfg) error {
	// Validate before anything else — workload/name/namespace feed KV paths
	// and kubectl argv below.
	if err := validateWorkloadName(cfg.workload, cfg.name); err != nil {
		return err
	}
	if err := validateNamespace(cfg.namespace); err != nil {
		return err
	}
	// Order: driver in-use pre-check FIRST (a refused destroy must leave the
	// KV entry intact — deleting the passphrase under a live volume orphans
	// its data at the next open), then the KV delete, then device teardown
	// (so a KV failure doesn't leave an orphaned block device).
	loop, img := "", ""
	switch cfg.driver {
	case "local":
		var err error
		if img, err = localImgPath(cfg.localBackingDir, cfg.workload, cfg.name); err != nil {
			return err
		}
		if loop, err = losetupLookup(img); err != nil {
			return err
		}
		if loop != "" && !cfg.force {
			held, err := loopHeld(loop)
			if err != nil {
				return err
			}
			if held {
				return fmt.Errorf("loop device %s for %s is held by an open mapping — luksClose it, or pass --force to destroy anyway", loop, img)
			}
		}
	case "pvc":
		users, err := pvcConsumers(ctx, claimName(cfg.workload, cfg.name), cfg.namespace)
		if err != nil {
			return err
		}
		if len(users) > 0 && !cfg.force {
			return fmt.Errorf("PVC %s/%s is mounted by pod(s) %s — pass --force to delete anyway (the claim stays Terminating until they exit)",
				cfg.namespace, claimName(cfg.workload, cfg.name), strings.Join(users, ", "))
		}
	case "csi":
		return errors.New("--driver csi: not yet implemented")
	default:
		return fmt.Errorf("--driver %q: want local | pvc | csi", cfg.driver)
	}

	if err := c.deleteVolume(ctx, cfg.workload, cfg.name); err != nil {
		if isNotFound(err) {
			// Openbao entry gone — still try to clean up the device.
			fmt.Fprintf(os.Stderr, "openbao entry already absent for %s/luks-%s; continuing\n", cfg.workload, cfg.name)
		} else {
			return fmt.Errorf("openbao KV delete: %w", err)
		}
	}

	if cfg.driver == "pvc" {
		return destroyPVC(ctx, cfg)
	}
	return destroyLocal(loop, img)
}

// localImgPath builds the backing-file path, refusing a --local-dir that is
// not absolute+clean or a result outside it (cf. cmd/c8s/uninstall.go
// validateSweepPath).
func localImgPath(dir, workload, name string) (string, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", fmt.Errorf("--local-dir %q must be an absolute, clean path", dir)
	}
	p := filepath.Join(dir, workload+"-"+name+".img")
	if filepath.Dir(p) != dir {
		return "", fmt.Errorf("backing file path %q escapes --local-dir %q", p, dir)
	}
	return p, nil
}

func destroyLocal(loop, imgPath string) error {
	if loop != "" {
		if err := losetupDetach(loop); err != nil {
			return err
		}
	}
	if err := os.Remove(imgPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove backing file %s: %w", imgPath, err)
	}
	return nil
}

// loopHeld reports whether dev has kernel holders (an open dm-crypt mapping).
// Mere attachment is create's normal end state, not in-use.
func loopHeld(dev string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join("/sys/block", filepath.Base(dev), "holders"))
	if err != nil {
		return false, fmt.Errorf("check holders of %s: %w", dev, err)
	}
	return len(entries) > 0, nil
}

// losetupLookup returns the loop device backing imgPath, or "" if none.
func losetupLookup(imgPath string) (string, error) {
	out, err := runOutput("losetup", "-j", imgPath)
	if err != nil {
		return "", err
	}
	// Output is empty when no attachment; when attached, first field is the
	// loop device path followed by ":".
	line := trimNewline(out)
	if line == "" {
		return "", nil
	}
	dev, _, ok := cutColon(line)
	if !ok {
		return "", fmt.Errorf("unexpected losetup -j output: %q", line)
	}
	return dev, nil
}
