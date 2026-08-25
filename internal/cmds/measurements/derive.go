package measurements

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"github.com/spf13/cobra"
)

// manifestSchemaVersion is the confos manifest this command reads. confos
// rejects other versions rather than migrating, so pin the same one.
const manifestSchemaVersion = 3

type manifestHeader struct {
	Version int `json:"version"`
	Build   struct {
		Platform string `json:"platform"`
	} `json:"build"`
}

func newDeriveCmd() *cobra.Command {
	var tee, out string

	cmd := &cobra.Command{
		Use:   "derive <image-dir|manifest.json>...",
		Short: "Derive a measurements config from confidential-os-builder images",
		Long: "Reads the manifest.json of each built image and writes a measurements config\n" +
			"pinning them. An SNP image contributes one entry per vCPU variant; a TDX image\n" +
			"contributes its MRTD with RTMR[1] and RTMR[2].",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := derive(args, tee)
			if err != nil {
				return err
			}
			doc, err := measurements.Format(set)
			if err != nil {
				return err
			}
			// Round-trip so derive can only emit what every component loads.
			if _, err := measurements.Parse(doc); err != nil {
				return fmt.Errorf("derived config is not valid: %w", err)
			}
			if out == "" {
				_, err := cmd.OutOrStdout().Write(doc)
				return err
			}
			return os.WriteFile(out, doc, 0o644)
		},
	}
	cmd.Flags().StringVar(&tee, "tee", "", "platform to derive for (sev-snp or tdx); required when an image is built for both")
	cmd.Flags().StringVar(&out, "out", "", "write to this path instead of stdout")
	return cmd
}

func derive(inputs []string, tee string) (measurements.ReferenceValues, error) {
	if tee != "" && tee != measurements.TEESNP && tee != measurements.TEETDX {
		return measurements.ReferenceValues{}, fmt.Errorf("--tee %q, want %q or %q", tee, measurements.TEESNP, measurements.TEETDX)
	}
	var set measurements.ReferenceValues
	for _, in := range inputs {
		path, name, err := resolveManifest(in)
		if err != nil {
			return measurements.ReferenceValues{}, err
		}
		platform, err := manifestPlatform(path, tee)
		if err != nil {
			return measurements.ReferenceValues{}, err
		}
		if set.TEE == "" {
			set.TEE = platform
		}
		// One file describes one platform: a cluster mixing SNP and TDX
		// images is not supported.
		if platform != set.TEE {
			return measurements.ReferenceValues{}, fmt.Errorf("%s is %s but an earlier input is %s; derive one config per platform", path, platform, set.TEE)
		}
		entries, err := entriesFor(path, name, platform)
		if err != nil {
			return measurements.ReferenceValues{}, err
		}
		fmt.Fprintf(os.Stderr, "%s: %d %s entr%s from %s\n", name, len(entries), platform, plural(len(entries)), path)
		set.Entries = append(set.Entries, entries...)
	}
	return set, nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// resolveManifest accepts a build output directory or the manifest itself and
// names the entry after the directory the image was built into.
func resolveManifest(in string) (path, name string, err error) {
	info, err := os.Stat(in)
	if err != nil {
		return "", "", fmt.Errorf("read image: %w", err)
	}
	path = in
	if info.IsDir() {
		path = filepath.Join(in, "manifest.json")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	return path, filepath.Base(filepath.Dir(abs)), nil
}

func manifestPlatform(path, tee string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read image manifest: %w", err)
	}
	var h manifestHeader
	if err := json.Unmarshal(data, &h); err != nil {
		return "", fmt.Errorf("image manifest %s is not a JSON object: %w", path, err)
	}
	if h.Version != manifestSchemaVersion {
		return "", fmt.Errorf("image manifest %s is schema version %d, want %d — rebuild with the current confos", path, h.Version, manifestSchemaVersion)
	}
	switch h.Build.Platform {
	case "snp":
		return measurements.TEESNP, nil
	case "tdx":
		return measurements.TEETDX, nil
	case "multi":
		if tee == "" {
			return "", fmt.Errorf("image manifest %s is built for both platforms; pass --tee %s or --tee %s", path, measurements.TEESNP, measurements.TEETDX)
		}
		return tee, nil
	default:
		return "", fmt.Errorf("image manifest %s has platform %q, want snp, tdx or multi", path, h.Build.Platform)
	}
}

func entriesFor(path, name, platform string) ([]measurements.Entry, error) {
	if platform == measurements.TEESNP {
		pins, err := runtimemeasure.LoadSNPImageManifest(path)
		if err != nil {
			return nil, err
		}
		smps := make([]int, 0, len(pins.BySMP))
		for smp := range pins.BySMP {
			smps = append(smps, smp)
		}
		sort.Ints(smps)
		out := make([]measurements.Entry, 0, len(smps))
		for _, smp := range smps {
			d := pins.BySMP[smp]
			out = append(out, measurements.Entry{
				Name:   fmt.Sprintf("%s-smp%d", name, smp),
				Digest: append([]byte(nil), d[:]...),
			})
		}
		return out, nil
	}

	pins, err := runtimemeasure.LoadImageManifest(path)
	if err != nil {
		return nil, err
	}
	// RTMR[0] varies with the VM shape and RTMR[3] is extended at runtime, so
	// an image pins only RTMR[1] and RTMR[2].
	return []measurements.Entry{{
		Name:   name,
		Digest: append([]byte(nil), pins.MRTD[:]...),
		RTMRs: map[int][]byte{
			1: append([]byte(nil), pins.RTMR1[:]...),
			2: append([]byte(nil), pins.RTMR2[:]...),
		},
	}}, nil
}
