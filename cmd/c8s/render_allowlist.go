package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

var renderAllowlistCmd = &cobra.Command{
	Use:   "render-allowlist",
	Short: "Compose the complete allowlist a sealed node image bakes",
	Long: `Render the allowlist document a sealed deployment enforces: the chart's own
component images at --image-tag (resolved to digests, exactly as c8s install
seeds them) plus the floor digests and workload entries of --bootstrap-allowlist.
The output is the canonical document to bake into the node image
(node-guest-image/build C8S_STATIC_ALLOWLIST=<file>) and to pass back to
c8s install --static-allowlist --bootstrap-allowlist <file>, which pins its
digest. c8s allowlist digest <file> prints the value relying parties pin.

Needs helm and crane on PATH; touches no cluster.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateCvmMode(installCvmMode); err != nil {
			return err
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		dir, err := extractChart()
		if err != nil {
			return fmt.Errorf("extract embedded chart: %w", err)
		}
		defer os.RemoveAll(dir)
		chartPath := filepath.Join(dir, helmchart.ChartRoot)
		components, err := chartComponents(cmd.Context(), chartPath)
		if err != nil {
			return fmt.Errorf("read chart components: %w", err)
		}
		distro := ""
		if cmd.Flags().Changed("distro") {
			distro = renderValuesDistro
		}
		setArgs, err := buildValueArgs(cmd.Context(), cmd, chartPath, components, resolveImageTag(), distro, appendResolvedDigestArgs)
		if err != nil {
			return err
		}
		computed, err := writeComputedValues(setArgs)
		if err != nil {
			return err
		}
		defer os.Remove(computed)
		seed, err := renderSeedDocument(cmd.Context(), chartPath, nil, computed, renderAllowlistKubeVersion)
		if err != nil {
			return err
		}
		doc, err := pkgallowlist.ParseJSON(seed)
		if err != nil {
			return fmt.Errorf("rendered allowlist seed: %w", err)
		}
		canonical, err := doc.Canonical()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(canonical, '\n'))
		return err
	},
}

var renderAllowlistKubeVersion string

func init() {
	f := renderAllowlistCmd.Flags()
	f.StringVar(&installCvmMode, flagCvmMode, "", "CVM deployment shape the document is for (REQUIRED): node, pod, gke, or aks")
	f.StringVar(&installHardwarePlatform, flagHardwarePlatform, "", "CPU TEE (sev-snp or tdx); selects the same component set an install would")
	f.StringVar(&installImageTag, "image-tag", "", "component image tag to resolve digests at (default: the CLI build version, or 'main')")
	f.StringVar(&installBootstrapAllowlist, "bootstrap-allowlist", "", "path to a c8s.allowlist/v1 document whose floor digests and workload entries join the composed policy")
	f.BoolVar(&installVolumes, "volumes", false, "include volumed, as `c8s install --volumes` would")
	f.BoolVar(&installAttestEnabled, "attest", true, "include the tls-lb attestation sidecar, as the install default does")
	f.StringVar(&renderValuesDistro, "distro", "", "host Kubernetes distro (k8s | rke2) the install would autodetect")
	f.StringVar(&installImagePullSecret, "image-pull-secret", "", "registry-credential Secret name, when the install will use one (no effect on the document; accepted for flag parity)")
	f.StringVar(&renderAllowlistKubeVersion, "kube-version", "1.30.0", "Kubernetes version used to render the c8s chart")
	rootCmd.AddCommand(renderAllowlistCmd)
}
