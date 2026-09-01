package allowlist

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/systempolicy"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newDeriveSystemCmd() *cobra.Command {
	var basePath string
	cmd := &cobra.Command{
		Use:   "derive-system <rendered-manifest|->",
		Short: "Derive exact c8s system policy from a rendered Helm manifest",
		Long: `Read a rendered Kubernetes manifest and inspect each digest-pinned OCI image.
The command writes one canonical allowlist with an exact named workload for
each steady Deployment, DaemonSet, and StatefulSet. Use --base to preserve an
application allowlist. A generated system name must not conflict with a base
entry. This command reads the image registry. It does not contact CDS or the
Kubernetes API.

Set enableServiceLinks: false in every Pod template. The command rejects image
tags, envFrom, unsupported volumes, and inputs that cannot produce exact
runtime policy.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] == "-" && basePath == "-" {
				return fmt.Errorf("the rendered manifest and --base cannot both read stdin")
			}
			if err := crane.Require(); err != nil {
				return err
			}
			manifest, err := readFileOrStdin(cmd, args[0])
			if err != nil {
				return err
			}
			base := &pkgallowlist.Allowlist{
				Schema:    pkgallowlist.Schema,
				Digests:   map[string]string{},
				Workloads: map[string]pkgallowlist.Workload{},
			}
			if basePath != "" {
				data, err := readFileOrStdin(cmd, basePath)
				if err != nil {
					return err
				}
				base, err = pkgallowlist.ParseJSON(data)
				if err != nil {
					return fmt.Errorf("parse base allowlist %q: %w", basePath, err)
				}
			}
			derived, err := systempolicy.Derive(ctx(cmd), manifest, func(ctx context.Context, image string) (systempolicy.ImageConfig, error) {
				config, err := crane.Config(ctx, image)
				if err != nil {
					return systempolicy.ImageConfig{}, err
				}
				return systempolicy.ImageConfig{
					Entrypoint: config.Config.Entrypoint,
					Cmd:        config.Config.Cmd,
					Env:        config.Config.Env,
				}, nil
			})
			if err != nil {
				return err
			}
			if base.Digests == nil {
				base.Digests = map[string]string{}
			}
			if base.Workloads == nil {
				base.Workloads = map[string]pkgallowlist.Workload{}
			}
			for name, workload := range derived {
				if current, exists := base.Workloads[name]; exists {
					same, err := sameWorkloadPolicy(current, workload)
					if err != nil {
						return err
					}
					if !same {
						return fmt.Errorf("derived system workload %q conflicts with the base allowlist", name)
					}
				}
				base.Workloads[name] = workload
			}

			// Parse the generated document through the same strict path used by CDS.
			// This normalizes it before bytes become a release input.
			raw, err := json.Marshal(base)
			if err != nil {
				return err
			}
			normalized, err := pkgallowlist.ParseJSON(raw)
			if err != nil {
				return fmt.Errorf("validate generated system allowlist: %w", err)
			}
			canonical, err := normalized.Canonical()
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(canonical)
			return err
		},
	}
	cmd.Flags().StringVar(&basePath, "base", "", "canonical application allowlist to merge with the derived system policy")
	return cmd
}

func sameWorkloadPolicy(a, b pkgallowlist.Workload) (bool, error) {
	canonical := func(workload pkgallowlist.Workload) ([]byte, error) {
		raw, err := json.Marshal(workload)
		if err != nil {
			return nil, err
		}
		normalized, err := pkgallowlist.ParseWorkloadJSON(raw)
		if err != nil {
			return nil, err
		}
		return json.Marshal(normalized)
	}
	aBytes, err := canonical(a)
	if err != nil {
		return false, err
	}
	bBytes, err := canonical(b)
	if err != nil {
		return false, err
	}
	return string(aBytes) == string(bBytes), nil
}
