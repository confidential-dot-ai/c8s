package allowlist

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// podTemplate is the slice of a Deployment/StatefulSet/DaemonSet/Pod we need.
// Decoding into this rather than the k8s API types keeps the CLI free of a
// client-go dependency for what is a pure text transformation.
type podTemplate struct {
	InitContainers []templateContainer `json:"initContainers"`
	Containers     []templateContainer `json:"containers"`
}

type templateContainer struct {
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	Command []string `json:"command"`
	Args    []string `json:"args"`
}

// podSpecOf finds the pod spec in a Pod or in any workload that carries a pod
// template, so `kubectl get deploy/x -o json` and `kubectl get pod/x -o json`
// both work without the caller reaching for jq first.
func podSpecOf(data []byte) (podTemplate, error) {
	var probe struct {
		Kind string `json:"kind"`
		Spec struct {
			podTemplate
			Template struct {
				Spec podTemplate `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return podTemplate{}, fmt.Errorf("parse object: %w", err)
	}
	if len(probe.Spec.Template.Spec.Containers) > 0 {
		return probe.Spec.Template.Spec, nil
	}
	if len(probe.Spec.Containers) > 0 {
		return probe.Spec.podTemplate, nil
	}
	kind := probe.Kind
	if kind == "" {
		kind = "object"
	}
	return podTemplate{}, fmt.Errorf("%s carries no containers: expected a Pod or a workload with a pod template", kind)
}

// argvPolicy renders one half of a container's argv policy.
//
// An empty argv is Deny, never Exact: Exact requires equality against a
// non-empty argv and the apply is rejected outright, and Any would be looser
// than what the container actually runs.
func argvPolicy(argv []string) allowlist.ArgvPolicy {
	if len(argv) == 0 {
		return allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny}
	}
	return allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: argv}
}

func deriveContainers(cs []templateContainer) ([]allowlist.Container, error) {
	out := make([]allowlist.Container, 0, len(cs))
	for _, c := range cs {
		_, raw, found := strings.Cut(c.Image, "@")
		if !found {
			return nil, fmt.Errorf("container %q is not pinned by digest: %s", c.Name, c.Image)
		}
		digest, err := types.ParseDigest(raw)
		if err != nil {
			return nil, fmt.Errorf("container %q: %w", c.Name, err)
		}
		out = append(out, allowlist.Container{
			Digest:  digest,
			Image:   c.Image,
			Command: argvPolicy(c.Command),
			Args:    argvPolicy(c.Args),
		})
	}
	return out, nil
}

func newWorkloadDeriveCmd(_ *options) *cobra.Command {
	var secrets []string
	var label string
	cmd := &cobra.Command{
		Use:   "derive <name> <file|->",
		Short: "Build a workload entry from a live Kubernetes object",
		Long: `Emit a workload entry for <name> from a Pod, Deployment, StatefulSet or
DaemonSet given as JSON in <file> (or stdin with '-'). Nothing is sent; pipe the
result to 'workload apply'.

Deriving from the live object keeps the entry from drifting away from what is
actually running, and handles two things a hand-written entry usually gets
wrong. Init containers are part of the set CDS matches, so omitting them makes
every release fail with "no workload entry matches the running containers". And
a container with a command and no args needs an args policy of "deny", because
"exact" requires a non-empty argv.

The entry pins argv, so it expires the moment a container command changes:
re-derive and re-apply whenever the workload is edited.

c8s injects its own sidecars and drops them before matching, so they are
deliberately absent from the derived entry.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileOrStdin(cmd, args[1])
			if err != nil {
				return err
			}
			spec, err := podSpecOf(data)
			if err != nil {
				return err
			}
			containers, err := deriveContainers(spec.Containers)
			if err != nil {
				return err
			}
			initContainers, err := deriveContainers(spec.InitContainers)
			if err != nil {
				return err
			}
			w := allowlist.Workload{
				Label:          label,
				InitContainers: initContainers,
				Containers:     containers,
			}
			if len(secrets) > 0 {
				w.Secrets = &allowlist.SecretsPolicy{
					Policy: allowlist.PolicyAllow,
					Read:   secrets,
				}
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]allowlist.Workload{args[0]: w})
		},
	}
	cmd.Flags().StringArrayVar(&secrets, "secret-read", nil,
		"grant read on this secret path (repeatable); omit for no secrets block")
	cmd.Flags().StringVar(&label, "label", "", "optional entry label")
	return cmd
}
