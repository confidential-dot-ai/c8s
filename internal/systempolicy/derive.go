// Package systempolicy derives exact c8s system-workload policy from the same
// rendered Pod templates that Kubernetes receives.
package systempolicy

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ImageConfig is the OCI process configuration that the image contributes.
type ImageConfig struct {
	Entrypoint []string
	Cmd        []string
	Env        []string
}

// ImageConfigSource returns the config for one digest-pinned image.
type ImageConfigSource func(context.Context, string) (ImageConfig, error)

type renderedWorkload struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
	Spec       struct {
		Template corev1.PodTemplateSpec `json:"template"`
	} `json:"spec"`
}

// Derive returns one exact named entry for each steady chart workload.
// Jobs are not steady state and are not included.
func Derive(ctx context.Context, manifest []byte, imageConfig ImageConfigSource) (map[string]allowlist.Workload, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(manifest)), 64<<10)
	var objects []renderedWorkload
	for {
		var object renderedWorkload
		if err := decoder.Decode(&object); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode rendered chart: %w", err)
		}
		switch object.Kind {
		case "Deployment", "DaemonSet", "StatefulSet":
			if object.Metadata.Annotations["helm.sh/hook"] != "" {
				continue
			}
			objects = append(objects, object)
		}
	}
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].Metadata.Namespace != objects[j].Metadata.Namespace {
			return objects[i].Metadata.Namespace < objects[j].Metadata.Namespace
		}
		return objects[i].Metadata.Name < objects[j].Metadata.Name
	})

	out := make(map[string]allowlist.Workload, len(objects))
	cache := map[string]ImageConfig{}
	for _, object := range objects {
		name := object.Metadata.Name
		if !allowlist.ValidWorkloadName(name) {
			return nil, fmt.Errorf("system workload name %q is not an allowlist name", name)
		}
		pod := object.Spec.Template.Spec
		if pod.EnableServiceLinks == nil || *pod.EnableServiceLinks {
			return nil, fmt.Errorf("system workload %s must set enableServiceLinks: false for exact environment policy", name)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("rendered chart has more than one steady workload named %q", name)
		}
		serviceAccountMount := pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken
		volumes, err := volumeKinds(pod.Volumes)
		if err != nil {
			return nil, fmt.Errorf("system workload %s: %w", name, err)
		}
		entry := allowlist.Workload{}
		for _, container := range pod.InitContainers {
			policy, err := deriveContainer(ctx, container, volumes, serviceAccountMount, cache, imageConfig)
			if err != nil {
				return nil, fmt.Errorf("system workload %s init container %s: %w", name, container.Name, err)
			}
			entry.InitContainers = append(entry.InitContainers, policy)
		}
		for _, container := range pod.Containers {
			policy, err := deriveContainer(ctx, container, volumes, serviceAccountMount, cache, imageConfig)
			if err != nil {
				return nil, fmt.Errorf("system workload %s container %s: %w", name, container.Name, err)
			}
			entry.Containers = append(entry.Containers, policy)
		}
		if len(entry.Containers) == 0 {
			return nil, fmt.Errorf("system workload %s has no main containers", name)
		}
		out[name] = entry
	}
	return out, nil
}

func deriveContainer(ctx context.Context, container corev1.Container, volumes map[string]string, serviceAccountMount bool, cache map[string]ImageConfig, source ImageConfigSource) (allowlist.Container, error) {
	digestAt := strings.LastIndex(container.Image, "@sha256:")
	if digestAt < 0 {
		return allowlist.Container{}, fmt.Errorf("image %q is not digest-pinned", container.Image)
	}
	digest, err := types.ParseDigest(container.Image[digestAt+1:])
	if err != nil {
		return allowlist.Container{}, err
	}
	config, ok := cache[container.Image]
	if !ok {
		config, err = source(ctx, container.Image)
		if err != nil {
			return allowlist.Container{}, fmt.Errorf("read OCI config for %s: %w", container.Image, err)
		}
		cache[container.Image] = config
	}
	command := config.Entrypoint
	if len(container.Command) > 0 {
		command = container.Command
	}
	args := config.Cmd
	if len(container.Args) > 0 {
		args = container.Args
	}
	argv := append(slices.Clone(command), args...)
	if len(argv) == 0 {
		return allowlist.Container{}, fmt.Errorf("effective OCI argv is empty")
	}

	envNames := make([]string, 0, len(config.Env)+len(container.Env))
	for _, value := range config.Env {
		name, _, _ := strings.Cut(value, "=")
		if name == "" {
			return allowlist.Container{}, fmt.Errorf("OCI config has an invalid environment entry")
		}
		envNames = append(envNames, name)
	}
	if len(container.EnvFrom) != 0 {
		return allowlist.Container{}, fmt.Errorf("envFrom cannot produce exact environment names")
	}
	for _, env := range container.Env {
		envNames = append(envNames, env.Name)
	}
	sort.Strings(envNames)
	envNames = slices.Compact(envNames)

	destinations := []string{"/dev/shm", "/dev/termination-log", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}
	kinds := map[string]string{}
	for _, mount := range container.VolumeMounts {
		destinations = append(destinations, mount.MountPath)
		kind, ok := volumes[mount.Name]
		if !ok {
			return allowlist.Container{}, fmt.Errorf("mount %s refers to unknown volume %s", mount.MountPath, mount.Name)
		}
		kinds[mount.MountPath] = kind
	}
	// Kubelet adds this mount when the ServiceAccount token is enabled.
	if serviceAccountMount && containerNeedsImplicitServiceAccountMount(container) {
		destinations = append(destinations, "/var/run/secrets/kubernetes.io/serviceaccount")
		kinds["/var/run/secrets/kubernetes.io/serviceaccount"] = "projected"
	}
	sort.Strings(destinations)
	destinations = slices.Compact(destinations)

	return allowlist.Container{
		Digest: digest,
		Image:  container.Image,
		Command: allowlist.ArgvPolicy{
			Policy: allowlist.PolicyExact,
			Argv:   argv,
		},
		Args:   allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Destinations: destinations, Kinds: kinds},
		Env:    allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: envNames},
	}, nil
}

// The implicit ServiceAccount mount does not appear in Container.VolumeMounts
// in a rendered manifest. The caller adds it for Pods that permit it. This
// helper only avoids a duplicate when a chart rendered it explicitly.
func containerNeedsImplicitServiceAccountMount(container corev1.Container) bool {
	for _, mount := range container.VolumeMounts {
		if mount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
			return false
		}
	}
	return true
}

func volumeKinds(volumes []corev1.Volume) (map[string]string, error) {
	out := make(map[string]string, len(volumes))
	for _, volume := range volumes {
		var kind string
		switch {
		case volume.EmptyDir != nil:
			kind = "empty-dir"
		case volume.ConfigMap != nil:
			kind = "configmap"
		case volume.Secret != nil:
			kind = "secret"
		case volume.Projected != nil:
			kind = "projected"
		case volume.DownwardAPI != nil:
			kind = "downward-api"
		case volume.HostPath != nil:
			kind = "node"
		case volume.PersistentVolumeClaim != nil:
			// CRI exposes the resolved kubelet bind source, not the Kubernetes
			// volume object. The enforcer can prove that this is a pod-scoped
			// host bind, but it cannot prove the PVC name.
			kind = "host-path"
		default:
			return nil, fmt.Errorf("volume %s has an unsupported source for exact policy", volume.Name)
		}
		out[volume.Name] = kind
	}
	return out, nil
}
