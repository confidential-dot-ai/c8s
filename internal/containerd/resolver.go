// Package containerd provides tag-to-digest resolution via the containerd image store.
package containerd

import (
	"context"
	"fmt"
	"syscall"

	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/distribution/reference"
)

// Resolver resolves image tags to digests using containerd's image store.
type Resolver struct {
	client    *containerdclient.Client
	namespace string
}

// NewResolver creates a resolver connected to the containerd socket.
func NewResolver(socket, namespace string) (*Resolver, error) {
	c, err := containerdclient.New(socket)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd at %s: %w", socket, err)
	}

	return &Resolver{
		client:    c,
		namespace: namespace,
	}, nil
}

// Resolve looks up the digest for an image reference (e.g. "docker.io/grafana/grafana:12.3.1")
// by querying containerd's image store. The image must already be pulled.
func (r *Resolver) Resolve(ctx context.Context, imageRef string) (string, error) {
	nsCtx := namespaces.WithNamespace(ctx, r.namespace)

	// containerd stores images under their fully-qualified names
	// (e.g. docker.io/library/nginx:1.27); kubelet may pass short
	// forms (nginx:1.27, rancher/local-path-provisioner:v0.0.30).
	// Normalize before looking up.
	normalized := imageRef
	if named, err := reference.ParseDockerRef(imageRef); err == nil {
		normalized = named.String()
	}

	img, err := r.client.GetImage(nsCtx, normalized)
	if err != nil {
		return "", fmt.Errorf("image not found in containerd store: %s: %w", normalized, err)
	}

	return img.Target().Digest.String(), nil
}

// StopContainer kills a container by its containerd ID.
func (r *Resolver) StopContainer(ctx context.Context, containerID string) error {
	nsCtx := namespaces.WithNamespace(ctx, r.namespace)

	container, err := r.client.LoadContainer(nsCtx, containerID)
	if err != nil {
		return fmt.Errorf("load container %s: %w", containerID, err)
	}

	task, err := container.Task(nsCtx, nil)
	if err != nil {
		return fmt.Errorf("get task for %s: %w", containerID, err)
	}

	if err := task.Kill(nsCtx, syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill task for %s: %w", containerID, err)
	}

	return nil
}

// Close closes the containerd client connection.
func (r *Resolver) Close() error {
	return r.client.Close()
}
