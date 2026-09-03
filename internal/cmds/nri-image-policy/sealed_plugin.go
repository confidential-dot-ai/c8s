package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// sealedHookTimeout is the plugin's own deadline for a sealed-mode hook,
// below containerd's plugin_request_timeout (2s on the node image). nri
// v0.12.2 admits a request whose plugin call times out; answering first with
// a deny closes that window until the patched containerd ships. A var so
// tests shrink it.
var sealedHookTimeout = 1500 * time.Millisecond

// errSealedFatal is what a sealed hook returns after asking for power-off, so
// containerd also drops the request should the power-off not land.
var errSealedFatal = errors.New("sealed image policy: fatal condition, node is powering off")

// sealedVerdict is the decision PostCreateContainer cached for StartContainer.
type sealedVerdict struct {
	denied bool
	reason string
}

// verdictCache keeps per-container verdicts between hooks, keyed by
// container ID. RemoveContainer evicts.
type verdictCache struct {
	mu sync.Mutex
	m  map[string]sealedVerdict
}

func (c *verdictCache) put(id string, v sealedVerdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]sealedVerdict{}
	}
	c.m[id] = v
}

func (c *verdictCache) get(id string) (sealedVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[id]
	return v, ok
}

func (c *verdictCache) drop(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, id)
}

// fatal handles a sealed-mode condition the node must not survive: log,
// power off, and return the error the hook answers with.
func (p *plugin) fatal(reason string, args ...any) error {
	p.logger.Error("sealed image policy: fatal, powering the node off: "+reason, args...)
	if err := p.poweroff(); err != nil {
		p.logger.Error("power-off failed", "error", err)
	}
	return errSealedFatal
}

// sealedSynchronize refuses a node that already runs containers: containerd
// starts after the measured unit and this plugin registers before the first
// create, so anything present ran unchecked and stopping it now is too late.
func (p *plugin) sealedSynchronize(pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	if len(ctrs) > 0 {
		podByID := make(map[string]*api.PodSandbox, len(pods))
		for _, pod := range pods {
			podByID[pod.GetId()] = pod
		}
		for _, ctr := range ctrs {
			pod := podByID[ctr.GetPodSandboxId()]
			p.logger.Error("container present before the sealed plugin registered",
				"namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(),
				"image", ctr.GetAnnotations()[annotationImageName], "id", ctr.GetId())
		}
		return nil, p.fatal("containers were running at Synchronize", "containers", len(ctrs))
	}
	if p.inventory != nil {
		for _, pod := range pods {
			p.inventory.recordSandbox(pod.GetId())
		}
	}
	p.logger.Info("sealed: no containers at Synchronize", "pods", len(pods))
	return nil, nil
}

// withinDeadline runs check under sealedHookTimeout and answers a deny when
// it does not finish in time, so the runtime always hears a verdict before
// its own timeout admits the request. A check that finishes after the deny
// keeps running to its end, so callers keep side effects out of it and act
// on the returned verdict instead.
func (p *plugin) withinDeadline(ctx context.Context, hook string, check func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, sealedHookTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- check(ctx) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		p.logger.Error("sealed hook did not answer in time; denying", "hook", hook, "timeout", sealedHookTimeout)
		return fmt.Errorf("image policy %s did not complete within %s", hook, sealedHookTimeout)
	}
}

// sealedCreate is the sealed CreateContainer: everything the NRI message
// carries is matched against a complete rule, and OCI hooks are refused here
// because runc runs them at create, before StartContainer could deny.
func (p *plugin) sealedCreate(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	imageRef := ctr.GetAnnotations()[annotationImageName]
	var digest string
	err := p.withinDeadline(ctx, "CreateContainer", func(ctx context.Context) error {
		if verdict, reason := p.checkLabels(p.cfg, pod.GetNamespace(), pod.GetName(), ctr.GetName(), pod.GetLabels()); verdict == verdictDeny {
			return errors.New(reason)
		}
		obs, err := p.sealedObservation(ctx, pod, ctr, imageRef)
		if err != nil {
			return err
		}
		digest = obs.Digest
		return p.sealedAdmit(pod, ctr, imageRef, obs, "CreateContainer")
	})
	if err != nil {
		return err
	}
	// Recorded only for a delivered admission: a check that admits after
	// the deadline describes a container the runtime never created.
	p.recordDigest(ctr, digest)
	return nil
}

// PostCreateContainer evaluates the stored OCI spec, which carries what the
// NRI message lacks, and caches the verdict for StartContainer. containerd
// ignores this hook's error, so the deny lands at start; the round trip to
// containerd happens here, where a slow answer only delays.
func (p *plugin) PostCreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if p.sealed == nil {
		return nil
	}
	err := p.withinDeadline(ctx, "PostCreateContainer", func(ctx context.Context) error {
		return p.evaluateSpec(ctx, pod, ctr, "PostCreateContainer")
	})
	p.verdicts.put(ctr.GetId(), sealedVerdict{denied: err != nil, reason: errString(err)})
	return err
}

// StartContainer answers from the PostCreateContainer verdict: containerd
// deletes the created task on error before the entrypoint runs. A container
// with no cached verdict is evaluated here, and a failure to evaluate is a
// deny.
func (p *plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if p.sealed == nil {
		return nil
	}
	if v, ok := p.verdicts.get(ctr.GetId()); ok {
		if v.denied {
			return errors.New(v.reason)
		}
		return nil
	}
	p.logger.Warn("no cached verdict at StartContainer; evaluating the spec now", "container", ctr.GetName())
	err := p.withinDeadline(ctx, "StartContainer", func(ctx context.Context) error {
		return p.evaluateSpec(ctx, pod, ctr, "StartContainer")
	})
	p.verdicts.put(ctr.GetId(), sealedVerdict{denied: err != nil, reason: errString(err)})
	return err
}

// evaluateSpec re-observes the container from the message and the stored
// spec together and matches the result.
func (p *plugin) evaluateSpec(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, hook string) error {
	imageRef := ctr.GetAnnotations()[annotationImageName]
	obs, err := p.sealedObservation(ctx, pod, ctr, imageRef)
	if err != nil {
		return err
	}
	spec, err := p.containerd.Spec(ctx, ctr.GetId())
	if err != nil {
		p.logger.Error("cannot load the OCI spec; denying", "container", ctr.GetName(), "error", err)
		return fmt.Errorf("image policy cannot load the OCI spec of %s", imageRef)
	}
	obs = observeSpec(obs, spec)
	return p.sealedAdmit(pod, ctr, imageRef, obs, hook, specSecurity(spec)...)
}

// sealedObservation resolves the digest and builds the observation. A
// missing annotation or an unresolvable reference is a deny: the sealed
// document admits nothing without a digest.
func (p *plugin) sealedObservation(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, imageRef string) (allowlist.Observation, error) {
	if imageRef == "" {
		return allowlist.Observation{}, errors.New("container has no image annotation")
	}
	digest := extractDigest(imageRef)
	if digest == "" {
		resolved, err := p.containerd.Resolve(ctx, imageRef)
		if err != nil {
			return allowlist.Observation{}, fmt.Errorf("cannot resolve digest for %s: %v", imageRef, err)
		}
		digest = resolved
	}
	return p.observer.observe(pod, ctr, digest), nil
}

// sealedAdmit matches an observation and logs the whole of it on a deny,
// which is how a reviewer completes a floor rule from a dynamic node. The
// returned reason names only the image (see checkImage).
func (p *plugin) sealedAdmit(pod *api.PodSandbox, ctr *api.Container, imageRef string, obs allowlist.Observation, hook string, extra ...any) error {
	snap := p.policy.current()
	if snap == nil || snap.index == nil {
		return fmt.Errorf("no allowlist available for %s", imageRef)
	}
	event := audit.Event{
		Namespace: pod.GetNamespace(), Pod: pod.GetName(), Container: ctr.GetName(), Image: imageRef,
	}
	rule, ok := snap.index.Admit(obs)
	if !ok {
		p.logger.Warn("sealed: container not admitted",
			append([]any{
				"hook", hook, "namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(),
				"image", imageRef, "digest", obs.Digest, "argv", obs.Argv, "env", obs.Env, "mounts", obs.Mounts,
				"host_namespaces", obs.HostNamespaces, "devices", obs.Devices, "capabilities", obs.Capabilities,
				"hooks", obs.Hooks, "privileged", obs.Privileged, "unmasked_proc", obs.UnmaskedProc, "sources", obs.Sources,
			}, extra...)...)
		event.Action, event.Reason = "deny", "sealed_not_admitted"
		p.audit.Log(event)
		return fmt.Errorf("container not admitted by the sealed allowlist: %s", imageRef)
	}
	p.logger.Info("sealed: container admitted", "hook", hook, "rule", rule,
		"namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName(), "image", imageRef)
	event.Action, event.Reason, event.Rule = "allow", "sealed_verified", rule
	p.audit.Log(event)
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
