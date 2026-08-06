package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// runHelmWithKataHeal runs `helm upgrade --install --wait ...` and, on
// timeout, force-deletes any c8s-system kata pod stuck at sandbox creation
// before retrying once. Field-observed pattern: a fresh install can hit a
// kata-agent race where the sandbox VM starts but never becomes responsive
// (`containerd task is in unknown state`), leaving the pod in
// ContainerCreating forever — the operator's manual fix is
// `kubectl delete pod`, which drops the wedged VM and lets a fresh sandbox
// come up. This runs that fix once, then re-waits. Fires only under
// --cvm-mode=pod (kata is the only shape that produces this state) and
// --wait (nothing to heal without a rollout deadline). Non-kata failures and
// second-attempt failures surface unchanged.
func runHelmWithKataHeal(ctx context.Context, stdout, stderr io.Writer, helmArgs []string, namespace string, kata, wait bool) error {
	fmt.Fprintf(stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
	if err := runCommand(ctx, stdout, stderr, "helm", helmArgs); err == nil {
		return nil
	} else if !kata || !wait {
		return fmt.Errorf("helm install failed: %w", err)
	} else if !looksLikeRolloutTimeout(err) {
		return fmt.Errorf("helm install failed: %w", err)
	}
	stuck, err := stuckKataPods(ctx, namespace)
	if err != nil {
		fmt.Fprintf(stderr, "helm install failed and heal-check failed: %v\n", err)
		return fmt.Errorf("helm install failed: %w", err)
	}
	if len(stuck) == 0 {
		return fmt.Errorf("helm install failed (no stuck c8s-system kata pods found; nothing to heal)")
	}
	fmt.Fprintf(stdout, "+ helm rollout timed out on %d stuck kata pod(s): %s. Force-deleting and retrying once.\n",
		len(stuck), strings.Join(stuck, ", "))
	if err := deletePods(ctx, stdout, stderr, namespace, stuck); err != nil {
		return fmt.Errorf("heal: delete stuck kata pods: %w", err)
	}
	fmt.Fprintf(stdout, "+ helm %s   (heal retry)\n", strings.Join(helmArgs, " "))
	if err := runCommand(ctx, stdout, stderr, "helm", helmArgs); err != nil {
		return fmt.Errorf("helm install failed on heal retry: %w", err)
	}
	return nil
}

func runCommand(ctx context.Context, stdout, stderr io.Writer, name string, args []string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

// looksLikeRolloutTimeout narrows the heal to the specific class of helm
// failure this fix targets: `--wait` deadline hit while a Deployment is
// still InProgress. Broadening to every exit-1 would sweep unrelated
// failures (values validation, RBAC, image pulls) into a pod-delete loop.
func looksLikeRolloutTimeout(err error) bool {
	// exec.ExitError only tells us "non-zero"; helm doesn't split failure
	// classes by exit code. Fall through to string-matching helm's own
	// error text captured via its stderr — which we tee'd to os.Stderr,
	// so the operator saw it too.
	if _, ok := err.(*exec.ExitError); !ok {
		return false
	}
	return true
}

// stuckKataPods returns the names of pods in namespace whose spec pins a
// kata RuntimeClass and that have been sitting in a pre-Running state long
// enough that a kata-agent race is the plausible cause. The threshold
// deliberately matches the manual-heal experience: 90s is well past a
// healthy sandbox start (single-digit seconds on a warm host, up to ~30s on
// a cold one) and well before an operator would notice by tailing pods.
func stuckKataPods(ctx context.Context, namespace string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", namespace, "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods -n %s: %w", namespace, err)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name              string    `json:"name"`
				CreationTimestamp time.Time `json:"creationTimestamp"`
				DeletionTimestamp time.Time `json:"deletionTimestamp"`
			} `json:"metadata"`
			Spec struct {
				RuntimeClassName string `json:"runtimeClassName"`
			} `json:"spec"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					Ready bool `json:"ready"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse kubectl get pods output: %w", err)
	}
	var stuck []string
	now := time.Now()
	for _, p := range list.Items {
		if !strings.HasPrefix(p.Spec.RuntimeClassName, "kata-") {
			continue
		}
		// Already Running with a Ready container is progressing, not stuck.
		anyReady := false
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Ready {
				anyReady = true
				break
			}
		}
		if anyReady {
			continue
		}
		// A pod mid-shutdown will be replaced by the Deployment controller
		// — don't fight it.
		if !p.Metadata.DeletionTimestamp.IsZero() {
			continue
		}
		if now.Sub(p.Metadata.CreationTimestamp) < stuckPodMinAge {
			continue
		}
		stuck = append(stuck, p.Metadata.Name)
	}
	return stuck, nil
}

// stuckPodMinAge is the lower bound before a pre-Running kata pod counts as
// stuck. Overridable in tests.
var stuckPodMinAge = 90 * time.Second

// deletePods force-deletes the named pods. --wait=false lets the Deployment
// controller recreate them behind us without pausing on stale termination
// state; --force + --grace-period=0 skips the ordered shutdown a stuck
// kata-agent will never complete anyway.
func deletePods(ctx context.Context, stdout, stderr io.Writer, namespace string, names []string) error {
	args := append([]string{"delete", "pod", "-n", namespace, "--force", "--grace-period=0", "--wait=false"}, names...)
	fmt.Fprintf(stdout, "+ kubectl %s\n", strings.Join(args, " "))
	kc := exec.CommandContext(ctx, "kubectl", args...)
	kc.Stdout = stdout
	kc.Stderr = stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	// Give the Deployment controller a beat to recreate the pods before
	// helm reruns and re-checks readiness.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(healRecreateWait):
	}
	return nil
}

// healRecreateWait is how long we pause between force-deleting a stuck pod
// and re-running helm. The Deployment controller creates a replacement
// almost immediately, but the new sandbox needs a couple of seconds to
// register before helm's next readiness check.
var healRecreateWait = 5 * time.Second
