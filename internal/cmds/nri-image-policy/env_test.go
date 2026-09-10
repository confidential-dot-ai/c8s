package nriimagepolicy

import (
	"context"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/containerd/nri/pkg/api"
	"slices"
	"strings"
	"testing"
)

// Exercise containerd's create/start lifecycle for older admission tests.
func createAndStart(p *plugin, ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	a, u, err := p.CreateContainer(ctx, pod, ctr)
	if err != nil {
		return nil, nil, err
	}
	if err = p.ValidateContainerAdjustment(ctx, &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: a}); err != nil {
		return nil, nil, err
	}
	if err = p.StartContainer(ctx, pod, ctr); err != nil {
		return nil, nil, err
	}
	return a, u, nil
}

func TestEnvAdmissionUsesFinalStartSpec(t *testing.T) {
	for _, tc := range []struct {
		name           string
		initial, final []string
		want           bool
	}{
		{"later injection", nil, []string{"MODE=production"}, true},
		{"later tampering", []string{"MODE=production"}, []string{"MODE=unsafe"}, false},
		{"duplicate", nil, []string{"MODE=unsafe", "MODE=production"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Env = allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: map[string]string{"MODE": "production"}}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "floor"}}}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			ctr := makeCtrWithImage(pod.Id, "ctr", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app", "--serve"}
			ctr.Env = tc.initial
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatal(err)
			}
			if len(p.inventory.containers) != 0 {
				t.Fatal("pre-final environment recorded")
			}
			ctr.Env = tc.final
			err := p.StartContainer(context.Background(), pod, ctr)
			if (err == nil) != tc.want {
				t.Fatalf("start=%v", err)
			}
			_, cs, _, err := p.inventory.DigestsForSandbox(pod.Id)
			if tc.want {
				if err != nil || len(cs) != 1 || !cs[0].Env.Valid() {
					t.Fatalf("missing final evidence: %v %v", cs, err)
				}
			} else if len(cs) != 0 {
				t.Fatal("denied start recorded")
			}
		})
	}
}

func TestIncompleteProcessIsNotEmptyEnv(t *testing.T) {
	if containerEnv(&api.Container{}) != nil {
		t.Fatal("missing OCI process looks like empty env")
	}
	o := containerEnv(&api.Container{Args: []string{"/app"}})
	if !o.Valid() {
		t.Fatal("observed empty OCI env lost")
	}
}

func TestEnvCreationValidatorChecksCumulativeEdits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial []string
		edits   []*api.KeyValue
		cdi     bool
		any     bool
		want    bool
	}{
		{name: "unchanged", initial: []string{"MODE=production"}, want: true},
		{name: "override", initial: []string{"MODE=unsafe"}, edits: []*api.KeyValue{{Key: "MODE", Value: "production"}}, want: true},
		{name: "tamper", initial: []string{"MODE=production"}, edits: []*api.KeyValue{{Key: "MODE", Value: "unsafe"}}},
		{name: "remove extra", initial: []string{"MODE=production", "EXTRA=x"}, edits: []*api.KeyValue{{Key: "-EXTRA"}}, want: true},
		{name: "remove required", initial: []string{"MODE=production"}, edits: []*api.KeyValue{{Key: "-MODE"}}},
		{name: "extra", initial: []string{"MODE=production"}, edits: []*api.KeyValue{{Key: "EXTRA", Value: "x"}}},
		{name: "last edit", edits: []*api.KeyValue{{Key: "MODE", Value: "unsafe"}, {Key: "MODE", Value: "production"}}, want: true},
		{name: "bad original", initial: []string{"MODE=unsafe", "MODE=production"}, edits: []*api.KeyValue{{Key: "MODE", Value: "production"}}},
		{name: "bad edit", edits: []*api.KeyValue{{Key: "MODE=production", Value: ""}}},
		{name: "deferred CDI", initial: []string{"MODE=production"}, cdi: true},
		{name: "unrestricted CDI", cdi: true, any: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			policy := allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: map[string]string{"MODE": "production"}}
			if tc.any {
				policy = allowlist.EnvPolicy{Policy: allowlist.PolicyAny}
			}
			al.Workloads["w"].Containers[0].Env = policy
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "floor"}}}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			ctr := makeCtrWithImageArgs(pod.Id, "ctr", "registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
			ctr.Env = tc.initial
			adjust := &api.ContainerAdjustment{Env: tc.edits}
			if tc.cdi {
				adjust.CDIDevices = []*api.CDIDevice{{Name: "vendor/device=gpu"}}
			}
			req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: adjust}
			err := p.ValidateContainerAdjustment(context.Background(), req)
			if (err == nil) != tc.want {
				t.Fatalf("validation=%v want admitted=%v", err, tc.want)
			}
			if len(p.inventory.containers) != 0 {
				t.Fatal("validator prematurely recorded an admission")
			}
			if !slices.Equal(ctr.Env, tc.initial) {
				t.Fatal("validator mutated request")
			}
			if err != nil && strings.Contains(err.Error(), "unsafe") {
				t.Fatal("denial disclosed env value")
			}
		})
	}
}
