package nriimagepolicy

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestMountAdmissionUsesFinalStartSpec(t *testing.T) {
	const platformSource = kubeletRoot + "/pods/pod-uid/etc-hosts"
	for _, tc := range []struct {
		name, initialSource, finalSource string
		policy                           allowlist.MountPolicy
		want                             bool
	}{
		{"platform baseline", platformSource, platformSource, allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, true},
		{"later host injection", platformSource, "/host/hosts", allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, false},
		{"later foreign pod injection", platformSource, kubeletRoot + "/pods/another-pod/etc-hosts", allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, false},
		{"later correction", "/host/hosts", platformSource, allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, true},
		{"explicit unrestricted mounts", platformSource, "/host/hosts", allowlist.MountPolicy{Policy: allowlist.PolicyAny}, true},
		{"exact rule missing", platformSource, platformSource, allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/cache", Kind: allowlist.MountEmptyDir}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = tc.policy
			p, _ := newCachedPlugin(&config{
				Policy:    policyConfig{Mode: ModeFailClosed},
				Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}},
			}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			pod.Uid = "pod-uid"
			ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app", "--serve"}
			ctr.Mounts = []*api.Mount{{Source: tc.initialSource, Destination: "/etc/hosts", Type: "bind"}}
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("preliminary admission considered unfinished mount table: %v", err)
			}
			if len(p.inventory.containers) != 0 {
				t.Fatal("preliminary mount evidence recorded")
			}
			ctr.Mounts = []*api.Mount{{Source: tc.finalSource, Destination: "/etc/hosts", Type: "bind"}}
			err := p.StartContainer(context.Background(), pod, ctr)
			if (err == nil) != tc.want {
				t.Fatalf("final admission error=%v, want allowed=%v", err, tc.want)
			}
			_, containers, _, inventoryErr := p.inventory.DigestsForSandbox(pod.Id)
			if !tc.want {
				if len(containers) != 0 {
					t.Fatal("denied final mount table recorded as admitted")
				}
				return
			}
			if inventoryErr != nil || len(containers) != 1 || len(containers[0].Mounts) != 1 {
				t.Fatalf("missing final mount evidence: containers=%+v error=%v", containers, inventoryErr)
			}
			wantClass := allowlist.MountHost
			if tc.finalSource == platformSource {
				wantClass = allowlist.MountPlatform
			}
			if got := containers[0].Mounts[0]; got.Destination != "/etc/hosts" || got.Class != wantClass || got.Storage != allowlist.MountUnknown {
				t.Fatalf("final mount evidence=%+v, want /etc/hosts %s/unknown", got, wantClass)
			}
		})
	}
}
