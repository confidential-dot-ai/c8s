package nriimagepolicy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestBlockedLoaderEnv(t *testing.T) {
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT", "LD_PROFILE", "LD_TRACE_LOADED_OBJECTS", "LD_FUTURE_CONTROL", "GLIBC_TUNABLES", "GLIBC_TUNABLES_DEBUG", "GLIBC_TUNABLES_EXTRA", "GLIBC_TUNABLES2", "GCONV_PATH", "GCONV_PATH_DEBUG", "GCONV_PATH2"} {
		for _, suffix := range []string{"", "=", "=/private/value=with-equals"} {
			t.Run(name+suffix, func(t *testing.T) {
				if got := blockedLoaderEnv([]string{"PATH=/usr/bin", name + suffix}); got != name {
					t.Fatalf("got %q, want %q", got, name)
				}
			})
		}
	}
	for _, env := range [][]string{nil, {"PATH=/usr/bin", "HOME=/app", "MODEL_PATH=/models", "TOKEN=LD_PRELOAD=secret"}, {"ld_preload=x", "MY_LD_PRELOAD=x", "MY_GLIBC_TUNABLES=x", "MY_GCONV_PATH=x", "glibc_tunables=x", "gconv_path=x"}} {
		if got := blockedLoaderEnv(env); got != "" {
			t.Fatalf("ordinary environment rejected: %q", got)
		}
	}
	if got := blockedLoaderEnv([]string{"LD_PRELOAD=", "LD_PRELOAD=/injected"}); got != "LD_PRELOAD" {
		t.Fatalf("duplicate blocked variable admitted: %q", got)
	}
}

func TestCreateContainerLoaderEnvHardGate(t *testing.T) {
	for _, ready := range []bool{false, true} {
		for _, mode := range []string{ModeFailClosed, ModeAudit} {
			for _, admission := range []string{"floor", "workload", "namespace-snapshot", "allowlist-disabled"} {
				t.Run(fmt.Sprintf("ready=%t/%s/%s", ready, mode, admission), func(t *testing.T) {
					p := floorPlugin(t)
					p.cfg.Policy.Mode = mode
					if ready {
						p.SetReady()
					}
					pod := makePod("kube-system", "pod")
					digest := pushDigestA
					switch admission {
					case "workload":
						digest = pushDigestB
						p.policy.apply(workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"}), 1)
					case "namespace-snapshot":
						digest = pushDigestB
						p.cfg.Policy.ExemptNamespaces = []string{"kube-system"}
						snapshot := newExemptSnapshot(p.cfg.Policy.ExemptNamespaces)
						snapshot.add("kube-system", digest)
						p.exempt.Store(snapshot)
					case "allowlist-disabled":
						p.cfg.Allowlist = allowlistConfig{}
					}
					ctr := makeCtrWithImage(pod.Id, "ctr", "registry/repo@"+digest)
					ctr.Args = []string{"/bin/app", "--serve"}
					ctr.Env = []string{"LD_PRELOAD=/sensitive-value"}
					var logs bytes.Buffer
					p.logger = slog.New(slog.NewJSONHandler(&logs, nil))
					events := captureAudit(t, func() {
						adjustment, updates, err := p.CreateContainer(context.Background(), pod, ctr)
						if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") {
							t.Fatalf("want named denial, got %v", err)
						}
						if strings.Contains(err.Error(), "sensitive-value") {
							t.Fatal("denial exposed environment value")
						}
						if adjustment != nil || len(updates) != 0 {
							t.Fatal("denied container produced adjustments")
						}
					})
					if len(events) != 1 || events[0]["reason"] != "loader_env_blocked" || events[0]["action"] != "deny" {
						t.Fatalf("unexpected audit events: %v", events)
					}
					if _, recorded := p.inventory.containers[ctr.Id]; recorded {
						t.Fatal("denied container was recorded in inventory")
					}
					if strings.Contains(logs.String(), "sensitive-value") || strings.Contains(fmt.Sprint(events), "sensitive-value") {
						t.Fatal("policy logs exposed environment value")
					}
					// The same admission route accepts ordinary configuration.
					ctr.Env = []string{"MODEL_PATH=/models", "TOKEN=ordinary"}
					if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
						t.Fatalf("ordinary environment rejected: %v", err)
					}
				})
			}
		}
	}
}
