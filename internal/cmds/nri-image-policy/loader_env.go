package nriimagepolicy

import (
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/containerd/nri/pkg/api"
)

// See docs/loader-environment-policy.md for the reserved prefixes.
func blockedLoaderEnv(env []string) string {
	prefixes := [...]string{"LD_", "GLIBC_TUNABLES", "GCONV_PATH"}
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		for _, prefix := range prefixes {
			if strings.HasPrefix(name, prefix) {
				return name
			}
		}
	}
	return ""
}

// enforceLoaderEnv is an unconditional container-creation gate. Floor images,
// namespace snapshots, initialization, and image-policy audit mode all pass
// through this gate before admission or inventory registration.
func (p *plugin) enforceLoaderEnv(pod *api.PodSandbox, ctr *api.Container) error {
	name := blockedLoaderEnv(ctr.GetEnv())
	if name == "" {
		return nil
	}
	// Values can contain credentials. Only the variable name is reported.
	p.logger.Warn("blocked loader-control environment variable",
		"namespace", pod.GetNamespace(), "pod", pod.GetName(),
		"container", ctr.GetName(), "variable", name)
	p.audit.Log(audit.Event{
		Action: "deny", Reason: "loader_env_blocked",
		Namespace: pod.GetNamespace(), Pod: pod.GetName(), Container: ctr.GetName(),
	})
	return fmt.Errorf("loader-control environment variable %q is blocked", name)
}
