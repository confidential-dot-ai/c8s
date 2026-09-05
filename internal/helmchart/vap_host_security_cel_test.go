// Behaviorally evaluates the rendered tenant pod-security policies with cel-go.
// Kubernetes performs schema-aware VAP type checking at apply time; these tests
// evaluate the same rendered expressions over dynamic admission objects so each
// security boundary is exercised directly.
package helmchart

import (
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

const (
	testClaimsHostDir   = "/var/run/nri-image-policy"
	testClaimsMountPath = "/run/c8s/workload-claims"
	testC8sImage        = "ghcr.io/confidential-dot-ai/c8s-operator:dev"
)

func renderedHostSecurityPolicies(t *testing.T) map[string][]admissionregv1.Validation {
	t.Helper()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	policies := map[string][]admissionregv1.Validation{}
	iterateManifests(t, out, func(doc []byte) bool {
		var policy admissionregv1.ValidatingAdmissionPolicy
		if err := sigsyaml.Unmarshal(doc, &policy); err != nil {
			return false
		}
		if policy.Kind == "ValidatingAdmissionPolicy" {
			policies[policy.Name] = policy.Spec.Validations
		}
		return false
	})
	for _, name := range []string{
		"c8s-deny-host-namespaces",
		"c8s-deny-host-namespaces-ephemeral",
	} {
		if _, ok := policies[name]; !ok {
			t.Fatalf("%s policy not rendered", name)
		}
	}
	return policies
}

func restrictedTestSecurityContext(explicitRuntimeDefaults bool) map[string]any {
	sc := map[string]any{
		"allowPrivilegeEscalation": false,
		"privileged":               false,
		"runAsUser":                int64(1000),
		"capabilities": map[string]any{
			"drop": []any{"ALL"},
			"add":  []any{"NET_BIND_SERVICE"},
		},
		"appArmorProfile": map[string]any{"type": "RuntimeDefault"},
		"seLinuxOptions":  map[string]any{"type": "container_t"},
		"procMount":       "Default",
	}
	if explicitRuntimeDefaults {
		sc["runAsNonRoot"] = true
		sc["seccompProfile"] = map[string]any{"type": "RuntimeDefault"}
	}
	return sc
}

func restrictedTestContainer(name string, explicitRuntimeDefaults bool) map[string]any {
	return map[string]any{
		"name":            name,
		"image":           "registry.example/restricted:test",
		"securityContext": restrictedTestSecurityContext(explicitRuntimeDefaults),
	}
}

func validClaimsSidecar(name, mode string) map[string]any {
	sidecar := restrictedTestContainer(name, false)
	sidecar["image"] = testC8sImage
	sidecar["restartPolicy"] = "Always"
	sidecar["args"] = []any{mode}
	if mode == "get-cert" {
		sidecar["args"] = append(sidecar["args"].([]any), "--workload-claims")
	}
	sidecar["volumeMounts"] = []any{map[string]any{
		"name":      "c8s-workload-claims",
		"mountPath": testClaimsMountPath,
		"readOnly":  true,
	}}
	return sidecar
}

func validRestrictedTestPod() map[string]any {
	app := restrictedTestContainer("app", false)
	cert := validClaimsSidecar("c8s-cert", "get-cert")
	debugger := restrictedTestContainer("debugger", false)
	return map[string]any{
		"metadata": map[string]any{
			"name": "restricted",
			"annotations": map[string]any{
				"confidential.ai/cw":           "restricted",
				"confidential.ai/c8s-injected": "true",
			},
			"labels": map[string]any{"confidential.ai/cw": "restricted"},
		},
		"spec": map[string]any{
			"securityContext": map[string]any{
				"runAsNonRoot":   true,
				"runAsUser":      int64(1000),
				"seccompProfile": map[string]any{"type": "RuntimeDefault"},
				"appArmorProfile": map[string]any{
					"type": "RuntimeDefault",
				},
				"seLinuxOptions": map[string]any{"type": "container_t"},
				"sysctls": []any{map[string]any{
					"name":  "net.ipv4.ip_unprivileged_port_start",
					"value": "1024",
				}},
			},
			"volumes": []any{
				map[string]any{"name": "settings", "configMap": map[string]any{}},
				map[string]any{
					"name": "c8s-workload-claims",
					"hostPath": map[string]any{
						"path": testClaimsHostDir,
						"type": "Directory",
					},
				},
			},
			"containers":          []any{app},
			"initContainers":      []any{cert},
			"ephemeralContainers": []any{debugger},
		},
	}
}

func validRestrictedEphemeralUpdate() map[string]any {
	return map[string]any{
		"spec": map[string]any{
			"ephemeralContainers": []any{
				restrictedTestContainer("debugger", true),
			},
		},
	}
}

func hostSecuritySpec(object map[string]any) map[string]any {
	return object["spec"].(map[string]any)
}

func hostSecurityContainer(object map[string]any, field string) map[string]any {
	return hostSecuritySpec(object)[field].([]any)[0].(map[string]any)
}

func hostSecurityContainerSC(object map[string]any, field string) map[string]any {
	return hostSecurityContainer(object, field)["securityContext"].(map[string]any)
}

func hostSecurityClaimsMount(object map[string]any) map[string]any {
	return hostSecurityContainer(object, "initContainers")["volumeMounts"].([]any)[0].(map[string]any)
}

func TestHostSecurityPodPolicyAllowsRestrictedPod(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	allTrue(t, validations, validRestrictedTestPod())

	v134Fields := validRestrictedTestPod()
	v134PodSC := hostSecuritySpec(v134Fields)["securityContext"].(map[string]any)
	v134PodSC["seLinuxOptions"] = map[string]any{"type": "container_engine_t"}
	v134PodSC["sysctls"] = []any{
		map[string]any{"name": "net.ipv4.tcp_rmem", "value": "4096 131072 6291456"},
		map[string]any{"name": "net.ipv4.tcp_wmem", "value": "4096 16384 4194304"},
	}
	allTrue(t, validations, v134Fields)

	withFetchers := validRestrictedTestPod()
	withFetchers["metadata"].(map[string]any)["annotations"].(map[string]any)["confidential.ai/c8s-secrets"] = "api-key=/prod/api-key"
	withFetchers["metadata"].(map[string]any)["annotations"].(map[string]any)["confidential.ai/c8s-volumes"] = "data=/prod/data"
	hostSecuritySpec(withFetchers)["initContainers"] = append(
		hostSecuritySpec(withFetchers)["initContainers"].([]any),
		validClaimsSidecar("c8s-secret", "get-secret"),
		validClaimsSidecar("c8s-volume", "get-volume"),
	)
	allTrue(t, validations, withFetchers)

	withoutCarveOut := validRestrictedTestPod()
	spec := hostSecuritySpec(withoutCarveOut)
	delete(spec, "initContainers")
	spec["volumes"] = []any{map[string]any{
		"name":     "scratch",
		"emptyDir": map[string]any{},
	}}
	allTrue(t, validations, withoutCarveOut)

	explicitContainerDefaults := validRestrictedTestPod()
	podSC := hostSecuritySpec(explicitContainerDefaults)["securityContext"].(map[string]any)
	podSC["runAsNonRoot"] = false
	delete(podSC, "seccompProfile")
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		sc := hostSecurityContainerSC(explicitContainerDefaults, field)
		sc["runAsNonRoot"] = true
		sc["seccompProfile"] = map[string]any{"type": "Localhost"}
	}
	allTrue(t, validations, explicitContainerDefaults)
}

func TestHostSecurityPodPolicyRejectsProbeAndLifecycleHosts(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"liveness HTTP", func(c map[string]any) {
			c["livenessProbe"] = map[string]any{
				"httpGet": map[string]any{"host": "127.0.0.1", "port": int64(8080)},
			}
		}},
		{"readiness TCP", func(c map[string]any) {
			c["readinessProbe"] = map[string]any{
				"tcpSocket": map[string]any{"host": "127.0.0.1", "port": int64(8080)},
			}
		}},
		{"startup HTTP", func(c map[string]any) {
			c["startupProbe"] = map[string]any{
				"httpGet": map[string]any{"host": "localhost", "port": int64(8080)},
			}
		}},
		{"postStart HTTP", func(c map[string]any) {
			c["lifecycle"] = map[string]any{
				"postStart": map[string]any{
					"httpGet": map[string]any{"host": "localhost", "port": int64(8080)},
				},
			}
		}},
		{"preStop TCP", func(c map[string]any) {
			c["lifecycle"] = map[string]any{
				"preStop": map[string]any{
					"tcpSocket": map[string]any{"host": "localhost", "port": int64(8080)},
				},
			}
		}},
	}
	for _, field := range []string{"containers", "initContainers"} {
		for _, tc := range tests {
			t.Run(field+" "+tc.name, func(t *testing.T) {
				object := validRestrictedTestPod()
				tc.mutate(hostSecurityContainer(object, field))
				anyFalse(t, validations, object)
			})
		}
	}
}

func TestHostSecurityPodPolicyRejectsNamespaceAndVolumeBypasses(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"host network", func(o map[string]any) { hostSecuritySpec(o)["hostNetwork"] = true }},
		{"host pid", func(o map[string]any) { hostSecuritySpec(o)["hostPID"] = true }},
		{"host ipc", func(o map[string]any) { hostSecuritySpec(o)["hostIPC"] = true }},
		{"disallowed volume source", func(o map[string]any) {
			hostSecuritySpec(o)["volumes"].([]any)[0] = map[string]any{
				"name": "network-share",
				"nfs":  map[string]any{"server": "127.0.0.1", "path": "/"},
			}
		}},
		{"claims volume wrong name", func(o map[string]any) {
			hostSecuritySpec(o)["volumes"].([]any)[1].(map[string]any)["name"] = "claims-alias"
		}},
		{"claims volume wrong host path", func(o map[string]any) {
			hostSecuritySpec(o)["volumes"].([]any)[1].(map[string]any)["hostPath"].(map[string]any)["path"] = "/"
		}},
		{"claims volume wrong host path type", func(o map[string]any) {
			hostSecuritySpec(o)["volumes"].([]any)[1].(map[string]any)["hostPath"].(map[string]any)["type"] = "DirectoryOrCreate"
		}},
		{"two claims host paths", func(o map[string]any) {
			volumes := hostSecuritySpec(o)["volumes"].([]any)
			hostSecuritySpec(o)["volumes"] = append(volumes, map[string]any{
				"name": "c8s-workload-claims",
				"hostPath": map[string]any{
					"path": testClaimsHostDir,
					"type": "Directory",
				},
			})
		}},
		{"claims volume not mounted", func(o map[string]any) {
			delete(hostSecurityContainer(o, "initContainers"), "volumeMounts")
		}},
		{"claims mount writable", func(o map[string]any) {
			hostSecurityClaimsMount(o)["readOnly"] = false
		}},
		{"claims mount wrong path", func(o map[string]any) {
			hostSecurityClaimsMount(o)["mountPath"] = "/tmp/claims"
		}},
		{"claims mount subPath", func(o map[string]any) {
			hostSecurityClaimsMount(o)["subPath"] = "inventory.sock"
		}},
		{"claims mount subPathExpr", func(o map[string]any) {
			hostSecurityClaimsMount(o)["subPathExpr"] = "$(POD_NAME)"
		}},
		{"claims mount propagation", func(o map[string]any) {
			hostSecurityClaimsMount(o)["mountPropagation"] = "HostToContainer"
		}},
		{"claims mount run-once init", func(o map[string]any) {
			delete(hostSecurityContainer(o, "initContainers"), "restartPolicy")
		}},
		{"claims mount attacker init", func(o map[string]any) {
			hostSecurityContainer(o, "initContainers")["name"] = "attacker"
		}},
		{"claims mount missing injected marker", func(o map[string]any) {
			delete(o["metadata"].(map[string]any)["annotations"].(map[string]any), "confidential.ai/c8s-injected")
		}},
		{"claims mount missing workload identity", func(o map[string]any) {
			delete(o["metadata"].(map[string]any)["annotations"].(map[string]any), "confidential.ai/cw")
		}},
		{"claims mount mismatched workload label", func(o map[string]any) {
			o["metadata"].(map[string]any)["labels"].(map[string]any)["confidential.ai/cw"] = "other"
		}},
		{"claims mount wrong sidecar image", func(o map[string]any) {
			hostSecurityContainer(o, "initContainers")["image"] = "attacker.example/claims-client:latest"
		}},
		{"claims mount wrong sidecar mode", func(o map[string]any) {
			hostSecurityContainer(o, "initContainers")["args"] = []any{"operator"}
		}},
		{"claims mount overridden entrypoint", func(o map[string]any) {
			hostSecurityContainer(o, "initContainers")["command"] = []any{"/c8s", "operator"}
		}},
		{"claims mount lifecycle execution", func(o map[string]any) {
			hostSecurityContainer(o, "initContainers")["lifecycle"] = map[string]any{
				"postStart": map[string]any{"exec": map[string]any{"command": []any{"/c8s", "operator"}}},
			}
		}},
		{"claims mount probe execution", func(o map[string]any) {
			hostSecurityContainer(o, "initContainers")["livenessProbe"] = map[string]any{
				"exec": map[string]any{"command": []any{"/c8s", "operator"}},
			}
		}},
		{"claims mount secret mode without request", func(o map[string]any) {
			container := hostSecurityContainer(o, "initContainers")
			container["name"] = "c8s-secret"
			container["args"] = []any{"get-secret"}
		}},
		{"claims mount regular container", func(o map[string]any) {
			hostSecurityContainer(o, "containers")["volumeMounts"] = []any{map[string]any{
				"name":      "c8s-workload-claims",
				"mountPath": testClaimsMountPath,
				"readOnly":  true,
			}}
		}},
		{"claims mount ephemeral container", func(o map[string]any) {
			hostSecurityContainer(o, "ephemeralContainers")["volumeMounts"] = []any{map[string]any{
				"name":      "c8s-workload-claims",
				"mountPath": testClaimsMountPath,
				"readOnly":  true,
			}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object := validRestrictedTestPod()
			tc.mutate(object)
			anyFalse(t, validations, object)
		})
	}

	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		t.Run(field+" host port", func(t *testing.T) {
			object := validRestrictedTestPod()
			hostSecurityContainer(object, field)["ports"] = []any{map[string]any{
				"containerPort": int64(1019),
				"hostPort":      int64(1019),
			}}
			anyFalse(t, validations, object)
		})
	}
}

func TestHostSecurityPodPolicyRejectsContainerSecurityBypasses(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		t.Run(field, func(t *testing.T) {
			tests := []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"host process", func(sc map[string]any) {
					sc["windowsOptions"] = map[string]any{"hostProcess": true}
				}},
				{"privileged", func(sc map[string]any) { sc["privileged"] = true }},
				{"privilege escalation", func(sc map[string]any) {
					sc["allowPrivilegeEscalation"] = true
				}},
				{"missing privilege escalation", func(sc map[string]any) {
					delete(sc, "allowPrivilegeEscalation")
				}},
				{"run as root", func(sc map[string]any) { sc["runAsUser"] = int64(0) }},
				{"runAsNonRoot override false", func(sc map[string]any) {
					sc["runAsNonRoot"] = false
				}},
				{"capabilities missing drop", func(sc map[string]any) {
					delete(sc["capabilities"].(map[string]any), "drop")
				}},
				{"capabilities do not drop all", func(sc map[string]any) {
					sc["capabilities"].(map[string]any)["drop"] = []any{"NET_RAW"}
				}},
				{"capabilities add sys admin", func(sc map[string]any) {
					sc["capabilities"].(map[string]any)["add"] = []any{"SYS_ADMIN"}
				}},
				{"unconfined seccomp override", func(sc map[string]any) {
					sc["seccompProfile"] = map[string]any{"type": "Unconfined"}
				}},
				{"unconfined apparmor", func(sc map[string]any) {
					sc["appArmorProfile"] = map[string]any{"type": "Unconfined"}
				}},
				{"unsafe selinux type", func(sc map[string]any) {
					sc["seLinuxOptions"] = map[string]any{"type": "spc_t"}
				}},
				{"custom selinux user", func(sc map[string]any) {
					sc["seLinuxOptions"] = map[string]any{"type": "container_t", "user": "system_u"}
				}},
				{"custom selinux role", func(sc map[string]any) {
					sc["seLinuxOptions"] = map[string]any{"type": "container_t", "role": "system_r"}
				}},
				{"unmasked proc", func(sc map[string]any) { sc["procMount"] = "Unmasked" }},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					object := validRestrictedTestPod()
					tc.mutate(hostSecurityContainerSC(object, field))
					anyFalse(t, validations, object)
				})
			}
		})
	}
}

func TestHostSecurityPodPolicyRejectsPodSecurityBypasses(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"pod host process", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["windowsOptions"] =
				map[string]any{"hostProcess": true}
		}},
		{"pod run as root", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["runAsUser"] = int64(0)
		}},
		{"missing inherited runAsNonRoot", func(o map[string]any) {
			delete(hostSecuritySpec(o)["securityContext"].(map[string]any), "runAsNonRoot")
		}},
		{"missing inherited seccomp", func(o map[string]any) {
			delete(hostSecuritySpec(o)["securityContext"].(map[string]any), "seccompProfile")
		}},
		{"pod unconfined apparmor", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["appArmorProfile"] =
				map[string]any{"type": "Unconfined"}
		}},
		{"legacy unconfined apparmor", func(o map[string]any) {
			o["metadata"].(map[string]any)["annotations"] = map[string]any{
				"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
			}
		}},
		{"pod unsafe selinux type", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] =
				map[string]any{"type": "spc_t"}
		}},
		{"pod custom selinux user", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] =
				map[string]any{"type": "container_t", "user": "system_u"}
		}},
		{"pod custom selinux role", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] =
				map[string]any{"type": "container_t", "role": "system_r"}
		}},
		{"unsafe sysctl", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["sysctls"] =
				[]any{map[string]any{"name": "kernel.core_pattern", "value": "|/bin/sh"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object := validRestrictedTestPod()
			tc.mutate(object)
			anyFalse(t, validations, object)
		})
	}
}

func TestHostSecurityEphemeralPolicyBehaviors(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces-ephemeral"]
	allTrue(t, validations, map[string]any{"spec": map[string]any{}})
	allTrue(t, validations, validRestrictedEphemeralUpdate())

	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"host port", func(c, _ map[string]any) {
			c["ports"] = []any{map[string]any{
				"containerPort": int64(1019),
				"hostPort":      int64(1019),
			}}
		}},
		{"claims mount", func(c, _ map[string]any) {
			c["volumeMounts"] = []any{map[string]any{
				"name":      "c8s-workload-claims",
				"mountPath": testClaimsMountPath,
				"readOnly":  true,
			}}
		}},
		{"host process", func(_, sc map[string]any) {
			sc["windowsOptions"] = map[string]any{"hostProcess": true}
		}},
		{"privileged", func(_, sc map[string]any) { sc["privileged"] = true }},
		{"privilege escalation", func(_, sc map[string]any) {
			sc["allowPrivilegeEscalation"] = true
		}},
		{"missing privilege escalation", func(_, sc map[string]any) {
			delete(sc, "allowPrivilegeEscalation")
		}},
		{"missing explicit runAsNonRoot", func(_, sc map[string]any) {
			delete(sc, "runAsNonRoot")
		}},
		{"runAsNonRoot false", func(_, sc map[string]any) {
			sc["runAsNonRoot"] = false
		}},
		{"run as root", func(_, sc map[string]any) { sc["runAsUser"] = int64(0) }},
		{"capabilities missing drop", func(_, sc map[string]any) {
			delete(sc["capabilities"].(map[string]any), "drop")
		}},
		{"capabilities do not drop all", func(_, sc map[string]any) {
			sc["capabilities"].(map[string]any)["drop"] = []any{"NET_RAW"}
		}},
		{"capabilities add sys admin", func(_, sc map[string]any) {
			sc["capabilities"].(map[string]any)["add"] = []any{"SYS_ADMIN"}
		}},
		{"missing explicit seccomp", func(_, sc map[string]any) {
			delete(sc, "seccompProfile")
		}},
		{"unconfined seccomp", func(_, sc map[string]any) {
			sc["seccompProfile"] = map[string]any{"type": "Unconfined"}
		}},
		{"unconfined apparmor", func(_, sc map[string]any) {
			sc["appArmorProfile"] = map[string]any{"type": "Unconfined"}
		}},
		{"unsafe selinux type", func(_, sc map[string]any) {
			sc["seLinuxOptions"] = map[string]any{"type": "spc_t"}
		}},
		{"custom selinux user", func(_, sc map[string]any) {
			sc["seLinuxOptions"] = map[string]any{"type": "container_t", "user": "system_u"}
		}},
		{"custom selinux role", func(_, sc map[string]any) {
			sc["seLinuxOptions"] = map[string]any{"type": "container_t", "role": "system_r"}
		}},
		{"unmasked proc", func(_, sc map[string]any) { sc["procMount"] = "Unmasked" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object := validRestrictedEphemeralUpdate()
			container := hostSecurityContainer(object, "ephemeralContainers")
			tc.mutate(container, container["securityContext"].(map[string]any))
			anyFalse(t, validations, object)
		})
	}
}
