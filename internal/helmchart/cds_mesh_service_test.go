package helmchart

import (
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestChartCDSMeshService(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("mesh=%t", enabled), func(t *testing.T) {
			out, err := helmTemplate(t, "--set", fmt.Sprintf("ratlsMesh.enabled=%t", enabled), "--set", "cds.port=9443")
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			external := renderedService(t, out, "c8s-cds")
			if external.Spec.Type != corev1.ServiceTypeNodePort || len(external.Spec.Ports) != 1 || external.Spec.Ports[0].NodePort != 30808 {
				t.Fatalf("CDS external service changed: %+v", external.Spec)
			}
			var headless corev1.Service
			found := findDoc(t, out, "Service", "c8s-cds-mesh", &headless)
			if found != enabled {
				t.Fatalf("headless service present=%t, want %t", found, enabled)
			}
			name := "c8s-cds"
			if enabled {
				name = "c8s-cds-mesh"
				if headless.Spec.ClusterIP != corev1.ClusterIPNone || headless.Spec.PublishNotReadyAddresses {
					t.Fatalf("CDS mesh service must resolve ready pod IPs: %+v", headless.Spec)
				}
				if !reflect.DeepEqual(headless.Spec.Selector, external.Spec.Selector) {
					t.Fatalf("CDS service selectors differ: headless=%v external=%v", headless.Spec.Selector, external.Spec.Selector)
				}
				if len(headless.Spec.Ports) != 1 || headless.Spec.Ports[0].Port != 9443 || headless.Spec.Ports[0].TargetPort.StrVal != "https" {
					t.Fatalf("CDS mesh service port: %+v", headless.Spec.Ports)
				}
			}
			wantURL := "https://" + name + ".c8s-system.svc:9443"
			assertContainerHasArg(t, "operator", renderedOperatorArgs(t, out), "--cds-url="+wantURL)
			assertContainerHasArg(t, "router get-cert", routerGetCertContainer(t, out, "c8s-cert").Args, "--cds-url="+wantURL)
			assertContainerHasArg(t, "allowlist-proxy", renderedDeploymentContainer(t, out, "c8s-router", "allowlist-proxy").Args, "--cds-url="+wantURL)
			if enabled {
				args := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh").Args
				const wantBootstrapURL = "https://c8s-cds.c8s-system.svc:9443"
				if got, ok := containerArgValue(args, "--cds-url"); !ok || got != wantBootstrapURL {
					t.Fatalf("mesh CDS bootstrap URL=%q, want %q", got, wantBootstrapURL)
				}
			}
		})
	}
}
