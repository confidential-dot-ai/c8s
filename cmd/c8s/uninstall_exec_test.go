//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
)

// kataReleaseValuesFile writes the computed-values JSON `helm get values --all`
// returns for a release, shaped like the chart's kata block.
func kataReleaseValuesFile(t *testing.T, kataEnabled bool, guestPath, gpuPath string) string {
	t.Helper()
	tree := map[string]any{
		"kata": map[string]any{
			"enabled":             kataEnabled,
			"distro":              "k8s",
			"containerdConfigDir": "",
			"nodeSelector":        map[string]any{},
			"containerdPrep": map[string]any{
				"image": map[string]any{"repository": "busybox", "tag": "", "digest": testDigest},
			},
			"guestImage": map[string]any{"hostPath": guestPath},
			"gpu":        map[string]any{"guestImage": map[string]any{"hostPath": gpuPath}},
		},
	}
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release-values.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type uninstallStubs struct {
	f       *fakeBin
	applied string
}

// newUninstallStubs wires stub helm/kubectl for `c8s uninstall` runs.
// valuesFile == "" makes `helm get values` answer release-not-found. Every
// kubectl query not overridden by extra answers empty (no pods, no labelled
// nodes), which is the healthy post-drain cluster.
func newUninstallStubs(t *testing.T, valuesFile, kubectlExtra string, helmUninstallFails bool) *uninstallStubs {
	t.Helper()
	f := newFakeBin(t)
	s := &uninstallStubs{f: f, applied: filepath.Join(f.dir, "applied.json")}
	getBody := `echo 'Error: release: not found' >&2; exit 1`
	if valuesFile != "" {
		getBody = `/bin/cat '` + valuesFile + `'`
	}
	fail := ""
	if helmUninstallFails {
		fail = "exit 1"
	}
	f.tool(t, "helm", `case "$1" in
get) `+getBody+` ;;
show) /bin/cat "$3/values.yaml" ;;
uninstall) `+fail+` ;;
esac`)
	f.tool(t, "kubectl", `case "$*" in
`+kubectlExtra+`"apply -f -") /bin/cat >> '`+s.applied+`' ;;
esac`)
	return s
}

// appliedDocs splits the captured `kubectl apply -f -` stream into its JSON
// documents.
func appliedDocs(t *testing.T, path string) []json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read applied manifests: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var docs []json.RawMessage
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode applied manifests: %v\n%s", err, data)
		}
		docs = append(docs, raw)
	}
	return docs
}

func appliedDaemonSet(t *testing.T, path string) *appsv1.DaemonSet {
	t.Helper()
	for _, raw := range appliedDocs(t, path) {
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatalf("peek kind: %v", err)
		}
		if meta.Kind == "DaemonSet" {
			var ds appsv1.DaemonSet
			if err := json.Unmarshal(raw, &ds); err != nil {
				t.Fatalf("decode DaemonSet: %v", err)
			}
			return &ds
		}
	}
	t.Fatal("no DaemonSet was applied")
	return nil
}

func TestUninstallReleaseNotFound(t *testing.T) {
	s := newUninstallStubs(t, "", "", false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "--host-sweep-only") {
		t.Fatalf("want a not-found error pointing at --host-sweep-only, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
}

func TestUninstallHelmGetValuesFailure(t *testing.T) {
	f := newFakeBin(t)
	f.tool(t, "helm", `case "$1" in
get) echo boom >&2; exit 1 ;;
esac`)
	f.tool(t, "kubectl", "")
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want the helm stderr surfaced, got %v", err)
	}
}

func TestUninstallRejectsMalformedReleaseValues(t *testing.T) {
	// A kata block without distro/guestImage cannot parameterize the sweep.
	path := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(path, []byte(`{"kata":{"enabled":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newUninstallStubs(t, path, "", false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "read kata config") {
		t.Fatalf("want a kata-config error, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
}

func TestUninstallNonKataSkipsSweep(t *testing.T) {
	values := kataReleaseValuesFile(t, false, "/var/lib/c8s/kata-images", "/var/lib/c8s/kata-images-nvidia")
	s := newUninstallStubs(t, values, "", false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	calls := s.f.calls(t)
	mustContainLine(t, calls, "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	// No sweep: nothing applied, nothing rolled out, nothing deleted.
	mustNotContainPrefix(t, calls, "kubectl apply")
	mustNotContainPrefix(t, calls, "kubectl rollout")
	mustNotContainPrefix(t, calls, "kubectl delete")
}

func TestUninstallRefusesWhileKataPodsRun(t *testing.T) {
	values := kataReleaseValuesFile(t, true, "/var/lib/c8s/kata-images", "")
	running := `*runtimeClassName*) /usr/bin/printf 'default\tinference-0\tkata-qemu-snp\tinference\n' ;;
`

	t.Run("refuses and names the pods", func(t *testing.T) {
		s := newUninstallStubs(t, values, running, false)
		err := runC8s(t, "uninstall")
		if err == nil || !strings.Contains(err.Error(), "default/inference-0 (kata-qemu-snp)") {
			t.Fatalf("want the running kata pod named, got %v", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
	})

	t.Run("--force proceeds", func(t *testing.T) {
		s := newUninstallStubs(t, values, running, false)
		if err := runC8s(t, "uninstall", "--force"); err != nil {
			t.Fatalf("uninstall --force: %v", err)
		}
		mustContainLine(t, s.f.calls(t), "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	})

	t.Run("pod listing failure surfaces", func(t *testing.T) {
		s := newUninstallStubs(t, values, "*runtimeClassName*) exit 1 ;;\n", false)
		if err := runC8s(t, "uninstall"); err == nil {
			t.Fatal("want error when the kata pod listing fails")
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
	})
}

func TestUninstallKataSweepHappyPath(t *testing.T) {
	values := kataReleaseValuesFile(t, true, "/var/lib/c8s/kata-images", "/var/lib/c8s/kata-images-nvidia")
	s := newUninstallStubs(t, values, "", false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	calls := s.f.calls(t)

	// helm uninstall, kata-pod drain waits, sweep DaemonSet, rollout wait,
	// then cleanup, in that order.
	hi := lineIndex(calls, "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
	ai := lineIndex(calls, "kubectl apply -f -")
	ri := lineIndex(calls, "kubectl rollout status daemonset/c8s-kata-sweep -n c8s-system --timeout=5m")
	di := lineIndex(calls, "kubectl delete daemonset c8s-kata-sweep -n c8s-system --ignore-not-found")
	if hi < 0 || ai < hi || ri < ai || di < ri {
		t.Fatalf("sweep order wrong (helm=%d apply=%d rollout=%d delete=%d):\n%s", hi, ai, ri, di, strings.Join(calls, "\n"))
	}
	for _, component := range []string{"kata-deploy", "kata-image-puller", "kata-image-puller-nvidia"} {
		mustContainLine(t, calls, "kubectl get pods -n c8s-system -l app.kubernetes.io/instance=c8s,app.kubernetes.io/component="+component+" -o name")
	}
	// No node carried a leftover label, so nothing is unlabelled.
	mustNotContainPrefix(t, calls, "kubectl label")

	// The sweep DaemonSet the cluster received, decoded and pinned.
	ds := appliedDaemonSet(t, s.applied)
	if ds.Name != "c8s-kata-sweep" || ds.Namespace != "c8s-system" {
		t.Errorf("DaemonSet = %s/%s, want c8s-system/c8s-kata-sweep", ds.Namespace, ds.Name)
	}
	sweep := ds.Spec.Template.Spec.InitContainers[0]
	if sweep.Image != "busybox@"+testDigest {
		t.Errorf("sweep image = %q, want the digest-pinned containerd-prep image", sweep.Image)
	}
	env := map[string]string{}
	for _, e := range sweep.Env {
		env[e.Name] = e.Value
	}
	if env["GUEST_IMAGE_DIR"] != "/var/lib/c8s/kata-images" || env["GUEST_IMAGE_DIR_NVIDIA"] != "/var/lib/c8s/kata-images-nvidia" {
		t.Errorf("sweep env = %v, want the release guest-image paths", env)
	}
}

func TestUninstallSweepRemovesLeftoverNodeLabels(t *testing.T) {
	values := kataReleaseValuesFile(t, true, "/var/lib/c8s/kata-images", "")
	s := newUninstallStubs(t, values,
		`"get nodes -l katacontainers.io/kata-runtime -o name") echo node/node-a ;;
`, false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	mustContainLine(t, s.f.calls(t),
		"kubectl label nodes -l katacontainers.io/kata-runtime katacontainers.io/kata-runtime-")
	// The other label keys stayed empty and must not be touched.
	mustNotContainPrefix(t, s.f.calls(t), "kubectl label nodes -l confidential.ai/sev-snp")
}

func TestUninstallSweepRefusesUnsafeGuestImagePaths(t *testing.T) {
	t.Run("guest image path outside the c8s prefix", func(t *testing.T) {
		values := kataReleaseValuesFile(t, true, "/opt/kata", "")
		s := newUninstallStubs(t, values, "", false)
		err := runC8s(t, "uninstall")
		if err == nil || !strings.Contains(err.Error(), "/var/lib/c8s/") {
			t.Fatalf("want the sweep-prefix refusal, got %v", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "kubectl apply")
	})
	t.Run("gpu guest image path outside the c8s prefix", func(t *testing.T) {
		values := kataReleaseValuesFile(t, true, "/var/lib/c8s/kata-images", "/etc")
		s := newUninstallStubs(t, values, "", false)
		err := runC8s(t, "uninstall")
		if err == nil || !strings.Contains(err.Error(), "kata.gpu.guestImage.hostPath") {
			t.Fatalf("want the GPU path refusal, got %v", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "kubectl apply")
	})
}

func TestUninstallSweepRolloutFailureKeepsDaemonSet(t *testing.T) {
	values := kataReleaseValuesFile(t, true, "/var/lib/c8s/kata-images", "")
	s := newUninstallStubs(t, values,
		`"rollout status daemonset/c8s-kata-sweep -n c8s-system --timeout=5m") exit 1 ;;
`, false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "did not complete") {
		t.Fatalf("want the sweep-incomplete error, got %v", err)
	}
	// The DaemonSet holds the only per-node failure logs; it must survive.
	mustNotContainPrefix(t, s.f.calls(t), "kubectl delete daemonset")
}

func TestUninstallSweepNamespaceApplyFailure(t *testing.T) {
	values := kataReleaseValuesFile(t, true, "/var/lib/c8s/kata-images", "")
	s := newUninstallStubs(t, values, `"apply -f -") exit 1 ;;
`, false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "kubectl apply namespace") {
		t.Fatalf("want the namespace apply failure, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "kubectl rollout")
}

func TestUninstallSweepWaitFailure(t *testing.T) {
	values := kataReleaseValuesFile(t, true, "/var/lib/c8s/kata-images", "")
	s := newUninstallStubs(t, values, `"get pods -n c8s-system -l "*) exit 1 ;;
`, false)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "waiting for kata-deploy pods") {
		t.Fatalf("want the drain-wait failure, got %v", err)
	}
	mustNotContainPrefix(t, s.f.calls(t), "kubectl apply")
}

func TestUninstallHelmUninstallFailure(t *testing.T) {
	values := kataReleaseValuesFile(t, false, "/var/lib/c8s/kata-images", "")
	s := newUninstallStubs(t, values, "", true)
	err := runC8s(t, "uninstall")
	if err == nil || !strings.Contains(err.Error(), "helm uninstall failed") {
		t.Fatalf("want the helm failure surfaced, got %v", err)
	}
	mustContainLine(t, s.f.calls(t), "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
}

func TestUninstallDeleteCRDsAndNamespace(t *testing.T) {
	values := kataReleaseValuesFile(t, false, "/var/lib/c8s/kata-images", "")

	t.Run("deletes on request", func(t *testing.T) {
		s := newUninstallStubs(t, values, "", false)
		if err := runC8s(t, "uninstall", "--delete-crds", "--delete-namespace"); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		calls := s.f.calls(t)
		mustContainLine(t, calls, "kubectl delete crd "+confidentialWorkloadCRD+" --ignore-not-found")
		mustContainLine(t, calls, "kubectl delete namespace c8s-system --ignore-not-found")
	})

	t.Run("delete failure surfaces", func(t *testing.T) {
		newUninstallStubs(t, values, `"delete crd "*) exit 1 ;;
`, false)
		err := runC8s(t, "uninstall", "--delete-crds")
		if err == nil || !strings.Contains(err.Error(), "kubectl delete crd") {
			t.Fatalf("want the delete failure surfaced, got %v", err)
		}
	})
}

func TestUninstallHostSweepOnlyUsesChartDefaults(t *testing.T) {
	// Release already gone: config comes from the embedded chart defaults and
	// the detected distro, and the helm uninstall step is skipped entirely.
	s := newUninstallStubs(t, "", "", false)
	if err := runC8s(t, "uninstall", "--host-sweep-only"); err != nil {
		t.Fatalf("uninstall --host-sweep-only: %v", err)
	}
	calls := s.f.calls(t)
	mustNotContainPrefix(t, calls, "helm uninstall")
	mustContainLine(t, calls, "kubectl rollout status daemonset/c8s-kata-sweep -n c8s-system --timeout=5m")
	ds := appliedDaemonSet(t, s.applied)
	env := map[string]string{}
	for _, e := range ds.Spec.Template.Spec.InitContainers[0].Env {
		env[e.Name] = e.Value
	}
	// Chart defaults: both guest-image dirs under the c8s prefix.
	if env["GUEST_IMAGE_DIR"] != "/var/lib/c8s/kata-images" || env["GUEST_IMAGE_DIR_NVIDIA"] != "/var/lib/c8s/kata-images-nvidia" {
		t.Errorf("sweep env = %v, want the chart-default guest-image paths", env)
	}
}

func TestUninstallHostSweepOnlyRejectsSweepDisabled(t *testing.T) {
	newUninstallStubs(t, "", "", false)
	if err := runC8s(t, "uninstall", "--host-sweep-only", "--kata-sweep=false"); err == nil {
		t.Fatal("want the contradictory-flags error")
	}
}

func TestReleaseValuesExec(t *testing.T) {
	t.Run("found release decodes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "v.json")
		if err := os.WriteFile(path, []byte(`{"kata":{"enabled":true}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		f := newFakeBin(t)
		f.tool(t, "helm", "/bin/cat '"+path+"'")
		tree, found, err := releaseValues(context.Background(), "c8s", "ns")
		if err != nil || !found {
			t.Fatalf("releaseValues = (found=%t, %v), want found", found, err)
		}
		kata, ok := tree["kata"].(map[string]any)
		if !ok || kata["enabled"] != true {
			t.Fatalf("tree = %#v, want kata.enabled true", tree)
		}
		mustContainLine(t, f.calls(t), "helm get values c8s --namespace ns --all --output json")
	})

	t.Run("missing release is found=false", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", `echo 'Error: release: not found' >&2; exit 1`)
		tree, found, err := releaseValues(context.Background(), "c8s", "ns")
		if err != nil || found || tree != nil {
			t.Fatalf("releaseValues = (%v, %t, %v), want (nil, false, nil)", tree, found, err)
		}
	})

	t.Run("other helm failure surfaces stderr", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", `echo 'permission denied' >&2; exit 1`)
		_, _, err := releaseValues(context.Background(), "c8s", "ns")
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("want the helm stderr surfaced, got %v", err)
		}
	})

	t.Run("unparseable values surface", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "helm", "echo not-json")
		if _, _, err := releaseValues(context.Background(), "c8s", "ns"); err == nil {
			t.Fatal("want error for unparseable values")
		}
	})
}

func TestWaitPodsGone(t *testing.T) {
	t.Run("returns once no pod matches", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := waitPodsGone(ctx, "ns", "a=b"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContainLine(t, f.calls(t), "kubectl get pods -n ns -l a=b -o name")
	})

	t.Run("polls at the 5s interval until pods are gone", func(t *testing.T) {
		f := newFakeBin(t)
		state := filepath.Join(f.dir, "first-poll-done")
		f.tool(t, "kubectl", `if [ ! -f '`+state+`' ]; then : > '`+state+`'; echo pod/kata-deploy-x; fi`)
		start := time.Now()
		if err := waitPodsGone(context.Background(), "ns", "a=b"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := len(f.calls(t)); n < 2 {
			t.Errorf("polled %d times, want at least 2", n)
		}
		if elapsed := time.Since(start); elapsed < 4*time.Second {
			t.Errorf("second poll after %v, want the 5s interval respected", elapsed)
		}
	})

	t.Run("kubectl failure surfaces", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", "exit 1")
		if err := waitPodsGone(context.Background(), "ns", "a=b"); err == nil {
			t.Fatal("want error when kubectl fails")
		}
	})
}

// volumedReleaseValuesFile writes the computed-values JSON `helm get values
// --all` returns for a release with the volume node agent deployed.
func volumedReleaseValuesFile(t *testing.T) string {
	t.Helper()
	path := kataReleaseValuesFile(t, false, "/var/lib/c8s/kata-images", "")
	tree := map[string]any{}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	tree["volumed"] = map[string]any{"enabled": true}
	if data, err = json.Marshal(tree); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Deleting volumed under a pod that holds a volume strands the dm stack on the
// node — nothing else reaps it, and it keeps the disk open against the next
// install. Refuse, name the pods, and say what to do.
func TestUninstallRefusesWhileVolumePodsRun(t *testing.T) {
	values := volumedReleaseValuesFile(t)
	holding := `*c8s-volumes*) /usr/bin/printf 'default\tinference-0\tRunning\tweights=/tenant-a/volumes/weights\n' ;;
`

	t.Run("refuses and names the pods", func(t *testing.T) {
		s := newUninstallStubs(t, values, holding, false)
		err := runC8s(t, "uninstall")
		if err == nil || !strings.Contains(err.Error(), "default/inference-0") {
			t.Fatalf("want the volume-holding pod named, got %v", err)
		}
		if !strings.Contains(err.Error(), "scale those workloads to zero") {
			t.Errorf("refusal %q does not say what to do instead", err)
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
	})

	t.Run("--force proceeds, having still asked which pods hold volumes", func(t *testing.T) {
		s := newUninstallStubs(t, values, holding, false)
		if err := runC8s(t, "uninstall", "--force"); err != nil {
			t.Fatalf("uninstall --force: %v", err)
		}
		mustContainLine(t, s.f.calls(t), "helm uninstall c8s --namespace c8s-system --wait --timeout=5m")
		// The pre-delete hook cannot close what these pods hold, so --force has
		// to name them here; a failed hook's logs go with the release.
		var listed bool
		for _, c := range s.f.calls(t) {
			if strings.HasPrefix(c, "kubectl get pods --all-namespaces") {
				listed = true
			}
		}
		if !listed {
			t.Errorf("--force skipped the volume-pod listing, so the mappings it strands are never named; calls: %v", s.f.calls(t))
		}
	})

	t.Run("pod listing failure surfaces", func(t *testing.T) {
		s := newUninstallStubs(t, values, "*c8s-volumes*) exit 1 ;;\n", false)
		if err := runC8s(t, "uninstall"); err == nil {
			t.Fatal("want error when the volume pod listing fails")
		}
		mustNotContainPrefix(t, s.f.calls(t), "helm uninstall")
	})
}

// A release that never deployed volumed has no mappings to strand, so the
// guard must not query for them at all.
func TestUninstallWithoutVolumedSkipsTheVolumeGuard(t *testing.T) {
	values := kataReleaseValuesFile(t, false, "/var/lib/c8s/kata-images", "")
	s := newUninstallStubs(t, values, "", false)
	if err := runC8s(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	for _, l := range s.f.calls(t) {
		if strings.Contains(l, "c8s-volumes") {
			t.Errorf("volume guard queried for a release without volumed: %q", l)
		}
	}
}
