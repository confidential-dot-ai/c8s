package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The heal returns the specific pod names it will delete: kata-RC pods that
// have been sitting pre-Running long enough to be stuck, and nothing else.
func TestStuckKataPods_Filters(t *testing.T) {
	old := stuckPodMinAge
	stuckPodMinAge = 30 * time.Second
	t.Cleanup(func() { stuckPodMinAge = old })

	list := podList{Items: []pod{
		{ // stuck kata pod — the case we want to heal
			Metadata: podMeta{Name: "cds-stuck", CreationTimestamp: time.Now().Add(-2 * time.Minute)},
			Spec:     podSpec{RuntimeClassName: "kata-qemu-snp"},
			Status:   podStatus{Phase: "Pending"},
		},
		{ // running fine — do not disturb
			Metadata: podMeta{Name: "cds-running", CreationTimestamp: time.Now().Add(-2 * time.Minute)},
			Spec:     podSpec{RuntimeClassName: "kata-qemu-snp"},
			Status:   podStatus{Phase: "Running", ContainerStatuses: []podContainerStatus{{Ready: true}}},
		},
		{ // non-kata — not in the failure mode we heal
			Metadata: podMeta{Name: "operator", CreationTimestamp: time.Now().Add(-2 * time.Minute)},
			Spec:     podSpec{RuntimeClassName: ""},
			Status:   podStatus{Phase: "Pending"},
		},
		{ // too young — normal sandbox creation, do not race it
			Metadata: podMeta{Name: "cds-fresh", CreationTimestamp: time.Now().Add(-5 * time.Second)},
			Spec:     podSpec{RuntimeClassName: "kata-qemu-snp"},
			Status:   podStatus{Phase: "Pending"},
		},
		{ // already being deleted — let the Deployment controller handle it
			Metadata: podMeta{Name: "cds-terminating", CreationTimestamp: time.Now().Add(-2 * time.Minute), DeletionTimestamp: time.Now().Add(-10 * time.Second)},
			Spec:     podSpec{RuntimeClassName: "kata-qemu-snp"},
			Status:   podStatus{Phase: "Pending"},
		},
	}}
	got, err := runStuckKataPodsWithFakeKubectl(t, list)
	if err != nil {
		t.Fatalf("stuckKataPods: %v", err)
	}
	want := []string{"cds-stuck"}
	if !equalStringSlice(got, want) {
		t.Fatalf("stuck = %v, want %v", got, want)
	}
}

// runStuckKataPodsWithFakeKubectl runs the production stuckKataPods against a
// fake `kubectl` on PATH that returns the given pod list — the same shape the
// real one emits with `-o json`. Keeps the exec path in the test rather than
// splitting the parser out into a private helper the production code would
// then have to route around.
func runStuckKataPodsWithFakeKubectl(t *testing.T, list podList) ([]string, error) {
	t.Helper()
	body, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	fixture := filepath.Join(t.TempDir(), "pods.json")
	if err := os.WriteFile(fixture, body, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	// Shim kubectl to `cat` our fixture: stuckKataPods runs `kubectl get
	// pods -n <ns> -o json`, whose only real dependency is stdout.
	shimDir := t.TempDir()
	shim := filepath.Join(shimDir, "kubectl")
	shimBody := []byte("#!/bin/sh\nexec cat " + fixture + "\n")
	if err := os.WriteFile(shim, shimBody, 0o755); err != nil {
		t.Fatalf("write kubectl shim: %v", err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return stuckKataPods(context.Background(), "c8s-system")
}

// Helm succeeded: no kubectl calls, no heal message, nil error.
func TestRunHelmWithKataHeal_HelmSucceedsFirstTry(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	shimDir := t.TempDir()
	writeShim(t, shimDir, "helm", "#!/bin/sh\necho ok\n")
	// A kubectl shim that always errors would let the test catch an
	// accidental heal-check on the happy path.
	writeShim(t, shimDir, "kubectl", "#!/bin/sh\necho should-not-run >&2\nexit 3\n")
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runHelmWithKataHeal(context.Background(), stdout, stderr, []string{"upgrade", "--install"}, "c8s-system", true, true); err != nil {
		t.Fatalf("want nil error on helm success, got %v (stderr: %s)", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("kubectl should not have run on the happy path (stderr: %s)", stderr.String())
	}
}

// Kata + wait + rollout timeout + a stuck pod present → delete + retry.
// The retry helm succeeds, so the overall call returns nil.
func TestRunHelmWithKataHeal_HealsAndRetriesOnce(t *testing.T) {
	old := stuckPodMinAge
	oldWait := healRecreateWait
	stuckPodMinAge = 100 * time.Millisecond
	healRecreateWait = 0
	t.Cleanup(func() { stuckPodMinAge = old; healRecreateWait = oldWait })

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	shimDir := t.TempDir()

	// helm fails the first time and passes the second. Track invocations
	// by an inline counter in the shim.
	counterPath := filepath.Join(t.TempDir(), "helm-calls")
	os.WriteFile(counterPath, []byte("0"), 0o644)
	helmShim := `#!/bin/sh
n=$(cat ` + counterPath + `)
n=$((n+1))
echo $n > ` + counterPath + `
if [ "$n" = "1" ]; then
  echo "Error: UPGRADE FAILED: ... context deadline exceeded" >&2
  exit 1
fi
echo "helm ok"
`
	writeShim(t, shimDir, "helm", helmShim)

	list := podList{Items: []pod{{
		Metadata: podMeta{Name: "c8s-cds-stuck", CreationTimestamp: time.Now().Add(-1 * time.Minute)},
		Spec:     podSpec{RuntimeClassName: "kata-qemu-snp"},
		Status:   podStatus{Phase: "Pending"},
	}}}
	body, _ := json.Marshal(list)
	fixture := filepath.Join(t.TempDir(), "pods.json")
	os.WriteFile(fixture, body, 0o644)
	// kubectl shim: `get pods … -o json` cats the fixture; `delete pod …`
	// no-ops. The first arg tells us which one to serve.
	writeShim(t, shimDir, "kubectl", `#!/bin/sh
case "$1" in
  get) exec cat `+fixture+` ;;
  delete) echo "pod deleted (fake)"; exit 0 ;;
esac
`)
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runHelmWithKataHeal(context.Background(), stdout, stderr, []string{"upgrade", "--install"}, "c8s-system", true, true); err != nil {
		t.Fatalf("want heal to succeed; got %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if got := readCounter(t, counterPath); got != "2" {
		t.Fatalf("helm should have been called twice, saw %s", got)
	}
	if !bytesContainsAll(stdout.Bytes(),
		[]byte("Force-deleting and retrying once"),
		[]byte("heal retry")) {
		t.Fatalf("heal narration missing from stdout:\n%s", stdout.String())
	}
}

// Non-kata failure path: heal does NOT run, and the original error surfaces
// unchanged. A retry loop on non-rollout errors would mask real bugs
// (values validation, RBAC).
func TestRunHelmWithKataHeal_NonKataDoesNotHeal(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	shimDir := t.TempDir()
	writeShim(t, shimDir, "helm", "#!/bin/sh\necho boom >&2\nexit 1\n")
	writeShim(t, shimDir, "kubectl", "#!/bin/sh\necho should-not-run >&2\nexit 3\n")
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	err := runHelmWithKataHeal(context.Background(), stdout, stderr, []string{"upgrade", "--install"}, "c8s-system", false /* kata=false */, true)
	if err == nil {
		t.Fatal("want error to surface on non-kata failure")
	}
	if _, ok := err.(interface{ Unwrap() error }); !ok {
		t.Fatalf("want wrapped exec.ExitError; got %T (%v)", err, err)
	}
	if want := "helm install failed"; !contains(err.Error(), want) {
		t.Fatalf("error %q missing %q", err.Error(), want)
	}
}

// --- helpers --------------------------------------------------------------

type podList struct {
	Items []pod `json:"items"`
}
type pod struct {
	Metadata podMeta   `json:"metadata"`
	Spec     podSpec   `json:"spec"`
	Status   podStatus `json:"status"`
}
type podMeta struct {
	Name              string    `json:"name"`
	CreationTimestamp time.Time `json:"creationTimestamp"`
	DeletionTimestamp time.Time `json:"deletionTimestamp,omitempty"`
}
type podSpec struct {
	RuntimeClassName string `json:"runtimeClassName"`
}
type podStatus struct {
	Phase             string               `json:"phase"`
	ContainerStatuses []podContainerStatus `json:"containerStatuses"`
}
type podContainerStatus struct {
	Ready bool `json:"ready"`
}

func writeShim(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatalf("write shim %s: %v", name, err)
	}
}

func readCounter(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return string(bytes.TrimSpace(b))
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesContainsAll(hay []byte, needles ...[]byte) bool {
	for _, n := range needles {
		if !bytes.Contains(hay, n) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
