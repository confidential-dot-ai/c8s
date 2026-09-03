package getkubeconfig

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

// writeStaticBundle writes a one-member bundle directory holding a sealed
// static-allowlist.json and returns its path and the member bytes.
func writeStaticBundle(t *testing.T) (string, []byte) {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","digests":{},"workloads":{"web":{"containers":[{
		"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
		"mounts":{"policy":"exact","destinations":["/etc/hosts"],"rules":{"/etc/hosts":{"source":"platform"}}},
		"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, policybundle.MemberStaticAllowlist), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, doc
}

// staticRegister recomputes the static register by hand from the convention
// in pkg/runtimemeasure — deliberately without the helpers the code under
// test calls, so the two cannot agree by construction:
// Extend(Extend(Zero, SHA-384("c8s/rtmr3/mode/static/v1")),
// SHA-384("c8s/rtmr3/policy/v1:" + index)), index = {"static-allowlist.json":
// "sha256:<hex of member>"}.
func staticRegister(member []byte) []byte {
	sum := sha256.Sum256(member)
	index := `{"static-allowlist.json":"sha256:` + hex.EncodeToString(sum[:]) + `"}`
	mode := sha512.Sum384([]byte("c8s/rtmr3/mode/static/v1"))
	h := sha512.New384()
	h.Write(make([]byte, 48))
	h.Write(mode[:])
	afterMode := h.Sum(nil)
	policy := sha512.Sum384([]byte("c8s/rtmr3/policy/v1:" + index))
	h = sha512.New384()
	h.Write(afterMode)
	h.Write(policy[:])
	return h.Sum(nil)
}

func TestPolicyForStaticPinsTheBundleRegister(t *testing.T) {
	dir, member := writeStaticBundle(t)
	exp, err := policyForStatic(writeTestManifest(t, tdxManifest()), dir)
	if err != nil {
		t.Fatalf("policyForStatic: %v", err)
	}
	if got, want := hex.EncodeToString(exp.rtmr3[:]), hex.EncodeToString(staticRegister(member)); got != want {
		t.Errorf("policyForStatic rtmr3 = %s, want %s", got, want)
	}
	if hex.EncodeToString(exp.pins.MRTD[:]) != testMRTDHex {
		t.Errorf("policyForStatic MRTD = %x, want the manifest's %s", exp.pins.MRTD, testMRTDHex)
	}
	if exp.chainMeaning != staticRTMR3Meaning {
		t.Errorf("chainMeaning = %q, want %q", exp.chainMeaning, staticRTMR3Meaning)
	}

	// The loose file is the same one-member bundle.
	loose, err := policyForStatic(writeTestManifest(t, tdxManifest()), filepath.Join(dir, policybundle.MemberStaticAllowlist))
	if err != nil {
		t.Fatalf("policyForStatic(file): %v", err)
	}
	if loose.rtmr3 != exp.rtmr3 {
		t.Errorf("policyForStatic(file) rtmr3 = %x, want the directory's %x", loose.rtmr3, exp.rtmr3)
	}
}

func TestPolicyForStaticErrors(t *testing.T) {
	dir, member := writeStaticBundle(t)
	unsealed := t.TempDir()
	if err := os.WriteFile(filepath.Join(unsealed, policybundle.MemberStaticAllowlist), append(member, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		manifest string
		bundle   string
		want     string
	}{
		{"snp manifest", writeTestManifest(t, snpManifest()), dir, "TDX manifest"},
		{"iso refused", writeTestManifest(t, tdxManifest()), filepath.Join(dir, "policydata.iso"), "ISO images cannot be read here"},
		{"missing bundle", writeTestManifest(t, tdxManifest()), filepath.Join(dir, "absent"), "--static-allowlist"},
		{"unsealed member", writeTestManifest(t, tdxManifest()), unsealed, "not its canonical form"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policyForStatic(tc.manifest, tc.bundle)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("policyForStatic(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
		})
	}
}

// staticReleaseHandler is releaseHandler for a static cred-release: the
// request must carry NO Authorization header — the static server checks no
// operator token, and a client that still sent one would be asserting a key
// the node never measured.
func staticReleaseHandler(t *testing.T, respBody string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != credrelease.ReleasePath {
			t.Errorf("release path = %s, want %s", r.URL.Path, credrelease.ReleasePath)
		}
		if _, set := r.Header["Authorization"]; set {
			t.Errorf("static release sent Authorization %q, want no header at all", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var req credrelease.ReleaseRequest
		if err := json.Unmarshal(body, &req); err != nil || !strings.Contains(req.CSRPEM, "CERTIFICATE REQUEST") {
			t.Errorf("release body %q: %v", body, err)
		}
		fmt.Fprint(w, respBody)
	})
}

// TestRunStaticEndToEnd drives the static flow: bundle-derived gate, RA-TLS
// dial pinned to the same policy, JWT-less release, kubeconfig on disk.
func TestRunStaticEndToEnd(t *testing.T) {
	dir, _ := writeStaticBundle(t)
	manifest := writeTestManifest(t, tdxManifest())
	exp, err := policyForStatic(manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	stubVerify(t, verifiedResultFor(exp), nil)
	release := newAttestedTLSServer(t, staticReleaseHandler(t, goodRelease))
	out := filepath.Join(t.TempDir(), "kubeconfig")

	err = execCmd(t,
		"--attest-url", newAttestStub(t).URL+"/attest",
		"--release-url", release.URL,
		"--apiserver-url", "https://node:6443",
		"--static-allowlist", dir,
		"--image-manifest", manifest,
		"--out", out,
		"--timeout", "10s")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	kc, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := "client-certificate-data: " + base64.StdEncoding.EncodeToString([]byte("CERTPEM")); !strings.Contains(string(kc), want) {
		t.Errorf("kubeconfig missing %q", want)
	}
}

// A node whose register is the dynamic operator-key shape — the same image,
// not sealed — must be refused before any credential request.
func TestRunStaticRejectsUnsealedNode(t *testing.T) {
	dir, _ := writeStaticBundle(t)
	manifest := writeTestManifest(t, tdxManifest())
	exp, err := policyForStatic(manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	res := verifiedResultFor(exp)
	dynamic := testPolicy(t, operatorPub(t))
	res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(dynamic.rtmr3[:])
	stubVerify(t, res, nil)

	cfg := Config{
		AttestURL:           newAttestStub(t).URL + "/attest",
		ReleaseBaseURL:      "https://127.0.0.1:1",
		APIServerURL:        "https://node:6443",
		StaticAllowlistPath: dir,
		ImageManifestPath:   manifest,
		OutPath:             filepath.Join(t.TempDir(), "kc"),
		Timeout:             5 * time.Second,
	}
	err = Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "RTMR[3] mismatch ("+staticRTMR3Meaning+")") {
		t.Fatalf("Run = %v, want an RTMR[3] mismatch naming the static chain", err)
	}
}

func TestStaticFlagConflicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"with operator key", []string{"--static-allowlist", "b", "--operator-key", "k.pem"}, "none of the others can be"},
		{"with workload image", []string{"--static-allowlist", "b", "--workload-image", "sha256:00"}, "none of the others can be"},
		{"without image manifest", []string{"--static-allowlist", "b"}, "--image-manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := execCmd(t, append([]string{"--node", "127.0.0.1", "--out", "kc"}, tc.args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Execute(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
		})
	}
	// Run itself refuses the pair too, for callers that build Config directly.
	err := Run(context.Background(), Config{StaticAllowlistPath: "b", OperatorKeyPath: "k", ImageManifestPath: "m", OutPath: "o"})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("Run(static + operator key) = %v, want a refusal", err)
	}
}

// Every policy names what it bound beyond the image tuple: the status line
// interpolates it, and an empty phrase there would report a chain nobody
// checked.
func TestAttestedSummaryNamesEveryChain(t *testing.T) {
	dir, _ := writeStaticBundle(t)
	static, err := policyForStatic(writeTestManifest(t, tdxManifest()), dir)
	if err != nil {
		t.Fatal(err)
	}
	snp, err := policyFor(writeTestManifest(t, snpManifest()), operatorPub(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		exp  measuredPolicy
		want string
	}{
		{"tdx operator key", testPolicy(t, operatorPub(t)), "image tuple + operator-key + dynamic mode event + workload chain verified"},
		{"tdx static", static, "image tuple + " + staticRTMR3Meaning + " verified"},
		{"snp operator key", snp, "image tuple + operator-key HOSTDATA binding verified"},
	} {
		if got := tc.exp.attestedSummary(); got != tc.want {
			t.Errorf("attestedSummary(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
