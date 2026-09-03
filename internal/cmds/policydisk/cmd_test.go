package policydisk

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
)

// sealedDoc is a complete one-entry sealed allowlist in canonical bytes, the
// only shape the member lint accepts.
// goldenIndexDigest and goldenRTMR3 are IndexDigest and RTMR3 of the
// one-member bundle holding sealedDoc, frozen so a change to what
// policy-disk prints fails here rather than on a node.
const (
	goldenIndexDigest = "a9fcb41b544900137e2c78a784149e94e45ecc3ce1e17e385f471f876f124343"
	goldenRTMR3       = "37f566599428ed639fac1e806a3c1dc0e18b3cd5a4443ed1f0bcd8b9098971d70be1bd83daf104409e9a9802025874c5"
)

func sealedDoc(t *testing.T) []byte {
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
	return doc
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubISOTool puts a fake ISO tool named name on PATH. It records its argv
// and the staged directory listing, and creates the -o output.
func stubISOTool(t *testing.T, name string) (argvLog, stagedLog string) {
	t.Helper()
	bin := t.TempDir()
	argvLog = filepath.Join(bin, name+".argv")
	stagedLog = filepath.Join(bin, name+".staged")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" > '" + argvLog + "'\n" +
		"out=''\nwhile [ $# -gt 1 ]; do if [ \"$1\" = -o ]; then out=$2; fi; shift; done\n" +
		"ls -1 \"$1\" > '" + stagedLog + "'\n" +
		": > \"$out\"\n"
	if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return argvLog, stagedLog
}

func TestRunWritesISOAndPrintsMeasurements(t *testing.T) {
	argvLog, stagedLog := stubISOTool(t, "xorrisofs")
	doc := sealedDoc(t)
	member := writeFile(t, t.TempDir(), "static-allowlist.json", doc)
	out := filepath.Join(t.TempDir(), "policydata.iso")

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), Config{Members: []string{member}, Output: out}, &stdout, &stderr); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Frozen for sealedDoc: the two lines are what a reviewer pastes into
	// launch tooling, so they are held to fixed vectors, not recomputed
	// through the helpers Run itself calls.
	want := "index-digest: sha256:" + goldenIndexDigest + "\nrtmr3: " + goldenRTMR3 + "\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
	bundle, err := policybundle.FromMembers(map[string][]byte{policybundle.MemberStaticAllowlist: doc})
	if err != nil {
		t.Fatal(err)
	}
	if digest, rtmr3 := bundle.IndexDigest(), bundle.RTMR3(); hex.EncodeToString(digest[:]) != goldenIndexDigest || hex.EncodeToString(rtmr3[:]) != goldenRTMR3 {
		t.Errorf("policybundle derives %x / %x for sealedDoc, want the frozen %s / %s", digest, rtmr3, goldenIndexDigest, goldenRTMR3)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty without --kubevirt-secret", stderr.String())
	}

	argv, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("the ISO tool was not run: %v", err)
	}
	if !strings.HasPrefix(string(argv), "-V policydata -J -R -o "+out+" ") {
		t.Errorf("ISO tool argv = %q, want -V policydata -J -R -o %s <stage dir>", argv, out)
	}
	staged, _ := os.ReadFile(stagedLog)
	if strings.TrimSpace(string(staged)) != policybundle.MemberStaticAllowlist {
		t.Errorf("staged dir lists %q, want exactly %s", staged, policybundle.MemberStaticAllowlist)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("output ISO not created: %v", err)
	}
}

// The member name is the basename: a file reviewed under another name is
// staged and indexed as static-allowlist.json only when it is called that.
func TestRunKubeVirtSecret(t *testing.T) {
	stubISOTool(t, "genisoimage")
	doc := sealedDoc(t)
	member := writeFile(t, t.TempDir(), "static-allowlist.json", doc)

	var stdout, stderr bytes.Buffer
	cfg := Config{Members: []string{member}, Output: filepath.Join(t.TempDir(), "p.iso"), KubeVirtSecret: "vm-policy"}
	if err := Run(context.Background(), cfg, &stdout, &stderr); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.HasPrefix(stderr.String(), "index-digest: sha256:") || !strings.Contains(stderr.String(), "\nrtmr3: ") {
		t.Errorf("stderr = %q, want the digest lines moved off stdout", stderr.String())
	}
	docs := strings.SplitN(stdout.String(), "\n---\n", 2)
	if len(docs) != 2 {
		t.Fatalf("stdout = %q, want a Secret document followed by the volume notes", stdout.String())
	}
	var secret corev1.Secret
	if err := sigsyaml.Unmarshal([]byte(docs[0]), &secret); err != nil {
		t.Fatalf("decode Secret: %v\n%s", err, docs[0])
	}
	if secret.Kind != "Secret" || secret.Name != "vm-policy" {
		t.Errorf("Secret = %s/%s, want Secret/vm-policy", secret.Kind, secret.Name)
	}
	if got := secret.Data[policybundle.MemberStaticAllowlist]; !bytes.Equal(got, doc) {
		t.Errorf("Secret data[%s] differs from the member bytes", policybundle.MemberStaticAllowlist)
	}
	for _, want := range []string{"secretName: vm-policy", "volumeLabel: policydata", "bus: virtio"} {
		if !strings.Contains(docs[1], want) {
			t.Errorf("volume notes missing %q:\n%s", want, docs[1])
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(docs[1]), "\n") {
		if !strings.HasPrefix(line, "#") {
			t.Errorf("volume notes line %q is not a comment; kubectl apply would read it as a second document", line)
		}
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	doc := sealedDoc(t)
	sealed := writeFile(t, dir, "static-allowlist.json", doc)
	if err := os.MkdirAll(filepath.Join(dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	unsealed := writeFile(t, filepath.Join(dir, "x"), "static-allowlist.json", append(slices.Clone(doc), '\n'))
	if err := os.MkdirAll(filepath.Join(dir, "y"), 0o755); err != nil {
		t.Fatal(err)
	}
	nullDigests := writeFile(t, filepath.Join(dir, "y"), "static-allowlist.json", bytes.Replace(doc, []byte(`"digests":{}`), []byte(`"digests":null`), 1))
	routes := writeFile(t, dir, "routes.json", []byte("{}"))
	renamed := writeFile(t, dir, "reviewed.json", doc)

	for _, tc := range []struct {
		name    string
		members []string
		tool    string
		want    string
	}{
		{"no static-allowlist.json", []string{routes}, "xorrisofs", "no static-allowlist.json member"},
		{"renamed member", []string{renamed}, "xorrisofs", "no static-allowlist.json member"},
		{"unknown member", []string{sealed, routes}, "xorrisofs", `member "routes.json" is unknown`},
		{"non-canonical member", []string{unsealed}, "xorrisofs", "not its canonical form"},
		{"digests null", []string{nullDigests}, "xorrisofs", `"digests" must be {}`},
		{"duplicate basename", []string{sealed, unsealed}, "xorrisofs", "already given"},
		{"missing file", []string{filepath.Join(dir, "absent.json")}, "xorrisofs", "--member"},
		{"no ISO tool", []string{sealed}, "", "install one of xorrisofs, genisoimage, mkisofs"},
		{"ISO tool fails", []string{sealed}, "failing", "mkisofs: exit status 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.tool {
			case "":
				t.Setenv("PATH", t.TempDir())
			case "failing":
				bin := t.TempDir()
				if err := os.WriteFile(filepath.Join(bin, "mkisofs"), []byte("#!/bin/sh\necho no space; exit 3\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", bin)
			default:
				stubISOTool(t, tc.tool)
			}
			var stdout, stderr bytes.Buffer
			err := Run(context.Background(), Config{Members: tc.members, Output: filepath.Join(t.TempDir(), "p.iso")}, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("Run(%s) printed %q before failing", tc.name, stdout.String())
			}
		})
	}
}

// The first tool on PATH in the documented order wins, whatever else is
// installed.
func TestFindISOToolOrder(t *testing.T) {
	bin := t.TempDir()
	for _, name := range []string{"mkisofs", "genisoimage"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	got, err := findISOTool()
	if err != nil {
		t.Fatalf("findISOTool: %v", err)
	}
	if filepath.Base(got) != "genisoimage" {
		t.Errorf("findISOTool() = %s, want genisoimage ahead of mkisofs", got)
	}
}

func TestNewCmdFlags(t *testing.T) {
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"-o", "x.iso"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), `"member"`) {
		t.Fatalf("Execute without --member = %v, want the required-flag error", err)
	}
	for _, name := range []string{"member", "output", "kubevirt-secret"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
	if !slices.Contains(isoTools, "xorrisofs") {
		t.Error("xorrisofs must stay a supported tool")
	}
}
