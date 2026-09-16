//go:build linux

package nriimagepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedC8sCryptDeviceThroughVerity(t *testing.T) {
	for _, tc := range []struct {
		name, mapper, uuid string
		want               bool
	}{
		{"encrypted volume", "c8s-crypt-pod-data", "CRYPT-PLAIN-test", true},
		{"name without crypt", "c8s-crypt-pod-data", "DM-LINEAR-test", false},
		{"crypt without c8s name", "unrelated", "CRYPT-PLAIN-test", false},
		{"missing uuid", "c8s-crypt-pod-data", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			crypt, verity := filepath.Join(root, "crypt"), filepath.Join(root, "verity")
			for _, dir := range []string{filepath.Join(crypt, "dm"), filepath.Join(verity, "slaves")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for name, value := range map[string]string{"name": tc.mapper, "uuid": tc.uuid} {
				if err := os.WriteFile(filepath.Join(crypt, "dm", name), []byte(value+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(crypt, filepath.Join(verity, "slaves", "crypt")); err != nil {
				t.Fatal(err)
			}
			inspector := linuxStorageInspector{}
			for _, device := range []string{crypt, verity} {
				if got := inspector.trustedEncryptedDevice(device, map[string]bool{}); got != tc.want {
					t.Fatalf("device %s trusted=%v, want %v", device, got, tc.want)
				}
			}
			if inspector.trustedEncryptedDevice(filepath.Join(root, "missing"), map[string]bool{}) {
				t.Fatal("missing device reported encrypted")
			}
		})
	}
}

func TestTrustedEncryptedDeviceRejectsSlaveCycle(t *testing.T) {
	device := t.TempDir()
	if err := os.Mkdir(filepath.Join(device, "slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(device, filepath.Join(device, "slaves", "self")); err != nil {
		t.Fatal(err)
	}
	if (linuxStorageInspector{}).trustedEncryptedDevice(device, map[string]bool{}) {
		t.Fatal("device cycle reported encrypted")
	}
}

func TestOverlayUpperDirDoesNotInheritHiddenAncestor(t *testing.T) {
	for _, nested := range []struct {
		name string
		fs   string
		want string
	}{
		{"lower-only overlay", "overlay overlay ro,lowerdir=/plaintext", ""},
		{"empty upperdir", "overlay overlay rw,upperdir=,lowerdir=/lower", ""},
		{"bare upperdir", "overlay overlay rw,upperdir,lowerdir=/lower", ""},
		{"workdir only", "overlay overlay rw,workdir=/work", ""},
		{"lookalike upperdir prefix", "overlay overlay rw,otherupperdir=/scratch", ""},
		{"lookalike upperdir suffix", "overlay overlay rw,upperdir_extra=/scratch", ""},
		{"non-overlay", "ext4 /dev/plaintext rw", ""},
		{"writable overlay", "overlay overlay rw,upperdir=/child-upper,lowerdir=/lower", "/child-upper"},
		{"upperdir first", "overlay overlay upperdir=/child-upper,rw,lowerdir=/lower", "/child-upper"},
		{"upperdir last", "overlay overlay rw,lowerdir=/lower,upperdir=/child-upper", "/child-upper"},
		{"equals in upperdir", "overlay overlay rw,upperdir=/child=upper", "/child=upper"},
	} {
		t.Run(nested.name, func(t *testing.T) {
			ancestor := "21 20 0:2 / /var rw - overlay overlay rw,upperdir=/encrypted-upper,lowerdir=/lower\n"
			child := "22 21 0:3 / /var/lib rw - " + nested.fs + "\n"
			for _, data := range []string{ancestor + child, child + ancestor} {
				file := filepath.Join(t.TempDir(), "mountinfo")
				if err := os.WriteFile(file, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				for _, source := range []string{"/var/lib", "/var/lib/kubelet/pods/x"} {
					got, ok := overlayUpperDir(file, source)
					if got != nested.want || ok != (nested.want != "") {
						t.Fatalf("upper for %s = %q, %v; want %q", source, got, ok, nested.want)
					}
				}
			}
		})
	}
}

func TestTrustedScratchRejectsIncompleteProvenance(t *testing.T) {
	for _, missing := range []string{"version", "boot_id", "device", "name", "uuid"} {
		t.Run(missing, func(t *testing.T) {
			root := t.TempDir()
			bootID := filepath.Join(root, "boot-id")
			provenance := filepath.Join(root, "provenance")
			fields := map[string]any{"version": 1, "boot_id": "boot-a", "device": "253:0", "name": "scratch", "uuid": "CRYPT-test"}
			delete(fields, missing)
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			for path, content := range map[string][]byte{bootID: []byte("boot-a"), provenance: data, filepath.Join(root, "dev"): []byte("253:0")} {
				if err := os.WriteFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			i := linuxStorageInspector{provenanceFile: provenance, bootIDFile: bootID}
			if i.trustedScratchProvenance(root, "CRYPT-test") {
				t.Fatal("incomplete provenance trusted")
			}
			if missing == "device" {
				if err := os.Remove(filepath.Join(root, "dev")); err != nil {
					t.Fatal(err)
				}
				if i.trustedScratchProvenance(root, "CRYPT-test") {
					t.Fatal("missing provenance and sysfs device numbers trusted")
				}
			}
		})
	}
}

func TestOverlayUpperDirUsesContainingMount(t *testing.T) {
	file := filepath.Join(t.TempDir(), "mountinfo")
	data := "20 1 0:1 / / rw - ext4 /dev/root rw\n" +
		"21 20 0:2 / /var rw - overlay overlay rw,lowerdir=/lower,upperdir=/scratch\\040upper,workdir=/work\n"
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, ok := overlayUpperDir(file, "/var/lib/kubelet/pods/x")
	if !ok || got != "/scratch upper" {
		t.Fatalf("upper = %q, %v", got, ok)
	}
}

func TestOverlayUpperDirEscapedPaths(t *testing.T) {
	for _, tc := range []struct {
		name, encoded, decoded string
	}{
		{"space", `\040`, " "},
		{"tab", `\011`, "\t"},
		{"newline", `\012`, "\n"},
		{"backslash", `\134`, `\`},
		{"literal octal sequence", `\134040`, `\040`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "mountinfo")
			data := "21 20 0:2 / /var" + tc.encoded + "lib rw - overlay overlay rw,upperdir=/scratch" + tc.encoded + "upper\n"
			if err := os.WriteFile(file, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{"/var" + tc.decoded + "lib", "/var" + tc.decoded + "lib/pods/x"} {
				got, ok := overlayUpperDir(file, source)
				want := "/scratch" + tc.decoded + "upper"
				if !ok || got != want {
					t.Fatalf("upper for %q = %q, %v; want %q", source, got, ok, want)
				}
			}
		})
	}
}

func TestTrustedScratchRequiresCryptAndBackingSerial(t *testing.T) {
	root := t.TempDir()
	dev, class := filepath.Join(root, "dev", "dm-0"), filepath.Join(root, "class")
	for _, dir := range []string{filepath.Join(dev, "dm"), filepath.Join(dev, "slaves"), filepath.Join(class, "vda", "device")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, value string) {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dev, "dm/name"), "scratch\n")
	write(filepath.Join(dev, "dm/uuid"), "CRYPT-PLAIN-test\n")
	write(filepath.Join(dev, "dev"), "253:0\n")
	write(filepath.Join(class, "vda", "device/serial"), "confai-scratch\n")
	if err := os.Symlink(filepath.Join(class, "vda"), filepath.Join(dev, "slaves", "vda")); err != nil {
		t.Fatal(err)
	}
	bootID := filepath.Join(root, "boot-id")
	provenance := filepath.Join(root, "scratch-provenance.json")
	write(bootID, "boot-a\n")
	write(provenance, `{"version":1,"boot_id":"boot-a","device":"253:0","name":"scratch","uuid":"CRYPT-PLAIN-test"}`)
	i := linuxStorageInspector{sysClassBlock: class, provenanceFile: provenance, bootIDFile: bootID}
	if !i.trustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("complete scratch proof rejected")
	}
	write(filepath.Join(dev, "dm/uuid"), "DM-LINEAR-test\n")
	if i.trustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("non-crypt scratch trusted")
	}
	write(filepath.Join(dev, "dm/uuid"), "CRYPT-PLAIN-test\n")
	write(filepath.Join(class, "vda", "device/serial"), "scratch-lookalike\n")
	if i.trustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("wrong backing serial trusted")
	}
	write(filepath.Join(class, "vda", "device/serial"), "confai-scratch\n")
	write(bootID, "boot-b\n")
	if i.trustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("stale boot provenance trusted")
	}
}
