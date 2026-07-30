package volumed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sysBlockWith builds a fake /sys/block where each entry maps a device name to
// its serial. An empty serial means the device has no serial file at all.
func sysBlockWith(t *testing.T, devices map[string]string) SerialDevices {
	t.Helper()
	root := t.TempDir()
	for dev, serial := range devices {
		dir := filepath.Join(root, dev)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dev, err)
		}
		if serial == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "serial"), []byte(serial+"\n"), 0o444); err != nil {
			t.Fatalf("write serial: %v", err)
		}
	}
	return SerialDevices{SysBlock: root, DevDir: "/dev"}
}

func TestDeviceFindsTheMatchingSerial(t *testing.T) {
	d := sysBlockWith(t, map[string]string{
		"vda": "confai-rootdisk",
		"vdb": "confai-scratch",
		"vdc": "c8s-vol-weights",
	})
	got, err := d.Device("weights")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if got != "/dev/vdc" {
		t.Fatalf("device = %q, want /dev/vdc", got)
	}
}

// The host can attach two devices claiming one serial. Picking either would
// make which volume a pod gets depend on scan order.
func TestDeviceRefusesADuplicateSerial(t *testing.T) {
	d := sysBlockWith(t, map[string]string{
		"vdb": "c8s-vol-weights",
		"vdc": "c8s-vol-weights",
	})
	_, err := d.Device("weights")
	if err == nil {
		t.Fatal("resolved an ambiguous serial")
	}
	if !strings.Contains(err.Error(), "2 block devices") {
		t.Errorf("error does not name the ambiguity: %v", err)
	}
}

func TestDeviceReportsNoSuchSerial(t *testing.T) {
	d := sysBlockWith(t, map[string]string{"vda": "confai-scratch"})
	if _, err := d.Device("weights"); err == nil {
		t.Fatal("resolved a volume with no device")
	}
}

// A device with no serial file is not a candidate, not an error: the root disk
// and the scratch disk sit alongside these.
func TestDeviceIgnoresDevicesWithoutSerials(t *testing.T) {
	d := sysBlockWith(t, map[string]string{
		"loop0": "",
		"vda":   "",
		"vdb":   "c8s-vol-weights",
	})
	got, err := d.Device("weights")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if got != "/dev/vdb" {
		t.Fatalf("device = %q", got)
	}
}

// The name is part of a serial the transport truncates at 20 bytes, so a name
// too long to fit is refused rather than matched against a truncated serial.
func TestDeviceRefusesANameTooLongForASerial(t *testing.T) {
	d := sysBlockWith(t, map[string]string{"vdb": "c8s-vol-thirteenchar"})
	if _, err := d.Device("thirteenchars"); err == nil {
		t.Fatal("accepted a name longer than the serial holds")
	}
	if maxSerialNameLen != 12 {
		t.Fatalf("maxSerialNameLen = %d, want 12", maxSerialNameLen)
	}
}

func TestDeviceRefusesAMalformedName(t *testing.T) {
	d := sysBlockWith(t, map[string]string{"vdb": "c8s-vol-weights"})
	for _, name := range []string{"", "Weights", "../../etc", "we/ights", "-weights"} {
		if _, err := d.Device(name); err == nil {
			t.Errorf("name %q: accepted", name)
		}
	}
}

// A serial that merely starts with the volume's is a different volume.
func TestDeviceMatchesTheWholeSerial(t *testing.T) {
	d := sysBlockWith(t, map[string]string{"vdb": "c8s-vol-weights2"})
	if _, err := d.Device("weights"); err == nil {
		t.Fatal("matched a serial that only shares a prefix")
	}
}

func TestDeviceReportsAnUnreadableSysBlock(t *testing.T) {
	d := SerialDevices{SysBlock: filepath.Join(t.TempDir(), "absent")}
	if _, err := d.Device("weights"); err == nil {
		t.Fatal("succeeded with no sysfs to read")
	}
}

func TestSerialDevicesSatisfiesDevices(t *testing.T) {
	var _ Devices = SerialDevices{}
}

func TestSerialDevicesDefaultTheirPaths(t *testing.T) {
	var d SerialDevices
	if got := d.sysBlock(); got != SysBlock {
		t.Errorf("sysBlock = %q, want %q", got, SysBlock)
	}
	if got := d.devDir(); got != "/dev" {
		t.Errorf("devDir = %q, want /dev", got)
	}
}

// vpd80 builds a SCSI VPD page 0x80 payload the way the kernel exposes it:
// device type, page code, big-endian length, then the padded serial.
func vpd80(serial string, width int) []byte {
	body := make([]byte, width)
	copy(body, serial)
	out := []byte{0x00, 0x80, byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// sysBlockSCSI builds a fake /sys/block where devices carry their serial as
// VPD page 0x80 under device/, which is how a SCSI disk presents it — there is
// no <dev>/serial at all. This is the shape a KubeVirt hotplugged disk takes,
// since its webhook admits hotplugs on a scsi bus alone.
func sysBlockSCSI(t *testing.T, devices map[string]string) SerialDevices {
	t.Helper()
	root := t.TempDir()
	for dev, serial := range devices {
		dir := filepath.Join(root, dev, "device")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dev, err)
		}
		if serial == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "vpd_pg80"), vpd80(serial, 20), 0o444); err != nil {
			t.Fatalf("write vpd_pg80: %v", err)
		}
	}
	return SerialDevices{SysBlock: root, DevDir: "/dev"}
}

func TestDeviceFindsASCSISerialFromVPD80(t *testing.T) {
	d := sysBlockSCSI(t, map[string]string{
		"sda": "confai-containerd",
		"sdb": "confai-models",
		"sdc": "c8s-vol-weights",
	})
	got, err := d.Device("weights")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if got != "/dev/sdc" {
		t.Fatalf("device = %q, want /dev/sdc", got)
	}
}

// A mixed node: the root disk is virtio and the hotplugged ciphertext is SCSI.
// Both spellings have to resolve in one sweep.
func TestDeviceResolvesVirtioAndSCSITogether(t *testing.T) {
	root := t.TempDir()
	mkVirtio := func(dev, serial string) {
		dir := filepath.Join(root, dev)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "serial"), []byte(serial+"\n"), 0o444); err != nil {
			t.Fatalf("write serial: %v", err)
		}
	}
	mkSCSI := func(dev, serial string) {
		dir := filepath.Join(root, dev, "device")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vpd_pg80"), vpd80(serial, 20), 0o444); err != nil {
			t.Fatalf("write vpd_pg80: %v", err)
		}
	}
	mkVirtio("vda", "confai-scratch")
	mkSCSI("sdc", "c8s-vol-weights")
	d := SerialDevices{SysBlock: root, DevDir: "/dev"}

	got, err := d.Device("weights")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if got != "/dev/sdc" {
		t.Fatalf("device = %q, want /dev/sdc", got)
	}
}

// The same serial on a virtio and a SCSI disk is still ambiguous; reading two
// spellings must not turn a refusal into a scan-order-dependent pick.
func TestDeviceRefusesADuplicateAcrossTransports(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "vdb"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "vdb", "serial"), []byte("c8s-vol-weights\n"), 0o444); err != nil {
		t.Fatalf("write serial: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sdc", "device"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sdc", "device", "vpd_pg80"), vpd80("c8s-vol-weights", 20), 0o444); err != nil {
		t.Fatalf("write vpd_pg80: %v", err)
	}
	d := SerialDevices{SysBlock: root, DevDir: "/dev"}

	if _, err := d.Device("weights"); err == nil {
		t.Fatal("resolved an ambiguous serial across transports")
	}
}

// virtio wins when a device somehow carries both, so behaviour on existing
// nodes is exactly what it was before VPD was consulted.
func TestDevicePrefersTheVirtioSpelling(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vdc", "device")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "vdc", "serial"), []byte("c8s-vol-weights\n"), 0o444); err != nil {
		t.Fatalf("write serial: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vpd_pg80"), vpd80("c8s-vol-other", 20), 0o444); err != nil {
		t.Fatalf("write vpd_pg80: %v", err)
	}
	d := SerialDevices{SysBlock: root, DevDir: "/dev"}

	got, err := d.Device("weights")
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	if got != "/dev/vdc" {
		t.Fatalf("device = %q, want /dev/vdc", got)
	}
}

func TestParseVPD80(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want string
		ok   bool
	}{
		{"padded", vpd80("c8s-vol-weights", 20), "c8s-vol-weights", true},
		{"exact", vpd80("c8s-vol-weights", 15), "c8s-vol-weights", true},
		{"empty page", vpd80("", 20), "", false},
		{"truncated header", []byte{0x00, 0x80}, "", false},
		{"length overruns buffer", []byte{0x00, 0x80, 0x00, 0xff, 'a', 'b'}, "ab", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseVPD80(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseVPD80 = %q,%v; want %q,%v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
