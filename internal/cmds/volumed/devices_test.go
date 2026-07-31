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
