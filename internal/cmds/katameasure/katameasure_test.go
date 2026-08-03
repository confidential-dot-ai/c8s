package katameasure

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// liveVerityParams and liveRootfsType are the kata-guest-base c8s-debug build's
// manifest values that produced testdata/cmdline-vcpus*.txt.
const (
	liveVerityParams = "root_hash=4ee3b801e8e5de67e8c15ce8f8938455fc3b19d4990131acc1819f808e2d021d," +
		"salt=c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8," +
		"data_blocks=96512,data_block_size=4096,hash_block_size=4096"
	liveRootfsType = "ext4"
)

func goldenCmdline(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	return strings.TrimRight(string(b), "\n")
}

// TestCmdlineMatchesLiveGuest is the load-bearing test for the derivation: the
// golden files are the exact qemu -append strings captured from /proc on a live
// SEV-SNP node running kata 3.30.0 with the c8s-debug guest. A byte of drift
// here is a wrong launch measurement.
func TestCmdlineMatchesLiveGuest(t *testing.T) {
	for _, tc := range []struct {
		vcpus  int
		golden string
	}{
		{1, "cmdline-vcpus1.txt"},
		{2, "cmdline-vcpus2.txt"},
	} {
		got, err := Cmdline(CmdlineParams{
			VCPUs:                tc.vcpus,
			VerityParams:         liveVerityParams,
			RootfsType:           liveRootfsType,
			DebugConsole:         true,
			LaunchProcessTimeout: DefaultLaunchProcessTimeout,
			KernelParams:         DefaultKernelParams,
		})
		if err != nil {
			t.Fatalf("vcpus=%d: %v", tc.vcpus, err)
		}
		if want := goldenCmdline(t, tc.golden); got != want {
			t.Errorf("vcpus=%d cmdline mismatch\n got %q\nwant %q", tc.vcpus, got, want)
		}
	}
}

func TestCmdlineOptionalParts(t *testing.T) {
	p := CmdlineParams{
		VCPUs: 1, VerityParams: liveVerityParams, RootfsType: liveRootfsType,
		LaunchProcessTimeout: DefaultLaunchProcessTimeout, KernelParams: DefaultKernelParams,
	}
	nonDebug, err := Cmdline(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nonDebug, "debug_console") {
		t.Error("non-debug guest must not carry agent.debug_console")
	}
	// The debug guest's line is the non-debug one plus exactly that pair.
	if want := goldenCmdline(t, "cmdline-vcpus1.txt"); !strings.Contains(want, "agent.debug_console agent.debug_console_vport=1026 ") ||
		strings.Replace(want, "agent.debug_console agent.debug_console_vport=1026 ", "", 1) != nonDebug {
		t.Error("debug console parameters are not the only delta")
	}

	p.LaunchProcessTimeout = 0
	p.KernelParams = ""
	bare, err := Cmdline(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bare, "launch_process_timeout") || strings.Contains(bare, "cgroup_no_v1") {
		t.Errorf("zero-valued options must be omitted: %q", bare)
	}
}

func TestCmdlineRejectsBadInput(t *testing.T) {
	ok := CmdlineParams{VCPUs: 1, VerityParams: liveVerityParams, RootfsType: liveRootfsType}
	cases := map[string]CmdlineParams{
		"zero vcpus":       {VCPUs: 0, VerityParams: liveVerityParams, RootfsType: liveRootfsType},
		"no verity params": {VCPUs: 1, RootfsType: liveRootfsType},
		"bad rootfs type":  {VCPUs: 1, VerityParams: liveVerityParams, RootfsType: "btrfs"},
		"unknown key": {VCPUs: 1, RootfsType: liveRootfsType,
			VerityParams: liveVerityParams + ",bogus=1"},
		"missing key": {VCPUs: 1, RootfsType: liveRootfsType,
			VerityParams: "root_hash=aa,salt=bb,data_blocks=1,data_block_size=4096"},
		"non-numeric block count": {VCPUs: 1, RootfsType: liveRootfsType,
			VerityParams: strings.Replace(liveVerityParams, "data_blocks=96512", "data_blocks=lots", 1)},
		"block size not sector aligned": {VCPUs: 1, RootfsType: liveRootfsType,
			VerityParams: strings.Replace(liveVerityParams, "data_block_size=4096", "data_block_size=100", 1)},
	}
	for name, p := range cases {
		if _, err := Cmdline(p); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := Cmdline(ok); err != nil {
		t.Fatalf("control case failed: %v", err)
	}
}

// TestVCPUsForPod pins kata's static_sandbox_resource_mgmt sizing. The 500m
// case is the observed CDS pod: default_vcpus 1 + 0.5 rounds up to 2 vCPUs, and
// its measurement differed from every unlimited pod's.
func TestVCPUsForPod(t *testing.T) {
	cases := []struct {
		defaultVCPUs float64
		limit        float64
		want         int
	}{
		{1, 0, 1},
		{1, 0.5, 2},
		{1, 1, 2},
		{1, 1.5, 3},
		{1, 2, 3},
		{2, 0, 2},
		{2, 0.25, 3},
	}
	for _, tc := range cases {
		got, err := VCPUsForPod(tc.defaultVCPUs, tc.limit)
		if err != nil {
			t.Fatalf("(%v,%v): %v", tc.defaultVCPUs, tc.limit, err)
		}
		if got != tc.want {
			t.Errorf("VCPUsForPod(%v, %v) = %d, want %d", tc.defaultVCPUs, tc.limit, got, tc.want)
		}
	}
	if _, err := VCPUsForPod(0, 1); err == nil {
		t.Error("default_vcpus 0 must fail")
	}
	if _, err := VCPUsForPod(1, -1); err == nil {
		t.Error("negative cpu limit must fail")
	}
}

// testKernel is the synthetic vmlinuz writeGuest lays down; its sha256 is what
// manifest.outputs.kernel.sha256 must record for VerifyKernel to pass.
const testKernel = "c8s-test-kernel"

// writeGuest lays out a minimal kata-guest-base artifact directory.
func writeGuest(t *testing.T, variant, kataVersion, bootModel string) string {
	t.Helper()
	dir := t.TempDir()
	manifest := map[string]any{
		"version":              ManifestVersion,
		"boot_model":           bootModel,
		"kata_version":         kataVersion,
		"rootfs_type":          liveRootfsType,
		"build_variant":        variant,
		"kernel_verity_params": liveVerityParams,
		"outputs": map[string]any{
			"kernel": map[string]any{"path": "vmlinuz", "sha256": ""},
		},
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmlinuz"), []byte(testKernel), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestGuestSidecarsWin: the puller copies the sidecar files, not the manifest
// mirror, into the kata config that produces the measured command line.
func TestGuestSidecarsWin(t *testing.T) {
	dir := writeGuest(t, "c8s", SupportedKataVersion, bootModelDirectKernel)
	altVerity := strings.Replace(liveVerityParams, "data_blocks=96512", "data_blocks=12345", 1)
	for name, content := range map[string]string{
		"kernel_verity_params": altVerity + "\n",
		"rootfs_type":          "xfs\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g, err := LoadGuest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if g.VerityParams != altVerity {
		t.Errorf("VerityParams = %q, want the sidecar value", g.VerityParams)
	}
	if g.RootfsType != "xfs" {
		t.Errorf("RootfsType = %q, want xfs", g.RootfsType)
	}

	// An empty sidecar falls back: manifest first, then the puller's ext4.
	if err := os.WriteFile(filepath.Join(dir, "rootfs_type"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err = LoadGuest(dir); err != nil {
		t.Fatal(err)
	}
	if g.RootfsType != liveRootfsType {
		t.Errorf("RootfsType = %q, want the manifest value %q", g.RootfsType, liveRootfsType)
	}
}

func TestVerifyKernel(t *testing.T) {
	g, err := LoadGuest(writeGuest(t, "c8s", SupportedKataVersion, bootModelDirectKernel))
	if err != nil {
		t.Fatal(err)
	}
	// writeGuest records an empty sha256, which means "not recorded".
	if err := g.VerifyKernel("whatever"); err != nil {
		t.Errorf("empty manifest sha256 must not fail: %v", err)
	}
	sum := sha256.Sum256([]byte(testKernel))
	g.Manifest.Outputs.Kernel.SHA256 = hex.EncodeToString(sum[:])
	if err := g.VerifyKernel(hex.EncodeToString(sum[:])); err != nil {
		t.Errorf("matching sha256 must pass: %v", err)
	}
	if err := g.VerifyKernel(strings.Repeat("00", sha256.Size)); err == nil {
		t.Error("mismatched kernel sha256 must fail")
	}
}

func TestLoadGuestRejectsUnknownManifestVersion(t *testing.T) {
	dir := writeGuest(t, "c8s", SupportedKataVersion, bootModelDirectKernel)
	path := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = ManifestVersion + 1
	if raw, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGuest(dir); err == nil {
		t.Error("an unknown manifest version must be refused")
	}
}

func TestLoadGuest(t *testing.T) {
	g, err := LoadGuest(writeGuest(t, "c8s-debug", SupportedKataVersion, bootModelDirectKernel))
	if err != nil {
		t.Fatal(err)
	}
	if !g.DebugVariant() {
		t.Error("c8s-debug must be recognised as the debug variant")
	}
	if g.Manifest.KernelVerityParams != liveVerityParams {
		t.Error("verity params not loaded")
	}

	plain, err := LoadGuest(writeGuest(t, "c8s", SupportedKataVersion, bootModelDirectKernel))
	if err != nil {
		t.Fatal(err)
	}
	if plain.DebugVariant() {
		t.Error("c8s must not be recognised as the debug variant")
	}

	if _, err := LoadGuest(writeGuest(t, "c8s", SupportedKataVersion, "igvm")); err == nil {
		t.Error("a non-direct-kernel boot model must be rejected")
	}
	if _, err := LoadGuest(t.TempDir()); err == nil {
		t.Error("missing manifest must fail")
	}

	noKernel := writeGuest(t, "c8s", SupportedKataVersion, bootModelDirectKernel)
	os.Remove(filepath.Join(noKernel, "vmlinuz"))
	if _, err := LoadGuest(noKernel); err == nil {
		t.Error("missing kernel must fail")
	}
}

// TestRunEndToEnd drives the command over a synthetic guest and the OVMF
// fixture. The expected digest was produced independently by sev-snp-measure
// (v0.0.13) over the same inputs.
func TestRunEndToEnd(t *testing.T) {
	const want = "203430d272b5becce47feb25ffd8e2cb00fda84e563e6b2dc48e2c07ebf0aadaaa2a5168fe77c589ac7e06ec29dd65d7"
	base := config{
		guestDir:      writeGuest(t, "c8s", SupportedKataVersion, bootModelDirectKernel),
		firmware:      filepath.Join("testdata", "ovmf_AmdSev_suffix.bin"),
		vcpus:         1,
		vcpuType:      DefaultVCPUType,
		kernelParams:  DefaultKernelParams,
		launchTimeout: DefaultLaunchProcessTimeout,
		guestFeatures: 1,
		defaultVCPUs:  1,
	}

	var out, errOut bytes.Buffer
	if err := run(base, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != want {
		t.Errorf("digest\n got %s\nwant %s", got, want)
	}

	// --pod-cpu-limit must reach the same digest as the equivalent --vcpus.
	byLimit := base
	byLimit.vcpus = 0
	byLimit.podCPULimit = "0"
	out.Reset()
	if err := run(byLimit, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != want {
		t.Errorf("--pod-cpu-limit digest\n got %s\nwant %s", got, want)
	}

	jsonCfg := base
	jsonCfg.asJSON = true
	out.Reset()
	if err := run(jsonCfg, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("parse --json output: %v", err)
	}
	if res.Measurement != want {
		t.Errorf("json measurement = %s, want %s", res.Measurement, want)
	}
	if res.VCPUs != 1 || res.VCPUType != DefaultVCPUType || res.VCPUSignature != "0x800f12" {
		t.Errorf("json vcpu fields = %+v", res)
	}
	if !strings.Contains(res.Cmdline, "nr_cpus=1") || strings.Contains(res.Cmdline, "debug_console") {
		t.Errorf("json cmdline = %q", res.Cmdline)
	}
	if res.KataVersion != SupportedKataVersion || res.BuildVariant != "c8s" {
		t.Errorf("json guest fields = %+v", res)
	}

	// An explicit --cmdline must override derivation, changing the digest.
	override := base
	override.cmdline = "console=ttyS0"
	out.Reset()
	if err := run(override, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got == want {
		t.Error("--cmdline did not change the measurement")
	}
}

func TestRunRejectsUnsupportedKataVersion(t *testing.T) {
	cfg := config{
		guestDir:      writeGuest(t, "c8s", "3.31.0", bootModelDirectKernel),
		firmware:      filepath.Join("testdata", "ovmf_AmdSev_suffix.bin"),
		vcpus:         1,
		vcpuType:      DefaultVCPUType,
		kernelParams:  DefaultKernelParams,
		launchTimeout: DefaultLaunchProcessTimeout,
		guestFeatures: 1,
		defaultVCPUs:  1,
	}
	var out, errOut bytes.Buffer
	err := run(cfg, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), SupportedKataVersion) {
		t.Fatalf("want a kata version error, got %v", err)
	}

	// --skip-version-check and an explicit --cmdline are both escape hatches.
	skip := cfg
	skip.skipVersion = true
	if err := run(skip, &out, &errOut); err != nil {
		t.Errorf("--skip-version-check: %v", err)
	}
	explicit := cfg
	explicit.cmdline = "console=ttyS0"
	if err := run(explicit, &out, &errOut); err != nil {
		t.Errorf("--cmdline: %v", err)
	}
}

func TestRunRejectsMissingVCPUs(t *testing.T) {
	cfg := config{
		guestDir:      writeGuest(t, "c8s", SupportedKataVersion, bootModelDirectKernel),
		firmware:      filepath.Join("testdata", "ovmf_AmdSev_suffix.bin"),
		vcpuType:      DefaultVCPUType,
		guestFeatures: 1,
		defaultVCPUs:  1,
	}
	var out, errOut bytes.Buffer
	if err := run(cfg, &out, &errOut); err == nil {
		t.Error("neither --vcpus nor --pod-cpu-limit must fail")
	}

	bad := cfg
	bad.podCPULimit = "half a core"
	if err := run(bad, &out, &errOut); err == nil {
		t.Error("unparseable --pod-cpu-limit must fail")
	}

	badFirmware := cfg
	badFirmware.vcpus = 1
	badFirmware.firmware = filepath.Join("testdata", "absent.fd")
	if err := run(badFirmware, &out, &errOut); err == nil {
		t.Error("missing firmware must fail")
	}

	badType := cfg
	badType.vcpus = 1
	badType.vcpuType = "EPYC-v99"
	if err := run(badType, &out, &errOut); err == nil {
		t.Error("unknown --vcpu-type must fail")
	}
}

func TestNewCmdWiring(t *testing.T) {
	kata := NewCmd()
	if kata.Use != "kata" {
		t.Errorf("group Use = %q", kata.Use)
	}
	sub, _, err := kata.Find([]string{"measure"})
	if err != nil || sub.Use != "measure" {
		t.Fatalf("measure subcommand not registered: %v", err)
	}
	for _, name := range []string{"guest-dir", "firmware", "vcpus", "pod-cpu-limit", "vcpu-type", "cmdline", "json", "platform"} {
		if sub.Flags().Lookup(name) == nil {
			t.Errorf("missing flag --%s", name)
		}
	}
	if got := sub.Flags().Lookup("platform").DefValue; got != platformSNP {
		t.Errorf("--platform default = %q, want %q", got, platformSNP)
	}
}

// writeTDVF builds a minimal well-formed TDVF image so the CLI path can be
// exercised without the 4 MiB real firmware. The digest it produces is pinned
// in pkg/tdxmeasure; here only the wiring matters.
func writeTDVF(t *testing.T) string {
	t.Helper()
	const (
		page  = 4096
		pages = 3
		size  = pages * page
		// Trailer: 32 bytes padding, the footer entry, the metadata entry's
		// header and its 4-byte payload.
		trailer = 32 + 18 + 18 + 4
	)
	img := make([]byte, size)
	for i := range img {
		img[i] = byte(i * 5)
	}
	// The FVs must tile the whole image, as they do in a real TDVF: CFV first,
	// BFV covering the rest — including the metadata and footer at the end.
	// dataOffset, rawSize, gpa, memSize, sectionType, attributes.
	sections := [][6]uint64{
		{0, page, 0xffc00000, page, 1 /*CFV*/, 0},
		{page, 2 * page, 0xffc01000, 2 * page, 0 /*BFV*/, 1 /*MR_EXTEND*/},
		{0, 0, 0x809000, page, 2 /*TD HOB*/, 0},
		{0, 0, 0x800000, page, 3 /*TempMem*/, 0},
	}
	desc := make([]byte, 16)
	copy(desc, "TDVF")
	binary.LittleEndian.PutUint32(desc[4:], uint32(16+32*len(sections)))
	binary.LittleEndian.PutUint32(desc[8:], 1)
	binary.LittleEndian.PutUint32(desc[12:], uint32(len(sections)))
	for _, s := range sections {
		b := make([]byte, 32)
		binary.LittleEndian.PutUint32(b[0:], uint32(s[0]))
		binary.LittleEndian.PutUint32(b[4:], uint32(s[1]))
		binary.LittleEndian.PutUint64(b[8:], s[2])
		binary.LittleEndian.PutUint64(b[16:], s[3])
		binary.LittleEndian.PutUint32(b[24:], uint32(s[4]))
		binary.LittleEndian.PutUint32(b[28:], uint32(s[5]))
		desc = append(desc, b...)
	}

	guid := func(s string) []byte {
		f := strings.Split(s, "-")
		b, err := hex.DecodeString(strings.Join(f, ""))
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 16)
		copy(out, b)
		binary.LittleEndian.PutUint32(out[0:4], binary.BigEndian.Uint32(b[0:4]))
		binary.LittleEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(b[4:6]))
		binary.LittleEndian.PutUint16(out[6:8], binary.BigEndian.Uint16(b[6:8]))
		return out
	}
	// Metadata and footer live at the end of the image, inside the BFV, the way
	// a real TDVF lays them out. The descriptor is preceded by the TDX metadata
	// GUID; the footer entry records the descriptor's offset back from the end.
	descAt := size - trailer - len(desc)
	copy(img[descAt-16:], guid("e9eaf9f3-168e-44d5-a8eb-7f4d8738f6ae"))
	copy(img[descAt:], desc)

	payloadAt := size - trailer
	binary.LittleEndian.PutUint32(img[payloadAt:], uint32(size-descAt))
	entryHdr := img[payloadAt+4:]
	binary.LittleEndian.PutUint16(entryHdr, 22)
	copy(entryHdr[2:], guid("e47a6535-984a-4798-865e-4685a7bf8ec2"))

	footer := img[payloadAt+22:]
	binary.LittleEndian.PutUint16(footer, 40)
	copy(footer[2:], guid("96b582de-1fb2-45f7-baea-a366c55a082d"))
	clear(img[payloadAt+40:])

	path := filepath.Join(t.TempDir(), "tdvf.fd")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunTDX(t *testing.T) {
	cfg := config{platform: platformTDX, firmware: writeTDVF(t), firmwareSet: true}

	var out, errOut bytes.Buffer
	if err := run(cfg, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimSpace(out.String())
	if len(digest) != 96 {
		t.Fatalf("MRTD hex length = %d, want 96: %q", len(digest), digest)
	}

	// No guest artifacts are read: MRTD covers the firmware alone, so a bogus
	// --guest-dir must not affect the result.
	withGuest := cfg
	withGuest.guestDir = filepath.Join(t.TempDir(), "does-not-exist")
	out.Reset()
	if err := run(withGuest, &out, &errOut); err != nil {
		t.Fatalf("TDX path read guest artifacts: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != digest {
		t.Errorf("digest changed with --guest-dir: %s vs %s", got, digest)
	}

	jsonCfg := cfg
	jsonCfg.asJSON = true
	out.Reset()
	if err := run(jsonCfg, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Platform != platformTDX || res.Measurement != digest {
		t.Errorf("json = %+v, want platform tdx and measurement %s", res, digest)
	}
	// SNP-shaped fields must be absent, not zero-valued noise.
	if res.VCPUs != 0 || res.Cmdline != "" || res.KernelPath != "" {
		t.Errorf("TDX result carries SNP fields: %+v", res)
	}
}

func TestRunTDXRejectsPodShapeFlags(t *testing.T) {
	base := config{platform: platformTDX, firmware: writeTDVF(t), firmwareSet: true}
	for _, tc := range []struct {
		name string
		mut  func(*config)
	}{
		{"vcpus", func(c *config) { c.vcpus = 2 }},
		{"pod-cpu-limit", func(c *config) { c.podCPULimit = "500m" }},
		{"cmdline", func(c *config) { c.cmdline = "root=/dev/dm-0" }},
		{"debug-console", func(c *config) { c.debugConsoleSet = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)
			var out, errOut bytes.Buffer
			err := run(cfg, &out, &errOut)
			if err == nil {
				t.Fatalf("--%s accepted on the TDX path", tc.name)
			}
			if !strings.Contains(err.Error(), tc.name) {
				t.Errorf("error %q does not name --%s", err, tc.name)
			}
		})
	}
}

func TestRunRejectsUnknownPlatform(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run(config{platform: "sev-snp"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "--platform") {
		t.Fatalf("want a --platform error, got %v", err)
	}
}
