package attestationclient

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func hexReg(b byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{b}), launchMeasurementSize)
}

func TestOwnTupleEntry(t *testing.T) {
	good := testattest.TDXVerdict(hexReg(0x11), map[int]string{0: hexReg(0x00), 1: hexReg(0x21), 2: hexReg(0x22), 3: hexReg(0x33)})
	with := func(edit func(v *testattest.Verdict)) testattest.Verdict {
		v := good
		v.Claims.PlatformData = map[string]any{}
		for k, reg := range good.Claims.PlatformData {
			v.Claims.PlatformData[k] = reg
		}
		edit(&v)
		return v
	}
	for _, tc := range []struct {
		name     string
		platform types.Platform
		verdict  testattest.Verdict
		wantErr  string
	}{
		{"own tuple", types.PlatformTdx, good, ""},
		{"snp evidence", types.PlatformSnp, good, "want TDX"},
		{"signature invalid", types.PlatformTdx, with(func(v *testattest.Verdict) { v.SignatureValid = false }), "verify self-report"},
		{"report data mismatch", types.PlatformTdx, with(func(v *testattest.Verdict) { f := false; v.ReportDataMatch = &f }), "verify self-report"},
		{"report data unchecked", types.PlatformTdx, with(func(v *testattest.Verdict) { v.ReportDataMatch = nil }), "verify self-report"},
		{"launch digest short", types.PlatformTdx, with(func(v *testattest.Verdict) { v.Claims.LaunchDigest = "abcd" }), "verify self-report"},
		{"launch digest missing", types.PlatformTdx, with(func(v *testattest.Verdict) { v.Claims.LaunchDigest = "" }), "launch digest"},
		{"rtmr_3 missing", types.PlatformTdx, with(func(v *testattest.Verdict) { delete(v.Claims.PlatformData, "rtmr_3") }), "rtmr_3"},
		{"rtmr_1 not a string", types.PlatformTdx, with(func(v *testattest.Verdict) { v.Claims.PlatformData["rtmr_1"] = 7 }), "rtmr_1"},
		{"rtmr_2 short", types.PlatformTdx, with(func(v *testattest.Verdict) { v.Claims.PlatformData["rtmr_2"] = "abcd" }), "rtmr_2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub, url := testattest.NewUnix(t)
			stub.SetPlatform(tc.platform)
			stub.SetVerdict(tc.verdict)
			entry, err := NewClient(url).OwnTupleEntry(t.Context())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("OwnTupleEntry(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("OwnTupleEntry(%s) = %v, want nil", tc.name, err)
			}
			if hex.EncodeToString(entry.Digest) != hexReg(0x11) || len(entry.RTMRs) != 3 {
				t.Fatalf("OwnTupleEntry(%s) = digest %x, %d RTMRs; want %s, 3", tc.name, entry.Digest, len(entry.RTMRs), hexReg(0x11))
			}
			for i, want := range map[int]byte{1: 0x21, 2: 0x22, 3: 0x33} {
				if !bytes.Equal(entry.RTMRs[i], bytes.Repeat([]byte{want}, launchMeasurementSize)) {
					t.Errorf("OwnTupleEntry(%s) RTMR[%d] = %x, want %s", tc.name, i, entry.RTMRs[i], hexReg(want))
				}
			}
			attests, verifies := stub.AttestRequests(), stub.VerifyRequests()
			if len(attests) != 1 || len(verifies) != 1 {
				t.Fatalf("attest/verify requests = %d/%d, want 1/1", len(attests), len(verifies))
			}
			if verifies[0].Params == nil || verifies[0].Params.ExpectedReportData == nil {
				t.Fatal("self-report verified without an expected report_data: the verdict would be replayable")
			}
			if got := verifies[0].Params.ExpectedReportData.Bytes(); !bytes.Equal(got[:launchMeasurementSize], attests[0].ReportData.Bytes()) || len(got) != 64 {
				t.Fatalf("verify expected report_data = %x (%d bytes), want the attested nonce zero-extended to 64", got, len(got))
			}
		})
	}
}

func TestOwnTupleEntry_SocketAbsentIsAnError(t *testing.T) {
	_, err := NewClient("unix://" + filepath.Join(t.TempDir(), "absent.sock")).OwnTupleEntry(t.Context())
	if err == nil || !strings.Contains(err.Error(), "attest self") {
		t.Fatalf("OwnTupleEntry(absent socket) = %v, want an attest error", err)
	}
}

// The tuple is only this node's when the verifier is the node's own socket;
// refusal happens before any request so a network stub is never dialed.
func TestOwnTupleEntry_NetworkVerifierRefused(t *testing.T) {
	stub := testattest.New(t)
	stub.SetPlatform(types.PlatformTdx)
	stub.SetVerdict(testattest.TDXVerdict(hexReg(0x11), map[int]string{1: hexReg(0x21), 2: hexReg(0x22), 3: hexReg(0x33)}))
	for _, tc := range []struct {
		name   string
		client Client
	}{
		{"NewClient", NewClient(stub.URL)},
		{"NewClientWithHTTP", NewClientWithHTTP(stub.URL, &http.Client{})},
	} {
		_, err := tc.client.OwnTupleEntry(t.Context())
		if err == nil || !strings.Contains(err.Error(), "unix://") {
			t.Errorf("OwnTupleEntry(%s over http) = %v, want an error naming unix://", tc.name, err)
		}
	}
	if n := len(stub.AttestRequests()); n != 0 {
		t.Fatalf("attest requests over the network verifier = %d, want 0", n)
	}
}

func TestTupleEntry(t *testing.T) {
	reg := hexReg(0xab)
	valid := map[string]any{"rtmr_0": reg, "rtmr_1": reg, "rtmr_2": reg, "rtmr_3": reg}
	for _, tc := range []struct {
		name    string
		digest  string
		data    map[string]any
		wantErr string
	}{
		{"complete", reg, valid, ""},
		{"digest upper case", strings.ToUpper(reg), valid, ""},
		{"digest short", "abcd", valid, "launch digest"},
		{"digest missing", "", valid, "launch digest"},
		{"rtmr missing", reg, map[string]any{"rtmr_1": reg, "rtmr_2": reg}, "rtmr_3"},
		{"rtmr not a string", reg, map[string]any{"rtmr_1": reg, "rtmr_2": reg, "rtmr_3": 7}, "rtmr_3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := types.VerifyResponse{Result: types.VerificationResult{Claims: types.Claims{LaunchDigest: tc.digest, PlatformData: tc.data}}}
			entry, err := tupleEntry(resp)
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("tupleEntry(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
			}
			if err == nil && (len(entry.RTMRs) != 3 || hex.EncodeToString(entry.Digest) != reg) {
				t.Fatalf("tupleEntry(%s) = %d RTMRs, digest %x; want 3, %s", tc.name, len(entry.RTMRs), entry.Digest, reg)
			}
		})
	}
}
