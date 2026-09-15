package cds

import (
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

func TestAttestKeepsNodeOperatorBoundToImage(t *testing.T) {
	digest := make([]byte, 48)
	digest[0] = 0xaa
	leader, follower := []byte("leader key"), []byte("follower key")
	stub := newStubAttestationApi(t, hex.EncodeToString(digest))
	h := newTestAttestHandler(t, stub.URL(), nil)
	h.NodeEntries = []measurements.Entry{{Name: "leader", Digest: digest, OperatorKey: leader}}
	csr, _ := generateCSR(t)
	for _, tc := range []struct {
		name   string
		key    []byte
		status int
	}{
		{"leader", leader, http.StatusOK}, {"same image wrong operator", follower, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := mockapi.PassingVerdict(hex.EncodeToString(digest))
			binding := runtimemeasure.HostData(tc.key)
			verdict.Claims.InitData = binding[:]
			stub.SetVerdict(verdict)
			response := postAttest(t, h, issueChallenge(t, h), csr)
			if response.Code != tc.status {
				t.Fatalf("status=%d want=%d: %s", response.Code, tc.status, response.Body.String())
			}
		})
	}
}

func TestCDSConfigPreservesNodeKeys(t *testing.T) {
	cfg := config{measurementsConfig: "../../../pkg/measurements/testdata/node-identities.json", ratlsPlatform: "tdx"}
	got, err := resolveMeasurementsConfig(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 || !got.PinsOperatorKeys() {
		t.Fatal("CDS startup dropped node identities")
	}
	encoded, err := measurements.Format(got)
	if err != nil {
		t.Fatal(err)
	}
	served, err := measurements.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	missing, extra := measurements.Diff(got, served)
	if len(missing)+len(extra) != 0 {
		t.Fatal("served policy dropped identities")
	}
}
