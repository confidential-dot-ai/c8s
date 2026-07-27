package cds

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secretstore"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ctxWithChiParams stubs chi URL parameters for direct handler invocation.
func ctxWithChiParams(r *http.Request, params map[string]string) context.Context {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
}

func mustRootPool(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append CA PEM")
	}
	return pool
}

const (
	secDigestVLLM   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	secDigestOther  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	secLaunchDigest = "abcd1234"
)

func vllmEntry() pkgallowlist.Workload {
	return pkgallowlist.Workload{
		Label: "docker.io/vllm/vllm-openai:v0.6.3",
		Containers: []pkgallowlist.Container{
			{
				Digest:  mustParseDigest(secDigestVLLM),
				Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"python3"}},
				Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"-m", "vllm.entrypoints.openai.api_server"}},
				Paths: pkgallowlist.PathPolicy{
					Policy: pkgallowlist.PolicyAllow,
					Read:   []string{"/secrets/model/**"},
					Write:  []string{"/secrets/session"},
				},
			},
		},
	}
}

func mustParseDigest(s string) types.Digest {
	d, err := types.ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

func newTestSecretsHandler(t *testing.T, measurements map[string]bool, workloads map[string]pkgallowlist.Workload) SecretsHandler {
	t.Helper()
	ca, err := issuer.NewCA("test ca", 2*issuer.MaxLeafTTL)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	id, err := newBrokerIdentity(ca, certutil.EncodeCertPEM(ca.Cert.Raw))
	if err != nil {
		t.Fatalf("broker identity: %v", err)
	}
	mock := newMockAttestationApi(t, secLaunchDigest)
	store := attestation.NewChallengeStore(30 * time.Second)
	secretsStore := secretstore.NewMemStore()
	return SecretsHandler{
		Challenges:        &store,
		AttestationClient: attestationclient.NewClient(mock.URL),
		Measurements:      measurements,
		AllowlistStore:    fakeStore{floor: map[string]bool{}, workloads: workloads},
		Store:             secretsStore,
		Identity:          id,
	}
}

func fetchBody(t *testing.T, h SecretsHandler, req secrets.FetchRequest) ([]byte, secrets.FetchRequest) {
	t.Helper()
	c := h.Challenges.Create()
	req.Challenge = base64.StdEncoding.EncodeToString(c[:])
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body, req
}

func doFetch(t *testing.T, h SecretsHandler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/secrets/fetch", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleFetch(w, req)
	return w
}

func goodFetchRequest(t *testing.T) secrets.FetchRequest {
	t.Helper()
	_, pub, err := secrets.GenerateX25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return secrets.FetchRequest{
		ContainerDigests: []string{secDigestVLLM},
		ResponsePubkey:   base64.StdEncoding.EncodeToString(pub),
		Requests:         []secrets.SecretRequest{{Digest: secDigestVLLM, Paths: []string{"/secrets/model/dek"}}},
	}
}

func TestFetchHappyPath(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	if err := h.Store.Set(t.Context(), secretstore.Ref{Entry: "vllm-llama", Path: "/secrets/model/dek"}, []byte("supersecret")); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	priv, pub, _ := secrets.GenerateX25519()
	req := goodFetchRequest(t)
	req.ResponsePubkey = base64.StdEncoding.EncodeToString(pub)
	body, canonicalReq := fetchBody(t, h, req)
	w := doFetch(t, h, body)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}

	var resp secrets.FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// The transcript must be computable by the client for its own request —
	// this is what the evidence would have bound on a real TEE.
	if _, err := secrets.ReportDataForFetch(mustChallengeBytes(t, canonicalReq.Challenge), canonicalReq); err != nil {
		t.Fatalf("transcript: %v", err)
	}

	// Verify the broker identity chains to the mesh CA, then the signature,
	// then unwrap.
	signingPub, _, err := h.Identity.doc.Verify(mustRootPool(t, h.Identity.doc.CAChainPEM))
	if err != nil {
		t.Fatalf("verify identity: %v", err)
	}
	if err := secrets.VerifyResponseSignature(signingPub, resp.Payload, resp.Signature); err != nil {
		t.Fatalf("response signature: %v", err)
	}
	payloadJSON, err := secrets.Unwrap(priv, []byte(secrets.FetchAAD), resp.Payload)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	var values map[string]string
	if err := json.Unmarshal(payloadJSON, &values); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(values["/secrets/model/dek"])
	if err != nil || string(got) != "supersecret" {
		t.Fatalf("got %q (err %v)", got, err)
	}
}

func mustChallengeBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	return b
}

func TestFetchFailsClosedOnEmptyMeasurements(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	body, _ := fetchBody(t, h, goodFetchRequest(t))
	w := doFetch(t, h, body)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), types.ErrorCodeMeasurementNotConfigured) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchMeasurementDenied(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{"someone-else": true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	body, _ := fetchBody(t, h, goodFetchRequest(t))
	w := doFetch(t, h, body)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), types.ErrorCodeMeasurementDenied) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchNoMatchingEntry(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	req := goodFetchRequest(t)
	req.ContainerDigests = []string{secDigestOther}
	body, _ := fetchBody(t, h, req)
	w := doFetch(t, h, body)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), types.ErrorCodeGrantDenied) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchAmbiguousEntries(t *testing.T) {
	// Two entries with identical container sets but different grants.
	e2 := vllmEntry()
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{
		"vllm-a": vllmEntry(),
		"vllm-b": e2,
	})
	body, _ := fetchBody(t, h, goodFetchRequest(t))
	w := doFetch(t, h, body)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), types.ErrorCodeEntryAmbiguous) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchDigestNotInEntry(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	req := goodFetchRequest(t)
	req.Requests = []secrets.SecretRequest{{Digest: secDigestOther, Paths: []string{"/secrets/model/dek"}}}
	body, _ := fetchBody(t, h, req)
	w := doFetch(t, h, body)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), types.ErrorCodeGrantDenied) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchPathNotGranted(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	req := goodFetchRequest(t)
	req.Requests = []secrets.SecretRequest{{Digest: secDigestVLLM, Paths: []string{"/secrets/other/key"}}}
	body, _ := fetchBody(t, h, req)
	w := doFetch(t, h, body)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), types.ErrorCodeGrantDenied) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchSecretNotFound(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	body, _ := fetchBody(t, h, goodFetchRequest(t))
	w := doFetch(t, h, body)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), types.ErrorCodeSecretNotFound) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchInvalidChallenge(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	req := goodFetchRequest(t)
	req.Challenge = base64.StdEncoding.EncodeToString([]byte("bogus-bogus-bogus-bogus-bogus-bogus-bo"))
	body, _ := json.Marshal(req)
	w := doFetch(t, h, body)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), types.ErrorCodeInvalidChallenge) {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestFetchPathGlobMatching(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	_ = h.Store.Set(t.Context(), secretstore.Ref{Entry: "vllm-llama", Path: "/secrets/model/v2/key"}, []byte("v2"))
	req := goodFetchRequest(t)
	req.Requests = []secrets.SecretRequest{{Digest: secDigestVLLM, Paths: []string{"/secrets/model/v2/key"}}}
	body, _ := fetchBody(t, h, req)
	w := doFetch(t, h, body)
	if w.Code != http.StatusOK {
		t.Fatalf("subtree glob not honored: got %d: %s", w.Code, w.Body.String())
	}
}

func TestOperatorPutGetDelete(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	h.WriteAuthorizer = func(*http.Request, []byte) error { return nil }

	// PUT wrapped to the broker encryption key.
	signingPub, encPub, err := h.Identity.doc.Verify(mustRootPool(t, h.Identity.doc.CAChainPEM))
	if err != nil {
		t.Fatalf("verify identity: %v", err)
	}
	wrapped, err := secrets.Wrap(encPub, []byte("deposit-value"), secrets.DepositAAD("vllm-llama", "/secrets/model/dek"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	body, _ := json.Marshal(wrapped)
	putReq := httptest.NewRequest(http.MethodPut, "/secrets/entries/vllm-llama/paths/secrets/model/dek", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOperatorPut(w, putReq.WithContext(ctxWithChiParams(putReq, map[string]string{"entry": "vllm-llama", "*": "secrets/model/dek"})))
	if w.Code != http.StatusNoContent {
		t.Fatalf("put got %d: %s", w.Code, w.Body.String())
	}

	// GET read-back wrapped to an ephemeral key.
	priv, pub, _ := secrets.GenerateX25519()
	getReq := httptest.NewRequest(http.MethodGet, "/secrets/entries/vllm-llama/paths/secrets/model/dek?pubkey="+base64.StdEncoding.EncodeToString(pub), nil)
	w = httptest.NewRecorder()
	h.HandleOperatorGet(w, getReq.WithContext(ctxWithChiParams(getReq, map[string]string{"entry": "vllm-llama", "*": "secrets/model/dek"})))
	if w.Code != http.StatusOK {
		t.Fatalf("get got %d: %s", w.Code, w.Body.String())
	}
	var wrappedResp secrets.FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &wrappedResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if err := secrets.VerifyResponseSignature(signingPub, wrappedResp.Payload, wrappedResp.Signature); err != nil {
		t.Fatalf("get response signature: %v", err)
	}
	value, err := secrets.Unwrap(priv, secrets.DepositAAD("vllm-llama", "/secrets/model/dek"), wrappedResp.Payload)
	if err != nil || string(value) != "deposit-value" {
		t.Fatalf("read-back got %q (err %v)", value, err)
	}

	// DELETE.
	delReq := httptest.NewRequest(http.MethodDelete, "/secrets/entries/vllm-llama/paths/secrets/model/dek", nil)
	w = httptest.NewRecorder()
	h.HandleOperatorDelete(w, delReq.WithContext(ctxWithChiParams(delReq, map[string]string{"entry": "vllm-llama", "*": "secrets/model/dek"})))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete got %d: %s", w.Code, w.Body.String())
	}
	if _, err := h.Store.Get(t.Context(), secretstore.Ref{Entry: "vllm-llama", Path: "/secrets/model/dek"}, types.Digest{}); err == nil {
		t.Fatal("secret survived delete")
	}
}

func TestOperatorPutRejectsUnknownEntry(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	h.WriteAuthorizer = func(*http.Request, []byte) error { return nil }
	_, encPub, _ := h.Identity.doc.Verify(mustRootPool(t, h.Identity.doc.CAChainPEM))
	wrapped, _ := secrets.Wrap(encPub, []byte("v"), secrets.DepositAAD("nope", "/secrets/x"))
	body, _ := json.Marshal(wrapped)
	putReq := httptest.NewRequest(http.MethodPut, "/secrets/entries/nope/paths/secrets/x", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOperatorPut(w, putReq.WithContext(ctxWithChiParams(putReq, map[string]string{"entry": "nope", "*": "secrets/x"})))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestOperatorUnauthorizedWhenNoKeys(t *testing.T) {
	h := newTestSecretsHandler(t, map[string]bool{secLaunchDigest: true}, map[string]pkgallowlist.Workload{"vllm-llama": vllmEntry()})
	putReq := httptest.NewRequest(http.MethodPut, "/secrets/entries/vllm-llama/paths/secrets/x", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.HandleOperatorPut(w, putReq.WithContext(ctxWithChiParams(putReq, map[string]string{"entry": "vllm-llama", "*": "secrets/x"})))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}
