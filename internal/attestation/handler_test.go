package attestation_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func testKeyPEM() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mockVerifyResponse(signatureValid, reportDataMatch bool) string {
	return mustJSON(types.VerifyResponse{
		Result: types.VerificationResult{
			Platform:        "snp",
			SignatureValid:  signatureValid,
			Claims:          types.Claims{},
			ReportDataMatch: &reportDataMatch,
		},
	})
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// testApp mounts the attestation routes /authenticate and /attest-key. CSR
// signing happens in-process in cds, so these handlers carry no signer
// dependency.
func testApp(attestationURL string) http.Handler {
	return testAppWithOperatorPolicy(attestationURL, "")
}

func testAppWithOperatorPolicy(attestationURL, operatorKeysHash string) http.Handler {
	challengeStore := attestation.NewChallengeStore(60 * time.Second)

	earIssuer, err := ear.NewIssuer(testKeyPEM(), "test-issuer", 24*time.Hour)
	if err != nil {
		panic(err)
	}

	h := attestation.Handler{
		Challenges:        &challengeStore,
		AttestationClient: attestationclient.NewClient(attestationURL),
		EarIssuer:         earIssuer,
		OperatorKeysHash:  operatorKeysHash,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /authenticate", attestation.HandleAuthenticate(h.Challenges))
	mux.HandleFunc("POST /attest-key", h.HandleAttestKey)
	return mux
}

func authenticate(t *testing.T, appURL string) string {
	t.Helper()
	resp, err := http.Post(appURL+"/authenticate", "application/json", nil)
	if err != nil {
		t.Fatalf("authenticate request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticate status = %d, want 200", resp.StatusCode)
	}
	var out types.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return out.Challenge
}

func TestAuthenticateReturnsBase64Challenge(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	challenge := authenticate(t, app.URL)

	decoded, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatalf("challenge is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("challenge decoded to %d bytes, want 32", len(decoded))
	}
}

func TestAuthenticateReturnsUniqueChallenges(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	c1 := authenticate(t, app.URL)
	c2 := authenticate(t, app.URL)
	if c1 == c2 {
		t.Fatal("two authenticate calls returned the same challenge")
	}
}

func TestAuthenticateRejectsGetMethod(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	resp, err := http.Get(app.URL + "/authenticate")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want 405", resp.StatusCode)
	}
}

func TestAttestKeyReturnsEARForAttestedPubkey(t *testing.T) {
	const operatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testAppWithOperatorPolicy(mockAS.URL, operatorKeysHash))
	defer app.Close()

	challenge := authenticate(t, app.URL)

	pubKey := generateAttestKeyPubKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}

	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence: types.AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{"quote":"abc"}`),
		},
		PublicKey:        base64.StdEncoding.EncodeToString(pubDER),
		OperatorKeysHash: operatorKeysHash,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp, err := http.Post(app.URL+"/attest-key", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /attest-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}

	var out types.AttestKeyResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.EAR == "" {
		t.Fatal("response missing ear")
	}

	var claims map[string]any
	decodeJWTPayload(t, out.EAR, &claims)
	if claims[earclaims.TEEPublicKey] == nil {
		t.Fatal("EAR missing tee_public_key claim")
	}
	wantPubKeyClaim := base64.RawURLEncoding.EncodeToString(pubDER)
	if got, _ := claims[earclaims.TEEPublicKey].(string); got != wantPubKeyClaim {
		t.Fatalf("tee_public_key = %q, want %q", got, wantPubKeyClaim)
	}
	if got, _ := claims[earclaims.OperatorKeysHash].(string); got != operatorKeysHash {
		t.Fatalf("operator_keys_hash = %q, want %q", got, operatorKeysHash)
	}
}

// TestAttestKeyEmbedsSubmittedEvidence: the issued EAR's ear_raw_evidence must
// carry the evidence envelope the caller submitted, verbatim.
func TestAttestKeyEmbedsSubmittedEvidence(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mockVerifyResponse(true, true))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testApp(mockAS.URL))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	pubDER, err := x509.MarshalPKIXPublicKey(generateAttestKeyPubKey(t))
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	submitted := types.AttestationEvidence{
		Platform: "snp",
		Evidence: json.RawMessage(`{"quote":"abc"}`),
	}
	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence:  submitted,
		PublicKey: base64.StdEncoding.EncodeToString(pubDER),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp, err := http.Post(app.URL+"/attest-key", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /attest-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}
	var out types.AttestKeyResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	var claims struct {
		Submods map[string]struct {
			RawEvidence json.RawMessage `json:"ear_raw_evidence"`
		} `json:"submods"`
	}
	decodeJWTPayload(t, out.EAR, &claims)
	att, ok := claims.Submods[earclaims.SubmodAttester]
	if !ok {
		t.Fatalf("EAR missing %q submod", earclaims.SubmodAttester)
	}
	var got types.AttestationEvidence
	if err := json.Unmarshal(att.RawEvidence, &got); err != nil {
		t.Fatalf("unmarshal ear_raw_evidence %s: %v", att.RawEvidence, err)
	}
	if got.Platform != submitted.Platform {
		t.Errorf("ear_raw_evidence platform = %q, want %q", got.Platform, submitted.Platform)
	}
	if string(got.Evidence) != string(submitted.Evidence) {
		t.Errorf("ear_raw_evidence evidence = %s, want %s", got.Evidence, submitted.Evidence)
	}
}

func TestAttestKeyRejectsMismatchedOperatorPolicy(t *testing.T) {
	const requiredHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	app := httptest.NewServer(testAppWithOperatorPolicy("http://unused", requiredHash))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	pubDER, err := x509.MarshalPKIXPublicKey(generateAttestKeyPubKey(t))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge:        challenge,
		Evidence:         types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		PublicKey:        base64.StdEncoding.EncodeToString(pubDER),
		OperatorKeysHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(app.URL+"/attest-key", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAttestKeyRejectsNonECDSAPubkey(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		PublicKey: base64.StdEncoding.EncodeToString([]byte("not-a-pubkey")),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(app.URL+"/attest-key", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func generateAttestKeyPubKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &key.PublicKey
}

func decodeJWTPayload(t *testing.T, token string, v any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		t.Fatalf("unmarshal JWT payload: %v", err)
	}
}

func ecdsaCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func rsaCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestParseAndVerifyCSRValid(t *testing.T) {
	csr, err := attestation.ParseAndVerifyCSR(ecdsaCSRPEM(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if csr == nil {
		t.Fatal("expected non-nil CSR")
	}
	if csr.Subject.CommonName != "test" {
		t.Fatalf("CN = %q, want test", csr.Subject.CommonName)
	}
}

func TestParseAndVerifyCSRNotPEM(t *testing.T) {
	if _, err := attestation.ParseAndVerifyCSR("not a pem block"); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestParseAndVerifyCSRWrongPEMType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("xx")})
	if _, err := attestation.ParseAndVerifyCSR(string(block)); err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func TestParseAndVerifyCSRMalformedBody(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")})
	if _, err := attestation.ParseAndVerifyCSR(string(block)); err == nil {
		t.Fatal("expected error for malformed CSR body")
	}
}

func TestParseAndVerifyCSRBadSignature(t *testing.T) {
	// Take a valid CSR and tamper with the signed CertificationRequestInfo
	// (TBS) region so the self-signature no longer verifies. ParseCertificate-
	// Request still succeeds structurally, but CheckSignature fails.
	valid := ecdsaCSRPEM(t)
	block, _ := pem.Decode([]byte(valid))
	raw := make([]byte, len(block.Bytes))
	copy(raw, block.Bytes)

	// Mutate a byte well inside the TBS portion (the subject/key region near the
	// front) rather than the trailing signature, so ParseCertificateRequest
	// still accepts the structure but the signature check fails.
	raw[40] ^= 0xff
	corrupted := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})

	// Either parsing fails outright or the signature check fails; both are
	// error returns from ParseAndVerifyCSR, which is what we assert.
	if _, err := attestation.ParseAndVerifyCSR(string(corrupted)); err == nil {
		t.Fatal("expected error for corrupted CSR")
	}
}

func TestECDSAPublicKeyFromCSRSuccess(t *testing.T) {
	csr, err := attestation.ParseAndVerifyCSR(ecdsaCSRPEM(t))
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	pub, err := attestation.ECDSAPublicKeyFromCSR(csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
	if !pub.Equal(csr.PublicKey) {
		t.Fatal("returned key does not match the CSR public key")
	}
}

func TestECDSAPublicKeyFromCSRNonECDSA(t *testing.T) {
	csr, err := attestation.ParseAndVerifyCSR(rsaCSRPEM(t))
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if _, err := attestation.ECDSAPublicKeyFromCSR(csr); err == nil {
		t.Fatal("expected error for non-ECDSA CSR public key")
	}
}

func TestHandleReadyzReady(t *testing.T) {
	h := attestation.HandleReadyz(func() bool { return true })
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestHandleReadyzNotReady(t *testing.T) {
	h := attestation.HandleReadyz(func() bool { return false })
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	attestation.WriteError(rec, http.StatusTeapot, "some_code", "some message")
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var out types.ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if out.Error != "some_code" || out.Message != "some message" {
		t.Fatalf("unexpected error envelope: %+v", out)
	}
}

func postAttestKey(t *testing.T, appURL, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(appURL+"/attest-key", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /attest-key: %v", err)
	}
	return resp
}

func TestAttestKeyInvalidJSONBody(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	resp := postAttestKey(t, app.URL, `{"unknown_field": 1}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
}

func TestAttestKeyInvalidChallengeBase64(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	body := mustJSON(types.AttestKeyRequestBody{
		Challenge: "!!!not-base64!!!",
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		PublicKey: "",
	})
	resp := postAttestKey(t, app.URL, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAttestKeyUnknownChallenge(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	// Valid base64 but never issued by the store.
	unknown := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := mustJSON(types.AttestKeyRequestBody{
		Challenge: unknown,
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		PublicKey: "",
	})
	resp := postAttestKey(t, app.URL, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAttestKeyInvalidPublicKeyBase64(t *testing.T) {
	app := httptest.NewServer(testApp("http://unused"))
	defer app.Close()

	challenge := authenticate(t, app.URL)
	body := mustJSON(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence:  types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		PublicKey: "!!!not-base64!!!",
	})
	resp := postAttestKey(t, app.URL, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// attestKeyBody builds a valid request body for a freshly authenticated
// challenge against the given app.
func attestKeyBody(t *testing.T, appURL string) string {
	t.Helper()
	challenge := authenticate(t, appURL)
	pubKey := generateAttestKeyPubKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return mustJSON(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence: types.AttestationEvidence{
			Platform: "snp",
			Evidence: json.RawMessage(`{"quote":"abc"}`),
		},
		PublicKey: base64.StdEncoding.EncodeToString(pubDER),
	})
}

func TestAttestKeySignatureInvalid(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, mockVerifyResponse(false, true))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testApp(mockAS.URL))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBody(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAttestKeyReportDataMismatch(t *testing.T) {
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, mockVerifyResponse(true, false))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testApp(mockAS.URL))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBody(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAttestKeyReportDataMatchNil(t *testing.T) {
	// ReportDataMatch omitted (nil) should be treated as a mismatch.
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, mustJSON(types.VerifyResponse{
			Result: types.VerificationResult{
				Platform:       "snp",
				SignatureValid: true,
				Claims:         types.Claims{},
				// ReportDataMatch left nil
			},
		}))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testApp(mockAS.URL))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBody(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAttestKeyAttestationAPIError(t *testing.T) {
	// Structured JSON error -> APIError -> 502.
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, mustJSON(types.ErrorResponse{Error: "bad", Message: "nope"}))
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testApp(mockAS.URL))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBody(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestAttestKeyAttestationUnexpectedError(t *testing.T) {
	// Non-JSON error body -> UnexpectedError -> 502.
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "plain text boom")
	}))
	defer mockAS.Close()

	app := httptest.NewServer(testApp(mockAS.URL))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBody(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestAttestKeyAttestationUnreachable(t *testing.T) {
	// Closed server -> transport RequestError -> 502.
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	asURL := mockAS.URL
	mockAS.Close() // immediately closed so the connection is refused

	app := httptest.NewServer(testApp(asURL))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBody(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}
