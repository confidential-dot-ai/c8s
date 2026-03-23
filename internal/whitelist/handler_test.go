package whitelist_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/readiness"
	"github.com/lunal-dev/c8s/internal/server"
	"github.com/lunal-dev/c8s/internal/whitelist"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/types"
)

const (
	digestA       = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	digestMissing = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	testPassword  = "test-password"
)

var adminPasswordB64 = base64.StdEncoding.EncodeToString([]byte(testPassword))

func authHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(testPassword))
}

func testWhitelistApp() (http.Handler, *readiness.Checker) {
	store, err := whitelist.OpenInMemory()
	if err != nil {
		panic(err)
	}

	asClient := attestationclient.NewClient("http://localhost:0")
	checker := readiness.NewChecker(asClient, 10*time.Second)

	challengeStore := attestation.NewChallengeStore(60 * time.Second)

	deps := server.Dependencies{
		AttestationHandler: attestation.Handler{
			Challenges: &challengeStore,
		},
		WhitelistHandler: whitelist.Handler{
			Store:            &store,
			AdminPasswordB64: adminPasswordB64,
		},
		ReadyFn: checker.Ready,
	}

	return server.NewRouter(deps), &checker
}

func TestHealthzReturnsOK(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
}

func TestReadyzReturnsUnavailableInitially(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want 503", resp.StatusCode)
	}
}

func TestWhitelistListEmpty(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/whitelist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var version string
	if err := json.Unmarshal(raw["version"], &version); err != nil {
		t.Fatalf("unmarshal version: %v", err)
	}
	if version != "1" {
		t.Fatalf("version = %q, want 1", version)
	}

	var digests map[string]string
	if err := json.Unmarshal(raw["digests"], &digests); err != nil {
		t.Fatalf("unmarshal digests: %v", err)
	}
	if len(digests) != 0 {
		t.Fatalf("expected empty digests, got %d entries", len(digests))
	}
}

func TestWhitelistAddRequiresAuth(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digest":"%s","image":"test-image"}`, digestA)
	resp, err := http.Post(srv.URL+"/whitelist", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestWhitelistAddRejectsWrongPassword(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digest":"%s","image":"test-image"}`, digestA)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/whitelist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("wrong-password")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func addDigest(t *testing.T, srvURL, digest, image string) {
	t.Helper()
	body := fmt.Sprintf(`{"digest":"%s","image":"%s"}`, digest, image)
	req, err := http.NewRequest(http.MethodPost, srvURL+"/whitelist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add digest got status %d, want 204", resp.StatusCode)
	}
}

func TestWhitelistAddAndListRoundtrip(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, digestA, "test-image")

	resp, err := http.Get(srv.URL + "/whitelist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}

	var result types.WhitelistListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	expectedDigest, _ := types.ParseDigest(digestA)
	img, ok := result.Digests[expectedDigest]
	if !ok {
		t.Fatal("digest not found in whitelist")
	}
	if img != "test-image" {
		t.Fatalf("image = %q, want test-image", img)
	}

	// version should have been incremented from "1" to "2"
	if result.Version != "2" {
		t.Fatalf("version = %q, want 2", result.Version)
	}
}

func TestWhitelistDeleteExistingReturnsNoContent(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	addDigest(t, srv.URL, digestA, "test-image")

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestA)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/whitelist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got status %d, want 204", resp.StatusCode)
	}

	// verify empty
	listResp, err := http.Get(srv.URL + "/whitelist")
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer listResp.Body.Close()

	var result types.WhitelistListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.Digests) != 0 {
		t.Fatalf("expected empty digests, got %d", len(result.Digests))
	}
}

func TestWhitelistDeleteNonexistentReturnsNotFound(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestMissing)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/whitelist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", resp.StatusCode)
	}
}

func TestWhitelistDeleteRequiresAuth(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := fmt.Sprintf(`{"digests":["%s"]}`, digestA)
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/whitelist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// no auth header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", resp.StatusCode)
	}
}

func TestWhitelistAddRejectsInvalidDigest(t *testing.T) {
	app, _ := testWhitelistApp()
	srv := httptest.NewServer(app)
	defer srv.Close()

	body := `{"digest":"sha256:abc","image":"test-image"}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/whitelist", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got status %d, want 422", resp.StatusCode)
	}
}
