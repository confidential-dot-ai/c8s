package credrelease

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// stageMeasuredOperatorKey writes pubPEM to the (test-overridden) staging path
// and a matching fake RTMR[3], as the measured initrd would have.
func stageMeasuredOperatorKey(t *testing.T, pubPEM []byte) {
	t.Helper()
	pubPath, rtmrPath := overrideBindingPaths(t)
	writeFileT(t, pubPath, pubPEM)
	writeFileT(t, rtmrPath, expectedRTMR3ForKey(pubPEM))
}

// freshOperatorPubPEM generates a fresh ECDSA keypair and returns the PKIX
// public-key PEM the initrd would stage.
func freshOperatorPubPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// fakeAttestationAPI is a stand-in for the local attestation-api: POST /attest
// returns a syntactically valid TDX evidence envelope (no real quote — the
// RA-TLS serving cert only embeds it, nothing verifies it in these tests).
func fakeAttestationAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.AttestResponse{
			Platform: string(types.PlatformTdx),
			Evidence: json.RawMessage(`{"quote":"ZmFrZS1xdW90ZQ=="}`),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// policyDir writes what c8s-policy-measure leaves for the given mode and
// returns the directory. members is the static bundle (nil on dynamic).
func policyDir(t *testing.T, mode string, members map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	if members != nil {
		bundle, err := policybundle.FromMembers(members)
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range members {
			writeFileT(t, filepath.Join(dir, name), data)
		}
		sum := bundle.IndexDigest()
		writeFileT(t, filepath.Join(dir, policybundle.DigestFile), []byte(hex.EncodeToString(sum[:])))
	}
	writeFileT(t, filepath.Join(dir, policybundle.ModeFile), []byte(mode+"\n"))
	return dir
}

// sealedBundle is a one-member bundle whose allowlist LintSealed accepts.
func sealedBundle(t *testing.T) map[string][]byte {
	t.Helper()
	doc := `{"schema":"c8s.allowlist/v1","digests":{},"workloads":{"web":{"containers":[{"digest":"sha256:` + strings.Repeat("a", 64) + `",` +
		`"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","destinations":["/etc/hosts"],"rules":{"/etc/hosts":{"source":"platform"}}},` +
		`"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}}}]}}}`
	al, err := allowlist.ParseJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{policybundle.MemberStaticAllowlist: canonical}
}

// runnableConfig stages a measured operator key, a dynamic policy dir,
// on-disk CAs, and a fake attestation-api, returning a Config Run can fully
// start from.
func runnableConfig(t *testing.T) Config {
	t.Helper()
	stageMeasuredOperatorKey(t, freshOperatorPubPEM(t))
	dir := t.TempDir()
	clientCert, clientKey, _ := namedCA(t, dir, "client-ca")
	serverCert, _, _ := namedCA(t, dir, "server-ca")
	return Config{
		ListenAddr:        "127.0.0.1:0",
		AttestationAPIURL: fakeAttestationAPI(t).URL,
		Platform:          "tdx",
		PolicyDir:         policyDir(t, policybundle.DynamicMode, nil),
		ClientCACert:      clientCert,
		ClientCAKey:       clientKey,
		ServerCACert:      serverCert,
		CertTTL:           defaultCertTTL,
		CertOrg:           defaultCertOrg,
		CertCN:            defaultCertCN,
	}
}

// staticConfig is runnableConfig for a static boot: no operator key, the
// bundle published under the policy dir, RTMR[3] at the bundle's value.
func staticConfig(t *testing.T) Config {
	t.Helper()
	cfg := runnableConfig(t)
	members := sealedBundle(t)
	bundle, err := policybundle.FromMembers(members)
	if err != nil {
		t.Fatal(err)
	}
	_, rtmrPath := overrideBindingPaths(t) // no pubkey staged
	reg := bundle.RTMR3()
	writeFileT(t, rtmrPath, reg[:])
	cfg.PolicyDir = policyDir(t, policybundle.StaticMode, members)
	return cfg
}

// TestRunStartupErrors walks Run's fail-closed startup ladder: missing
// platform, unwritten or tampered policy state, unmeasured key or bundle,
// unreadable CA, non-ECDSA key, and a dead attestation-api at warm-up. Each
// row names the rung it fails on, so a later rung cannot mask a removed one.
func TestRunStartupErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func(t *testing.T) Config
		wantErr string // substring naming the rung that failed
	}{
		{
			name:    "platform required",
			wantErr: "--platform is required",
			cfg: func(t *testing.T) Config {
				return Config{Platform: ""}
			},
		},
		{
			name:    "platform value validated before privileged reads",
			wantErr: "--platform:",
			cfg: func(t *testing.T) Config {
				return Config{Platform: "foo"}
			},
		},
		{
			name:    "policy mode not written",
			wantErr: "policy mode",
			cfg: func(t *testing.T) Config {
				overrideBindingPaths(t)
				return Config{Platform: "tdx", PolicyDir: t.TempDir()}
			},
		},
		{
			name:    "operator key not staged",
			wantErr: "load measured operator key",
			cfg: func(t *testing.T) Config {
				cfg := runnableConfig(t)
				overrideBindingPaths(t) // paths exist, files do not
				return cfg
			},
		},
		{
			name:    "static mode on snp",
			wantErr: "TDX-only",
			cfg: func(t *testing.T) Config {
				cfg := staticConfig(t)
				cfg.Platform = "snp"
				return cfg
			},
		},
		{
			name:    "static mode with the register at the dynamic value",
			wantErr: "does not match the measured RTMR[3]",
			cfg: func(t *testing.T) Config {
				cfg := staticConfig(t)
				_, rtmrPath := overrideBindingPaths(t)
				reg := runtimemeasure.ForDynamic(runtimemeasure.Zero)
				writeFileT(t, rtmrPath, reg[:])
				return cfg
			},
		},
		{
			name:    "static mode with a member rewritten after measurement",
			wantErr: "members index to",
			cfg: func(t *testing.T) Config {
				cfg := staticConfig(t)
				member := filepath.Join(cfg.PolicyDir, policybundle.MemberStaticAllowlist)
				data, err := os.ReadFile(member)
				if err != nil {
					t.Fatal(err)
				}
				writeFileT(t, member, append(data, ' '))
				return cfg
			},
		},
		{
			name:    "static mode with the register missing",
			wantErr: "verify static bundle: read",
			cfg: func(t *testing.T) Config {
				cfg := staticConfig(t)
				overrideBindingPaths(t)
				return cfg
			},
		},
		{
			name:    "cluster CA unreadable",
			wantErr: "load cluster CA",
			cfg: func(t *testing.T) Config {
				stageMeasuredOperatorKey(t, freshOperatorPubPEM(t))
				missing := filepath.Join(t.TempDir(), "missing")
				return Config{Platform: "tdx", PolicyDir: policyDir(t, policybundle.DynamicMode, nil), ClientCACert: missing, ClientCAKey: missing, ServerCACert: missing}
			},
		},
		{
			name:    "measured key is not an ECDSA PKIX PEM",
			wantErr: "build handler",
			cfg: func(t *testing.T) Config {
				cfg := runnableConfig(t)
				// Measured (RTMR matches) but unusable for operatorauth.
				stageMeasuredOperatorKey(t, []byte("measured but not a key"))
				return cfg
			},
		},
		{
			name:    "attestation-api down at warm-up",
			wantErr: "warm up RA-TLS serving cert",
			cfg: func(t *testing.T) Config {
				cfg := runnableConfig(t)
				cfg.AttestationAPIURL = "http://127.0.0.1:1" // nothing listens
				return cfg
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Run(context.Background(), tc.cfg(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Run(%s) = %v, want error containing %q", tc.name, err, tc.wantErr)
			}
		})
	}
}

// TestRunServesAndShutsDown starts the full service (fake attestation-api,
// temp CAs, measured key or published bundle), waits for it to accept
// connections, then cancels the context and expects a clean shutdown.
func TestRunServesAndShutsDown(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func(t *testing.T) Config
	}{
		{"dynamic", runnableConfig},
		{"static", staticConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runServesAndShutsDown(t, tc.cfg(t))
		})
	}
}

func runServesAndShutsDown(t *testing.T, cfg Config) {
	t.Helper()
	// Reserve a port so the test knows where to probe.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenAddr = ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", cfg.ListenAddr, time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never started accepting connections")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestRunReturnsListenError: with the port already taken, the serve goroutine
// fails and Run surfaces the bind error (the errCh select arm). Everything else
// in the config is startable, so the only possible failure is the bind.
func TestRunReturnsListenError(t *testing.T) {
	cfg := runnableConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg.ListenAddr = ln.Addr().String() // already bound

	if err := Run(context.Background(), cfg); err == nil {
		t.Error("Run with an already-bound listen address returned nil, want bind error")
	}
}
