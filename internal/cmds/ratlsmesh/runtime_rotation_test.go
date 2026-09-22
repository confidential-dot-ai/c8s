//go:build linux

package ratlsmesh

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

type rotationTestEnvironment struct{ proxy *Proxy }

func (e rotationTestEnvironment) configure(*meshRuntime) *Proxy     { return e.proxy }
func (rotationTestEnvironment) start(context.Context, *meshRuntime) {}

func TestMeshRuntimeRotationFailuresIdentifyCertificateRole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, err := newMeshRuntime(&ratls.ServerConfig{
			Platform: "sev-snp", ClientPolicy: &ratls.VerifyPolicy{},
			AttestFunc: func(context.Context, string) (string, error) {
				return "", errors.New("attestation unavailable")
			},
		}, testLogger(), 0)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go r.serverCertMgr.RunRotation(ctx)
		go r.clientCertMgr.RunRotation(ctx)
		synctest.Wait()
		for _, role := range []string{"server", "client"} {
			if got := registryValue(t, r.metrics, "ratls_mesh_cert_rotation_failures_total", map[string]string{"role": role}); got != 1 {
				t.Errorf("%s rotation failures = %v, want 1", role, got)
			}
		}
		if r.serverCertMgr.CertReady() || r.clientCertMgr.CertReady() {
			t.Error("failed initial provisioning must leave both certificates unready")
		}
		cancel()
		synctest.Wait()
	})
}

func TestMeshRuntimeRotatesBothCertificatesWithoutBidirectionalTraffic(t *testing.T) {
	for _, traffic := range []string{"idle", "inbound only", "outbound only"} {
		t.Run(traffic, func(t *testing.T) {
			t.Parallel()
			const ttl = 4 * time.Second
			attest := mockapi.New(t)
			r, err := newMeshRuntime(&ratls.ServerConfig{
				Platform: "sev-snp", CertTTL: ttl, RotationTimeout: time.Second,
				AttestFunc:   makeAttestFunc(attestclient.NewClient(""), attest.URL()),
				ClientPolicy: &ratls.VerifyPolicy{AttestationApiURL: attest.URL()},
			}, testLogger(), 0)
			if err != nil {
				t.Fatal(err)
			}
			r.health = newHealthServer(r.metrics, r.serverCertMgr, r.clientCertMgr, 10, time.Second, time.Second)
			r.healthListener = bindLoopback(t)
			env := rotationTestEnvironment{proxy: &Proxy{
				inboundLn: bindLoopback(t), outboundLn: bindLoopback(t), drainTimeout: time.Second,
			}}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- r.run(ctx, env) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("runtime shutdown: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("runtime did not stop")
				}
			})
			assertEventually(t, 5*time.Second, func() bool {
				return rotationReadiness(r) == http.StatusOK
			}, "runtime did not become ready")
			initialServerExpiry := r.serverCertMgr.CertExpiry()
			initialClientExpiry := r.clientCertMgr.CertExpiry()
			peerServer, peerClient := testTLSConfigs(t)
			var exchange func()
			switch traffic {
			case "inbound only":
				exchange = func() { rotationHandshake(t, r.serverTLS, peerClient) }
			case "outbound only":
				exchange = func() { rotationHandshake(t, peerServer, r.clientTLS) }
			}
			deadline := time.Now().Add(ttl + time.Second)
			for time.Now().Before(deadline) {
				if status := rotationReadiness(r); status != http.StatusOK {
					t.Fatalf("readiness became %d during %s traffic", status, traffic)
				}
				if exchange != nil {
					exchange()
				}
				time.Sleep(100 * time.Millisecond)
			}
			if status := rotationReadiness(r); status != http.StatusOK {
				t.Fatalf("readiness after initial certificate lifetime = %d", status)
			}
			if !r.serverCertMgr.CertExpiry().After(initialServerExpiry) {
				t.Error("server certificate was not renewed")
			}
			if !r.clientCertMgr.CertExpiry().After(initialClientExpiry) {
				t.Error("client certificate was not renewed")
			}
		})
	}
}

func rotationReadiness(r *meshRuntime) int {
	response := httptest.NewRecorder()
	r.health.mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	return response.Code
}

func rotationHandshake(t *testing.T, server, client *tls.Config) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- tls.Server(serverConn, server).HandshakeContext(ctx) }()
	clientErr := tls.Client(clientConn, client).HandshakeContext(ctx)
	serverErr := <-serverDone
	if clientErr != nil || serverErr != nil {
		t.Fatalf("TLS handshake: client = %v, server = %v", clientErr, serverErr)
	}
}
