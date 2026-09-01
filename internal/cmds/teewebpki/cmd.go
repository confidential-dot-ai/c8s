// Package teewebpki runs the tls-lb helper for tee-webpki mode.
package teewebpki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

type config struct {
	CDSURL          string
	CDSMeasurements string
	CDSRTMRs        string
	AttestationURL  string
	MeshCert        string
	MeshKey         string
	DNSNames        []string
	OutCert         string
	OutKey          string
	OutCSR          string
	PublicRoots     string
	ReadyAddress    string
	PollInterval    time.Duration
	WaitTimeout     time.Duration
	Once            bool
	ReloadNginx     bool
}

// NewCmd returns the TEE WebPKI state helper.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "tee-webpki",
		Short: "Load the cluster WebPKI key from CDS inside an attested tls-lb",
		RunE: func(*cobra.Command, []string) error {
			return run(cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.CDSURL, "cds-url", "", "direct RA-TLS CDS base URL")
	f.StringVar(&cfg.CDSMeasurements, "cds-measurements", "", "comma-separated pinned CDS launch measurements")
	f.StringVar(&cfg.CDSRTMRs, "cds-rtmrs", "", "comma-separated pinned CDS TDX RTMR values")
	f.StringVar(&cfg.AttestationURL, "attestation-api-url", "", "local attestation-api URL")
	f.StringVar(&cfg.MeshCert, "mesh-cert", "", "CDS-issued tls-lb mesh certificate")
	f.StringVar(&cfg.MeshKey, "mesh-key", "", "private key for --mesh-cert")
	f.StringSliceVar(&cfg.DNSNames, "dns-name", nil, "public DNS name for the CSR and certificate; repeatable")
	f.StringVar(&cfg.OutCert, "out-cert", "", "public certificate output path")
	f.StringVar(&cfg.OutKey, "out-key", "", "TEE-held private key output path")
	f.StringVar(&cfg.OutCSR, "out-csr", "", "public CSR output path")
	f.StringVar(&cfg.PublicRoots, "public-roots", "", "optional PEM roots used to verify the public certificate; empty uses system roots")
	f.StringVar(&cfg.ReadyAddress, "ready-address", "127.0.0.1:8801", "readiness listener address; empty disables it")
	f.DurationVar(&cfg.PollInterval, "poll-interval", 30*time.Second, "CDS state poll interval")
	f.DurationVar(&cfg.WaitTimeout, "wait-timeout", 15*time.Minute, "maximum time --once waits for a valid public certificate")
	f.BoolVar(&cfg.Once, "once", false, "publish the CSR, wait for a valid public certificate, then exit")
	f.BoolVar(&cfg.ReloadNginx, "reload-nginx", false, "SIGHUP nginx after the sidecar installs a new public certificate")
	cmd.AddCommand(newCSRCmd(), newInstallCertificateCmd())
	return cmd
}

func run(cfg config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	client, err := newClient(cfg)
	if err != nil {
		return err
	}
	s := &syncer{cfg: cfg, client: client, reload: reloadNginx}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Once {
		waitCtx, cancel := context.WithTimeout(ctx, cfg.WaitTimeout)
		defer cancel()
		return s.waitForCertificate(waitCtx)
	}
	go s.serveReady(ctx)
	for {
		ready, err := s.sync(ctx)
		s.setReady(ready)
		if err != nil {
			s.setReady(false)
			fmt.Fprintf(os.Stderr, "tee-webpki sync failed: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(cfg.PollInterval):
		}
	}
}

func (s *syncer) waitForCertificate(ctx context.Context) error {
	for {
		ready, syncErr := s.sync(ctx)
		if syncErr == nil && ready {
			return nil
		}
		select {
		case <-ctx.Done():
			if syncErr != nil {
				return fmt.Errorf("wait for public certificate: %w", syncErr)
			}
			return fmt.Errorf("wait for public certificate: %w", ctx.Err())
		case <-time.After(s.cfg.PollInterval):
		}
	}
}

func validateConfig(cfg config) error {
	for name, value := range map[string]string{
		"--cds-url": cfg.CDSURL, "--attestation-api-url": cfg.AttestationURL,
		"--mesh-cert": cfg.MeshCert, "--mesh-key": cfg.MeshKey,
		"--out-cert": cfg.OutCert, "--out-key": cfg.OutKey, "--out-csr": cfg.OutCSR,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	u, err := url.Parse(cfg.CDSURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("--cds-url must be a direct https RA-TLS endpoint")
	}
	if len(cfg.DNSNames) == 0 {
		return fmt.Errorf("at least one --dns-name is required")
	}
	for _, name := range cfg.DNSNames {
		if strings.TrimSpace(name) == "" || net.ParseIP(name) != nil {
			return fmt.Errorf("--dns-name %q must be a DNS name", name)
		}
	}
	if cfg.PollInterval <= 0 {
		return fmt.Errorf("--poll-interval must be positive")
	}
	if cfg.WaitTimeout <= 0 {
		return fmt.Errorf("--wait-timeout must be positive")
	}
	return nil
}

func newClient(cfg config) (*http.Client, error) {
	measurements, err := ratls.ParseHexMeasurements(cfg.CDSMeasurements)
	if err != nil {
		return nil, fmt.Errorf("--cds-measurements: %w", err)
	}
	if len(measurements) == 0 {
		return nil, fmt.Errorf("--cds-measurements must pin the CDS build")
	}
	rtmrs, err := ratls.ParseRTMRPinsString(cfg.CDSRTMRs)
	if err != nil {
		return nil, fmt.Errorf("--cds-rtmrs: %w", err)
	}
	client, err := ratls.NewVerifyingHTTPClient(ratls.Pins{Measurements: measurements, RTMRs: rtmrs}, cfg.AttestationURL)
	if err != nil {
		return nil, err
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return nil, fmt.Errorf("RA-TLS client has no TLS transport")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(cfg.MeshCert, cfg.MeshKey)
		if err != nil {
			return nil, fmt.Errorf("load tls-lb mesh identity: %w", err)
		}
		return &cert, nil
	}
	client.Transport = transport
	client.Timeout = 15 * time.Second
	return client, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return x509.SystemCertPool()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("public roots contain no certificates")
	}
	return pool, nil
}

func writePrivateKey(path string, key any) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func parseCertificateChain(chainPEM []byte) (*x509.Certificate, []*x509.Certificate, error) {
	certs, err := certutil.ParsePEMCertificates(chainPEM)
	if err != nil || len(certs) == 0 {
		return nil, nil, fmt.Errorf("parse public certificate chain: %w", err)
	}
	return certs[0], certs[1:], nil
}

func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }
