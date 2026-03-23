package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/ratls/kbsclient"
)

func main() {
	// Subcommand dispatch (before flag.Parse so flags don't conflict).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "iptables-setup":
			iptablesSetup()
			return
		case "iptables-cleanup":
			iptablesCleanup()
			return
		}
	}

	var (
		platform          = flag.String("platform", "sev-snp", "TEE platform: sev-snp, tdx")
		attestCmd         = flag.String("attest-cmd", "", "path to attestation binary (e.g. /opt/lunal-services/attest-sev-snp)")
		outboundPort      = flag.Int("outbound-port", 15001, "outbound listener port (intercepted app traffic)")
		inboundPort       = flag.Int("inbound-port", 15006, "inbound listener port (RA-TLS from remote nodes)")
		nodeIP            = flag.String("node-ip", "", "this node's IP (auto-detected from NODE_IP env if unset)")
		logLevel          = flag.String("log-level", "info", "log level: debug, info, warn, error")
		dialTimeout       = flag.Duration("dial-timeout", 5*time.Second, "plain TCP dial timeout")
		tlsDialTimeout    = flag.Duration("tls-dial-timeout", 10*time.Second, "RA-TLS dial timeout")
		destHeaderTimeout = flag.Duration("dest-header-timeout", 5*time.Second, "inbound destination header read timeout")
		drainTimeout      = flag.Duration("drain-timeout", 30*time.Second, "graceful shutdown drain timeout")
		keepAlive         = flag.Duration("keepalive", 30*time.Second, "TCP keepalive interval (0 to disable)")
		idleTimeout       = flag.Duration("idle-timeout", 0, "close connections idle longer than this (0=disabled)")
		maxConns          = flag.Int("max-conns", 0, "max concurrent connections (0=unlimited)")
		maxConnsPerSource = flag.Int("max-conns-per-source", 0, "max concurrent connections per source IP (0=unlimited)")
		healthPort        = flag.Int("health-port", 15021, "health/metrics HTTP port")
		measurements      = flag.String("measurements", "", "comma-separated hex SHA-384 launch measurements (empty = accept any TEE)")
		certTTL           = flag.Duration("cert-ttl", 24*time.Hour, "RA-TLS certificate lifetime (rotates at 50%)")
		rotationTimeout   = flag.Duration("rotation-timeout", 30*time.Second, "max time for background certificate rotation")

		// KBS certificate issuance flags.
		certMode       = flag.String("cert-mode", "self-signed", "certificate mode: self-signed (default), kbs (boots self-signed, upgrades to KBS-issued in background)")
		kbsURL         = flag.String("kbs-url", "", "KBS URL for attestation (required for kbs mode)")
		certIssuerURL  = flag.String("cert-issuer-url", "", "KBS cert issuer URL (required for kbs mode)")
		kbsTEEType     = flag.String("kbs-tee-type", "az-snp-vtpm", "KBS TEE type for RCAR auth (az-snp-vtpm, snp, tdx)")
		caCertPath     = flag.String("ca-cert", "", "path to CA certificate file for peer verification")
		caURL          = flag.String("ca-url", "", "cert-issuer /v1/ca URL for periodic CA bundle refresh (KBS mode, replaces ConfigMap)")
		caPollInterval = flag.Duration("ca-poll-interval", 5*time.Minute, "interval to poll cert-issuer /v1/ca for CA bundle updates")

		sessionCacheSize     = flag.Int("session-cache-size", 64, "TLS session cache size per node (0 disables session resumption)")
		accessLog            = flag.Bool("access-log", true, "emit per-connection structured access log")
		certPipelineProbeURL = flag.String("cert-pipeline-probe-url", "", "cert-issuer /ready URL for pipeline health probing (empty = disabled)")

		kbsRetryBackoff    = flag.Duration("kbs-retry-backoff", 2*time.Second, "initial backoff duration for KBS certificate upgrade retries")
		kbsRetryMaxBackoff = flag.Duration("kbs-retry-max-backoff", 60*time.Second, "maximum backoff duration for KBS certificate upgrade retries")

		maxDestHeaderSize  = flag.Int("max-dest-header-size", 256, "maximum destination header size in bytes")
		pipeBufferSize     = flag.Int("pipe-buffer-size", 32768, "buffer size for TCP pipe forwarding")
		acceptErrThreshold = flag.Int64("accept-error-threshold", 10, "consecutive accept errors before marking unhealthy")
		healthReadTimeout  = flag.Duration("health-read-timeout", 5*time.Second, "health server read timeout")
		healthWriteTimeout = flag.Duration("health-write-timeout", 10*time.Second, "health server write timeout")

		// Background task intervals and timeouts.
		metricsUpdateInterval     = flag.Duration("metrics-update-interval", 10*time.Second, "interval for resolver cache and cert expiry metric updates")
		kbsOpTimeout              = flag.Duration("kbs-op-timeout", 30*time.Second, "per-operation timeout for KBS certificate upgrade and CA bundle refresh")
		certPipelineProbeTimeout  = flag.Duration("cert-pipeline-probe-timeout", 5*time.Second, "HTTP client timeout for cert pipeline health probe requests")
		certPipelineProbeInterval = flag.Duration("cert-pipeline-probe-interval", 60*time.Second, "interval between cert pipeline health probe requests")
	)
	flag.Parse()

	logger := certutil.NewJSONLogger(*logLevel)

	// Auto-detect node IP from Kubernetes downward API.
	if *nodeIP == "" {
		*nodeIP = os.Getenv("NODE_IP")
	}
	if *nodeIP == "" {
		logger.Error("node IP required: set --node-ip or NODE_IP env var")
		os.Exit(1)
	}

	if err := validateConfig(*attestCmd, *outboundPort, *inboundPort, *certTTL); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Build resolver (k8s is the only production resolver).
	config, err := rest.InClusterConfig()
	if err != nil {
		logger.Error("k8s in-cluster config failed", "error", err)
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error("k8s clientset creation failed", "error", err)
		os.Exit(1)
	}
	resolver, err := newK8sResolver(ctx, clientset, *nodeIP, logger)
	if err != nil {
		logger.Error("k8s resolver failed", "error", err)
		os.Exit(1)
	}

	attestFunc := makeAttestFunc(*attestCmd)

	meshPolicy := &ratls.VerifyPolicy{}
	if *measurements != "" {
		for _, h := range strings.Split(*measurements, ",") {
			h = strings.TrimSpace(h)
			b, err := hex.DecodeString(h)
			if err != nil {
				logger.Error("invalid measurement hex", "value", h, "error", err)
				os.Exit(1)
			}
			if len(b) != ratls.SNPMeasurementSize {
				logger.Error("invalid measurement length",
					"value", h,
					"got_bytes", len(b),
					"want_bytes", ratls.SNPMeasurementSize,
					"hint", fmt.Sprintf("SHA-384 measurement must be exactly %d hex characters", ratls.SNPMeasurementSize*2))
				os.Exit(1)
			}
			meshPolicy.Measurements = append(meshPolicy.Measurements, b)
		}
		logger.Info("measurement pinning enabled", "count", len(meshPolicy.Measurements))
	} else {
		logger.Warn("no --measurements set: accepting any TEE attestation (unsafe for production)")
	}

	// Load CA certificate(s) for dual-mode verification (kbs mode).
	// Supports multi-PEM bundles for safe CA rotation.
	var caCerts []*x509.Certificate
	if *caCertPath != "" {
		var caErr error
		caCerts, caErr = certutil.LoadPEMCertificatesFile(*caCertPath)
		if caErr != nil {
			logger.Error("failed to load CA certificate(s)", "path", *caCertPath, "error", caErr)
			os.Exit(1)
		}
		names := make([]string, len(caCerts))
		for i, c := range caCerts {
			names[i] = c.Subject.CommonName
		}
		logger.Info("CA certificate(s) loaded for dual-mode verification", "count", len(caCerts), "subjects", names)
	}

	// Validate cert-mode specific flags.
	if *certMode != "self-signed" && *certMode != "kbs" {
		logger.Error("invalid --cert-mode", "mode", *certMode, "valid", "self-signed, kbs")
		os.Exit(1)
	}
	if *certMode == "kbs" && (*kbsURL == "" || *certIssuerURL == "") {
		logger.Error("--kbs-url and --cert-issuer-url are required for --cert-mode kbs")
		os.Exit(1)
	}

	serverTLS, serverCertMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:        *platform,
		AttestFunc:      attestFunc,
		DNSNames:        []string{*nodeIP},
		CertTTL:         *certTTL,
		ClientPolicy:    meshPolicy,
		CACert:          caCerts,
		DynamicCACert:   *caURL != "",
		RotationTimeout: *rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("failed to create server TLS config", "error", err)
		os.Exit(1)
	}

	clientTLS, clientCertMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:          meshPolicy,
		Platform:        *platform,
		AttestFunc:      attestFunc,
		CACert:          caCerts,
		DynamicCACert:   *caURL != "",
		CertTTL:         *certTTL,
		RotationTimeout: *rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("failed to create client TLS config", "error", err)
		os.Exit(1)
	}

	if *sessionCacheSize > 0 {
		clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(*sessionCacheSize)
	}

	m := newMetrics()
	if *certMode == "kbs" {
		m.certModeExpected.Store(1)
	}
	if len(meshPolicy.Measurements) > 0 {
		m.measurementPinning.Store(1)
	}

	// Wire attestation failure counter into TLS peer verification callbacks.
	wrapVerify := func(orig func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
		if orig == nil {
			return nil
		}
		return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			err := orig(rawCerts, chains)
			if err != nil {
				m.attestationFailures.Add(1)
			}
			return err
		}
	}
	serverTLS.VerifyPeerCertificate = wrapVerify(serverTLS.VerifyPeerCertificate)
	clientTLS.VerifyPeerCertificate = wrapVerify(clientTLS.VerifyPeerCertificate)

	// Wire rotation failure metrics.
	serverCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Add(1) })
	if clientCertMgr != nil {
		clientCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Add(1) })
	}

	health := newHealthServer(m, serverCertMgr, clientCertMgr, *acceptErrThreshold, *healthReadTimeout, *healthWriteTimeout)

	var connSem chan struct{}
	if *maxConns > 0 {
		connSem = make(chan struct{}, *maxConns)
	}

	proxy := &Proxy{
		outboundAddr:      fmt.Sprintf(":%d", *outboundPort),
		inboundAddr:       fmt.Sprintf(":%d", *inboundPort),
		serverTLS:         serverTLS,
		clientTLS:         clientTLS,
		nodeIP:            *nodeIP,
		inboundPort:       *inboundPort,
		resolver:          resolver,
		origDstFunc:       defaultOrigDstFunc,
		logger:            logger,
		metrics:           m,
		accessLog:         *accessLog,
		dialTimeout:       *dialTimeout,
		tlsDialTimeout:    *tlsDialTimeout,
		destHeaderTimeout: *destHeaderTimeout,
		drainTimeout:      *drainTimeout,
		keepAlive:         *keepAlive,
		idleTimeout:       *idleTimeout,
		maxDestHeaderSize: *maxDestHeaderSize,
		pipeBufferSize:    *pipeBufferSize,
		bufPool:           newBufPool(*pipeBufferSize),
		connSem:           connSem,
		maxConnsPerSrc:    *maxConnsPerSource,
		onReady: func() {
			// Eagerly provision certificates before marking ready.
			// Bound the warm-up so a hanging attestation binary (missing
			// /dev/sev, TPM not loaded) doesn't block readiness forever.
			warmupTimeout := 2 * durOrDefault(*rotationTimeout, 30*time.Second)
			warmupCtx, warmupCancel := context.WithTimeout(ctx, warmupTimeout)
			defer warmupCancel()

			if err := serverCertMgr.WarmUp(warmupCtx); err != nil {
				logger.Error("server certificate warm-up failed", "error", err)
			}
			if clientCertMgr != nil {
				if err := clientCertMgr.WarmUp(warmupCtx); err != nil {
					logger.Error("client certificate warm-up failed", "error", err)
				}
			}
			health.ready.Store(true)
		},
		onShutdown: func() { health.ready.Store(false) },
	}

	// Start health/metrics server.
	go func() {
		if err := health.serve(ctx, fmt.Sprintf(":%d", *healthPort)); err != nil {
			logger.Error("health server error", "error", err)
		}
	}()

	// Periodically update resolver cache and cert expiry metrics.
	go func() {
		t := time.NewTicker(*metricsUpdateInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.resolverCacheSize.Store(int64(resolver.CacheSize()))
				m.resolverLastEventTime.Store(resolver.LastEventTime())

				if exp := serverCertMgr.CertExpiry(); !exp.IsZero() {
					m.certExpiryServer.Store(exp.Unix())
				}
				if clientCertMgr != nil {
					if exp := clientCertMgr.CertExpiry(); !exp.IsZero() {
						m.certExpiryClient.Store(exp.Unix())
					}
				}
			}
		}
	}()

	// Shared KBS config for both certificate upgrade and CA bundle refresh.
	var kbsCfg *kbsclient.Config
	if *certMode == "kbs" {
		kbsCfg = &kbsclient.Config{
			KBSURL:     *kbsURL,
			IssuerURL:  *certIssuerURL,
			TEEType:    *kbsTEEType,
			AttestFunc: makeKBSAttestFunc(*attestCmd),
			CertTTL:    *certTTL,
			NodeIP:     *nodeIP,
		}
	}

	// KBS certificate upgrade: after self-signed RA-TLS
	// boot, a background goroutine contacts KBS, gets CA-signed certs, and
	// hot-swaps them via CertManager.SwapProvider.
	if *certMode == "kbs" {
		go func() {
			kbsProvider, err := kbsclient.NewProvider(kbsCfg, logger)
			if err != nil {
				logger.Error("kbs provider creation failed", "error", err)
				return
			}

			// Wait for KBS to become reachable. Retry with backoff.
			backoff := *kbsRetryBackoff
			maxBackoff := *kbsRetryMaxBackoff
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}

				upgradeCtx, cancel := context.WithTimeout(ctx, *kbsOpTimeout)
				err := serverCertMgr.SwapProvider(upgradeCtx, kbsProvider)
				cancel()
				if err == nil {
					logger.Info("certificate upgraded from self-signed to KBS-issued (server)")
					break
				}
				logger.Warn("KBS certificate upgrade attempt failed (will retry)", "error", err, "backoff", backoff)
				backoff = min(backoff*2, maxBackoff)
			}

			// Upgrade client cert too.
			if clientCertMgr != nil {
				upgradeCtx, cancel := context.WithTimeout(ctx, *kbsOpTimeout)
				if err := clientCertMgr.SwapProvider(upgradeCtx, kbsProvider); err != nil {
					logger.Warn("KBS client certificate upgrade failed", "error", err)
				} else {
					logger.Info("certificate upgraded from self-signed to KBS-issued (client)")
				}
				cancel()
			}

			m.certMode.Store(1) // 1 = kbs mode active
		}()
	}

	// CA bundle refresh: periodically poll cert-issuer /v1/ca for updated CA bundle.
	// In KBS key mode, the ConfigMap is not used; the cert-issuer serves the bundle.
	if *caURL != "" && *certMode == "kbs" {
		go func() {
			kbsClient := kbsclient.NewClient(kbsCfg)

			ticker := time.NewTicker(*caPollInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					refreshCtx, cancel := context.WithTimeout(ctx, *kbsOpTimeout)
					newCerts, err := kbsClient.RefreshCABundle(refreshCtx)
					cancel()
					if err != nil {
						logger.Warn("CA bundle refresh failed", "url", *caURL, "error", err)
						continue
					}
					// Update the server and client TLS configs with the new CA bundle.
					serverCertMgr.UpdateCACerts(newCerts)
					if clientCertMgr != nil {
						clientCertMgr.UpdateCACerts(newCerts)
					}
					logger.Debug("CA bundle refreshed from cert-issuer", "count", len(newCerts))
				}
			}
		}()
		logger.Info("CA bundle refresh enabled", "url", *caURL, "interval", *caPollInterval)
	}

	// Cert pipeline health probe: periodically check cert-issuer /ready.
	if *certPipelineProbeURL != "" {
		m.certPipelineHealthy.Store(0) // Start as unhealthy until first probe succeeds.
		go func() {
			client := &http.Client{Timeout: *certPipelineProbeTimeout}
			ticker := time.NewTicker(*certPipelineProbeInterval)
			defer ticker.Stop()

			probe := func() {
				resp, err := client.Get(*certPipelineProbeURL)
				if err != nil || resp.StatusCode != http.StatusOK {
					if m.certPipelineHealthy.Swap(0) != 0 {
						logger.Warn("cert pipeline probe failed", "url", *certPipelineProbeURL, "error", err)
					}
					if resp != nil {
						resp.Body.Close()
					}
					return
				}
				resp.Body.Close()
				if m.certPipelineHealthy.Swap(1) != 1 {
					logger.Info("cert pipeline probe healthy", "url", *certPipelineProbeURL)
				}
			}

			probe() // Initial probe immediately.
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					probe()
				}
			}
		}()
		logger.Info("cert pipeline health probe enabled", "url", *certPipelineProbeURL)
	} else {
		m.certPipelineHealthy.Store(-1) // Not configured.
	}

	logger.Info("starting ratls-mesh",
		"outbound", proxy.outboundAddr,
		"inbound", proxy.inboundAddr,
		"node", *nodeIP,
		"platform", *platform,
		"cert_mode", *certMode,
		"resolver", "k8s",
		"health_port", *healthPort,
		"max_conns", *maxConns,
		"max_conns_per_source", *maxConnsPerSource,
		"idle_timeout", *idleTimeout,
		"keepalive", *keepAlive,
		"session_cache_size", *sessionCacheSize,
	)

	if err := proxy.Run(ctx); err != nil {
		logger.Error("proxy error", "error", err)
		os.Exit(1)
	}
}

// validateConfig checks for misconfigurations that would cause cryptic runtime
// failures. Called once at startup before any goroutine.
func validateConfig(attestCmd string, outboundPort, inboundPort int, certTTL time.Duration) error {
	if attestCmd == "" {
		return fmt.Errorf("--attest-cmd is required (path to attestation binary)")
	}
	if _, err := exec.LookPath(attestCmd); err != nil {
		return fmt.Errorf("--attest-cmd %q not found in PATH: %w", attestCmd, err)
	}
	if outboundPort == inboundPort {
		return fmt.Errorf("--outbound-port and --inbound-port must differ (both are %d)", outboundPort)
	}
	if certTTL < time.Minute {
		return fmt.Errorf("--cert-ttl %s is too short (minimum 1m to avoid rotation thrashing)", certTTL)
	}
	return nil
}

// makeAttestFunc returns an AttestFunc that shells out to the attestation binary.
// Uses --report-data for RA-TLS self-signed certificates.
func makeAttestFunc(cmd string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, customData string) (string, error) {
		if cmd == "" {
			return "", fmt.Errorf("no attestation command configured (set --attest-cmd)")
		}
		c := exec.CommandContext(ctx, cmd, "--report-data", customData)
		out, err := c.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("attestation command failed: %w\noutput: %s", err, out)
		}
		return string(out), nil
	}
}

// makeKBSAttestFunc returns an AttestFunc for KBS RCAR attestation.
// Uses "attest --kbs <runtime_data>" subcommand which outputs JSON format
// compatible with Trustee KBS (unlike --report-data which is for RA-TLS self-signed).
// The binary may exit non-zero due to non-critical errors (e.g. read-only filesystem)
// while still producing valid evidence on stdout, so we accept the output if it
// starts with '{' (valid JSON evidence).
func makeKBSAttestFunc(cmd string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, runtimeDataB64 string) (string, error) {
		if cmd == "" {
			return "", fmt.Errorf("no attestation command configured (set --attest-cmd)")
		}
		c := exec.CommandContext(ctx, cmd, "attest", "--kbs", runtimeDataB64)
		var stdout, stderr bytes.Buffer
		c.Stdout = &stdout
		c.Stderr = &stderr
		err := c.Run()
		out := strings.TrimSpace(stdout.String())
		if err != nil {
			// The binary may produce valid evidence on stdout but exit non-zero
			// due to non-critical filesystem errors. Accept if stdout has JSON.
			if out != "" && out[0] == '{' {
				return out, nil
			}
			return "", fmt.Errorf("attestation command (kbs) failed: %w\nstderr: %s\nstdout: %s", err, stderr.String(), out)
		}
		return out, nil
	}
}
