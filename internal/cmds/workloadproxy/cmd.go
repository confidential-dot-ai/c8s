// Package workloadproxy provides a small L4 proxy that binds a connection to
// exact c8s workload identities. The application-facing hop is plaintext only
// on pod loopback. The cross-pod hop uses CDS-issued mesh certificates.
package workloadproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	modeClient = "client"
	modeServer = "server"

	defaultDialTimeout      = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	defaultIdleTimeout      = 5 * time.Minute
	defaultShutdownTimeout  = 30 * time.Second
	defaultMaxConnections   = 1024
	maxCredentialBytes      = 1 << 20
)

type config struct {
	mode             string
	listen           string
	upstream         string
	peerWorkload     string
	certFile         string
	keyFile          string
	caFile           string
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	idleTimeout      time.Duration
	shutdownTimeout  time.Duration
	maxConnections   int
}

// NewCmd returns the workload-proxy command.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:          "workload-proxy",
		Short:        "Proxy TCP to one exact c8s workload identity",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error {
			return run(cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.mode, "mode", "", "proxy mode: client or server")
	f.StringVar(&cfg.listen, "listen", "", "TCP listen address")
	f.StringVar(&cfg.upstream, "upstream", "", "client: TLS peer; server: fixed loopback plaintext target")
	f.StringVar(&cfg.peerWorkload, "peer-workload", "", "exact matched-workload name required in the peer certificate")
	f.StringVar(&cfg.certFile, "cert-file", "", "get-cert leaf and certificate chain PEM")
	f.StringVar(&cfg.keyFile, "key-file", "", "get-cert private key PEM")
	f.StringVar(&cfg.caFile, "ca-file", "", "CDS mesh CA bundle PEM")
	f.DurationVar(&cfg.dialTimeout, "dial-timeout", defaultDialTimeout, "upstream TCP dial timeout")
	f.DurationVar(&cfg.handshakeTimeout, "handshake-timeout", defaultHandshakeTimeout, "TLS handshake timeout")
	f.DurationVar(&cfg.idleTimeout, "idle-timeout", defaultIdleTimeout, "connection idle timeout")
	f.DurationVar(&cfg.shutdownTimeout, "shutdown-timeout", defaultShutdownTimeout, "maximum graceful shutdown wait")
	f.IntVar(&cfg.maxConnections, "max-connections", defaultMaxConnections, "maximum active connections")
	return cmd
}

func run(cfg config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.listen, err)
	}
	defer ln.Close()
	return serve(ctx, cfg, ln, slog.Default())
}

func validateConfig(cfg config) error {
	if cfg.mode != modeClient && cfg.mode != modeServer {
		return fmt.Errorf("--mode must be %q or %q", modeClient, modeServer)
	}
	listenIP, err := numericHostPort("--listen", cfg.listen)
	if err != nil {
		return err
	}
	if cfg.mode == modeClient && !listenIP.IsLoopback() {
		return fmt.Errorf("client --listen must be a numeric loopback address")
	}
	if cfg.upstream == "" {
		return fmt.Errorf("--upstream is required")
	}
	if cfg.mode == modeServer {
		targetIP, err := numericHostPort("server --upstream", cfg.upstream)
		if err != nil {
			return err
		}
		if !targetIP.IsLoopback() {
			return fmt.Errorf("server --upstream must be a numeric loopback address")
		}
	} else if _, _, err := net.SplitHostPort(cfg.upstream); err != nil {
		return fmt.Errorf("client --upstream must be host:port: %w", err)
	}
	if !allowlist.ValidWorkloadName(cfg.peerWorkload) {
		return fmt.Errorf("--peer-workload %q is not a valid c8s workload name", cfg.peerWorkload)
	}
	for flag, path := range map[string]string{
		"--cert-file": cfg.certFile,
		"--key-file":  cfg.keyFile,
		"--ca-file":   cfg.caFile,
	} {
		if path == "" {
			return fmt.Errorf("%s is required", flag)
		}
	}
	if cfg.dialTimeout <= 0 || cfg.handshakeTimeout <= 0 || cfg.idleTimeout <= 0 || cfg.shutdownTimeout <= 0 {
		return fmt.Errorf("all timeout values must be positive")
	}
	if cfg.maxConnections < 1 || cfg.maxConnections > 65536 {
		return fmt.Errorf("--max-connections must be between 1 and 65536")
	}
	return nil
}

func numericHostPort(flag, value string) (net.IP, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be a numeric IP and port: %w", flag, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("%s host %q is not a numeric IP", flag, host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("%s port %q is outside 1..65535", flag, port)
	}
	return ip, nil
}

func serve(ctx context.Context, cfg config, ln net.Listener, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if err := validateCredentialFiles(cfg); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	sem := make(chan struct{}, cfg.maxConnections)
	var active sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			return fmt.Errorf("accept: %w", err)
		}
		select {
		case sem <- struct{}{}:
			active.Add(1)
			go func() {
				defer active.Done()
				defer func() { <-sem }()
				if err := handleConnection(ctx, cfg, conn); err != nil && ctx.Err() == nil {
					logger.Warn("workload proxy connection failed", "mode", cfg.mode, "error", err)
				}
			}()
		default:
			_ = conn.Close()
			logger.Warn("workload proxy connection limit reached", "limit", cfg.maxConnections)
		}
	}

	done := make(chan struct{})
	go func() {
		active.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(cfg.shutdownTimeout):
		return fmt.Errorf("shutdown timed out with active connections")
	}
}

func validateCredentialFiles(cfg config) error {
	if _, err := loadIdentity(cfg.certFile, cfg.keyFile); err != nil {
		return fmt.Errorf("load local identity: %w", err)
	}
	if _, _, err := loadRoots(cfg.caFile); err != nil {
		return fmt.Errorf("load mesh CA: %w", err)
	}
	return nil
}

func handleConnection(ctx context.Context, cfg config, accepted net.Conn) error {
	defer accepted.Close()
	var left, right net.Conn
	var err error
	if cfg.mode == modeClient {
		left = accepted
		right, err = dialVerifiedPeer(ctx, cfg)
	} else {
		left, err = acceptVerifiedPeer(ctx, accepted, cfg)
		if err == nil {
			right, err = (&net.Dialer{Timeout: cfg.dialTimeout}).DialContext(ctx, "tcp", cfg.upstream)
		}
	}
	if err != nil {
		return err
	}
	if right != nil {
		defer right.Close()
	}
	stop := context.AfterFunc(ctx, func() {
		_ = left.Close()
		_ = right.Close()
	})
	defer stop()
	return proxyDuplex(withIdleTimeout(left, cfg.idleTimeout), withIdleTimeout(right, cfg.idleTimeout))
}

func dialVerifiedPeer(ctx context.Context, cfg config) (net.Conn, error) {
	identity, err := loadIdentity(cfg.certFile, cfg.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client identity: %w", err)
	}
	_, roots, err := loadRoots(cfg.caFile)
	if err != nil {
		return nil, fmt.Errorf("load client mesh CA: %w", err)
	}
	raw, err := (&net.Dialer{Timeout: cfg.dialTimeout}).DialContext(ctx, "tcp", cfg.upstream)
	if err != nil {
		return nil, fmt.Errorf("dial TLS peer: %w", err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{identity},
		InsecureSkipVerify: true, // The callback verifies the mesh CA and workload stamp.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPeer(cs.PeerCertificates, roots, cfg.peerWorkload, x509.ExtKeyUsageServerAuth)
		},
	})
	if err := handshake(ctx, tlsConn, cfg.handshakeTimeout); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("verify TLS peer %q: %w", cfg.peerWorkload, err)
	}
	return tlsConn, nil
}

func acceptVerifiedPeer(ctx context.Context, raw net.Conn, cfg config) (net.Conn, error) {
	identity, err := loadIdentity(cfg.certFile, cfg.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server identity: %w", err)
	}
	_, roots, err := loadRoots(cfg.caFile)
	if err != nil {
		return nil, fmt.Errorf("load server mesh CA: %w", err)
	}
	tlsConn := tls.Server(raw, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("peer certificate did not verify against the mesh CA")
			}
			return ratls.CheckWorkloadPin(cs.PeerCertificates[0], cfg.peerWorkload)
		},
	})
	if err := handshake(ctx, tlsConn, cfg.handshakeTimeout); err != nil {
		return nil, fmt.Errorf("verify TLS client %q: %w", cfg.peerWorkload, err)
	}
	return tlsConn, nil
}

func handshake(ctx context.Context, conn *tls.Conn, timeout time.Duration) error {
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

func verifyPeer(certs []*x509.Certificate, roots *x509.CertPool, expected string, usage x509.ExtKeyUsage) error {
	if len(certs) == 0 {
		return fmt.Errorf("peer sent no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	now := time.Now()
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{usage},
		CurrentTime:   now.Add(certutil.LeafValiditySkew),
	}); err != nil {
		return fmt.Errorf("peer certificate does not chain to the mesh CA: %w", err)
	}
	if err := certutil.CheckValidity(certs[0], now); err != nil {
		return fmt.Errorf("peer certificate validity: %w", err)
	}
	return ratls.CheckWorkloadPin(certs[0], expected)
}

func loadIdentity(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := readBounded(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read certificate: %w", err)
	}
	keyPEM, err := readBounded(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read private key: %w", err)
	}
	identity, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(identity.Certificate) == 0 {
		return tls.Certificate{}, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf: %w", err)
	}
	if err := certutil.CheckValidity(leaf, time.Now()); err != nil {
		return tls.Certificate{}, fmt.Errorf("local leaf validity: %w", err)
	}
	identity.Leaf = leaf
	return identity, nil
}

func loadRoots(path string) ([]*x509.Certificate, *x509.CertPool, error) {
	pemBytes, err := readBounded(path)
	if err != nil {
		return nil, nil, err
	}
	certs, err := certutil.ParsePEMCertificates(pemBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("CA bundle is empty")
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		if !cert.IsCA {
			return nil, nil, fmt.Errorf("CA bundle contains a non-CA certificate")
		}
		pool.AddCert(cert)
	}
	return certs, pool, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	if len(b) > maxCredentialBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxCredentialBytes)
	}
	return b, nil
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func withIdleTimeout(conn net.Conn, timeout time.Duration) net.Conn {
	return &idleConn{Conn: conn, timeout: timeout}
}

func (c *idleConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func proxyDuplex(a, b net.Conn) error {
	type result struct{ err error }
	results := make(chan result, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.CopyBuffer(dst, src, make([]byte, 32*1024))
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		results <- result{err: err}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	first := <-results
	second := <-results
	return joinCopyErrors(first.err, second.err)
}

func joinCopyErrors(errs ...error) error {
	kept := make([]error, 0, len(errs))
	for _, err := range errs {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
			continue
		}
		kept = append(kept, err)
	}
	return errors.Join(kept...)
}
