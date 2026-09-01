package teewebpki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	statepkg "github.com/confidential-dot-ai/c8s/internal/teewebpki"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type operatorOptions struct {
	cdsconn.Options
	out         string
	certificate string
	publicRoots string
}

func newCSRCmd() *cobra.Command {
	o := &operatorOptions{}
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Fetch the public CSR for the protected cluster TLS key",
		Long: `Fetch the CSR generated from the cluster TLS key held by CDS.

Point --url at a direct CDS RA-TLS endpoint and pin the CDS measurement. The
CSR is public. Give it to a public certificate authority. The private key never
leaves the attested cluster.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.Validate(); err != nil {
				return err
			}
			if err := requireAttestedPinnedEndpoint(&o.Options); err != nil {
				return fmt.Errorf("refusing to fetch a certificate CSR from an unpinned CDS: %w", err)
			}
			hc, err := o.HTTPClient(cmd.Context())
			if err != nil {
				return err
			}
			csr, version, err := fetchCSR(cmd.Context(), hc, o.URL)
			if err != nil {
				return err
			}
			if o.out == "-" {
				_, err = cmd.OutOrStdout().Write(csr)
			} else {
				err = fileutil.WriteAtomic(o.out, csr, 0o644)
			}
			if err != nil {
				return fmt.Errorf("write CSR: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "fetched tee-WebPKI CSR at state version %d\n", version)
			return nil
		},
	}
	cdsconn.BindFlags(cmd.Flags(), &o.Options)
	cmd.Flags().StringVarP(&o.out, "out", "o", "-", "CSR output file, or - for standard output")
	return cmd
}

func newInstallCertificateCmd() *cobra.Command {
	o := &operatorOptions{}
	cmd := &cobra.Command{
		Use:   "install-certificate",
		Short: "Install the public certificate for the protected cluster TLS key",
		Long: `Install a public certificate chain issued for the current cluster CSR.

The command fetches the current CSR and state version from a direct CDS RA-TLS
endpoint. It rejects a certificate for another key or DNS name. It signs the
exact update body with the c8s operator key before it changes CDS state.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return installCertificate(cmd.Context(), cmd.ErrOrStderr(), o)
		},
	}
	cdsconn.BindFlags(cmd.Flags(), &o.Options)
	cmd.Flags().StringVar(&o.certificate, "certificate", "", "PEM public certificate chain issued for the current cluster CSR")
	cmd.Flags().StringVar(&o.publicRoots, "public-roots", "", "optional PEM roots used to verify the public certificate; empty uses system roots")
	_ = cmd.MarkFlagRequired("certificate")
	return cmd
}

func fetchCSR(ctx context.Context, hc *http.Client, baseURL string) ([]byte, uint64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+statepkg.CSRRoute, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch tee-WebPKI CSR: %w", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, statepkg.MaxCertificate+1))
	if readErr != nil {
		return nil, 0, fmt.Errorf("read tee-WebPKI CSR: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetch tee-WebPKI CSR: CDS returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if len(body) > statepkg.MaxCertificate {
		return nil, 0, fmt.Errorf("tee-WebPKI CSR is too large")
	}
	csr, err := parseCSR(body)
	if err != nil {
		return nil, 0, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, 0, fmt.Errorf("verify tee-WebPKI CSR signature: %w", err)
	}
	version, err := strconv.ParseUint(resp.Header.Get(statepkg.VersionHeader), 10, 64)
	if err != nil || version == 0 {
		return nil, 0, fmt.Errorf("tee-WebPKI CSR response has no valid %s header", statepkg.VersionHeader)
	}
	return body, version, nil
}

func installCertificate(ctx context.Context, stderr io.Writer, o *operatorOptions) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if err := requireAttestedPinnedEndpoint(&o.Options); err != nil {
		return fmt.Errorf("refusing to install a certificate through an untrusted CDS endpoint: %w", err)
	}
	if strings.TrimSpace(o.certificate) == "" {
		return fmt.Errorf("--certificate is required")
	}
	chain, err := os.ReadFile(o.certificate)
	if err != nil {
		return fmt.Errorf("read public certificate: %w", err)
	}
	if len(chain) > statepkg.MaxCertificate {
		return fmt.Errorf("public certificate is too large")
	}
	roots, err := loadRoots(o.publicRoots)
	if err != nil {
		return fmt.Errorf("load public certificate roots: %w", err)
	}
	hc, err := o.HTTPClient(ctx)
	if err != nil {
		return err
	}
	signer, err := o.Signer()
	if err != nil {
		return err
	}
	return installCertificateWithClient(ctx, stderr, o.URL, chain, roots, hc, signer)
}

func installCertificateWithClient(ctx context.Context, stderr io.Writer, baseURL string, chain []byte, roots *x509.CertPool, hc *http.Client, signer *operatorauth.Signer) error {
	csrPEM, version, err := fetchCSR(ctx, hc, baseURL)
	if err != nil {
		return err
	}
	if err := validateCertificateForCSR(chain, csrPEM, roots); err != nil {
		return err
	}
	update := statepkg.PublicUpdate{Version: version, CertificatePEM: chain}
	body, err := json.Marshal(update)
	if err != nil {
		return err
	}
	path := statepkg.CertificateRoute
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	auth, err := signer.Authorization(http.MethodPut, path, body)
	if err != nil {
		return fmt.Errorf("authorize certificate update: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("install public certificate: %w", err)
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("install public certificate: CDS returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	fmt.Fprintf(stderr, "installed tee-WebPKI certificate from state version %d\n", version)
	return nil
}

func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return nil, fmt.Errorf("tee-WebPKI CSR PEM is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse tee-WebPKI CSR: %w", err)
	}
	return csr, nil
}

func validateCertificateForCSR(chainPEM, csrPEM []byte, roots *x509.CertPool) error {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return err
	}
	leaf, intermediates, err := parseCertificateChain(chainPEM)
	if err != nil {
		return err
	}
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal CSR public key: %w", err)
	}
	leafKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	if !bytes.Equal(csrKey, leafKey) {
		return fmt.Errorf("public certificate does not match the current cluster CSR key")
	}
	if len(csr.DNSNames) == 0 {
		return fmt.Errorf("current cluster CSR has no DNS SANs")
	}
	if roots == nil {
		return fmt.Errorf("public certificate roots are required")
	}
	csrNames := append([]string(nil), csr.DNSNames...)
	certificateNames := append([]string(nil), leaf.DNSNames...)
	sort.Strings(csrNames)
	sort.Strings(certificateNames)
	if len(csrNames) != len(certificateNames) {
		return fmt.Errorf("public certificate DNS SANs do not exactly match the current cluster CSR")
	}
	for index := range csrNames {
		if csrNames[index] != certificateNames[index] {
			return fmt.Errorf("public certificate DNS SANs do not exactly match the current cluster CSR")
		}
	}
	intermediatePool := x509.NewCertPool()
	for _, certificate := range intermediates {
		intermediatePool.AddCert(certificate)
	}
	for _, name := range csr.DNSNames {
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName: name, Roots: roots, Intermediates: intermediatePool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("verify public certificate for CSR DNS name %s: %w", name, err)
		}
	}
	return nil
}

func requireAttestedPinnedEndpoint(o *cdsconn.Options) error {
	u, err := url.Parse(o.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("--url must be a direct HTTPS RA-TLS CDS endpoint; plaintext and --insecure are not allowed")
	}
	if o.Insecure {
		return fmt.Errorf("--insecure is not allowed for tee-WebPKI certificate operations")
	}
	return o.RequirePinnedEndpoint()
}
