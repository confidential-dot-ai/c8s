package verify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

// maxServedMeasurements bounds the served document. Reference values for a
// realistic fleet are kilobytes; a larger body is a wrong endpoint, not a
// bigger policy.
const maxServedMeasurements = 1 << 20

// measurementsReport is the cross-check section of the verdict: what the
// attested target says it is enforcing, beside what the operator pinned.
type measurementsReport struct {
	served   measurements.ReferenceValues
	fetched  bool
	fetchErr error
	note     string
}

// fetchServedMeasurements GETs <base>/measurements bound to the endpoint whose
// attestation was just verified: the handshake requires the presented leaf's
// SHA-256 to equal wantCertSHA256, so a different endpoint — or a MITM on this
// second connection — cannot substitute its own set into the report.
func fetchServedMeasurements(ctx context.Context, base, serverName, wantCertSHA256 string, timeout time.Duration) (measurements.ReferenceValues, error) {
	if wantCertSHA256 == "" {
		return measurements.ReferenceValues{}, fmt.Errorf("no attested serving certificate to bind the fetch to")
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // trust comes from the attested-cert pin below, not PKI
		ServerName:         serverName,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if got := hex.EncodeToString(sum[:]); got != wantCertSHA256 {
				return fmt.Errorf("serving cert changed between attestation and measurement fetch (got sha256 %s, attested %s)", got, wantCertSHA256)
			}
			return nil
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/measurements", nil)
	if err != nil {
		return measurements.ReferenceValues{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return measurements.ReferenceValues{}, fmt.Errorf("fetch /measurements: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return measurements.ReferenceValues{}, fmt.Errorf("/measurements not served: this target predates the endpoint, so its enforced set cannot be checked")
	}
	if resp.StatusCode != http.StatusOK {
		return measurements.ReferenceValues{}, fmt.Errorf("/measurements returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxServedMeasurements+1))
	if err != nil {
		return measurements.ReferenceValues{}, fmt.Errorf("read /measurements: %w", err)
	}
	if len(body) > maxServedMeasurements {
		return measurements.ReferenceValues{}, fmt.Errorf("/measurements body exceeds %d bytes", maxServedMeasurements)
	}
	return measurements.ParseServed(body)
}

// checkServedMeasurements compares the served set against the operator's file.
// Equality is exact in both directions: an entry the target pins and the file
// does not is the substitution this check exists to catch, and one the file
// pins and the target does not means the cluster is enforcing less than the
// operator believes.
func checkServedMeasurements(want measurements.ReferenceValues, report measurementsReport, fail func(string, ...any)) {
	if report.fetchErr != nil {
		fail("could not fetch /measurements to check it against --measurements-config: %v", report.fetchErr)
		return
	}
	if !report.fetched {
		fail("--measurements-config cannot be checked: %s", report.note)
		return
	}
	if len(report.served.Entries) == 0 {
		fail("the target serves an empty measurement set: it admits any TEE attestation, while --measurements-config pins %d image(s)", len(want.Entries))
		return
	}
	if want.TEE != report.served.TEE {
		fail("--measurements-config is for %q but the target enforces %q", want.TEE, report.served.TEE)
		return
	}
	missing, extra := measurements.Diff(want, report.served)
	for _, e := range extra {
		fail("the target admits an image --measurements-config does not pin: %s (%x)", e.Name, e.Digest)
	}
	for _, e := range missing {
		fail("--measurements-config pins an image the target does not admit: %s (%x)", e.Name, e.Digest)
	}
}

// gatherMeasurements fetches the set the target reports enforcing. Like the
// operator-key fetch it never fails the run here; a fetch error is recorded so
// checkServedMeasurements can fail the verdict when --measurements-config
// asked for the check, rather than letting an erroring endpoint dodge it.
func gatherMeasurements(ctx context.Context, cfg config, ev *evidence) measurementsReport {
	if cfg.measurementsConfig == "" {
		return measurementsReport{}
	}
	if cfg.kind != "cds" {
		return measurementsReport{note: "target kind is not cds (use --kind cds to enable)"}
	}
	if cfg.url == "" {
		return measurementsReport{note: "not fetched (no target URL)"}
	}
	if ev.certSHA256 == "" {
		return measurementsReport{note: "not fetched (no serving cert to bind to)"}
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return measurementsReport{note: "not fetched: " + err.Error()}
	}
	served, err := fetchServedMeasurements(ctx, baseURL, cfg.server, ev.certSHA256, cfg.timeout)
	if err != nil {
		return measurementsReport{note: "not fetched: " + err.Error(), fetchErr: err}
	}
	return measurementsReport{served: served, fetched: true}
}
