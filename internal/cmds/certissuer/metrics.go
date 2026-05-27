package certissuer

import (
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// updateCACertFingerprint resets the fingerprint info gauge and sets the new
// value. Returns the hex fingerprint for logging.
func updateCACertFingerprint(raw []byte) string {
	fp := certutil.CertFingerprint(raw)
	caCertFingerprintInfo.Reset()
	caCertFingerprintInfo.WithLabelValues(fp).Set(1)
	return fp
}

var (
	signRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_issuer_sign_requests_total",
		Help: "Total sign-csr requests by result.",
	}, []string{"result"})

	signLatencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "cert_issuer_sign_latency_seconds",
		Help:    "Signing request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	certificatesIssuedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_certificates_issued_total",
		Help: "Total certificates successfully issued.",
	})

	activeRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_active_requests",
		Help: "Number of in-flight sign-csr requests.",
	})

	caCertExpirySeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_ca_cert_expiry_seconds",
		Help: "Seconds until CA certificate expires.",
	})

	tokenCertExpirySeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cert_issuer_token_cert_expiry_seconds",
		Help: "Seconds until token-signer certificate expires.",
	})

	certReloadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_cert_reloads_total",
		Help: "Total successful certificate reloads.",
	})

	caCertFingerprintInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cert_issuer_ca_cert_fingerprint_info",
		Help: "Info metric exposing the active CA certificate SHA-256 fingerprint.",
	}, []string{"fingerprint"})

	sanValidationFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_san_validation_failures_total",
		Help: "Total CSR SAN validation failures (IP SAN mismatch with source).",
	})

	dnsSanValidationFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cert_issuer_dns_san_validation_failures_total",
		Help: "Total CSR DNS SAN validation failures.",
	})
)
