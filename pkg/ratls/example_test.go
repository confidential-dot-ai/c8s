package ratls_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/lunal-dev/c8s/pkg/ratls"
)

func ExampleNewServerTLSConfig() {
	tlsCfg, _, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform: "sev-snp",
		AttestFunc: func(ctx context.Context, customData string) (string, error) {
			// In production: call your TEE attestation infrastructure
			// to generate an SNP report with customData as REPORTDATA.
			return "", fmt.Errorf("not running in a TEE")
		},
		DNSNames: []string{"app.internal"},
	})
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{TLSConfig: tlsCfg}
	// server.ListenAndServeTLS("", "") — cert is provisioned lazily, in memory
	_ = server
	fmt.Println("server configured")
	// Output: server configured
}

func ExampleNewClientTLSConfig() {
	tlsCfg, _, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy: &ratls.VerifyPolicy{
			// In production: set acceptable launch measurements.
			// Empty means accept any measurement (UNSAFE — dev only).
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	_ = client
	fmt.Println("client configured")
	// Output: client configured
}

func ExampleNewServerTLSConfig_mutualTLS() {
	tlsCfg, _, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform: "sev-snp",
		AttestFunc: func(ctx context.Context, customData string) (string, error) {
			return "", fmt.Errorf("not running in a TEE")
		},
		DNSNames:     []string{"app.internal"},
		ClientPolicy: &ratls.VerifyPolicy{
			// Require clients to present RA-TLS certificates.
			// Measurements: acceptable client launch measurements.
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = tlsCfg
	fmt.Println("mTLS server configured")
	// Output: mTLS server configured
}

func ExampleNewClientTLSConfig_mutualTLS() {
	tlsCfg, _, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy: &ratls.VerifyPolicy{},
		// Present own RA-TLS certificate to the server.
		Platform: "sev-snp",
		AttestFunc: func(ctx context.Context, customData string) (string, error) {
			return "", fmt.Errorf("not running in a TEE")
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = tlsCfg
	fmt.Println("mTLS client configured")
	// Output: mTLS client configured
}

func ExampleGenerateKeyPair() {
	key, reportData, err := ratls.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("key curve: %s\n", key.Curve.Params().Name)
	fmt.Printf("reportData length: %d bytes\n", len(reportData))
	// Output:
	// key curve: P-256
	// reportData length: 64 bytes
}

func ExampleCheckKeyBinding() {
	key, reportData, err := ratls.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	att := &ratls.Attestation{
		TEEType: ratls.TEETypeSEVSNP,
		Report:  makeFakeReport(reportData),
	}

	err = ratls.CheckKeyBinding(&key.PublicKey, att, nil)
	fmt.Printf("binding valid: %v\n", err == nil)
	// Output: binding valid: true
}

// makeFakeReport creates a minimal fake SNP report with the given reportData
// at the correct offset. For example purposes only.
func makeFakeReport(reportData [64]byte) []byte {
	report := make([]byte, ratls.SNPReportSize)
	report[0] = 0x02    // version
	report[0x0A] = 0x03 // SMT policy bit
	copy(report[0x50:], reportData[:])
	return report
}
