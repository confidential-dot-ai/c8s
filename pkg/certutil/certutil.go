// Package certutil provides common helper functions shared across the ratls
// project: serial number generation, fingerprinting, PEM encoding, and more.
package certutil

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"
)

// serialNumberLimit is 2^128, the upper bound for X.509 serial numbers.
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// GenerateSerial returns a cryptographically random 128-bit serial number
// suitable for X.509 certificates.
func GenerateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, serialNumberLimit)
}

// CertFingerprint returns the lowercase hex SHA-256 fingerprint of raw
// certificate bytes (DER or x509.Certificate.Raw).
func CertFingerprint(raw []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// EncodeCertPEM encodes DER certificate bytes as a PEM block.
func EncodeCertPEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// MarshalECKeyPEM marshals an EC private key to PEM format.
func MarshalECKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// ParseECPrivateKey parses a PEM-encoded EC private key, trying PKCS8 first
// then SEC 1 (EC) format.
func ParseECPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first (openssl genpkey), then EC (openssl ecparam).
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ec, ok := key.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, fmt.Errorf("pkcs8 key is not ECDSA")
	}
	ec, err2 := x509.ParseECPrivateKey(block.Bytes)
	if err2 != nil {
		return nil, fmt.Errorf("parse key: PKCS8: %w; EC: %w", err, err2)
	}
	return ec, nil
}

// LoadECPrivateKeyFile reads a PEM file and parses the EC private key.
func LoadECPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseECPrivateKey(data)
}

// ParseCertificatePEM parses a PEM-encoded certificate, returning the first
// CERTIFICATE block found. Use [LoadCertificateFile] for file-based loading.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadCertificateFile reads a PEM file and parses the first certificate.
func LoadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseCertificatePEM(data)
}

// NewJSONLogger creates a JSON [slog.Logger] writing to stdout at the given
// level string (debug, warn, error — anything else defaults to info).
func NewJSONLogger(levelStr string) *slog.Logger {
	level := ParseLogLevel(levelStr)
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// ParseLogLevel converts a log level string to [slog.Level].
// Recognized values (case-insensitive): debug, warn, error.
// Any other value returns [slog.LevelInfo].
func ParseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParsePEMCertificates parses all CERTIFICATE PEM blocks from data and returns
// the parsed certificates. It returns an error if no certificate blocks are found.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found")
	}
	return certs, nil
}

// LoadPEMCertificatesFile reads a PEM file and parses all CERTIFICATE blocks.
func LoadPEMCertificatesFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParsePEMCertificates(data)
}

// NewCATemplate returns an x509.Certificate template for a self-signed CA
// with the given serial number and expiry time.
func NewCATemplate(serial *big.Int, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Mesh CA"},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}
