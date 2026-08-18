package ratls

import "errors"

// Sentinel errors for programmatic error handling via [errors.Is].
// These cover the verification pipeline stages — callers can distinguish
// between different failure modes without string matching.
var (
	// ErrKeyBinding indicates that the attestation report's REPORTDATA
	// does not match hash(publicKey), meaning the key was not generated
	// inside the claimed TEE.
	ErrKeyBinding = errors.New("ratls: REPORTDATA does not match key")

	// ErrNotAttested indicates that a certificate does not contain
	// the RA-TLS attestation extension (OID 1.3.6.1.4.1.66378.1.1).
	ErrNotAttested = errors.New("ratls: certificate missing RA-TLS extension")

	// ErrSignatureInvalid indicates that the hardware attestation report's
	// signature could not be verified against the platform certificate chain
	// (e.g., AMD VCEK → ASK → ARK).
	ErrSignatureInvalid = errors.New("ratls: hardware signature verification failed")

	// ErrPolicyViolation indicates the evidence failed a caller-pinned
	// policy: the [VerifyPolicy] launch-measurement allowlist, or the
	// requested min-TCB floor / debug rejection the verified claims fail to
	// echo.
	ErrPolicyViolation = errors.New("ratls: attestation policy check failed")

	// ErrUnsupportedTEE indicates an unrecognized TEE platform type.
	ErrUnsupportedTEE = errors.New("ratls: unsupported TEE platform")

	// ErrInvalidReport indicates a structurally invalid attestation report
	// (e.g., wrong size for the platform, truncated, or corrupt).
	ErrInvalidReport = errors.New("ratls: invalid attestation report")

	// ErrCertValidity indicates the certificate is outside its validity
	// window: expired, or NotBefore further in the future than the shared
	// clock-skew allowance (certutil.LeafValiditySkew).
	ErrCertValidity = errors.New("ratls: certificate outside its validity window")
)
