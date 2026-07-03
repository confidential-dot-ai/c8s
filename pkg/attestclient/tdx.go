package attestclient

import (
	"encoding/json"
	"fmt"
)

// stripTDXEventlog returns the TDX evidence with cc_eventlog omitted.
// On bare-metal TDX the eventlog blob is ~85 KB, which pushes the
// RA-TLS cert past what TLS 1.3 handshake records tolerate (each
// record caps at 16 KB — go/crypto/tls silently sends
// alert.internal_error when the resulting cert doesn't fit).
// RTMR-chain replay isn't part of the c8s RA-TLS path; verifiers that
// want the eventlog can fetch it out-of-band.
//
// Kept as an explicit JSON round-trip (Unmarshal → mutate → Marshal)
// rather than string-hacking the field out, so future additions to
// attestation-rs's TdxEvidence don't silently sneak into the cert.
func stripTDXEventlog(raw json.RawMessage) (json.RawMessage, error) {
	var body struct {
		Quote      string `json:"quote"`
		CCEventlog string `json:"cc_eventlog,omitempty"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("parse tdx evidence for eventlog strip: %w", err)
	}
	body.CCEventlog = ""
	out, err := json.Marshal(struct {
		Quote string `json:"quote"`
	}{Quote: body.Quote})
	if err != nil {
		return nil, fmt.Errorf("re-marshal stripped tdx evidence: %w", err)
	}
	return out, nil
}
