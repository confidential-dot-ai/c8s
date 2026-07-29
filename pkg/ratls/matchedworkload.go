// Matched workload entry: which allowlist workload entry (or entries) the pod
// a leaf was issued to corresponds to, stamped by CDS as a CA-signed X.509
// extension after the workload-claims match succeeds.
//
// This is a statement BY CDS, not by the requester, so it lives outside the
// requester's REPORTDATA by construction — the match happens on the CDS side
// after the evidence is already frozen. Its trust comes from the mesh-CA
// signature plus CDS's own attestation: a verifier that attested CDS (whose
// config-claims commit the live allowlist) can recompute the expected value
// from that same allowlist via allowlist.MatchingWorkloadEntries /
// WorkloadEntriesDigest and confirm the stamp.
//
// The match is over image digests only — argv never reaches CDS — so when two
// entries share their digest sets and differ only in argv policy, BOTH are
// named. The stamp then means "one of these entries", which is the honest
// claim; the digest covers every named entry's full policy, argv included, so
// a verifier still learns the exact set of argv policies the pod is confined
// to. Anything narrower is for the admission side (the NRI plugin evaluates
// real argv), not for this extension.

package ratls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"
	"strings"
)

// OIDMatchedWorkload identifies the matched-workload-entry extension (see
// extension.go for the 1.3.6.1.4.1.59888 arc):
//
//	1.3.6.1.4.1.59888.1.5 - matched workload entry extension
var OIDMatchedWorkload = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 5}

// matchedWorkloadVersion is the only encoding version this package emits or
// parses.
const matchedWorkloadVersion = 1

// workloadEntryNamePattern mirrors allowlist workload-name validation
// (pkg/allowlist validWorkloadName): no commas can occur, which is what makes
// the comma-joined wire form unambiguous.
var workloadEntryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// MatchedWorkload names the allowlist entry (or entries) a leaf's attested
// container-digest sets matched at issuance.
type MatchedWorkload struct {
	// Names are the matched entry names, sorted. More than one means the
	// digest sets alone could not distinguish them (same images, different
	// argv policy) and the pod is one of them.
	Names []string
	// EntriesDigest is allowlist.WorkloadEntriesDigest over Names at issuance
	// time — SHA-256 of the canonical encoding of those entries, argv policies
	// included. Recomputable by any verifier holding the allowlist in force
	// when the leaf was issued.
	EntriesDigest []byte
}

// Ambiguous reports whether more than one entry matched — the leaf identifies
// a set, not a single workload.
func (m *MatchedWorkload) Ambiguous() bool { return len(m.Names) > 1 }

// matchedWorkloadASN1 is the DER encoding:
//
//	C8SMatchedWorkload ::= SEQUENCE {
//	    version        INTEGER,
//	    entriesDigest  OCTET STRING,
//	    names          IA5String   -- comma-joined sorted entry names
//	}
//
// Names ride as one comma-joined IA5String: entry names cannot contain commas
// (workloadEntryNamePattern), so the join is unambiguous, and a single string
// avoids encoding/asn1's underspecified []string handling.
type matchedWorkloadASN1 struct {
	Version       int
	EntriesDigest []byte
	Names         string `asn1:"ia5"`
}

func (m *MatchedWorkload) validate() error {
	if len(m.Names) == 0 {
		return fmt.Errorf("ratls: matched workload needs at least one entry name")
	}
	if !sortedUnique(m.Names) {
		return fmt.Errorf("ratls: matched workload names must be sorted and unique")
	}
	for _, n := range m.Names {
		if !workloadEntryNamePattern.MatchString(n) {
			return fmt.Errorf("ratls: matched workload name %q must match %s", n, workloadEntryNamePattern)
		}
	}
	if len(m.EntriesDigest) != ClaimsDigestSize {
		return fmt.Errorf("ratls: matched workload entries digest must be %d bytes, got %d", ClaimsDigestSize, len(m.EntriesDigest))
	}
	return nil
}

// MarshalMatchedWorkloadExtension encodes m as the non-critical
// matched-workload extension.
func MarshalMatchedWorkloadExtension(m *MatchedWorkload) (pkix.Extension, error) {
	if err := m.validate(); err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(matchedWorkloadASN1{
		Version:       matchedWorkloadVersion,
		EntriesDigest: m.EntriesDigest,
		Names:         strings.Join(m.Names, ","),
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ratls: marshal matched workload: %w", err)
	}
	return pkix.Extension{Id: OIDMatchedWorkload, Value: value}, nil
}

// UnmarshalMatchedWorkload decodes a DER-encoded matched-workload extension
// value, requiring the one canonical encoding (byte-exact round-trip, same
// posture as config-claims): no two distinct extension values may parse to the
// same MatchedWorkload.
func UnmarshalMatchedWorkload(der []byte) (*MatchedWorkload, error) {
	var raw matchedWorkloadASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: unmarshal matched workload: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ratls: %d trailing bytes after matched-workload extension", len(rest))
	}
	if raw.Version != matchedWorkloadVersion {
		return nil, fmt.Errorf("ratls: unsupported matched-workload version %d (supported: %d)", raw.Version, matchedWorkloadVersion)
	}
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("ratls: re-encode matched workload: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("ratls: matched-workload extension is not the exact v%d encoding (%d bytes, canonical is %d)", matchedWorkloadVersion, len(der), len(reencoded))
	}
	m := &MatchedWorkload{
		Names:         strings.Split(raw.Names, ","),
		EntriesDigest: raw.EntriesDigest,
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// MatchedWorkloadFromCert returns the certificate's matched-workload stamp, or
// nil when the certificate carries none. A present but malformed extension is
// an error, never nil — a verifier must not read damage as absence.
func MatchedWorkloadFromCert(cert *x509.Certificate) (*MatchedWorkload, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDMatchedWorkload) {
			continue
		}
		return UnmarshalMatchedWorkload(ext.Value)
	}
	return nil, nil
}

func sortedUnique(names []string) bool {
	for i := 1; i < len(names); i++ {
		if names[i] <= names[i-1] {
			return false
		}
	}
	return true
}
