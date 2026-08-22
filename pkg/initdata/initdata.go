// Package initdata builds and reads the kata init-data document c8s delivers
// into a confidential guest.
//
// The kata shim hashes the document's raw bytes into the SEV-SNP HOST_DATA
// field of the launch report, so the bytes are the contract: producer and
// consumer must agree byte-for-byte and nothing may re-render. Everything here
// derives from one buffer.
//
// HOST_DATA makes the document tamper-EVIDENT, not trusted. The host still
// chooses the content, and kata's guest agent never compares what it wrote to
// the guest against what the shim committed. A consumer must therefore
// re-derive sha256(raw) and compare it against the HOST_DATA of an attestation
// report a verifier has accepted — HOST_DATA read out of an unverified report
// is host-chosen on both sides. See docs/kata-image-policy.md — "Allowlist
// sourcing: baked seed + CDS refresh".
package initdata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// AnnotationKey is kata's per-pod init-data annotation. Its value is
	// base64(gzip(document)). Already in enable_annotations on the shipped
	// configuration-qemu-snp.toml.
	AnnotationKey = "io.katacontainers.config.hypervisor.cc_init_data"

	// Version is the only document version kata's guest agent accepts.
	Version = "0.1.0"

	// AlgorithmSHA256 is the only algorithm c8s emits. kata accepts sha384 and
	// sha512 but truncates both to 32 bytes for SNP, so they do not mean what
	// their names say.
	AlgorithmSHA256 = "sha256"

	// GuestDocumentPath is where kata-agent writes the raw document inside the
	// guest, verbatim (kata src/agent/src/initdata.rs, INITDATA_TOML_PATH).
	GuestDocumentPath = "/run/confidential-containers/initdata/initdata.toml"

	// DigestSize is sha256's, and the width of SNP HOST_DATA.
	DigestSize = sha256.Size
)

// [data] keys. These are a wire contract between the webhook that stamps the
// annotation and the in-guest consumers that read it back — treat renames as
// breaking changes and document them in docs/kata-image-policy.md.
const (
	// KeyRole names what the guest is. Consumers branch on it; see the Role
	// constants.
	KeyRole = "c8s.role"

	// KeyCDSMeasurements carries the comma-separated SHA-384 hex launch digests
	// the guest pins CDS's RA-TLS serving cert to. This is the value that
	// cannot be baked (it is a digest of the image it would live in).
	KeyCDSMeasurements = "c8s.cds.measurements"

	// KeyCDSRTMRs carries the comma-separated <index>=<sha384-hex> TDX RTMR
	// pins the guest additionally holds CDS's RA-TLS serving cert to. On TDX
	// the launch digest covers TDVF firmware alone, so without these the pin
	// in KeyCDSMeasurements says nothing about CDS's kernel or rootfs. Unbaked
	// for the same reason as the measurements. Absent = no RTMR pinning.
	KeyCDSRTMRs = "c8s.cds.rtmrs"

	// KeyCDSAllowlistSeedSHA256 is the hex sha256 of the allowlist document CDS
	// was started with (--allowlist-seed). Committed into CDS's own launch so a
	// measurement pin no longer says nothing about the content served.
	KeyCDSAllowlistSeedSHA256 = "c8s.cds.allowlist-seed-sha256"

	// KeyCDSOperatorKeysSHA256 is the hex sha256 of the operator public-key
	// bundle CDS admits allowlist writes from (--operator-keys).
	KeyCDSOperatorKeysSHA256 = "c8s.cds.operator-keys-sha256"
)

// Roles a guest can be launched as.
const (
	// RoleWorkload is any guest that consumes the CDS allowlist.
	RoleWorkload = "workload"

	// RoleCDS is CDS's own guest. It is the allowlist source, so it does not
	// refresh from itself.
	RoleCDS = "cds"
)

// maxDecodedSize caps Decode's output. The annotation is attacker-supplied
// wherever it is read back, and gzip expands.
const maxDecodedSize = 1 << 20

var (
	// ErrUnsupportedAlgorithm guards kata's shim: its switch on the algorithm
	// has no default arm and then hashes unconditionally, so an unrecognised
	// value panics the shim rather than failing the pod.
	ErrUnsupportedAlgorithm = errors.New("initdata: unsupported algorithm")

	// ErrUnsupportedVersion is a version kata's guest agent would reject.
	ErrUnsupportedVersion = errors.New("initdata: unsupported version")

	// ErrMalformed is a document outside the rendered subset (see Parse).
	ErrMalformed = errors.New("initdata: malformed document")

	// ErrUnrepresentable is a key or value Render refuses to emit.
	ErrUnrepresentable = errors.New("initdata: unrepresentable key or value")
)

// Document is an init-data document's logical content.
type Document struct {
	Version   string
	Algorithm string
	Data      map[string]string
}

// Built is one document in its three coupled forms. Annotation and Digest are
// both derived from Raw, which is the only authority: re-rendering Raw to
// recompute Digest is the failure mode this type exists to prevent.
type Built struct {
	// Raw is the exact byte sequence the guest receives and the shim hashes.
	Raw []byte

	// Annotation is base64(gzip(Raw)) — the AnnotationKey value.
	Annotation string

	// Digest is sha256(Raw), which the shim writes to SNP HOST_DATA.
	Digest [DigestSize]byte
}

// New returns a document with the fixed version and algorithm and the given
// [data] table.
func New(data map[string]string) Document {
	return Document{Version: Version, Algorithm: AlgorithmSHA256, Data: maps.Clone(data)}
}

// ValidateAlgorithm rejects anything c8s must not put in the annotation.
func ValidateAlgorithm(algorithm string) error {
	if algorithm != AlgorithmSHA256 {
		return fmt.Errorf("%w %q (only %q is emitted; kata truncates sha384/sha512 to 32 bytes for SNP)",
			ErrUnsupportedAlgorithm, algorithm, AlgorithmSHA256)
	}
	return nil
}

// Digest is the value the kata shim places in SNP HOST_DATA for raw.
func Digest(raw []byte) [DigestSize]byte {
	return sha256.Sum256(raw)
}

// Build renders the document and returns it alongside the annotation value and
// the digest, all from a single buffer.
func (d Document) Build() (Built, error) {
	raw, err := d.Render()
	if err != nil {
		return Built{}, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return Built{}, fmt.Errorf("initdata: gzip: %w", err)
	}
	if err := zw.Close(); err != nil {
		return Built{}, fmt.Errorf("initdata: gzip: %w", err)
	}
	return Built{
		Raw:        raw,
		Annotation: base64.StdEncoding.EncodeToString(buf.Bytes()),
		Digest:     Digest(raw),
	}, nil
}

// Render emits the canonical bytes: version, algorithm, then the [data] table
// with keys in lexicographic order and a trailing newline. Deterministic for a
// given Document — the digest depends on it.
func (d Document) Render() ([]byte, error) {
	if d.Version != Version {
		return nil, fmt.Errorf("%w %q (want %q)", ErrUnsupportedVersion, d.Version, Version)
	}
	if err := ValidateAlgorithm(d.Algorithm); err != nil {
		return nil, err
	}
	if len(d.Data) == 0 {
		return nil, fmt.Errorf("%w: [data] is empty", ErrMalformed)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "version = %s\n", quote(d.Version))
	fmt.Fprintf(&b, "algorithm = %s\n", quote(d.Algorithm))
	b.WriteString("\n[data]\n")
	for _, k := range slices.Sorted(maps.Keys(d.Data)) {
		if err := validateKey(k); err != nil {
			return nil, err
		}
		if err := validateValue(d.Data[k]); err != nil {
			return nil, fmt.Errorf("%w (key %q)", err, k)
		}
		fmt.Fprintf(&b, "%s = %s\n", quote(k), quote(d.Data[k]))
	}
	return []byte(b.String()), nil
}

// Parse reads back exactly what Render emits and rejects everything else. The
// strictness is deliberate: the only legitimate producer is c8s's own webhook,
// and a parser that accepts more than it needs to is surface a caller does not
// want on host-supplied bytes.
//
// Parse does not authenticate. Callers must compare Digest(raw) against the
// HOST_DATA of a verified report first.
func Parse(raw []byte) (Document, error) {
	if !utf8.Valid(raw) {
		return Document{}, fmt.Errorf("%w: not valid UTF-8", ErrMalformed)
	}
	body, ok := strings.CutSuffix(string(raw), "\n")
	if !ok {
		return Document{}, fmt.Errorf("%w: missing trailing newline", ErrMalformed)
	}

	doc := Document{Data: make(map[string]string)}
	inData := false
	for i, line := range strings.Split(body, "\n") {
		lineNo := i + 1
		switch {
		case line == "":
		case line == "[data]":
			if inData {
				return Document{}, fmt.Errorf("%w: duplicate [data] on line %d", ErrMalformed, lineNo)
			}
			inData = true
		case inData:
			key, value, err := parseAssignment(line, true)
			if err != nil {
				return Document{}, fmt.Errorf("%w on line %d", err, lineNo)
			}
			if _, dup := doc.Data[key]; dup {
				return Document{}, fmt.Errorf("%w: duplicate key %q on line %d", ErrMalformed, key, lineNo)
			}
			doc.Data[key] = value
		default:
			key, value, err := parseAssignment(line, false)
			if err != nil {
				return Document{}, fmt.Errorf("%w on line %d", err, lineNo)
			}
			switch {
			case key == "version" && doc.Version == "":
				doc.Version = value
			case key == "algorithm" && doc.Algorithm == "":
				doc.Algorithm = value
			default:
				return Document{}, fmt.Errorf("%w: unexpected key %q on line %d", ErrMalformed, key, lineNo)
			}
		}
	}

	if doc.Version != Version {
		return Document{}, fmt.Errorf("%w %q (want %q)", ErrUnsupportedVersion, doc.Version, Version)
	}
	if err := ValidateAlgorithm(doc.Algorithm); err != nil {
		return Document{}, err
	}
	if !inData || len(doc.Data) == 0 {
		return Document{}, fmt.Errorf("%w: no [data] entries", ErrMalformed)
	}
	return doc, nil
}

// Decode reverses the annotation encoding: base64 then gzip. Bounded output —
// the input is host-supplied wherever it is read back.
func Decode(annotation string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(annotation)
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %w", ErrMalformed, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %w", ErrMalformed, err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, maxDecodedSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %w", ErrMalformed, err)
	}
	if len(raw) > maxDecodedSize {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrMalformed, maxDecodedSize)
	}
	return raw, nil
}

// parseAssignment splits `key = "value"`, with the key itself quoted inside
// [data]. Spacing is exact — the rendered form is the only accepted form.
func parseAssignment(line string, quotedKey bool) (key, value string, err error) {
	lhs, rhs, ok := strings.Cut(line, " = ")
	if !ok {
		return "", "", fmt.Errorf("%w: expected `key = \"value\"`", ErrMalformed)
	}
	if quotedKey {
		if lhs, err = unquote(lhs); err != nil {
			return "", "", err
		}
	}
	if err := validateKey(lhs); err != nil {
		return "", "", err
	}
	if value, err = unquote(rhs); err != nil {
		return "", "", err
	}
	if err := validateValue(value); err != nil {
		return "", "", err
	}
	return lhs, value, nil
}

func quote(s string) string { return `"` + s + `"` }

func unquote(s string) (string, error) {
	inner, ok := strings.CutPrefix(s, `"`)
	if !ok {
		return "", fmt.Errorf("%w: unquoted token %q", ErrMalformed, s)
	}
	inner, ok = strings.CutSuffix(inner, `"`)
	if !ok {
		return "", fmt.Errorf("%w: unterminated token %q", ErrMalformed, s)
	}
	return inner, nil
}

// validateKey restricts keys to a set that cannot collide with the format's own
// punctuation, so parsing stays unambiguous without an escaping layer.
func validateKey(k string) error {
	if k == "" {
		return fmt.Errorf("%w: empty key", ErrUnrepresentable)
	}
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '/':
		default:
			return fmt.Errorf("%w: key %q contains %q", ErrUnrepresentable, k, r)
		}
	}
	return nil
}

// validateValue rejects anything the escape-free rendering cannot represent.
// Quotes and backslashes are refused rather than escaped: no c8s value needs
// them, and refusing keeps the reader a straight unquote.
func validateValue(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty value", ErrUnrepresentable)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("%w: value is not valid UTF-8", ErrUnrepresentable)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return fmt.Errorf("%w: value contains %q", ErrUnrepresentable, r)
		}
	}
	return nil
}
