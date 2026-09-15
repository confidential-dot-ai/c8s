// Package measurements extends shared image reference values with c8s launch
// identities. Image parsing and verification belong to attestation-go; this
// package only keeps the operator PEM bound atomically to each image.
package measurements

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

const (
	SchemaVersion1 = "1"
	TEESNP         = string(teetypes.FamilySNP)
	TEETDX         = string(teetypes.FamilyTDX)
	DigestSize     = refvalues.DigestSize
)

// Entry pins an image and, optionally, its exact launch-bound operator PEM.
type Entry struct {
	Name        string
	Digest      []byte
	RTMRs       map[int][]byte
	OperatorKey []byte
}

func (e Entry) image() remote.ImagePin {
	return remote.ImagePin{Name: e.Name, Digest: e.Digest, RTMRs: e.RTMRs}
}

// ReferenceValues is a c8s policy on one hardware family.
type ReferenceValues struct {
	TEE     string
	Entries []Entry
}

func (s ReferenceValues) Empty() bool { return len(s.Entries) == 0 }
func (s ReferenceValues) PinsOperatorKeys() bool {
	for _, e := range s.Entries {
		if len(e.OperatorKey) > 0 {
			return true
		}
	}
	return false
}
func (s ReferenceValues) images() refvalues.ReferenceValues {
	rv := refvalues.ReferenceValues{Family: teetypes.Family(s.TEE)}
	for _, e := range s.Entries {
		rv.Images = append(rv.Images, e.image())
	}
	return rv
}
func (s ReferenceValues) Digests() [][]byte    { return s.images().Digests() }
func (s ReferenceValues) HexDigests() []string { d, _, _ := s.images().Flatten(); return d }
func (s ReferenceValues) DigestSet() map[string]bool {
	out := map[string]bool{}
	for _, d := range s.HexDigests() {
		out[d] = true
	}
	return out
}
func (s ReferenceValues) CommonRTMRs() (map[int][]byte, bool) { return s.images().CommonRTMRs() }
func FromFlags(digests [][]byte, rtmrs map[int][]byte) ReferenceValues {
	var out ReferenceValues
	for _, e := range refvalues.FromFlags(digests, rtmrs).Images {
		out.Entries = append(out.Entries, Entry{Name: e.Name, Digest: e.Digest, RTMRs: e.RTMRs})
	}
	return out
}
func Load(path string) (ReferenceValues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("read measurements config: %w", err)
	}
	rv, err := Parse(data)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("measurements config %s: %w", path, err)
	}
	return rv, nil
}

type wire struct {
	SchemaVersion string            `json:"schema_version"`
	TEE           string            `json:"tee"`
	Measurements  []json.RawMessage `json:"measurements"`
}

// Parse removes only operator_key before delegating each image to the shared
// strict parser. Per-entry delegation permits one image with several operators;
// the complete tuple, including its exact key bytes, must still be unique.
func Parse(data []byte) (ReferenceValues, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return ReferenceValues{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc wire
	if err := dec.Decode(&doc); err != nil {
		return ReferenceValues{}, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return ReferenceValues{}, fmt.Errorf("trailing data after the JSON object")
	}
	if len(doc.Measurements) == 0 {
		_, err := refvalues.Parse(data)
		return ReferenceValues{}, err
	}
	out := ReferenceValues{TEE: doc.TEE}
	names := map[string]bool{}
	tuples := map[string]int{}
	for i, raw := range doc.Measurements {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return ReferenceValues{}, fmt.Errorf("measurements[%d]: %w", i, err)
		}
		key, err := parseOperatorKey(fields["operator_key"], i)
		if err != nil {
			return ReferenceValues{}, err
		}
		delete(fields, "operator_key")
		imageJSON, err := json.Marshal(fields)
		if err != nil {
			return ReferenceValues{}, err
		}
		imageDoc, err := json.Marshal(wire{SchemaVersion: doc.SchemaVersion, TEE: doc.TEE, Measurements: []json.RawMessage{imageJSON}})
		if err != nil {
			return ReferenceValues{}, err
		}
		rv, err := refvalues.Parse(imageDoc)
		if err != nil {
			return ReferenceValues{}, fmt.Errorf("measurements[%d]: %w", i, err)
		}
		img := rv.Images[0]
		e := Entry{Name: img.Name, Digest: img.Digest, RTMRs: img.RTMRs, OperatorKey: key}
		if names[e.Name] {
			return ReferenceValues{}, fmt.Errorf("measurements[%d]: duplicate name %q", i, e.Name)
		}
		names[e.Name] = true
		tuple := tupleKey(e)
		if prev, ok := tuples[tuple]; ok {
			return ReferenceValues{}, fmt.Errorf("measurements[%d] pins the same tuple as measurements[%d]", i, prev)
		}
		tuples[tuple] = i
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

func parseOperatorKey(raw json.RawMessage, i int) ([]byte, error) {
	if raw == nil {
		return nil, nil
	}
	at := fmt.Sprintf("measurements[%d].operator_key", i)
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, fmt.Errorf("%s: %w", at, err)
	}
	key := []byte(text)
	if _, err := ParsePublicKeyPEM(key); err != nil {
		return nil, fmt.Errorf("%s: %w", at, err)
	}
	return key, nil
}

// ParsePublicKeyPEM accepts exactly one headerless PEM PUBLIC KEY block, with
// nothing before or after it, holding an ECDSA P-256 key. It is the one strict
// parser for operator and launch keys, which are pinned byte-for-byte.
func ParsePublicKeyPEM(key []byte) (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN PUBLIC KEY-----")) {
		return nil, fmt.Errorf("want one PEM PUBLIC KEY")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("want an ECDSA P-256 key")
	}
	return ec, nil
}

// FormatRTMRPins renders register pins as the "<index>=<hex>" flag form, in
// index order so the output is stable for the flat flags and helm values.
func FormatRTMRPins(rtmrs map[int][]byte) []string {
	indices := make([]int, 0, len(rtmrs))
	for idx := range rtmrs {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	pins := make([]string, 0, len(indices))
	for _, idx := range indices {
		pins = append(pins, fmt.Sprintf("%d=%x", idx, rtmrs[idx]))
	}
	return pins
}

// Format uses the shared image formatter before adding exact operator PEM bytes.
func Format(s ReferenceValues) ([]byte, error) {
	doc := wire{SchemaVersion: SchemaVersion1, TEE: s.TEE, Measurements: []json.RawMessage{}}
	for _, e := range s.Entries {
		data, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.Family(s.TEE), Images: []remote.ImagePin{e.image()}})
		if err != nil {
			return nil, err
		}
		var imageDoc wire
		if err := json.Unmarshal(data, &imageDoc); err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(imageDoc.Measurements[0], &fields); err != nil {
			return nil, err
		}
		if len(e.OperatorKey) > 0 {
			fields["operator_key"], _ = json.Marshal(string(e.OperatorKey))
		}
		raw, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		doc.Measurements = append(doc.Measurements, raw)
	}
	if len(s.Entries) == 0 {
		if _, err := refvalues.Format(s.images()); err != nil {
			return nil, err
		}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func tupleKey(e Entry) string {
	var b strings.Builder
	b.WriteString(hex.EncodeToString(e.Digest))
	idx := make([]int, 0, len(e.RTMRs))
	for i := range e.RTMRs {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		fmt.Fprintf(&b, "|%d=%s", i, hex.EncodeToString(e.RTMRs[i]))
	}
	if len(e.OperatorKey) > 0 {
		fmt.Fprintf(&b, "|operator_key=%x", e.OperatorKey)
	}
	return b.String()
}

// rejectDuplicateKeys fails a document that names any key twice. encoding/json
// keeps the last occurrence silently, so without this the value a reviewer
// reads and the value a gate loads could differ. The schema is two levels, so
// the document and each entry are scanned directly.
func rejectDuplicateKeys(data []byte) error {
	if key, err := duplicateKey(data); err != nil || key != "" {
		if err != nil {
			return err
		}
		return fmt.Errorf("duplicate key %q", key)
	}
	// Tolerant: a document whose shape is wrong is Parse's error to report.
	var doc struct {
		Measurements []json.RawMessage `json:"measurements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	for i, entry := range doc.Measurements {
		key, err := duplicateKey(entry)
		if err != nil {
			return err
		}
		if key != "" {
			return fmt.Errorf("duplicate key %q in measurements[%d]", key, i)
		}
	}
	return nil
}

// duplicateKey returns the first key obj names twice, or "" if it names none
// twice or is not an object.
func duplicateKey(obj []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(obj))
	tok, err := dec.Token()
	if err != nil {
		return "", nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", nil
	}
	seen := make(map[string]bool)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("not valid JSON: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return "", fmt.Errorf("not valid JSON: object key is %T", keyTok)
		}
		if seen[key] {
			return key, nil
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", fmt.Errorf("not valid JSON: %w", err)
		}
	}
	return "", nil
}

// Diff reports the entries each side pins and the other does not, matched on
// what decides admission — the digest, registers, and operator. Names are diagnostic
// only, so two entries naming one image differently are still the same pin.
func Diff(want, got ReferenceValues) (missing, extra []Entry) {
	index := func(s ReferenceValues) map[string]Entry {
		m := make(map[string]Entry, len(s.Entries))
		for _, e := range s.Entries {
			m[tupleKey(e)] = e
		}
		return m
	}
	w, g := index(want), index(got)
	for k, e := range w {
		if _, ok := g[k]; !ok {
			missing = append(missing, e)
		}
	}
	for k, e := range g {
		if _, ok := w[k]; !ok {
			extra = append(extra, e)
		}
	}
	sortEntries(missing)
	sortEntries(extra)
	return missing, extra
}

func sortEntries(e []Entry) {
	sort.Slice(e, func(i, j int) bool { return tupleKey(e[i]) < tupleKey(e[j]) })
}

// ParseServed reads an enforced policy, permitting the empty set a verifier
// must be able to report as unpinned. Non-empty node policies stay strict.
func ParseServed(data []byte) (ReferenceValues, error) {
	var doc wire
	if err := json.Unmarshal(data, &doc); err != nil {
		return ReferenceValues{}, err
	}
	if len(doc.Measurements) != 0 {
		return Parse(data)
	}
	rv, err := refvalues.ParseRendered(data)
	if err != nil {
		return ReferenceValues{}, err
	}
	return ReferenceValues{TEE: string(rv.Family)}, nil
}
