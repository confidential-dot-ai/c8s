// Package measurements is the schema for a measurements config file: the set
// of VM images a cluster accepts, each pinned as one atomic tuple. A launch
// digest and its RTMRs only mean anything together — two images built against
// the same TDVF firmware share an MRTD — so an entry is matched whole or not
// at all, and the flat flag forms convert into entries rather than being
// enforced alongside them.
package measurements

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	// SchemaVersion1 is the only schema version this package accepts.
	SchemaVersion1 = "1"

	// TEESNP and TEETDX are the platforms a file may declare. One file
	// describes one platform: a cluster mixing SNP and TDX images is not
	// supported.
	TEESNP = "sev-snp"
	TEETDX = "tdx"

	// DigestSize is the SHA-384 width of every pinned register.
	DigestSize = 48

	// MaxRTMRs is the number of TDX runtime measurement registers.
	MaxRTMRs = 4
)

// Entry is one accepted VM image.
type Entry struct {
	// Name identifies the image in diagnostics and on accept. It carries no
	// matching semantics.
	Name string

	// Digest is the SNP LAUNCH_DIGEST or the TDX MRTD.
	Digest []byte

	// RTMRs pins TDX runtime measurement registers by index. An absent index
	// is unchecked; an all-zero value pins the register to zero.
	RTMRs map[int][]byte
}

// ReferenceValues is what a verifier compares evidence against: the images an
// inbound gate accepts. Gates that cannot express a tuple flatten these back
// to the flat shapes, so none is left reading a form the operator did not set.
type ReferenceValues struct {
	// TEE is the declared platform.
	TEE string

	// Entries are the accepted images. Empty means the set pins nothing.
	Entries []Entry
}

// Empty reports whether the set pins nothing, i.e. accepts any attested peer.
func (s ReferenceValues) Empty() bool { return len(s.Entries) == 0 }

// Digests returns every reference launch digest, for gates that match on
// the digest alone.
func (s ReferenceValues) Digests() [][]byte {
	out := make([][]byte, 0, len(s.Entries))
	for _, e := range s.Entries {
		out = append(out, e.Digest)
	}
	return out
}

// DigestSet returns the pinned digests as lowercase hex, for gates that hold
// them as a string set.
func (s ReferenceValues) DigestSet() map[string]bool {
	out := make(map[string]bool, len(s.Entries))
	for _, e := range s.Entries {
		out[hex.EncodeToString(e.Digest)] = true
	}
	return out
}

// CommonRTMRs returns the RTMR pins shared by every entry, and whether the
// entries agree. Gates that cannot express per-entry tuples take this; when
// ok is false they must say so rather than silently dropping the pins.
func (s ReferenceValues) CommonRTMRs() (map[int][]byte, bool) {
	if len(s.Entries) == 0 {
		return nil, true
	}
	first := s.Entries[0].RTMRs
	for _, e := range s.Entries[1:] {
		if !sameRTMRs(first, e.RTMRs) {
			return nil, false
		}
	}
	return first, true
}

func sameRTMRs(a, b map[int][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for idx, want := range a {
		got, ok := b[idx]
		if !ok || !bytes.Equal(got, want) {
			return false
		}
	}
	return true
}

// HexDigests returns the pinned digests as lowercase hex, for the flag and
// values shapes that carry a plain list.
func (s ReferenceValues) HexDigests() []string {
	out := make([]string, 0, len(s.Entries))
	for _, e := range s.Entries {
		out = append(out, hex.EncodeToString(e.Digest))
	}
	return out
}

// FromFlags converts the legacy flat pins into entries: every digest carries
// the same RTMR map, which is what the flat form enforced. Registers pinned
// without any digest have no entry form and stay on the flat path.
func FromFlags(digests [][]byte, rtmrs map[int][]byte) ReferenceValues {
	entries := make([]Entry, 0, len(digests))
	for _, d := range digests {
		// Each entry owns its map: callers mutate policy pins in place.
		own := make(map[int][]byte, len(rtmrs))
		for i, v := range rtmrs {
			own[i] = v
		}
		if len(own) == 0 {
			own = nil
		}
		entries = append(entries, Entry{Digest: d, RTMRs: own})
	}
	return ReferenceValues{Entries: entries}
}

// Load reads and validates a measurements config file. A missing or malformed
// file is an error, never an empty policy: the caller asked for pinning.
func Load(path string) (ReferenceValues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("read measurements config: %w", err)
	}
	s, err := Parse(data)
	if err != nil {
		return ReferenceValues{}, fmt.Errorf("measurements config %s: %w", path, err)
	}
	return s, nil
}

// Format renders a set as a measurements config document. The result is
// re-parsed by the caller, so a set that formats is a set that loads.
func Format(s ReferenceValues) ([]byte, error) {
	f := wire{SchemaVersion: SchemaVersion1, TEE: s.TEE}
	for _, e := range s.Entries {
		we := wireEntry{Name: e.Name}
		d := hex.EncodeToString(e.Digest)
		switch s.TEE {
		case TEESNP:
			we.Measurement = &d
		case TEETDX:
			we.MRTD = &d
			if len(e.RTMRs) > 0 {
				we.RTMR = make([]*string, MaxRTMRs)
				for idx, v := range e.RTMRs {
					h := hex.EncodeToString(v)
					we.RTMR[idx] = &h
				}
			}
		default:
			return nil, fmt.Errorf("tee %q, want %q or %q", s.TEE, TEESNP, TEETDX)
		}
		f.Measurements = append(f.Measurements, we)
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode measurements config: %w", err)
	}
	return append(out, '\n'), nil
}

// wire mirrors the file exactly; validation happens against these fields so an
// absent value stays distinguishable from an empty one.
type wire struct {
	SchemaVersion string      `json:"schema_version"`
	TEE           string      `json:"tee"`
	Measurements  []wireEntry `json:"measurements"`
}

type wireEntry struct {
	Name        string    `json:"name"`
	Measurement *string   `json:"measurement,omitempty"`
	MRTD        *string   `json:"mrtd,omitempty"`
	RTMR        []*string `json:"rtmr,omitempty"`
}

// Parse validates a measurements config document. Parsing and linting are the
// same strictness, so a file that lints clean is the file every component
// loads.
func Parse(data []byte) (ReferenceValues, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return ReferenceValues{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f wire
	if err := dec.Decode(&f); err != nil {
		return ReferenceValues{}, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return ReferenceValues{}, fmt.Errorf("trailing data after the JSON object")
	}
	return f.validate()
}

func (f wire) validate() (ReferenceValues, error) {
	if f.SchemaVersion != SchemaVersion1 {
		return ReferenceValues{}, fmt.Errorf("schema_version %q, want %q", f.SchemaVersion, SchemaVersion1)
	}
	if f.TEE != TEESNP && f.TEE != TEETDX {
		return ReferenceValues{}, fmt.Errorf("tee %q, want %q or %q", f.TEE, TEESNP, TEETDX)
	}
	// An empty list would pin nothing while reading as a pinned config;
	// omitting the flag is how an operator asks for no pinning.
	if len(f.Measurements) == 0 {
		return ReferenceValues{}, fmt.Errorf("measurements is empty: a config file must pin at least one image")
	}

	set := ReferenceValues{TEE: f.TEE, Entries: make([]Entry, 0, len(f.Measurements))}
	names := make(map[string]bool, len(f.Measurements))
	tuples := make(map[string]int, len(f.Measurements))
	for i, we := range f.Measurements {
		e, err := we.validate(f.TEE, i)
		if err != nil {
			return ReferenceValues{}, err
		}
		if names[e.Name] {
			return ReferenceValues{}, fmt.Errorf("measurements[%d]: duplicate name %q", i, e.Name)
		}
		names[e.Name] = true
		key := tupleKey(e)
		if prev, dup := tuples[key]; dup {
			return ReferenceValues{}, fmt.Errorf("measurements[%d] pins the same tuple as measurements[%d]", i, prev)
		}
		tuples[key] = i
		set.Entries = append(set.Entries, e)
	}
	return set, nil
}

func (we wireEntry) validate(tee string, i int) (Entry, error) {
	at := fmt.Sprintf("measurements[%d]", i)
	if strings.TrimSpace(we.Name) == "" {
		return Entry{}, fmt.Errorf("%s: name is required", at)
	}
	e := Entry{Name: we.Name}

	switch tee {
	case TEESNP:
		if we.MRTD != nil || we.RTMR != nil {
			return Entry{}, fmt.Errorf("%s: mrtd and rtmr are tdx fields, but tee is %q", at, TEESNP)
		}
		if we.Measurement == nil {
			return Entry{}, fmt.Errorf("%s: measurement is required", at)
		}
		d, err := decodeRegister(*we.Measurement)
		if err != nil {
			return Entry{}, fmt.Errorf("%s.measurement: %w", at, err)
		}
		e.Digest = d
	case TEETDX:
		if we.Measurement != nil {
			return Entry{}, fmt.Errorf("%s: measurement is a sev-snp field, but tee is %q", at, TEETDX)
		}
		if we.MRTD == nil {
			return Entry{}, fmt.Errorf("%s: mrtd is required", at)
		}
		d, err := decodeRegister(*we.MRTD)
		if err != nil {
			return Entry{}, fmt.Errorf("%s.mrtd: %w", at, err)
		}
		e.Digest = d
		rtmrs, err := decodeRTMRs(we.RTMR, at)
		if err != nil {
			return Entry{}, err
		}
		e.RTMRs = rtmrs
	}
	return e, nil
}

func decodeRTMRs(raw []*string, at string) (map[int][]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > MaxRTMRs {
		return nil, fmt.Errorf("%s.rtmr has %d entries, want at most %d", at, len(raw), MaxRTMRs)
	}
	out := make(map[int][]byte, len(raw))
	for idx, v := range raw {
		if v == nil {
			continue
		}
		// RTMR[0] mixes the TD HOB and VMM ACPI tables, so it varies with the
		// VM shape and can never be pinned to a stable value.
		if idx == 0 {
			return nil, fmt.Errorf("%s.rtmr[0]: must be null — RTMR[0] varies with vCPU and memory shape", at)
		}
		if *v == "" {
			out[idx] = make([]byte, DigestSize)
			continue
		}
		d, err := decodeRegister(*v)
		if err != nil {
			return nil, fmt.Errorf("%s.rtmr[%d]: %w", at, idx, err)
		}
		out[idx] = d
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// decodeRegister requires lowercase hex of exactly one register width.
// Uppercase is rejected rather than folded so one register has one spelling.
func decodeRegister(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, fmt.Errorf("%q is not lowercase hex", s)
	}
	if len(s) != hex.EncodedLen(DigestSize) {
		return nil, fmt.Errorf("is %d hex chars, want %d", len(s), hex.EncodedLen(DigestSize))
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("is not hex: %w", err)
	}
	return d, nil
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
