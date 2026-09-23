package policystate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Protocol identifies the journal entry, state statement, challenge and
// participant message format. Parsers reject any other value.
const Protocol = "c8s.policystate/v1"

// MaxCounter is the exclusive upper bound on every protocol counter: versions,
// positions and instance counts. It is 2^53, the largest integer a JavaScript
// verifier reads without loss, and Canonical enforces it on every number.
const MaxCounter uint64 = 1 << 53

// Canonical returns the canonical JSON encoding of v: object keys sorted
// bytewise, no insignificant whitespace, HTML characters verbatim, and only
// the escapes JSON requires.
//
// It works on the parse tree rather than on v's struct layout, so field order
// and the marshaller's HTML escaping cannot reach the bytes that get hashed,
// and an implementation in another language reproduces the result from the
// same JSON value.
//
// It rejects any non-integer number and any integer of magnitude MaxCounter or
// more, which is where the "no floats, JS-safe counters" rule is enforced.
func Canonical(v any) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	dec := json.NewDecoder(&raw)
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("canonical: reparse: %w", err)
	}
	return appendValue(nil, tree)
}

// Decode parses one protocol object strictly: unknown fields and trailing data
// are errors. Every parse of a value that will be hashed, signed or trusted
// goes through it, because a lossy parse would let a peer hide a field from
// the verifier that the signer covered.
func Decode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode: trailing data after the JSON value")
	}
	return nil
}

func appendValue(dst []byte, v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		return strconv.AppendBool(dst, t), nil
	case json.Number:
		return appendNumber(dst, t)
	case string:
		return appendString(dst, t), nil
	case []any:
		dst = append(dst, '[')
		for i, elem := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendValue(dst, elem); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = append(appendString(dst, k), ':')
			var err error
			if dst, err = appendValue(dst, t[k]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, fmt.Errorf("canonical: unsupported JSON value of type %T", v)
	}
}

// appendNumber writes an integer and rejects everything else. A float in a
// protocol object is a bug that would make two honest implementations disagree
// on the bytes to hash, so it fails loudly rather than round to something.
func appendNumber(dst []byte, n json.Number) ([]byte, error) {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return nil, fmt.Errorf("canonical: %s is not an integer", s)
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		if _, uerr := strconv.ParseUint(s, 10, 64); uerr == nil {
			return nil, fmt.Errorf("canonical: integer %s is at or above 2^53", s)
		}
		return nil, fmt.Errorf("canonical: %s is not a representable integer", s)
	}
	if v >= int64(MaxCounter) || v <= -int64(MaxCounter) {
		return nil, fmt.Errorf("canonical: integer %s is at or above 2^53 in magnitude", s)
	}
	return append(dst, s...), nil
}

const hexDigits = "0123456789abcdef"

// appendString writes a JSON string with the mandatory escapes only. Go's own
// encoder escapes U+2028 and U+2029 even with HTML escaping off; JSON.stringify
// does not, so emitting them verbatim is what keeps the vectors cross-language.
func appendString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for _, r := range s {
		switch r {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if r < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[r>>4], hexDigits[r&0xf])
				continue
			}
			dst = utf8.AppendRune(dst, r)
		}
	}
	return append(dst, '"')
}
