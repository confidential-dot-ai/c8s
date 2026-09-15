package readutil

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"
)

func TestReadAllBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limit       int64
		tooLarge    bool
	}{
		{"empty", "", 4, false},
		{"below", "abc", 4, false},
		{"exact", "abcd", 4, false},
		{"above", "abcde", 4, true},
		{"zero empty", "", 0, false},
		{"zero nonempty", "a", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := ReadAll(strings.NewReader(tc.input), tc.limit)
			if tc.tooLarge {
				if !errors.Is(err, ErrTooLarge) || body != nil {
					t.Fatalf("overflow = %q, %v", body, err)
				}
			} else if err != nil || body == nil || string(body) != tc.input {
				t.Fatalf("read = %q, %v; want %q", body, err, tc.input)
			}
		})
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestReadAllStopsAfterOverflowByte(t *testing.T) {
	var read int
	endless := readerFunc(func(p []byte) (int, error) {
		read += len(p)
		return len(p), nil
	})
	body, err := ReadAll(endless, 4096)
	if body != nil || !errors.Is(err, ErrTooLarge) || read != 4097 {
		t.Fatalf("read = %d bytes, body length = %d, error = %v", read, len(body), err)
	}
}

func TestReadAllPreservesReadErrors(t *testing.T) {
	cause := errors.New("broken stream")
	failure := fmt.Errorf("reader: %w", cause)
	for _, input := range []string{"", "abc", "abcd", "abcde"} {
		t.Run(input, func(t *testing.T) {
			r := readerFunc(func(p []byte) (int, error) {
				return copy(p, input), failure
			})
			body, err := ReadAll(r, 4)
			if body != nil || err != failure || !errors.Is(err, cause) {
				t.Fatalf("read = %q, %v; want original read error", body, err)
			}
		})
	}
}

func TestReadAllDataWithEOF(t *testing.T) {
	for _, input := range []string{"abcd", "abcde"} {
		r := readerFunc(func(p []byte) (int, error) { return copy(p, input), io.EOF })
		body, err := ReadAll(r, 4)
		if len(input) == 4 {
			if err != nil || string(body) != input {
				t.Fatalf("exact body with EOF = %q, %v", body, err)
			}
		} else if body != nil || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("overflow with EOF = %q, %v", body, err)
		}
	}
}

func TestReadAllInvalidLimitsDoNotRead(t *testing.T) {
	r := readerFunc(func([]byte) (int, error) {
		t.Fatal("read with invalid limit")
		return 0, io.EOF
	})
	for _, limit := range []int64{-1, math.MinInt64, math.MaxInt64} {
		if body, err := ReadAll(r, limit); err == nil || body != nil {
			t.Fatalf("limit %d: got %q, %v", limit, body, err)
		}
	}
}
