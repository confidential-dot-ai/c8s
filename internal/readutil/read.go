// Package readutil reads complete documents with a byte limit.
package readutil

import (
	"errors"
	"fmt"
	"io"
	"math"
)

// ErrTooLarge reports a document exceeding its byte limit.
var ErrTooLarge = errors.New("document exceeds byte limit")

// ReadAll reads at most maxBytes+1 bytes and returns no data on failure.
// Read errors take precedence over overflow. The caller owns the reader.
func ReadAll(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return nil, fmt.Errorf("invalid byte limit %d", maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, ErrTooLarge
	}
	return body, nil
}
