package ratls

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestOwnTuplePins(t *testing.T) {
	reg := func(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 48) }
	stub, url := testattest.NewUnix(t)
	stub.SetPlatform(types.PlatformTdx)
	stub.SetVerdict(testattest.TDXVerdict(reg(0x11), map[int]string{0: reg(0x00), 1: reg(0x21), 2: reg(0x22), 3: reg(0x33)}))

	pins, err := OwnTuplePins(t.Context(), attestationclient.NewClient(url))
	if err != nil {
		t.Fatalf("OwnTuplePins() = %v, want nil", err)
	}
	if len(pins.Entries) != 1 || len(pins.Measurements) != 0 || len(pins.RTMRs) != 0 {
		t.Fatalf("OwnTuplePins() = %+v, want exactly one entry and no loose pins", pins)
	}
	entry := pins.Entries[0]
	if hex.EncodeToString(entry.Digest) != reg(0x11) || len(entry.RTMRs) != 3 || !bytes.Equal(entry.RTMRs[3], bytes.Repeat([]byte{0x33}, 48)) {
		t.Fatalf("OwnTuplePins() entry = digest %x, %d RTMRs; want MRTD %s and RTMR[1..3]", entry.Digest, len(entry.RTMRs), reg(0x11))
	}

	// The round trip runs under the caller's context: a cancelled caller is
	// not held to OwnTupleTimeout.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := OwnTuplePins(ctx, attestationclient.NewClient(url)); !errors.Is(err, context.Canceled) {
		t.Fatalf("OwnTuplePins(cancelled) = %v, want %v", err, context.Canceled)
	}
}
