package ratls

import (
	"context"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
)

// OwnTuplePins holds a peer to this node's own image tuple {MRTD, RTMR1,
// RTMR2, RTMR3}, read from a fresh quote through client.OwnTupleEntry under
// attestationclient.OwnTupleTimeout. A sealed node's argv carries no
// per-cluster digest, and the tuple includes RTMR[3], so a peer on an
// unsealed node of the same image is refused.
func OwnTuplePins(ctx context.Context, client attestationclient.Client) (Pins, error) {
	ctx, cancel := context.WithTimeout(ctx, attestationclient.OwnTupleTimeout)
	defer cancel()
	entry, err := client.OwnTupleEntry(ctx)
	if err != nil {
		return Pins{}, err
	}
	return Pins{Entries: []measurements.Entry{entry}}, nil
}
