package allowlist

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// client wraps allowlistclient.Client with a bounded retry of transient
// transport failures. Each attempt re-runs the wrapped call, so writes
// re-mint their operator token.
type client struct {
	api    allowlistclient.Client
	stderr io.Writer
}

// Four attempts with doubling waits covers the <=3 consecutive transient
// failures seen in e2e. retryDelay is a var only so tests can shorten it.
const retryAttempts = 4

var retryDelay = time.Second

func (c client) List(ctx context.Context) (al *pkgallowlist.Allowlist, version string, err error) {
	err = c.retry(ctx, func() error {
		al, version, err = c.api.List(ctx)
		return err
	})
	return al, version, err
}

func (c client) AddDigest(ctx context.Context, digest types.Digest, image string, auth allowlistclient.Authorizer) error {
	return c.retry(ctx, func() error { return c.api.AddDigest(ctx, digest, image, auth) })
}

func (c client) DeleteDigests(ctx context.Context, digests []types.Digest, auth allowlistclient.Authorizer) error {
	return c.retry(ctx, func() error { return c.api.DeleteDigests(ctx, digests, auth) })
}

func (c client) ReplaceAll(ctx context.Context, al *pkgallowlist.Allowlist, auth allowlistclient.Authorizer) error {
	return c.retry(ctx, func() error { return c.api.ReplaceAll(ctx, al, auth) })
}

func (c client) PutWorkload(ctx context.Context, name string, w pkgallowlist.Workload, auth allowlistclient.Authorizer) error {
	return c.retry(ctx, func() error { return c.api.PutWorkload(ctx, name, w, auth) })
}

func (c client) DeleteWorkload(ctx context.Context, name string, auth allowlistclient.Authorizer) error {
	return c.retry(ctx, func() error { return c.api.DeleteWorkload(ctx, name, auth) })
}

// retry runs op, retrying only transient transport failures.
func (c client) retry(ctx context.Context, op func() error) error {
	delay := retryDelay
	for attempt := 1; ; attempt++ {
		err := op()
		if err == nil || attempt == retryAttempts || ctx.Err() != nil || !isTransient(err) {
			return err
		}
		fmt.Fprintf(c.stderr, "transient CDS connection failure (attempt %d/%d), retrying in %s: %v\n", attempt, retryAttempts, delay, err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// isTransient matches failed collateral fetches and transport-level failures
// only: never an HTTP status error, never an attestation verdict.
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	var pv *localverify.PeerVerificationError
	if errors.As(err, &pv) {
		var ce *localverify.CollateralError
		return errors.As(err, &ce)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	// net/http reports a close it observed while the connection was idle with
	// an unexported error that wraps nothing; match its fixed text.
	if strings.HasSuffix(err.Error(), "http: server closed idle connection") {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
