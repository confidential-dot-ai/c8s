package httputil

import (
	"context"
	"errors"
	"net"
	"net/url"
	"syscall"
	"time"
)

// RetryConnectionRefused retries an HTTP operation after a refused transport
// dial. HTTP responses and TLS verification failures are final. timeout sets
// each attempt's context deadline; wait bounds retries, with zero making one
// attempt. The caller context cancels retry sleeps and is inherited by each
// attempt. The operation must honor its supplied context for cancellation and
// deadlines to stop ongoing work.
func RetryConnectionRefused(ctx context.Context, timeout, wait time.Duration, operation func(context.Context) error) error {
	deadline := time.Now().Add(wait)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		stepCtx, cancel := context.WithTimeout(ctx, timeout)
		err := operation(stepCtx)
		cancel()
		if !shouldRetryConnectionRefused(err, deadline) {
			return err
		}
		timer := time.NewTimer(min(5*time.Second, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			if !time.Now().Before(deadline) {
				return err
			}
		}
	}
}

func shouldRetryConnectionRefused(err error, deadline time.Time) bool {
	if !time.Now().Before(deadline) {
		return false
	}
	var requestErr *url.Error
	if !errors.As(err, &requestErr) {
		return false
	}
	// Require a URL error whose immediate cause is a refused dial. An
	// intermediate verification-error wrapper does not establish that the
	// target listener is starting.
	dialErr, ok := requestErr.Err.(*net.OpError)
	return ok && dialErr.Op == "dial" && errors.Is(dialErr.Err, syscall.ECONNREFUSED)
}
