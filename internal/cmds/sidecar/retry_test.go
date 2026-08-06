package sidecar

import (
	"context"
	"testing"
)

func retryConfig() Config {
	cfg := testConfig("https://cds.example")
	cfg.Attempts = 3
	return cfg
}

func TestRetryRecoversOnceReleased(t *testing.T) {
	var calls int
	err := Retry(context.Background(), retryConfig(), "volume", func(context.Context) error {
		calls++
		if calls < 3 {
			return errNotYet
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if calls != 3 {
		t.Fatalf("attempted %d times, want 3", calls)
	}
}

func TestRetryGivesUp(t *testing.T) {
	cfg := retryConfig()
	var calls int
	err := Retry(context.Background(), cfg, "volume", func(context.Context) error {
		calls++
		return errNotYet
	})
	if err == nil {
		t.Fatal("retry never gave up")
	}
	if calls != cfg.Attempts {
		t.Fatalf("attempted %d times, want %d", calls, cfg.Attempts)
	}
}

func TestRetryStopsWhenTheContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Retry(ctx, retryConfig(), "volume", func(context.Context) error {
		return errNotYet
	})
	if err == nil {
		t.Fatal("retry ignored a cancelled context")
	}
}

var errNotYet = &notYetError{}

type notYetError struct{}

func (*notYetError) Error() string { return "not released yet" }
